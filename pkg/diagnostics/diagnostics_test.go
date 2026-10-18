package diagnostics

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
)

const testSecret = "diagnostics-test-key-only-32-characters"

func testHub() *Hub {
	return New(Config{Enabled: true, ListenAddr: "127.0.0.1:9320", Token: testSecret})
}

func request(h *Hub, method, path, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:45100"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, r)
	return w
}

func TestDiagnosticsValidationAuthenticationAndBounds(t *testing.T) {
	for _, c := range []Config{
		{Enabled: true, ListenAddr: "0.0.0.0:9000", Token: testSecret},
		{Enabled: true, ListenAddr: "localhost:9000", Token: testSecret},
		{Enabled: true, ListenAddr: "127.0.0.1:0", Token: testSecret},
		{Enabled: true, ListenAddr: "127.0.0.1:9320", Token: "short"},
	} {
		if c.Validate() == nil {
			t.Fatalf("invalid config accepted: %v", c.ListenAddr)
		}
	}
	h := testHub()
	if h.cfg.Validate() != nil {
		t.Fatal("valid config rejected")
	}
	if w := request(h, "GET", "/v1/snapshot", "incorrect", nil); w.Code != 401 {
		t.Fatalf("invalid token status %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/v1/snapshot", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set("Authorization", "Bearer "+testSecret)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("nonlocal HTTP caller accepted")
	}
	if w := request(h, "GET", "/v1/snapshot", testSecret, nil); w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatalf("snapshot failed %d: %s", w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/v1/capture", testSecret, []byte(`{"seconds":30}`)); w.Code != 200 {
		t.Fatal("capture start HTTP failed")
	}
	for range maxEvents + 25 {
		h.Event("proxy", "xtcp", "failed", "raw.example 192.0.2.1", time.Millisecond)
	}
	if len(h.Snapshot().Events) != maxEvents {
		t.Fatal("event ring unbounded")
	}
	if err := h.StartCapture(31); err == nil {
		t.Fatal("invalid capture interval accepted")
	}
	if _, err := h.Benchmark(context.Background(), 1_000_001, "download"); err == nil {
		t.Fatal("unbounded size accepted")
	}
	if _, err := h.Benchmark(context.Background(), 1_000_000, "invalid"); err == nil {
		t.Fatal("invalid direction accepted")
	}
}

func TestDiagnosticsStreamAccountingAndMissingValues(t *testing.T) {
	c := &connection{hub: testHub(), complete: true, ranges: map[uint64][]interval{}, drops: map[string]uint64{}}
	initial := c.snapshot()
	if initial.RTTMS != nil || initial.Cwnd != nil {
		t.Fatal("unobserved metrics reported as zero")
	}
	c.observeRange(1, 0, 100)
	c.observeRange(1, 100, 100)
	c.observeRange(1, 50, 100)
	c.observeRange(1, 300, 100)
	c.observeRange(1, 180, 140)
	if c.retrans != 140 || c.streamSent != 540 {
		t.Fatalf("stream overlap accounting = %d/%d, want 140/540", c.retrans, c.streamSent)
	}
	for i := uint64(2); i < 4100; i++ {
		c.observeRange(i, 0, 1)
	}
	v := c.snapshot()
	if v.RetransmissionComplete || v.StreamRetransmittedBytes != nil {
		t.Fatal("range capacity reported inaccurate retransmission count instead of unavailable")
	}
}

func TestDiagnosticsNativeQlogBoundedUnredacted(t *testing.T) {
	h := testHub()
	if err := h.StartCapture(30); err != nil {
		t.Fatal(err)
	}
	c := &connection{hub: h, id: "visitor:test-original-id", odcid: "test-original-id", role: "visitor"}
	c.captureEvent(qlog.ConnectionClosed{ApplicationError: ptr(qlog.ApplicationErrorCode(1)), Reason: "original.example 203.0.113.7:443"})
	h.StopCapture()
	files, status := h.CaptureData()
	if status == nil || status.State != "stopped" || len(files) != 1 {
		t.Fatal("capture did not retain events")
	}
	for _, text := range files {
		if !strings.Contains(text, "original.example 203.0.113.7:443") {
			t.Fatal("raw report was redacted")
		}
		for line := range bytes.SplitSeq([]byte(text), []byte{0x1e}) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			if !json.Valid(bytes.TrimSpace(line)) {
				t.Fatalf("invalid qlog JSON sequence %q", line)
			}
		}
	}
	if err := h.StartCapture(60); err != nil {
		t.Fatal(err)
	}
	recording := h.capture.Load()
	recording.mu.Lock()
	recording.status.Bytes = MaxCaptureBytes - 1
	recording.mu.Unlock()
	c.captureEvent(&qlog.ConnectionClosed{Reason: "size test"})
	if s := h.CaptureStatus(); s.State != "size_limit" || s.Complete {
		t.Fatal("capture did not stop at cap")
	}
}

func TestRawHeaderAuthenticationAndSize(t *testing.T) {
	var buf bytes.Buffer
	h := rawHeader{Kind: "upload", ID: newID(), Bytes: 1_000_000, Time: time.Now().Unix()}
	if err := sendHeader(&buf, testSecret, h); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), buf.Bytes()...)
	if _, err := readHeader(&buf, testSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := readHeader(bytes.NewReader(encoded), "wrong token"); err == nil {
		t.Fatal("forged diagnostic header accepted")
	}
	prefix := make([]byte, 8)
	copy(prefix, []byte(rawMagic))
	binary.BigEndian.PutUint32(prefix[4:], 1<<30)
	if _, err := readHeader(bytes.NewReader(prefix), testSecret); err == nil {
		t.Fatal("huge frame allocation accepted")
	}
}

func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "diagnostic-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"diag-test"}}
}

func realQUIC(t *testing.T) (*Hub, *Hub, *quic.Conn, *quic.Conn) {
	t.Helper()
	t.Setenv("QLOGDIR", "")
	ha, hb := testHub(), testHub()
	sa, sb := &Scope{role: "visitor", tag: "outside", hub: ha}, &Scope{role: "proxy", tag: "inside", hub: hb}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.Listen(socket, testTLS(t), &quic.Config{EnableDatagrams: true, Tracer: sb.Tracer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = socket.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSocket.Close() })
	accepted := make(chan *quic.Conn, 1)
	go func() {
		q, e := listener.Accept(ctx)
		if e == nil {
			accepted <- q
		}
	}()
	qa, err := quic.Dial(ctx, clientSocket, listener.Addr(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"diag-test"}},
		&quic.Config{EnableDatagrams: true, Tracer: sa.Tracer})
	if err != nil {
		t.Fatal(err)
	}
	var qb *quic.Conn
	select {
	case qb = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sa.Attach(qa, nil)
	sb.Attach(qb, nil)
	t.Cleanup(func() { _ = qa.CloseWithError(0, ""); _ = qb.CloseWithError(0, "") })
	for _, pair := range []struct {
		h *Hub
		q *quic.Conn
	}{{ha, qa}, {hb, qb}} {
		go func(h *Hub, q *quic.Conn) {
			for {
				p, err := q.ReceiveDatagram(q.Context())
				if err != nil {
					return
				}
				h.datagram(q, p)
			}
		}(pair.h, pair.q)
	}
	return ha, hb, qa, qb
}

func TestActualQUICDiagnosticsBothDirectionsAndCapture(t *testing.T) {
	ha, hb, qa, qb := realQUIC(t)
	if qa.Context().Err() != nil || qb.Context().Err() != nil {
		t.Fatal("QUIC connection unexpectedly closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := ha.StartCapture(30); err != nil {
		t.Fatal(err)
	}
	if err := hb.StartCapture(30); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"download", "upload"} {
		result, err := ha.Benchmark(ctx, 1_000_000, direction)
		if err != nil || !result.Verified || result.Bytes != 1_000_000 {
			t.Fatalf("%s raw QUIC result %+v: %v", direction, result, err)
		}
	}
	result, err := ha.UDPProbe(ctx)
	if err != nil || !result.Verified || result.Sent != 10 || result.Received != 10 {
		t.Fatalf("QUIC DATAGRAM test %+v: %v", result, err)
	}
	// Responses received while sending were timestamped at reception, not
	// later when drained from the result queue (~400ms after the first send).
	if len(result.RTTMS) != 10 {
		t.Fatal("missing RTT samples")
	}
	fast := 0
	for _, rtt := range result.RTTMS {
		if rtt < 300 {
			fast++
		}
	}
	if fast == 0 {
		t.Fatalf("UDP RTT contains application queue delay: %v", result.RTTMS)
	}
	for _, h := range []*Hub{ha, hb} {
		snapshot := h.Snapshot()
		if len(snapshot.Connections) != 1 {
			t.Fatal("missing actual QUIC identity")
		}
		c := snapshot.Connections[0]
		if c.SentBytes == 0 || c.ReceivedBytes == 0 || c.RTTMS == nil || c.Cwnd == nil {
			t.Fatalf("real metrics missing: %+v", c)
		}
		h.StopCapture()
		files, status := h.CaptureData()
		if len(files) == 0 || status.Bytes == 0 {
			t.Fatal("real QUIC qlog not generated")
		}
	}
}

type identity struct {
	q  *quic.Conn
	id uint64
}

func (i identity) DiagnosticQUIC() (*quic.Conn, uint64) { return i.q, i.id }
func TestSocketTupleCorrelationAndCancellation(t *testing.T) {
	ha, _, qa, _ := realQUIC(t)
	old := current.Swap(ha)
	defer current.Store(old)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	a, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	end := LinkTCP(identity{qa, 4}, b)
	values := url.Values{"local": {a.LocalAddr().String()}, "remote": {a.RemoteAddr().String()}}
	response := request(ha, http.MethodGet, "/v1/lookup?"+values.Encode(), testSecret, nil)
	if !strings.Contains(response.Body.String(), `"linked":true`) {
		t.Fatal(response.Body.String())
	}
	end()
	response = request(ha, http.MethodGet, "/v1/lookup?"+values.Encode(), testSecret, nil)
	if !strings.Contains(response.Body.String(), `"linked":false`) {
		t.Fatal("closed/reused tuple matched without time evidence")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ha.Benchmark(ctx, 50_000_000, "download"); err == nil {
		t.Fatal("cancelled benchmark succeeded")
	}
}

func BenchmarkTelemetryContiguousStream(b *testing.B) {
	c := &connection{complete: true, ranges: map[uint64][]interval{}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.observeRange(4, int64(i)*1200, 1200)
	}
}
