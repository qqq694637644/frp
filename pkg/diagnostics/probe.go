package diagnostics

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	quic "github.com/apernet/quic-go"
)

const (
	maxBenchmark = 50_000_000
	rawMagic     = "FDQ1"
)

type probeWait struct {
	ctx    context.Context
	result chan ProbeResult
}
type udpReply struct {
	packet   []byte
	received time.Time
}

type ProbeResult struct {
	State          string    `json:"state"`
	Kind           string    `json:"kind"`
	Direction      string    `json:"direction,omitempty"`
	ConnectionID   string    `json:"connection_id,omitempty"`
	Bytes          int64     `json:"bytes,omitempty"`
	DurationMS     float64   `json:"duration_ms,omitempty"`
	BytesPerSecond float64   `json:"bytes_per_second,omitempty"`
	Verified       bool      `json:"verified"`
	Error          string    `json:"error,omitempty"`
	Sent           int       `json:"sent,omitempty"`
	Received       int       `json:"received,omitempty"`
	LossPct        float64   `json:"loss_pct"`
	RTTMS          []float64 `json:"rtt_ms,omitempty"`
	JitterMS       float64   `json:"jitter_ms,omitempty"`
}
type rawHeader struct {
	Kind   string       `json:"kind"`
	ID     string       `json:"id"`
	Bytes  int64        `json:"bytes"`
	Time   int64        `json:"time"`
	Result *ProbeResult `json:"result,omitempty"`
}

func signed(secret string, data []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(data)
	return m.Sum(nil)
}

func sendHeader(w io.Writer, secret string, h rawHeader) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	for _, b := range [][]byte{[]byte(rawMagic), size[:], raw, signed(secret, raw)} {
		for len(b) > 0 {
			n, err := w.Write(b)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
	}
	return nil
}

func readHeader(r io.Reader, secret string) (rawHeader, error) {
	var h rawHeader
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return h, err
	}
	n := binary.BigEndian.Uint32(prefix[4:])
	if string(prefix[:4]) != rawMagic || n > 4096 || n == 0 {
		return h, errors.New("invalid diagnostic stream")
	}
	raw := make([]byte, n)
	var mac [32]byte
	if _, err := io.ReadFull(r, raw); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, mac[:]); err != nil {
		return h, err
	}
	if !hmac.Equal(mac[:], signed(secret, raw)) {
		return h, errors.New("invalid diagnostic stream HMAC")
	}
	if json.Unmarshal(raw, &h) != nil || len(h.ID) != 32 || h.Bytes < 0 || h.Bytes > maxBenchmark || math.Abs(float64(time.Now().Unix()-h.Time)) > 300 {
		return h, errors.New("invalid or stale diagnostic request")
	}
	return h, nil
}

func pattern() []byte {
	p := make([]byte, 32<<10)
	for i := range p {
		p[i] = byte(i % 251)
	}
	return p
}

func sendPayload(w io.Writer, n int64) error {
	p := pattern()
	hash := sha256.New()
	for n > 0 {
		k := min(n, int64(len(p)))
		chunk := p[:int(k)]
		written, err := w.Write(chunk)
		if written > 0 {
			_, _ = hash.Write(chunk[:written])
			n -= int64(written)
		}
		if err != nil {
			return err
		}
		if written != len(chunk) {
			return io.ErrShortWrite
		}
	}
	_, err := w.Write(hash.Sum(nil))
	return err
}

func readPayload(r io.Reader, n int64) (int64, error) {
	hash := sha256.New()
	received, err := io.CopyN(hash, r, n)
	if err != nil {
		return received, err
	}
	var expected [32]byte
	if _, err := io.ReadFull(r, expected[:]); err != nil {
		return received, err
	}
	if !hmac.Equal(expected[:], hash.Sum(nil)) {
		return received, errors.New("benchmark checksum mismatch")
	}
	return received, nil
}

func (c *connection) acceptDiagnostics() {
	sem := make(chan struct{}, 4)
	for {
		stream, err := c.q.AcceptUniStream(c.q.Context())
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				defer stream.CancelRead(0)
				_ = stream.SetReadDeadline(time.Now().Add(120 * time.Second))
				head, err := readHeader(stream, c.hub.cfg.Token)
				if err != nil {
					return
				}
				c.handleRaw(stream, head)
			}()
		default:
			stream.CancelRead(1)
		}
	}
}

func (c *connection) handleRaw(stream *quic.ReceiveStream, h rawHeader) {
	switch h.Kind {
	case "download":
		release, err := c.hub.exclusive()
		if err != nil {
			c.rawResult(h, ProbeResult{State: "failed", Error: err.Error()})
			return
		}
		defer release()
		s, err := c.q.OpenUniStreamSync(c.q.Context())
		if err != nil {
			return
		}
		defer s.Close()
		_ = s.SetWriteDeadline(time.Now().Add(120 * time.Second))
		if sendHeader(s, c.hub.cfg.Token, rawHeader{Kind: "data", ID: h.ID, Bytes: h.Bytes, Time: time.Now().Unix()}) == nil {
			_ = sendPayload(s, h.Bytes)
		}
	case "upload":
		release, err := c.hub.exclusive()
		if err != nil {
			c.rawResult(h, ProbeResult{State: "failed", Error: err.Error()})
			return
		}
		defer release()
		start := time.Now()
		n, err := readPayload(stream, h.Bytes)
		duration := time.Since(start)
		r := ProbeResult{
			State: "ok", Kind: "raw_quic", Direction: "upload", Bytes: n,
			DurationMS: float64(duration) / float64(time.Millisecond), Verified: err == nil,
		}
		if duration > 0 {
			r.BytesPerSecond = float64(n) / duration.Seconds()
		}
		if err != nil {
			r.State = "failed"
			r.Error = err.Error()
		}
		c.rawResult(h, r)
	case "data", "result":
		c.pendingMu.Lock()
		wait := c.pending[h.ID]
		c.pendingMu.Unlock()
		if wait == nil {
			return
		}
		stop := context.AfterFunc(wait.ctx, func() { stream.CancelRead(0) })
		defer stop()
		r := ProbeResult{State: "failed", Error: "missing probe result"}
		if h.Kind == "data" {
			start := time.Now()
			n, err := readPayload(stream, h.Bytes)
			d := time.Since(start)
			r = ProbeResult{State: "ok", Kind: "raw_quic", Direction: "download", Bytes: n, DurationMS: float64(d) / float64(time.Millisecond), Verified: err == nil}
			if d > 0 {
				r.BytesPerSecond = float64(n) / d.Seconds()
			}
			if err != nil {
				r.State = "failed"
				r.Error = err.Error()
			}
		} else if h.Result != nil {
			r = *h.Result
		}
		select {
		case wait.result <- r:
		default:
		}
	}
}

func (c *connection) rawResult(h rawHeader, r ProbeResult) {
	ctx, cancel := context.WithTimeout(c.q.Context(), 5*time.Second)
	defer cancel()
	s, err := c.q.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	defer s.Close()
	_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = sendHeader(s, c.hub.cfg.Token, rawHeader{Kind: "result", ID: h.ID, Time: time.Now().Unix(), Result: &r})
}

func (h *Hub) Benchmark(ctx context.Context, n int64, direction string) (ProbeResult, error) {
	if n != 1_000_000 && n != 10_000_000 && n != 50_000_000 {
		return ProbeResult{}, errors.New("test size must be 1, 10 or 50 MB")
	}
	if direction != "upload" && direction != "download" {
		return ProbeResult{}, errors.New("direction must be upload or download")
	}
	release, err := h.exclusive()
	if err != nil {
		return ProbeResult{}, err
	}
	defer release()
	c, err := h.activeConnection()
	if err != nil {
		return ProbeResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	h.probeMu.Lock()
	h.probeCancel = cancel
	h.probeMu.Unlock()
	defer func() { h.probeMu.Lock(); h.probeCancel = nil; h.probeMu.Unlock() }()
	id := newID()
	ch := make(chan ProbeResult, 1)
	c.pendingMu.Lock()
	c.pending[id] = &probeWait{ctx: ctx, result: ch}
	c.pendingMu.Unlock()
	defer func() { c.pendingMu.Lock(); delete(c.pending, id); c.pendingMu.Unlock() }()
	s, err := c.q.OpenUniStreamSync(ctx)
	if err != nil {
		return ProbeResult{}, err
	}
	deadline, _ := ctx.Deadline()
	_ = s.SetWriteDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { s.CancelWrite(0) })
	defer stop()
	if err = sendHeader(s, h.cfg.Token, rawHeader{Kind: direction, ID: id, Bytes: n, Time: time.Now().Unix()}); err == nil && direction == "upload" {
		err = sendPayload(s, n)
	}
	_ = s.Close()
	if err != nil {
		return ProbeResult{}, err
	}
	select {
	case r := <-ch:
		r.ConnectionID = c.id
		return r, nil
	case <-ctx.Done():
		return ProbeResult{}, fmt.Errorf("raw QUIC diagnostic unavailable or timed out: %w", ctx.Err())
	case <-c.q.Context().Done():
		return ProbeResult{}, errors.New("QUIC connection closed")
	}
}

// Reserved session ID zero prevents diagnostic DATAGRAMs from colliding with
// application traffic. Responses require a pending nonce and a valid HMAC.
func Datagram(q any, p []byte) bool {
	if len(p) < 8 || !bytes.Equal(p[:8], []byte{0, 0, 0, 0, 'R', 'D', 'G', '1'}) {
		return false
	}
	h := Current()
	if h == nil {
		return true
	}
	return h.datagram(q, p)
}

func (h *Hub) datagram(q any, p []byte) bool {
	c, ok := q.(*quic.Conn)
	if !ok || len(p) != 59 {
		return true
	}
	body, mac := p[:27], p[27:]
	if !hmac.Equal(mac, signed(h.cfg.Token, body)) {
		return true
	}
	id := hex.EncodeToString(p[9:25])
	flag := p[8]
	if flag == 0 {
		h.udpMu.Lock()
		sec := time.Now().Unix()
		if h.udpSecond != sec {
			h.udpSecond = sec
			h.udpRequests = 0
		}
		allowed := h.udpRequests < 32
		h.udpRequests++
		h.udpMu.Unlock()
		if !allowed {
			return true
		}
		reply := append([]byte(nil), body...)
		reply[8] = 1
		reply = append(reply, signed(h.cfg.Token, reply)...)
		_ = c.SendDatagram(reply)
		return true
	}
	if flag == 1 {
		h.udpMu.Lock()
		ch := h.udpPending[id]
		h.udpMu.Unlock()
		if ch != nil {
			select {
			case ch <- udpReply{append([]byte(nil), p...), time.Now()}:
			default:
			}
		}
	}
	return true
}

func (h *Hub) UDPProbe(ctx context.Context) (ProbeResult, error) {
	release, err := h.exclusive()
	if err != nil {
		return ProbeResult{}, err
	}
	defer release()
	c, err := h.activeConnection()
	if err != nil {
		return ProbeResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h.probeMu.Lock()
	h.probeCancel = cancel
	h.probeMu.Unlock()
	defer func() { h.probeMu.Lock(); h.probeCancel = nil; h.probeMu.Unlock() }()
	id := newID()
	nonce, _ := hex.DecodeString(id)
	ch := make(chan udpReply, 32)
	h.udpMu.Lock()
	h.udpPending[id] = ch
	h.udpMu.Unlock()
	defer func() { h.udpMu.Lock(); delete(h.udpPending, id); h.udpMu.Unlock() }()
	sentAt := make(map[uint16]time.Time)
	r := ProbeResult{State: "failed", Kind: "quic_datagram_echo", ConnectionID: c.id, RTTMS: []float64{}}
	for i := range 10 {
		p := append([]byte{0, 0, 0, 0, 'R', 'D', 'G', '1', 0}, nonce...)
		p = append(p, byte(i>>8), byte(i))
		p = append(p, signed(h.cfg.Token, p)...)
		sentAt[uint16(i)] = time.Now()
		if err := c.q.SendDatagram(p); err != nil {
			return r, err
		}
		r.Sent++
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
	seen := make(map[uint16]bool)
	for r.Received < r.Sent {
		select {
		case p := <-ch:
			seq := binary.BigEndian.Uint16(p.packet[25:27])
			at, ok := sentAt[seq]
			if !ok || seen[seq] {
				continue
			}
			seen[seq] = true
			r.Received++
			r.RTTMS = append(r.RTTMS, float64(p.received.Sub(at))/float64(time.Millisecond))
		case <-ctx.Done():
			r.LossPct = 100 * float64(r.Sent-r.Received) / float64(r.Sent)
			r.Error = "some DATAGRAM responses did not arrive"
			return r, nil
		case <-c.q.Context().Done():
			return r, errors.New("QUIC closed")
		}
	}
	r.State = "ok"
	r.Verified = true
	r.LossPct = 0
	if len(r.RTTMS) > 1 {
		v := append([]float64(nil), r.RTTMS...)
		sort.Float64s(v)
		r.JitterMS = v[len(v)-1] - v[0]
	}
	return r, nil
}
