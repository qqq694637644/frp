package xtcpdatagram

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

func loopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return port
}

func addr(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func TestValidate(t *testing.T) {
	for _, cfg := range []*Config{
		{ListenAddr: "0.0.0.0:9000", PeerAddr: "127.0.0.1:9001"},
		{ListenAddr: "127.0.0.1:9000", PeerAddr: "127.0.0.1:9000"},
		{ListenAddr: "localhost:9000", PeerAddr: "127.0.0.1:9001"},
		{ListenAddr: "127.0.0.1:0", PeerAddr: "127.0.0.1:9001"},
		{ListenAddr: "127.0.0.1:9000", PeerAddr: ""},
	} {
		if err := Validate(cfg); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
	if err := Validate(&Config{ListenAddr: "127.0.0.1:9000", PeerAddr: "127.0.0.1:9001"}); err != nil {
		t.Fatal(err)
	}
}

func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xtcp-test"}},
		&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "xtcp-test"}},
		&key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"frp"},
	}
}

func TestActualQUICDatagramAndTCPStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	listenerUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listenerUDP.Close()
	ql, err := quic.Listen(listenerUDP, testTLS(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ql.Close()
	accepted := make(chan *quic.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, e := ql.Accept(ctx)
		if e != nil {
			acceptErr <- e
			return
		}
		accepted <- c
	}()
	visitorUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer visitorUDP.Close()
	visitorQUIC, err := quic.Dial(ctx, visitorUDP, ql.Addr(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"frp"}}, // test-only cert
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer visitorQUIC.CloseWithError(0, "")
	var proxyQUIC *quic.Conn
	select {
	case proxyQUIC = <-accepted:
	case err = <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer proxyQUIC.CloseWithError(0, "")
	for _, conn := range []*quic.Conn{visitorQUIC, proxyQUIC} {
		state := conn.ConnectionState().SupportsDatagrams
		if !state.Local || !state.Remote {
			t.Fatalf("DATAGRAM not negotiated: %+v", state)
		}
	}

	// Each app owns a fixed UDP socket used for both sending and receiving.
	nodeApp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeApp.Close()
	exitApp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer exitApp.Close()
	nodePort := loopbackPort(t)
	exitPort := loopbackPort(t)
	nodeBridge, err := Start(ctx, proxyQUIC,
		&Config{ListenAddr: addr(nodePort), PeerAddr: nodeApp.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeBridge.Close()
	exitBridge, err := Start(ctx, visitorQUIC,
		&Config{ListenAddr: addr(exitPort), PeerAddr: exitApp.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer exitBridge.Close()

	packet := bytes.Repeat([]byte("a-udp-datagram"), 70)
	for _, tc := range []struct {
		src  *net.UDPConn
		dest *net.UDPConn
		port int
	}{
		{nodeApp, exitApp, nodePort},
		{exitApp, nodeApp, exitPort},
	} {
		if _, err := tc.src.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tc.port}); err != nil {
			t.Fatal(err)
		}
		if err := tc.dest.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 2048)
		n, _, err := tc.dest.ReadFromUDP(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:n], packet) {
			t.Fatal("QUIC DATAGRAM payload did not survive the local bridge")
		}
	}

	// The ordinary reliable XTCP TCP stream remains usable over the same QUIC.
	stream, err := visitorQUIC.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	// A newly opened QUIC stream is visible to AcceptStream after the first
	// STREAM frame is sent, not merely after OpenStreamSync returns.
	if _, err := stream.Write([]byte("xtcp-tcp-stream")); err != nil {
		t.Fatal(err)
	}
	proxyStream, err := proxyQUIC.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyStream.Close()
	got := make([]byte, 15)
	if _, err := proxyStream.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "xtcp-tcp-stream" {
		t.Fatalf("TCP stream corrupted: %q", got)
	}
}
