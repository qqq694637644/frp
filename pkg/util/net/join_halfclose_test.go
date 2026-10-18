package net

import (
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outbound := make(chan *net.TCPConn, 1)
	go func() {
		c, _ := listener.AcceptTCP()
		outbound <- c
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server := <-outbound
	return client, server
}

func TestJoinHalfClosePropagatesFINWithoutLosingDelayedResponse(t *testing.T) {
	leftPeer, leftBridge := tcpPair(t)
	rightPeer, rightBridge := tcpPair(t)
	defer leftPeer.Close()
	defer rightPeer.Close()
	defer leftBridge.Close()
	defer rightBridge.Close()
	for _, c := range []*net.TCPConn{leftPeer, rightPeer, leftBridge, rightBridge} {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	}

	done := make(chan error, 1)
	go func() {
		_, _, errs := JoinHalfClose(leftBridge, rightBridge)
		if len(errs) > 0 {
			done <- errs[0]
		} else {
			done <- nil
		}
	}()
	if _, err := leftPeer.Write([]byte("GET /\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := leftPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(rightPeer)
	if err != nil || string(request) != "GET /\r\n" {
		t.Fatalf("request EOF was not propagated: %q, %v", request, err)
	}
	// The left peer has already sent FIN, but the bridge must remain open
	// for a large response in the reverse direction.
	response := make([]byte, 1024*1024)
	for i := range response {
		response[i] = byte(i)
	}
	go func() {
		_, _ = rightPeer.Write(response)
		_ = rightPeer.CloseWrite()
	}()
	returned, err := io.ReadAll(leftPeer)
	if err != nil {
		t.Fatal(err)
	}
	if len(returned) != len(response) {
		t.Fatalf("received %d of %d response bytes after FIN", len(returned), len(response))
	}
	for i := range response {
		if returned[i] != response[i] {
			t.Fatalf("corrupted stream at %d", i)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("half-close bridge leaked a copy goroutine")
	}
}
