package socks5udp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5UDPAssociationOnlyUsesLoopbackRelay(t *testing.T) {
	for _, invalid := range []string{
		"", "udp://127.0.0.1:1080", "socks5://8.8.8.8:1080",
		"socks5://localhost:1080", "socks5://127.0.0.1:0",
		"socks5://127.0.0.1:1080/path",
	} {
		if err := ValidateURL(invalid); err == nil {
			t.Errorf("accepted unsafe socks proxy URL: %q", invalid)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	ready := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			ready <- e
			return
		}
		defer c.Close()
		buf := make([]byte, 3)
		if _, e = io.ReadFull(c, buf); e != nil {
			ready <- e
			return
		}
		if !bytes.Equal(buf, []byte{5, 1, 0}) {
			ready <- io.ErrUnexpectedEOF
			return
		}
		if _, e = c.Write([]byte{5, 0}); e != nil {
			ready <- e
			return
		}
		req := make([]byte, 10)
		if _, e = io.ReadFull(c, req); e != nil {
			ready <- e
			return
		}
		if !bytes.Equal(req[:4], []byte{5, 3, 0, 1}) {
			ready <- io.ErrUnexpectedEOF
			return
		}
		resp := []byte{5, 0, 0, 1, 127, 0, 0, 1}
		resp = binary.BigEndian.AppendUint16(resp, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		if _, e = c.Write(resp); e != nil {
			ready <- e
			return
		}
		ready <- nil
		_, _ = io.Copy(io.Discard, c)
	}()
	proxyURL := "socks5://" + listener.Addr().String()
	conn, err := Dial(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if e := <-ready; e != nil {
		t.Fatal(e)
	}
	remote := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 42), Port: 53}
	if _, err = conn.WriteToUDP([]byte("dns"), remote); err != nil {
		t.Fatal(err)
	}
	if err = relay.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, source, err := relay.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 198, 51, 100, 42, 0, 53, 'd', 'n', 's'}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("SOCKS5 request mismatch: %x", buf[:n])
	}
	if !source.IP.IsLoopback() {
		t.Fatal("UDP packet source is not loopback")
	}
	reply := append([]byte(nil), want...)
	copy(reply[10:], []byte("YES"))
	if _, err = relay.WriteToUDP(reply, source); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	n, addr, err := conn.ReadFromUDP(got)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != remote.String() || string(got[:n]) != "YES" {
		t.Fatalf("wrong SOCKS5 relay result: %s %q", addr, got[:n])
	}
	if _, err = conn.WriteTo([]byte("x"), &net.TCPAddr{}); err == nil {
		t.Fatal("accepted direct non-UDP socket destination")
	}
}

func TestSOCKS5ConnectionFailureDoesNotOpenDirectUDP(t *testing.T) {
	if _, err := Dial("socks5://127.0.0.1:1"); err == nil {
		t.Fatal("accepted unavailable WARP SOCKS5 proxy")
	}
}
