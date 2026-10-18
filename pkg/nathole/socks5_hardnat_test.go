package nathole

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport/socks5udp"
)

// fakeNATHoleSOCKS5 implements independent loopback-only SOCKS5 UDP
// ASSOCIATE sessions, including the ATYP=IPv6, BND.ADDR=:: response observed
// from the real WARP service. All UDP destinations in this test are loopback.
type fakeNATHoleSOCKS5 struct {
	listener net.Listener
	accepted atomic.Int32
	active   atomic.Int32
	limit    int32
	wg       sync.WaitGroup
}

func startFakeNATHoleSOCKS5(t *testing.T, limit int32) *fakeNATHoleSOCKS5 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeNATHoleSOCKS5{listener: listener, limit: limit}
	p.wg.Go(func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			p.wg.Go(func() {
				p.handle(c)
			})
		}
	})
	t.Cleanup(func() {
		_ = p.listener.Close()
		p.wg.Wait()
	})
	return p
}

func (p *fakeNATHoleSOCKS5) handle(control net.Conn) {
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	var greeting [3]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || !bytes.Equal(greeting[:], []byte{5, 1, 0}) {
		return
	}
	if _, err := control.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [10]byte
	if _, err := io.ReadFull(control, request[:]); err != nil || !bytes.Equal(request[:4], []byte{5, 3, 0, 1}) {
		return
	}
	count := p.accepted.Add(1)
	if p.limit > 0 && count > p.limit {
		_, _ = control.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0})
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer relay.Close()
	reply := []byte{5, 0, 0, 4}
	reply = append(reply, net.IPv6zero...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
	if _, err := control.Write(reply); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	p.active.Add(1)
	defer p.active.Add(-1)

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		var client *net.UDPAddr
		buffer := make([]byte, 2048)
		for {
			n, src, err := relay.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if client == nil {
				if n < 10 || !bytes.Equal(buffer[:4], []byte{0, 0, 0, 1}) {
					continue
				}
				client = src
			}
			if src.IP.Equal(client.IP) && src.Port == client.Port {
				if n < 10 || !bytes.Equal(buffer[:4], []byte{0, 0, 0, 1}) {
					continue
				}
				target := &net.UDPAddr{
					IP:   append(net.IP(nil), buffer[4:8]...),
					Port: int(binary.BigEndian.Uint16(buffer[8:10])),
				}
				if !target.IP.IsLoopback() {
					continue // test harness is strictly loopback
				}
				_, _ = relay.WriteToUDP(buffer[10:n], target)
			} else {
				frame := []byte{0, 0, 0, 1}
				frame = append(frame, src.IP.To4()...)
				frame = binary.BigEndian.AppendUint16(frame, uint16(src.Port))
				frame = append(frame, buffer[:n]...)
				_, _ = relay.WriteToUDP(frame, client)
			}
		}
	}()
	_, _ = io.Copy(io.Discard, control)
	_ = relay.Close()
	<-relayDone
}

func waitNATHoleProxyAssociations(t *testing.T, p *fakeNATHoleSOCKS5, expected int32) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if count := p.active.Load(); count == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d SOCKS5 associations alive, got %d", expected, p.active.Load())
}

func TestHardNATReceiverUsesWARPAssociations(t *testing.T) {
	for _, extra := range []int{8, 256} {
		t.Run(fmt.Sprintf("extra_%d", extra), func(t *testing.T) {
			proxy := startFakeNATHoleSOCKS5(t, 0)
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()

			secret := []byte("xtcp-hole-test-secret")
			sid := "test-hard-nat-sid"
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				buffer := make([]byte, 2048)
				for {
					n, src, err := peer.ReadFromUDP(buffer)
					if err != nil {
						return
					}
					var hole msg.NatHoleSid
					if err := DecodeMessageInto(buffer[:n], secret, &hole); err == nil && hole.Sid == sid {
						hole.Response = true
						reply, err := EncodeMessage(&hole, secret)
						if err == nil {
							_, _ = peer.WriteToUDP(reply, src)
						}
					} else if bytes.Equal(buffer[:n], []byte("quic-packet")) {
						_, _ = peer.WriteToUDP([]byte("quic-reply"), src)
					}
				}
			}()
			defer func() {
				_ = peer.Close()
				<-peerDone
			}()

			initial, err := socks5udp.Dial("socks5://" + proxy.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			winner, remote, err := MakeHole(ctx, initial, &msg.NatHoleResp{
				Sid:            sid,
				CandidateAddrs: []string{peer.LocalAddr().String()},
				DetectBehavior: msg.NatHoleDetectBehavior{
					Role:              DetectRoleReceiver,
					Mode:              DetectMode2,
					TTL:               7,
					ReadTimeoutMs:     9000,
					ListenRandomPorts: extra,
				},
			}, secret)
			if err != nil {
				t.Fatalf("WARP HardNAT %d extra ports: %v", extra, err)
			}
			defer winner.Close()
			if _, ok := winner.(*socks5udp.Conn); !ok {
				t.Fatalf("unexpected native UDP winner: %T", winner)
			}
			if remote.String() != peer.LocalAddr().String() {
				t.Fatalf("wrong peer: %v", remote)
			}
			if got := proxy.accepted.Load(); got != int32(extra+1) {
				t.Fatalf("expected %d WARP UDP ASSOCIATE sessions, got %d", extra+1, got)
			}
			waitNATHoleProxyAssociations(t, proxy, 1)
			if _, err := winner.WriteToUDP([]byte("quic-packet"), remote); err != nil {
				t.Fatal(err)
			}
			if err := winner.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 256)
			n, gotPeer, err := winner.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("WARP NAT-winning QUIC socket did not survive cleanup: %v", err)
			}
			if gotPeer.String() != remote.String() || string(buffer[:n]) != "quic-reply" {
				t.Fatalf("P2P QUIC socket lost relay framing: src=%v data=%q", gotPeer, buffer[:n])
			}
			_ = winner.Close()
			waitNATHoleProxyAssociations(t, proxy, 0)
		})
	}
}

func TestHardNATSOCKS5FailClosedAndCleansExtraSessions(t *testing.T) {
	t.Run("untrusted_association_count", func(t *testing.T) {
		proxy := startFakeNATHoleSOCKS5(t, 0)
		initial, err := socks5udp.Dial("socks5://" + proxy.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer initial.Close()
		_, _, err = MakeHole(context.Background(), initial, &msg.NatHoleResp{
			DetectBehavior: msg.NatHoleDetectBehavior{Role: DetectRoleReceiver, ListenRandomPorts: 257},
		}, []byte("key"))
		if err == nil || !strings.Contains(err.Error(), "limit 256") {
			t.Fatalf("untrusted frps count was not bounded: %v", err)
		}
		if proxy.accepted.Load() != 1 {
			t.Fatal("untrusted frps triggered additional UDP associations")
		}
	})
	t.Run("partial_SOCKS5_failure", func(t *testing.T) {
		proxy := startFakeNATHoleSOCKS5(t, 3)
		initial, err := socks5udp.Dial("socks5://" + proxy.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = MakeHole(context.Background(), initial, &msg.NatHoleResp{
			DetectBehavior: msg.NatHoleDetectBehavior{Role: DetectRoleReceiver, ListenRandomPorts: 8},
		}, []byte("key"))
		if err == nil || !strings.Contains(err.Error(), "WARP SOCKS5 UDP association 3/8") {
			t.Fatalf("did not fail closed after WARP session rejection: %v", err)
		}
		waitNATHoleProxyAssociations(t, proxy, 0)
	})
}
