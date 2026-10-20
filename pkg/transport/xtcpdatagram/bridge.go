// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package xtcpdatagram relays local application UDP datagrams over an existing
// P2P QUIC connection. It never changes frps protocol messages or opens a new
// NAT-traversal socket. The local UDP socket carries application payloads,
// whereas the QUIC connection carries unreliable DATAGRAM frames.
package xtcpdatagram

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/apernet/quic-go"

	"github.com/fatedier/frp/pkg/diagnostics"
)

// MaxPayload is a conservative per-packet application payload limit.
// QUIC DATAGRAM does not fragment/reassemble application datagrams.
const MaxPayload = 1100

type DatagramConn interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

// Config is strictly loopback-only. An application binds its own UDP socket
// to PeerAddr, and sends from that same socket to ListenAddr. Datagram payloads
// (including any application session IDs) are opaque to frpc.
type Config struct {
	ListenAddr string `json:"listenAddr"`
	PeerAddr   string `json:"peerAddr"`
}

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

func parseLocalAddr(raw string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, fmt.Errorf("UDP endpoint %q: %w", raw, err)
	}
	if host != "127.0.0.1" {
		return nil, fmt.Errorf("UDP endpoint %q must bind to 127.0.0.1", raw)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("UDP endpoint %q requires port 1-65535", raw)
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: n}, nil
}

func Validate(c *Config) error {
	if c == nil {
		return nil
	}
	if _, err := parseLocalAddr(c.ListenAddr); err != nil {
		return fmt.Errorf("datagram.listenAddr: %w", err)
	}
	if _, err := parseLocalAddr(c.PeerAddr); err != nil {
		return fmt.Errorf("datagram.peerAddr: %w", err)
	}
	if c.ListenAddr == c.PeerAddr {
		return errors.New("datagram.listenAddr and datagram.peerAddr must differ")
	}
	return nil
}

type Bridge struct {
	socket *net.UDPConn
	peer   *net.UDPAddr
	conn   DatagramConn
	cancel context.CancelFunc
	once   sync.Once
}

// Start attaches to an existing P2P QUIC DATAGRAM-capable connection.
// Both UDP directions run concurrently until Close.
func Start(ctx context.Context, c DatagramConn, cfg *Config) (*Bridge, error) {
	if c == nil || cfg == nil {
		return nil, errors.New("nil QUIC datagram endpoint or config")
	}
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	addr, _ := parseLocalAddr(cfg.ListenAddr)
	peer, _ := parseLocalAddr(cfg.PeerAddr)
	socket, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("bind local datagram socket %s: %w", cfg.ListenAddr, err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	b := &Bridge{socket: socket, peer: peer, conn: c, cancel: cancel}
	go b.fromApplication(runCtx)
	go b.toApplication(runCtx)
	return b, nil
}

func (b *Bridge) Close() {
	b.once.Do(func() {
		b.cancel()
		_ = b.socket.Close()
	})
}

func (b *Bridge) fromApplication(ctx context.Context) {
	defer b.Close()
	buf := make([]byte, 65535)
	for {
		n, from, err := b.socket.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Only the configured local application may inject UDP.
		if !from.IP.Equal(b.peer.IP) || from.Port != b.peer.Port {
			diagnostics.Drop(b.conn, "wrong_local_peer")
			continue
		}
		if n > MaxPayload {
			diagnostics.Drop(b.conn, "application_oversize")
			log.Printf("xtcp datagram: dropped %d-byte local packet (max %d)", n, MaxPayload)
			continue
		}
		// SendDatagram may queue data until packetization; the receive buffer
		// is reused for subsequent local application packets.
		if err = b.conn.SendDatagram(append([]byte(nil), buf[:n]...)); err != nil {
			// Packets exceeding the negotiated QUIC MTU are dropped rather
			// than silently converted into reliable streams.
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				diagnostics.Drop(b.conn, "path_mtu")
				log.Printf("xtcp datagram: packet exceeds QUIC path MTU: %v", err)
				continue
			}
			if ctx.Err() == nil {
				log.Printf("xtcp datagram: QUIC send failed: %v", err)
				diagnostics.Drop(b.conn, "quic_send")
			}
			return
		}
	}
}

func (b *Bridge) toApplication(ctx context.Context) {
	defer b.Close()
	for {
		packet, err := b.conn.ReceiveDatagram(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("xtcp datagram: QUIC receive stopped: %v", err)
			}
			return
		}
		if len(packet) > MaxPayload {
			diagnostics.Drop(b.conn, "remote_oversize")
			continue
		}
		if diagnostics.Datagram(b.conn, packet) {
			continue
		}
		if _, err := b.socket.WriteToUDP(packet, b.peer); err != nil {
			diagnostics.Drop(b.conn, "local_delivery")
			return
		}
	}
}
