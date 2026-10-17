// Copyright 2023 The frp Authors
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

package nathole

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatedier/golib/pool"
	"golang.org/x/net/ipv4"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/transport/socks5udp"
	"github.com/fatedier/frp/pkg/util/xlog"
)

var (
	// mode 0: simple detect mode, usually for both EasyNAT or HardNAT & EasyNAT(Public Network)
	// a. receiver sends detect message with low TTL
	// b. sender sends normal detect message to receiver
	// c. receiver receives detect message and sends back a message to sender
	//
	// mode 1: For HardNAT & EasyNAT, send detect messages to multiple guessed ports.
	// Usually applicable to scenarios where port changes are regular.
	// Most of the steps are the same as mode 0, but EasyNAT is fixed as the receiver and will send detect messages
	// with low TTL to multiple guessed ports of the sender.
	//
	// mode 2: For HardNAT & EasyNAT, ports changes are not regular.
	// a. HardNAT machine will listen on multiple ports and send detect messages with low TTL to EasyNAT machine
	// b. EasyNAT machine will send detect messages to random ports of HardNAT machine.
	//
	// mode 3: For HardNAT & HardNAT, both changes in the ports are regular.
	// Most of the steps are the same as mode 1, but the sender also needs to send detect messages to multiple guessed
	// ports of the receiver.
	//
	// mode 4: For HardNAT & HardNAT, one of the changes in the ports is regular.
	// Regular port changes are usually on the sender side.
	// a. Receiver listens on multiple ports and sends detect messages with low TTL to the sender's guessed range ports.
	// b. Sender sends detect messages to random ports of the receiver.
	SupportedModes = []int{DetectMode0, DetectMode1, DetectMode2, DetectMode3, DetectMode4}
	SupportedRoles = []string{DetectRoleSender, DetectRoleReceiver}

	DetectMode0        = 0
	DetectMode1        = 1
	DetectMode2        = 2
	DetectMode3        = 3
	DetectMode4        = 4
	DetectRoleSender   = "sender"
	DetectRoleReceiver = "receiver"

	// HardNAT mode 2/4 asks the receiver to open 256 additional UDP sockets.
	// A third-party frps must not be allowed to exhaust local SOCKS5
	// associations by asking the Visitor to open an arbitrary number.
	maxSOCKS5NATHoleAssociations = 256
)

// PrepareOptions defines options for NAT traversal preparation
type PrepareOptions struct {
	// DisableAssistedAddrs disables the use of local network interfaces
	// for assisted connections during NAT traversal
	DisableAssistedAddrs bool
	// UDPProxyURL forces Visitor STUN/hole punching and QUIC through SOCKS5
	// UDP ASSOCIATE, without opening a raw public UDP socket.
	UDPProxyURL string
}

// PacketConn is the subset used by XTCP NAT traversal and quic-go. The
// standard *net.UDPConn and the loopback-only SOCKS5 association both satisfy
// it. The latter can never send a packet directly to a public destination.
type PacketConn interface {
	net.PacketConn
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

type PrepareResult struct {
	Addrs         []string
	AssistedAddrs []string
	ListenConn    PacketConn
	NatType       string
	Behavior      string
}

// Each diagnostic counter is shared by the 257 concurrent receive workers.
// Counts describe successful local SOCKS5 I/O, not delivery across WARP.
type warpNATHoleDiagnostics struct {
	localWriteErrors atomic.Uint64
	decodeErrors     atomic.Uint64
	wrongSID         atomic.Uint64
	matchingSID      atomic.Uint64
	ignoredProbe     atomic.Uint64
}

// PreCheck is used to check if the proxy is ready for penetration.
// Call this function before calling Prepare to avoid unnecessary preparation work.
func PreCheck(
	ctx context.Context, transporter transport.MessageTransporter,
	proxyName string, timeout time.Duration,
) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var natHoleRespMsg *msg.NatHoleResp
	transactionID := NewTransactionID()
	m, err := transporter.Do(timeoutCtx, &msg.NatHoleVisitor{
		TransactionID: transactionID,
		ProxyName:     proxyName,
		PreCheck:      true,
	}, transactionID, msg.TypeNameNatHoleResp)
	if err != nil {
		return fmt.Errorf("get natHoleRespMsg error: %v", err)
	}
	mm, ok := m.(*msg.NatHoleResp)
	if !ok {
		return fmt.Errorf("get natHoleRespMsg error: invalid message type")
	}
	natHoleRespMsg = mm

	if natHoleRespMsg.Error != "" {
		return fmt.Errorf("%s", natHoleRespMsg.Error)
	}
	return nil
}

// Prepare is used to do some preparation work before penetration.
func Prepare(stunServers []string, opts PrepareOptions) (*PrepareResult, error) {
	if opts.UDPProxyURL != "" {
		return prepareThroughSOCKS5(stunServers, opts)
	}
	// discover for Nat type
	addrs, localAddr, err := Discover(stunServers, "")
	if err != nil {
		return nil, fmt.Errorf("discover error: %v", err)
	}
	if len(addrs) < 2 {
		return nil, fmt.Errorf("discover error: not enough addresses")
	}

	localIPs, _ := ListLocalIPsForNatHole(10)
	natFeature, err := ClassifyNATFeature(addrs, localIPs)
	if err != nil {
		return nil, fmt.Errorf("classify nat feature error: %v", err)
	}

	laddr, err := net.ResolveUDPAddr("udp4", localAddr.String())
	if err != nil {
		return nil, fmt.Errorf("resolve local udp addr error: %v", err)
	}
	listenConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen local udp addr error: %v", err)
	}

	// Apply NAT traversal options
	var assistedAddrs []string
	if !opts.DisableAssistedAddrs {
		assistedAddrs = make([]string, 0, len(localIPs))
		for _, ip := range localIPs {
			assistedAddrs = append(assistedAddrs, net.JoinHostPort(ip, strconv.Itoa(laddr.Port)))
		}
	}
	return &PrepareResult{
		Addrs:         addrs,
		AssistedAddrs: assistedAddrs,
		ListenConn:    listenConn,
		NatType:       natFeature.NatType,
		Behavior:      natFeature.Behavior,
	}, nil
}

// ExchangeInfo is used to exchange information between client and visitor.
// 1. Send input message to server by msgTransporter.
// 2. Server will gather information from client and visitor and analyze it. Then send back a NatHoleResp message to them to tell them how to do next.
// 3. Receive NatHoleResp message from server.
func ExchangeInfo(
	ctx context.Context, transporter transport.MessageTransporter,
	laneKey string, m msg.Message, timeout time.Duration,
) (*msg.NatHoleResp, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var natHoleRespMsg *msg.NatHoleResp
	m, err := transporter.Do(timeoutCtx, m, laneKey, msg.TypeNameNatHoleResp)
	if err != nil {
		return nil, fmt.Errorf("get natHoleRespMsg error: %v", err)
	}
	mm, ok := m.(*msg.NatHoleResp)
	if !ok {
		return nil, fmt.Errorf("get natHoleRespMsg error: invalid message type")
	}
	natHoleRespMsg = mm

	if natHoleRespMsg.Error != "" {
		return nil, fmt.Errorf("natHoleRespMsg get error info: %s", natHoleRespMsg.Error)
	}
	if len(natHoleRespMsg.CandidateAddrs) == 0 {
		return nil, fmt.Errorf("natHoleRespMsg get empty candidate addresses")
	}
	return natHoleRespMsg, nil
}

// MakeHole is used to make a NAT hole between client and visitor.
func MakeHole(ctx context.Context, listenConn PacketConn, m *msg.NatHoleResp, key []byte) (winningConn PacketConn, remoteAddr *net.UDPAddr, makeErr error) {
	xl := xlog.FromContextSafe(ctx)
	proxyConn, throughSOCKS5 := listenConn.(*socks5udp.Conn)
	var diag *warpNATHoleDiagnostics
	var before socks5udp.TrafficStats
	started := time.Now()
	if throughSOCKS5 {
		diag = &warpNATHoleDiagnostics{}
		before = proxyConn.TrafficStats()
	}
	if _, native := listenConn.(*net.UDPConn); !native {
		if !throughSOCKS5 {
			return nil, nil, fmt.Errorf("unsupported XTCP NAT socket: refusing native UDP fallback")
		}
		if m.DetectBehavior.ListenRandomPorts > maxSOCKS5NATHoleAssociations {
			return nil, nil, fmt.Errorf("XTCP NAT requested %d WARP SOCKS5 UDP associations, limit %d",
				m.DetectBehavior.ListenRandomPorts, maxSOCKS5NATHoleAssociations)
		}
	}
	transactionID := NewTransactionID()
	sendToRangePortsFunc := func(conn PacketConn, addr string) error {
		err := sendSidMessage(ctx, conn, m.Sid, transactionID, addr, key, m.DetectBehavior.TTL)
		if err != nil && diag != nil {
			diag.localWriteErrors.Add(1)
		}
		return err
	}

	listenConns := []PacketConn{listenConn}
	if throughSOCKS5 {
		defer func() {
			var localWrites, relayReads, rejectedFrames uint64
			for i, conn := range listenConns {
				proxied, ok := conn.(*socks5udp.Conn)
				if !ok {
					continue
				}
				stats := proxied.TrafficStats()
				if i == 0 {
					// Ignore previous STUN discovery traffic on the original
					// SOCKS5 association.
					stats.LocalRelayWrites -= before.LocalRelayWrites
					stats.LocalRelayReads -= before.LocalRelayReads
					stats.DroppedFrames -= before.DroppedFrames
				}
				localWrites += stats.LocalRelayWrites
				relayReads += stats.LocalRelayReads
				rejectedFrames += stats.DroppedFrames
			}
			result := "success"
			if makeErr != nil {
				result = "failed"
			}
			xl.Infof("XTCP WARP NAT diagnostic: sid=%s role=%s mode=%d result=%s elapsed=%s associations=%d localRelayWrites=%d localWriteErrors=%d relayReplies=%d discardedRelayFrames=%d decodedErrors=%d wrongSID=%d matchingSID=%d ignoredSenderProbes=%d",
				m.Sid, m.DetectBehavior.Role, m.DetectBehavior.Mode, result, time.Since(started).Round(time.Millisecond),
				len(listenConns), localWrites, diag.localWriteErrors.Load(), relayReads, rejectedFrames,
				diag.decodeErrors.Load(), diag.wrongSID.Load(),
				diag.matchingSID.Load(), diag.ignoredProbe.Load())
		}()
	}
	// The caller retains only the winning association for the QUIC tunnel.
	// In particular, close *all* losing SOCKS5 TCP+UDP associations as soon as
	// hole punching finishes, rather than leaving 256 WARP sessions waiting
	// until their receive deadlines expire.
	defer func() {
		for _, conn := range listenConns {
			if conn != winningConn {
				_ = conn.Close()
			}
		}
	}()
	var detectAddrs []string
	if m.DetectBehavior.Role == DetectRoleSender {
		// sender
		if m.DetectBehavior.SendDelayMs > 0 {
			time.Sleep(time.Duration(m.DetectBehavior.SendDelayMs) * time.Millisecond)
		}
		detectAddrs = m.AssistedAddrs
		detectAddrs = append(detectAddrs, m.CandidateAddrs...)
	} else {
		// receiver
		if len(m.DetectBehavior.CandidatePorts) == 0 {
			detectAddrs = m.CandidateAddrs
		}

		if m.DetectBehavior.ListenRandomPorts > 0 {
			for i := 0; i < m.DetectBehavior.ListenRandomPorts; i++ {
				var tmpConn PacketConn
				var err error
				if throughSOCKS5 {
					// Mode 2 HardNAT normally listens on 256 native UDP ports.
					// The proxied Visitor instead opens 256 distinct *loopback*
					// WARP SOCKS5 UDP ASSOCIATE sessions. No packet is sent to
					// the public Internet from an unproxied VPS UDP socket.
					tmpConn, err = proxyConn.NewAssociation()
				} else {
					tmpConn, err = net.ListenUDP("udp4", nil)
				}
				if err != nil {
					if throughSOCKS5 {
						return nil, nil, fmt.Errorf("open WARP SOCKS5 UDP association %d/%d: %w",
							i+1, m.DetectBehavior.ListenRandomPorts, err)
					}
					xl.Warnf("listen random udp addr error: %v", err)
					continue
				}
				listenConns = append(listenConns, tmpConn)
			}
			if throughSOCKS5 {
				xl.Infof("XTCP HardNAT receiver opened %d extra WARP SOCKS5 UDP associations (loopback-only)",
					len(listenConns)-1)
			}
		}
	}

	detectAddrs = slices.Compact(detectAddrs)
	for _, detectAddr := range detectAddrs {
		for _, conn := range listenConns {
			if err := sendToRangePortsFunc(conn, detectAddr); err != nil {
				xl.Tracef("send sid message from %s to %s error: %v", conn.LocalAddr(), detectAddr, err)
			}
		}
	}
	if len(m.DetectBehavior.CandidatePorts) > 0 {
		for _, conn := range listenConns {
			sendSidMessageToRangePorts(ctx, conn, m.CandidateAddrs, m.DetectBehavior.CandidatePorts, sendToRangePortsFunc)
		}
	}
	if m.DetectBehavior.SendRandomPorts > 0 {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		for i := range listenConns {
			go sendSidMessageToRandomPorts(ctx, listenConns[i], m.CandidateAddrs, m.DetectBehavior.SendRandomPorts, sendToRangePortsFunc)
		}
	}

	timeout := 5 * time.Second
	if m.DetectBehavior.ReadTimeoutMs > 0 {
		timeout = time.Duration(m.DetectBehavior.ReadTimeoutMs) * time.Millisecond
	}

	if len(listenConns) == 1 {
		raddr, err := waitDetectMessage(ctx, listenConns[0], m.Sid, key, timeout, m.DetectBehavior.Role, diag)
		if err != nil {
			return nil, nil, fmt.Errorf("wait detect message error: %v", err)
		}
		return listenConns[0], raddr, nil
	}

	type result struct {
		lConn PacketConn
		raddr *net.UDPAddr
	}
	// Buffer the first successful response. With 256 associations, a peer
	// reply may arrive before the main goroutine reaches the select below;
	// an unbuffered channel would otherwise discard that valid hole.
	resultCh := make(chan result, 1)
	for _, conn := range listenConns {
		go func(lConn PacketConn) {
			addr, err := waitDetectMessage(ctx, lConn, m.Sid, key, timeout, m.DetectBehavior.Role, diag)
			if err != nil {
				lConn.Close()
				return
			}
			select {
			case resultCh <- result{lConn: lConn, raddr: addr}:
			default:
				lConn.Close()
			}
		}(conn)
	}

	select {
	case result := <-resultCh:
		return result.lConn, result.raddr, nil
	case <-time.After(timeout):
		return nil, nil, fmt.Errorf("wait detect message timeout")
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("wait detect message canceled")
	}
}

func waitDetectMessage(
	ctx context.Context, conn PacketConn, sid string, key []byte,
	timeout time.Duration, role string, diag *warpNATHoleDiagnostics,
) (*net.UDPAddr, error) {
	xl := xlog.FromContextSafe(ctx)
	for {
		buf := pool.GetBuf(1024)
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := conn.ReadFromUDP(buf)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			pool.PutBuf(buf)
			return nil, err
		}
		xl.Debugf("get udp message local %s, from %s", conn.LocalAddr(), raddr)
		var m msg.NatHoleSid
		if err := DecodeMessageInto(buf[:n], key, &m); err != nil {
			pool.PutBuf(buf)
			if diag != nil {
				diag.decodeErrors.Add(1)
			}
			xl.Warnf("decode sid message error: %v", err)
			continue
		}
		pool.PutBuf(buf)

		if m.Sid != sid {
			if diag != nil {
				diag.wrongSID.Add(1)
			}
			xl.Warnf("get sid message with wrong sid: %s, expect: %s", m.Sid, sid)
			continue
		}
		if diag != nil {
			diag.matchingSID.Add(1)
		}

		if !m.Response {
			// only wait for response messages if we are a sender
			if role == DetectRoleSender {
				if diag != nil {
					diag.ignoredProbe.Add(1)
				}
				continue
			}

			m.Response = true
			buf2, err := EncodeMessage(&m, key)
			if err != nil {
				xl.Warnf("encode sid message error: %v", err)
				continue
			}
			_, _ = conn.WriteToUDP(buf2, raddr)
		}
		return raddr, nil
	}
}

func sendSidMessage(
	ctx context.Context, conn PacketConn,
	sid string, transactionID string, addr string, key []byte, ttl int,
) error {
	xl := xlog.FromContextSafe(ctx)
	ttlStr := ""
	if ttl > 0 {
		ttlStr = fmt.Sprintf(" with ttl %d", ttl)
	}
	xl.Tracef("send sid message from %s to %s%s", conn.LocalAddr(), addr, ttlStr)
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	if transactionID == "" {
		transactionID = NewTransactionID()
	}
	m := &msg.NatHoleSid{
		TransactionID: transactionID,
		Sid:           sid,
		Response:      false,
		Nonce:         strings.Repeat("0", rand.IntN(20)),
	}
	buf, err := EncodeMessage(m, key)
	if err != nil {
		return err
	}
	if ttl > 0 {
		// SOCKS5 UDP relays cannot set remote packet IP TTL. Keep the original
		// SOCKS5 association and send with its default TTL: this may reduce
		// punch success with difficult NATs, but never exposes a raw VPS IP.
		raw, ok := conn.(*net.UDPConn)
		if !ok {
			xl.Debugf("SOCKS5 UDP cannot apply TTL=%d NAT hint; sending via proxy with normal TTL", ttl)
		} else {
			uConn := ipv4.NewConn(raw)
			original, err := uConn.TTL()
			if err != nil {
				xl.Tracef("get ttl error %v", err)
				return err
			}
			xl.Tracef("original ttl %d", original)

			err = uConn.SetTTL(ttl)
			if err != nil {
				xl.Tracef("set ttl error %v", err)
			} else {
				defer func() {
					_ = uConn.SetTTL(original)
				}()
			}
		}
	}

	if _, err := conn.WriteToUDP(buf, raddr); err != nil {
		return err
	}
	return nil
}

func sendSidMessageToRangePorts(
	ctx context.Context, conn PacketConn, addrs []string, ports []msg.PortsRange,
	sendFunc func(PacketConn, string) error,
) {
	xl := xlog.FromContextSafe(ctx)
	for _, ip := range slices.Compact(parseIPs(addrs)) {
		for _, portsRange := range ports {
			for i := portsRange.From; i <= portsRange.To; i++ {
				detectAddr := net.JoinHostPort(ip, strconv.Itoa(i))
				if err := sendFunc(conn, detectAddr); err != nil {
					xl.Tracef("send sid message from %s to %s error: %v", conn.LocalAddr(), detectAddr, err)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
	}
}

func sendSidMessageToRandomPorts(
	ctx context.Context, conn PacketConn, addrs []string, count int,
	sendFunc func(PacketConn, string) error,
) {
	xl := xlog.FromContextSafe(ctx)
	used := sets.New[int]()
	getUnusedPort := func() int {
		for range 10 {
			port := rand.IntN(65535-1024) + 1024
			if !used.Has(port) {
				used.Insert(port)
				return port
			}
		}
		return 0
	}

	for range count {
		select {
		case <-ctx.Done():
			return
		default:
		}

		port := getUnusedPort()
		if port == 0 {
			continue
		}

		for _, ip := range slices.Compact(parseIPs(addrs)) {
			detectAddr := net.JoinHostPort(ip, strconv.Itoa(port))
			if err := sendFunc(conn, detectAddr); err != nil {
				xl.Tracef("send sid message from %s to %s error: %v", conn.LocalAddr(), detectAddr, err)
			}
			time.Sleep(time.Millisecond * 15)
		}
	}
}

func parseIPs(addrs []string) []string {
	var ips []string
	for _, addr := range addrs {
		if ip, _, err := net.SplitHostPort(addr); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
