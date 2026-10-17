// Package socks5udp provides a strict, loopback-only SOCKS5 UDP ASSOCIATE
// PacketConn for the XTCP visitor's STUN and QUIC P2P sockets.
//
// No packets are ever sent to a remote address on a native UDP socket.
// UDP leaves only for the explicitly configured local SOCKS5 relay, and
// SOCKS5 TCP control always dials the same local proxy. Fail closed.
package socks5udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	proxyURL string
	udp      *net.UDPConn
	control  *net.TCPConn
	relay    *net.UDPAddr
	once     sync.Once
	// NAT debugging counters describe traffic only as far as the local
	// SOCKS5 relay. A successful local UDP write does NOT prove that WARP
	// forwarded the datagram or that the remote peer received it.
	localRelayWrites atomic.Uint64
	localRelayReads  atomic.Uint64
	droppedFrames    atomic.Uint64
}

// TrafficStats is an atomic snapshot of the local SOCKS5 UDP transport.
// It intentionally never captures credentials or UDP payloads.
type TrafficStats struct {
	LocalRelayWrites uint64
	LocalRelayReads  uint64
	DroppedFrames    uint64
}

func (c *Conn) TrafficStats() TrafficStats {
	return TrafficStats{
		LocalRelayWrites: c.localRelayWrites.Load(),
		LocalRelayReads:  c.localRelayReads.Load(),
		DroppedFrames:    c.droppedFrames.Load(),
	}
}

func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return errors.New("NAT UDP proxy requires socks5:// or socks5h:// URL")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host != "127.0.0.1" {
		return errors.New("NAT UDP proxy must use literal 127.0.0.1:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid NAT UDP SOCKS5 proxy URL")
	}
	if u.User != nil {
		user := u.User.Username()
		pass, ok := u.User.Password()
		if !ok || len(user) == 0 || len(user) > 255 || len(pass) > 255 {
			return errors.New("NAT UDP SOCKS5 authentication requires username:password (max 255 bytes)")
		}
	}
	return nil
}

func Dial(raw string) (*Conn, error) {
	if err := ValidateURL(raw); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(raw)
	tcp, err := net.DialTimeout("tcp4", parsed.Host, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("NAT UDP SOCKS5 TCP unreachable: %w", err)
	}
	control := tcp.(*net.TCPConn)
	success := false
	defer func() {
		if !success {
			_ = control.Close()
		}
	}()
	_ = control.SetDeadline(time.Now().Add(8 * time.Second))
	method := byte(0)
	if parsed.User != nil {
		method = 2
	}
	if err := writeAll(control, []byte{5, 1, method}); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(control, reply[:2]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != method {
		return nil, errors.New("WARP SOCKS5 refused required auth method")
	}
	if method == 2 {
		username := []byte(parsed.User.Username())
		password, _ := parsed.User.Password()
		auth := make([]byte, 0, 3+len(username)+len(password))
		auth = append(auth, 1, byte(len(username)))
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if err := writeAll(control, auth); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(control, reply[:2]); err != nil {
			return nil, err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return nil, errors.New("WARP SOCKS5 username/password rejected")
		}
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	successUDP := false
	defer func() {
		if !successUDP {
			_ = udp.Close()
		}
	}()
	local := udp.LocalAddr().(*net.UDPAddr)
	request := []byte{5, 3, 0, 1}
	request = append(request, local.IP.To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(local.Port))
	if err := writeAll(control, request); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(control, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, fmt.Errorf("WARP SOCKS5 UDP ASSOCIATE failed with %d", reply[1])
	}
	var addr net.IP
	switch reply[3] {
	case 1:
		rawAddr := make([]byte, 4)
		if _, err := io.ReadFull(control, rawAddr); err != nil {
			return nil, err
		}
		addr = net.IP(rawAddr).To4()
	case 4:
		rawAddr := make([]byte, 16)
		if _, err := io.ReadFull(control, rawAddr); err != nil {
			return nil, err
		}
		addr = net.IP(rawAddr)
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(control, length[:]); err != nil {
			return nil, err
		}
		rawHost := make([]byte, length[0])
		if _, err := io.ReadFull(control, rawHost); err != nil {
			return nil, err
		}
		if string(rawHost) == "localhost" {
			addr = net.IPv4(127, 0, 0, 1)
		}
	default:
		return nil, errors.New("WARP SOCKS5 invalid UDP relay address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(control, port[:]); err != nil {
		return nil, err
	}
	relayPort := int(binary.BigEndian.Uint16(port[:]))
	// RFC 1928 UDP ASSOCIATE can report an unspecified bind address, either
	// 0.0.0.0 (IPv4) or :: (IPv6). Neither is a remote relay endpoint.
	// The SOCKS5 control connection was established to 127.0.0.1 and the
	// UDP socket is bound to IPv4 loopback, so try that same local proxy
	// address without ever sending a raw UDP datagram to the VPS interface.
	// IPv6-only local relays will fail closed until explicitly supported.
	if addr != nil && addr.IsUnspecified() {
		addr = net.IPv4(127, 0, 0, 1)
	}
	if addr.To4() == nil || !addr.IsLoopback() || relayPort == 0 {
		return nil, errors.New("WARP SOCKS5 relay is not IPv4 loopback (blocked to prevent VPS IP leak)")
	}
	_ = control.SetDeadline(time.Time{})
	successUDP = true
	success = true
	return &Conn{proxyURL: raw, udp: udp, control: control, relay: &net.UDPAddr{IP: addr.To4(), Port: relayPort}}, nil
}

// NewAssociation opens an independent UDP ASSOCIATE using the exact same
// loopback SOCKS5 proxy as this connection. An XTCP NAT receiver may need
// hundreds of separate source ports for hard-NAT hole punching. Each such
// port must belong to its own SOCKS5 association; opening a native UDP
// socket would expose the VPS's real source IP.
func (c *Conn) NewAssociation() (*Conn, error) {
	return Dial(c.proxyURL)
}

func writeAll(c net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := c.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// WriteToUDP sends to a remote destination *only through the loopback SOCKS5
// relay*. There is no direct UDP send to the requested peer.
func (c *Conn) WriteToUDP(data []byte, peer *net.UDPAddr) (int, error) {
	if peer == nil || peer.IP.To4() == nil || peer.Port <= 0 || peer.Port > 65535 {
		return 0, errors.New("SOCKS5 UDP only supports valid IPv4 destination")
	}
	frame := make([]byte, 0, 3+7+len(data))
	frame = append(frame, 0, 0, 0, 1)
	frame = append(frame, peer.IP.To4()...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(peer.Port))
	frame = append(frame, data...)
	if len(frame) > 65507 {
		return 0, errors.New("SOCKS5 UDP packet too large")
	}
	n, err := c.udp.WriteToUDP(frame, c.relay)
	if err != nil {
		return 0, err
	}
	if n != len(frame) {
		return 0, io.ErrShortWrite
	}
	c.localRelayWrites.Add(1)
	return len(data), nil
}

func (c *Conn) WriteTo(data []byte, addr net.Addr) (int, error) {
	peer, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("SOCKS5 UDP remote must be *net.UDPAddr")
	}
	return c.WriteToUDP(data, peer)
}

func (c *Conn) ReadFromUDP(dst []byte) (int, *net.UDPAddr, error) {
	// Allocate for the caller's receive buffer plus SOCKS5 UDP framing,
	// rather than allocating 64 KiB for every QUIC packet.
	buf := make([]byte, len(dst)+32)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if !from.IP.Equal(c.relay.IP) || from.Port != c.relay.Port || n < 10 ||
			buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
			c.droppedFrames.Add(1)
			continue
		}
		c.localRelayReads.Add(1)
		peer := &net.UDPAddr{
			IP:   append(net.IP(nil), buf[4:8]...),
			Port: int(binary.BigEndian.Uint16(buf[8:10])),
		}
		return copy(dst, buf[10:n]), peer, nil
	}
}

func (c *Conn) ReadFrom(dst []byte) (int, net.Addr, error) {
	n, addr, err := c.ReadFromUDP(dst)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}
func (c *Conn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }
func (c *Conn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() { err = c.udp.Close(); _ = c.control.Close() })
	return err
}
