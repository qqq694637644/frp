package nathole

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/fatedier/golib/net/stun"

	"github.com/fatedier/frp/pkg/transport/socks5udp"
)

// prepareThroughSOCKS5 uses the *same* SOCKS5 UDP association for STUN,
// NAT detection, and the eventual QUIC P2P connection. Opening a separate
// native UDP socket would invalidate the mapped address and disclose the
// VPS's direct source IP; this path never does that.
func prepareThroughSOCKS5(stunServers []string, opts PrepareOptions) (*PrepareResult, error) {
	conn, err := socks5udp.Dial(opts.UDPProxyURL)
	if err != nil {
		return nil, fmt.Errorf("WARP SOCKS5 UDP ASSOCIATE: %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			_ = conn.Close()
		}
	}()
	addresses := make([]string, 0, len(stunServers)*2)
	for _, server := range stunServers {
		response, err := discoverSTUNOnPacketConn(conn, server)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 STUN %s: %w", server, err)
		}
		if response.MappedAddr == nil {
			return nil, errors.New("SOCKS5 STUN did not report a mapped address")
		}
		addresses = append(addresses, response.MappedAddr.String())
		if response.OtherAddr != nil {
			second, err := discoverSTUNOnPacketConn(conn, response.OtherAddr.String())
			if err != nil {
				return nil, fmt.Errorf("SOCKS5 alternate STUN: %w", err)
			}
			if second.MappedAddr != nil {
				addresses = append(addresses, second.MappedAddr.String())
			}
		}
	}
	if len(addresses) < 2 {
		return nil, errors.New("SOCKS5 STUN returned fewer than two mapped addresses")
	}
	localIPs, _ := ListLocalIPsForNatHole(10)
	feature, err := ClassifyNATFeature(addresses, localIPs)
	if err != nil {
		return nil, err
	}
	// A proxied visitor must never send its raw interface IP addresses to
	// the third-party frps, regardless of the user's assisted-addrs option.
	ready = true
	return &PrepareResult{
		Addrs: addresses, AssistedAddrs: nil, ListenConn: conn,
		NatType: feature.NatType, Behavior: feature.Behavior,
	}, nil
}

func discoverSTUNOnPacketConn(conn PacketConn, server string) (stun.BindingResponse, error) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return stun.BindingResponse{}, err
	}
	tx, err := stun.NewBindingTransaction(addr)
	if err != nil {
		return stun.BindingResponse{}, err
	}
	packet, err := tx.MarshalBinary()
	if err != nil {
		return stun.BindingResponse{}, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return stun.BindingResponse{}, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	if _, err := conn.WriteToUDP(packet, addr); err != nil {
		return stun.BindingResponse{}, err
	}
	buf := make([]byte, 65535)
	for {
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			return stun.BindingResponse{}, err
		}
		response, matched, err := tx.Process(buf[:n], source)
		if !matched {
			continue
		}
		return response, err
	}
}
