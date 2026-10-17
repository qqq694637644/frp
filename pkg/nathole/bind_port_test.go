package nathole

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

func chooseUnusedUDPPort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	port := socket.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, socket.Close())
	return port
}

func TestPrepareFixedBindPortPreservesSTUNSocketForHolePunching(t *testing.T) {
	port := chooseUnusedUDPPort(t)
	primary := listenTestUDP4(t)
	alternate := listenTestUDP4(t)
	alternateAddr := alternate.LocalAddr().(*net.UDPAddr)

	primaryDone := serveOneSTUNRequest(primary, func(request []byte, _ *net.UDPAddr) ([]byte, error) {
		return makeTestSTUNResponse(request, testBindingSuccess,
			testSTUNAttribute{typ: testAttrXORMapped, value: testIPv4AddressValue(net.ParseIP("198.51.100.10"), 39999, true)},
			testSTUNAttribute{typ: testAttrOther, value: testIPv4AddressValue(alternateAddr.IP, alternateAddr.Port, false)},
		)
	})
	alternateDone := serveOneSTUNRequest(alternate, func(request []byte, _ *net.UDPAddr) ([]byte, error) {
		return makeTestSTUNResponse(request, testBindingSuccess,
			testSTUNAttribute{typ: testAttrXORMapped, value: testIPv4AddressValue(net.ParseIP("198.51.100.10"), 39999, true)},
		)
	})

	prepared, err := Prepare([]string{primary.LocalAddr().String()}, PrepareOptions{BindPort: port})
	require.NoError(t, err)
	t.Cleanup(func() { _ = prepared.ListenConn.Close() })
	require.Equal(t, port, prepared.ListenConn.LocalAddr().(*net.UDPAddr).Port)
	require.Equal(t, []string{"198.51.100.10:39999", "198.51.100.10:39999"}, prepared.Addrs)

	firstSource := waitSTUNExchange(t, primaryDone)
	secondSource := waitSTUNExchange(t, alternateDone)
	require.Equal(t, port, firstSource.Port, "primary STUN left the requested local port")
	require.Equal(t, port, secondSource.Port, "alternate STUN left the requested local port")

	// The same socket must still send and receive after STUN. In particular,
	// STUN's read deadline must not poison MakeHole's later UDP receives.
	peer := listenTestUDP4(t)
	_, err = prepared.ListenConn.WriteToUDP([]byte("hole-probe"), peer.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 128)
	n, from, err := peer.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "hole-probe", string(buf[:n]))
	require.Equal(t, port, from.Port, "punch sent from different UDP source port")

	_, err = peer.WriteToUDP([]byte("hole-response"), from)
	require.NoError(t, err)
	require.NoError(t, prepared.ListenConn.SetReadDeadline(time.Now().Add(time.Second)))
	n, from, err = prepared.ListenConn.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "hole-response", string(buf[:n]))
	require.Equal(t, peer.LocalAddr().String(), from.String())

	// Run the actual NAT hole-punching code on the STUN socket. This is the
	// socket whose local port is forwarded on the user's router, rather than
	// a newly opened random-port socket that the router would not forward.
	const sid = "xtcp-fixed-port-sid"
	secret := []byte("fixed-nat-port-test-key")
	responseDone := make(chan error, 1)
	go func() {
		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			responseDone <- err
			return
		}
		payload := make([]byte, 1024)
		n, source, err := peer.ReadFromUDP(payload)
		if err != nil {
			responseDone <- err
			return
		}
		var probe msg.NatHoleSid
		if err := DecodeMessageInto(payload[:n], secret, &probe); err != nil {
			responseDone <- err
			return
		}
		if probe.Sid != sid || probe.Response {
			responseDone <- fmt.Errorf("unexpected fixed-port SID request: %+v", probe)
			return
		}
		probe.Response = true
		response, err := EncodeMessage(&probe, secret)
		if err != nil {
			responseDone <- err
			return
		}
		_, err = peer.WriteToUDP(response, source)
		responseDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	winner, remote, err := MakeHole(ctx, prepared.ListenConn, &msg.NatHoleResp{
		Sid:            sid,
		CandidateAddrs: []string{peer.LocalAddr().String()},
		DetectBehavior: msg.NatHoleDetectBehavior{
			Role:          DetectRoleReceiver,
			Mode:          DetectMode0,
			ReadTimeoutMs: 1500,
		},
	}, secret)
	require.NoError(t, err)
	require.Same(t, prepared.ListenConn, winner)
	require.Equal(t, port, winner.LocalAddr().(*net.UDPAddr).Port)
	require.Equal(t, peer.LocalAddr().String(), remote.String())
	require.NoError(t, <-responseDone)
}

func TestPrepareFixedBindPortAlreadyUsedFailsClosed(t *testing.T) {
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	require.NoError(t, err)
	defer occupied.Close()

	_, err = Prepare(nil, PrepareOptions{BindPort: occupied.LocalAddr().(*net.UDPAddr).Port})
	require.ErrorContains(t, err, "bind NAT UDP socket")
}

func TestPrepareFixedBindPortReleasesSocketOnSTUNFailure(t *testing.T) {
	port := chooseUnusedUDPPort(t)
	stunServer := listenTestUDP4(t)
	done := serveOneSTUNRequest(stunServer, func(request []byte, _ *net.UDPAddr) ([]byte, error) {
		return makeTestSTUNResponse(request, testBindingSuccess,
			testSTUNAttribute{typ: testAttrXORMapped, value: testIPv4AddressValue(net.ParseIP("198.51.100.1"), 39999, true)},
		)
	})

	_, err := Prepare([]string{stunServer.LocalAddr().String()}, PrepareOptions{BindPort: port})
	require.EqualError(t, err, "discover error: not enough addresses")
	require.Equal(t, port, waitSTUNExchange(t, done).Port)

	rebound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	require.NoError(t, err, "failed to release native UDP socket after STUN error")
	require.NoError(t, rebound.Close())
}

func TestPrepareBindPortRejectsInvalidAndSOCKS5Combination(t *testing.T) {
	for _, invalid := range []int{-1, 65536} {
		_, err := Prepare(nil, PrepareOptions{BindPort: invalid})
		require.ErrorContains(t, err, "invalid NAT UDP bindPort")
	}
	_, err := Prepare(nil, PrepareOptions{
		BindPort:    39999,
		UDPProxyURL: "socks5://127.0.0.1:40000",
	})
	require.ErrorContains(t, err, "not supported with SOCKS5 UDP proxy")
}
