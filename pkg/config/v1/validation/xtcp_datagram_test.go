package validation

import (
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport/xtcpdatagram"
)

func TestXTCPProxyFixedNatUDPBindPortValidation(t *testing.T) {
	proxy := &v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "node", Type: "xtcp",
			ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: 9312},
		},
		NatTraversal: &v1.NatTraversalConfig{BindPort: 39999},
	}
	proxy.Complete()
	for _, port := range []int{0, 1, 39999, 65535} {
		proxy.NatTraversal.BindPort = port
		if err := ValidateProxyConfigurerForClient(proxy); err != nil {
			t.Fatalf("rejected valid natTraversal.bindPort %d: %v", port, err)
		}
	}
	for _, port := range []int{-1, 65536} {
		proxy.NatTraversal.BindPort = port
		err := ValidateProxyConfigurerForClient(proxy)
		if err == nil || !strings.Contains(err.Error(), "natTraversal.bindPort") {
			t.Fatalf("accepted invalid natTraversal.bindPort %d: %v", port, err)
		}
	}

	// The fixed native UDP socket is deliberately a mainland XTCP Proxy
	// option. The overseas SOCKS5-only Visitor must not silently ignore it.
	visitor := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name: "oversea", Type: "xtcp", ServerName: "node", BindPort: 6000,
		},
		Protocol: "quic",
		NatTraversal: &v1.NatTraversalConfig{
			BindPort:    39999,
			UDPProxyURL: "socks5://127.0.0.1:40000",
		},
	}
	visitor.Complete()
	if err := ValidateVisitorConfigurer(visitor); err == nil ||
		!strings.Contains(err.Error(), "only supported by XTCP proxies") {
		t.Fatalf("visitor silently accepted native NAT bindPort: %v", err)
	}
}

func TestXTCPDatagramIsQUICOnlyAndLocalOnly(t *testing.T) {
	proxy := &v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "node", Type: "xtcp",
			ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: 9312},
		},
		Datagram: &xtcpdatagram.Config{
			ListenAddr: "127.0.0.1:9313",
			PeerAddr:   "127.0.0.1:9314",
		},
	}
	proxy.Complete()
	if err := ValidateProxyConfigurerForClient(proxy); err != nil {
		t.Fatal(err)
	}
	visitor := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name: "oversea", Type: "xtcp", ServerName: "node", BindPort: 6000,
		},
		Datagram: &xtcpdatagram.Config{
			ListenAddr: "127.0.0.1:6001",
			PeerAddr:   "127.0.0.1:6002",
		},
		NatTraversal: &v1.NatTraversalConfig{UDPProxyURL: "socks5://127.0.0.1:40000"},
	}
	visitor.Complete()
	if err := ValidateVisitorConfigurer(visitor); err != nil {
		t.Fatal(err)
	}
	if !visitor.NatTraversal.DisableAssistedAddrs {
		t.Fatal("hidden visitor did not force assisted addresses off")
	}
	visitor.Protocol = "kcp"
	if err := ValidateVisitorConfigurer(visitor); err == nil {
		t.Fatal("accepted DATAGRAM on KCP")
	}
	visitor.Protocol = "quic"
	visitor.Datagram.ListenAddr = "0.0.0.0:6001"
	if err := ValidateVisitorConfigurer(visitor); err == nil {
		t.Fatal("accepted public UDP listener")
	}
	proxy.Datagram.ListenAddr = "0.0.0.0:9313"
	if err := ValidateProxyConfigurerForClient(proxy); err == nil {
		t.Fatal("accepted public UDP listener on proxy")
	}
}

func TestXTCPPrivacyModeFailsClosedOnUnproxiedControl(t *testing.T) {
	visitor := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name: "private", Type: "xtcp", ServerName: "node", BindPort: 6000,
		},
		Datagram:     &xtcpdatagram.Config{ListenAddr: "127.0.0.1:6001", PeerAddr: "127.0.0.1:6002"},
		NatTraversal: &v1.NatTraversalConfig{UDPProxyURL: "socks5://127.0.0.1:40000"},
	}
	visitor.Complete()
	common := &v1.ClientCommonConfig{}
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	common.Transport.ProxyURL = "socks5://127.0.0.1:40000"
	if _, err := ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{visitor}, nil); err != nil {
		t.Fatalf("valid private config rejected: %v", err)
	}
	common.Transport.ProxyURL = ""
	if _, err := ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil {
		t.Fatal("allowed raw frps control connection while private UDP mode enabled")
	}
	common.Transport.ProxyURL = "socks5://127.0.0.1:40001"
	if _, err := ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil {
		t.Fatal("allowed different WARP SOCKS5 proxies for frps and STUN")
	}
	common.Transport.ProxyURL = "socks5://127.0.0.1:40000"
	visitor.FallbackTo = "unprotected-alt"
	if _, err := ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil {
		t.Fatal("allowed alternate unprotected XTCP visitor fallback")
	}
	visitor.FallbackTo = ""
	visitor.NatTraversal.UDPProxyURL = ""
	if _, err := ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil {
		t.Fatal("allowed native UDP hole-punch with DATAGRAM enabled")
	}
}
