package validation

import (
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport/xtcpbrutal"
)

// Brutal is deliberately an opt-in XTCP QUIC transmit policy on both sides:
// the overseas Visitor requires WARP SOCKS5 UDP, the mainland Proxy retains
// its fixed native local UDP port. Neither config changes frps transport.
func TestBrutalStrictModeAndRateLimits(t *testing.T) {
	common := &v1.ClientCommonConfig{}
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []v1.QUICOptions{
		{CongestionMode: "brutal", TargetMbps: 0, MaxMbps: 24},
		{CongestionMode: "brutal", TargetMbps: 16, MaxMbps: 0},
		{CongestionMode: "brutal", TargetMbps: 24, MaxMbps: 16},
		{CongestionMode: "brutal", TargetMbps: 16, MaxMbps: xtcpbrutal.MaxSafeMbps + 1},
		{CongestionMode: "brutal", TargetMbps: xtcpbrutal.MaxSafeMbps + 1, MaxMbps: xtcpbrutal.MaxSafeMbps + 1},
		{CongestionMode: "brutal", TargetMbps: -1, MaxMbps: 24},
		{CongestionMode: "wrong"},
		{CongestionMode: "cubic", TargetMbps: 16, MaxMbps: 24},
		{TargetMbps: 16, MaxMbps: 24},
	} {
		common.Transport.QUIC = opts
		if _, err := NewConfigValidator(nil).ValidateClientCommonConfig(common); err == nil {
			t.Fatalf("invalid congestion configuration accepted: %+v", opts)
		}
	}
	for _, mode := range []string{"", "cubic", "brutal"} {
		opts := v1.QUICOptions{CongestionMode: mode}
		if mode == "brutal" {
			opts.TargetMbps, opts.MaxMbps = 16, 24
		}
		common.Transport.QUIC = opts
		if _, err := NewConfigValidator(nil).ValidateClientCommonConfig(common); err != nil {
			t.Fatalf("valid congestion configuration %q rejected: %v", mode, err)
		}
	}
	for _, limits := range [][2]int{{65, 65}, {128, 192}, {256, 512}, {1000, 2000}, {xtcpbrutal.MaxSafeMbps, xtcpbrutal.MaxSafeMbps}} {
		common.Transport.QUIC = v1.QUICOptions{CongestionMode: "brutal", TargetMbps: limits[0], MaxMbps: limits[1]}
		if _, err := NewConfigValidator(nil).ValidateClientCommonConfig(common); err != nil {
			t.Fatalf("valid expanded rate %v rejected: %v", limits, err)
		}
	}
}

func TestBrutalProxyAndVisitorDualEndpointConfig(t *testing.T) {
	proxyCommon := &v1.ClientCommonConfig{}
	if err := proxyCommon.Complete(); err != nil {
		t.Fatal(err)
	}
	proxyCommon.Transport.QUIC = v1.QUICOptions{
		CongestionMode: "brutal", TargetMbps: 16, MaxMbps: 24,
	}
	proxy := &v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "inside", Type: "xtcp",
			ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: 9312},
		},
		NatTraversal: &v1.NatTraversalConfig{BindPort: 39999},
	}
	proxy.Complete()
	if _, err := ValidateAllClientConfig(proxyCommon, []v1.ProxyConfigurer{proxy}, nil, nil); err != nil {
		t.Fatalf("mainland Brutal Proxy rejected: %v", err)
	}
	if proxy.NatTraversal.BindPort != 39999 {
		t.Fatal("fixed mainland NAT port changed")
	}

	visitorCommon := &v1.ClientCommonConfig{}
	if err := visitorCommon.Complete(); err != nil {
		t.Fatal(err)
	}
	visitorCommon.Transport.ProxyURL = "socks5://127.0.0.1:40000"
	visitorCommon.Transport.QUIC = proxyCommon.Transport.QUIC
	visitor := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name: "outside", Type: "xtcp", ServerName: "inside", BindPort: 6000,
		},
		Protocol: "quic",
		NatTraversal: &v1.NatTraversalConfig{
			UDPProxyURL:          "socks5://127.0.0.1:40000",
			DisableAssistedAddrs: true,
		},
	}
	visitor.Complete()
	if _, err := ValidateAllClientConfig(visitorCommon, nil, []v1.VisitorConfigurer{visitor}, nil); err != nil {
		t.Fatalf("overseas WARP-only Brutal Visitor rejected: %v", err)
	}

	visitor.NatTraversal.UDPProxyURL = ""
	if _, err := ValidateAllClientConfig(visitorCommon, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil ||
		!strings.Contains(err.Error(), "WARP SOCKS5") {
		t.Fatalf("Brutal outside Visitor bypassed WARP UDP requirement: %v", err)
	}
	visitor.NatTraversal.UDPProxyURL = "socks5://127.0.0.1:40000"
	visitorCommon.Transport.ProxyURL = ""
	if _, err := ValidateAllClientConfig(visitorCommon, nil, []v1.VisitorConfigurer{visitor}, nil); err == nil {
		t.Fatal("Brutal outside Visitor bypassed WARP TCP control")
	}
}

func TestBrutalRejectedOnNonXTCPOrMissingVisitor(t *testing.T) {
	common := &v1.ClientCommonConfig{}
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	common.Transport.QUIC = v1.QUICOptions{
		CongestionMode: "brutal", TargetMbps: 16, MaxMbps: 24,
	}
	if _, err := ValidateAllClientConfig(common, nil, nil, nil); err == nil {
		t.Fatal("Brutal accepted without any XTCP endpoint")
	}
}
