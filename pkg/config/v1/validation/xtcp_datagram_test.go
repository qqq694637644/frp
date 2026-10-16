package validation

import (
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport/xtcpdatagram"
)

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
	}
	visitor.Complete()
	if err := ValidateVisitorConfigurer(visitor); err != nil {
		t.Fatal(err)
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
