package v1

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport/xtcpdatagram"
)

func TestXTCPDatagramSettingsRemainFrpcLocal(t *testing.T) {
	proxy := &XTCPProxyConfig{
		ProxyBaseConfig: ProxyBaseConfig{Name: "inside", Type: "xtcp"},
		Secretkey:       "xtcp-secret",
		Datagram:        &xtcpdatagram.Config{ListenAddr: "127.0.0.1:9313", PeerAddr: "127.0.0.1:9314"},
	}
	var registration msg.NewProxy
	proxy.MarshalToMsg(&registration)
	wire, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "datagram") || strings.Contains(string(wire), "9313") {
		t.Fatalf("new frpc-local fields leaked into frps registration: %s", wire)
	}
	clonedProxy := proxy.Clone().(*XTCPProxyConfig)
	clonedProxy.Datagram.PeerAddr = "127.0.0.1:9999"
	if proxy.Datagram.PeerAddr != "127.0.0.1:9314" {
		t.Fatal("XTCP proxy clone shares mutable DATAGRAM options")
	}
	visitor := &XTCPVisitorConfig{
		VisitorBaseConfig: VisitorBaseConfig{Type: "xtcp", Name: "outside", ServerName: "inside"},
		Datagram:          &xtcpdatagram.Config{ListenAddr: "127.0.0.1:6001", PeerAddr: "127.0.0.1:6002"},
	}
	visitorCopy := visitor.Clone().(*XTCPVisitorConfig)
	visitorCopy.Datagram.PeerAddr = "127.0.0.1:9998"
	if visitor.Datagram.PeerAddr != "127.0.0.1:6002" {
		t.Fatal("XTCP visitor clone shares mutable DATAGRAM options")
	}
}
