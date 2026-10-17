package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

func TestXTCPProxyNatTraversalBindPortTOMLStrict(t *testing.T) {
	const toml = `
serverAddr = "127.0.0.1"
serverPort = 7000
transport.wireProtocol = "v1"

[[proxies]]
name = "vvvvv"
type = "xtcp"
secretKey = "local-test-secret"
localIP = "127.0.0.1"
localPort = 9312

[proxies.natTraversal]
bindPort = 39999

[proxies.datagram]
listenAddr = "127.0.0.1:9313"
peerAddr = "127.0.0.1:9314"
`
	path := filepath.Join(t.TempDir(), "frpc.toml")
	require.NoError(t, os.WriteFile(path, []byte(toml), 0o600))

	_, proxies, visitors, legacy, err := LoadClientConfig(path, true)
	require.NoError(t, err)
	require.False(t, legacy)
	require.Empty(t, visitors)
	require.Len(t, proxies, 1)
	proxy, ok := proxies[0].(*v1.XTCPProxyConfig)
	require.True(t, ok)
	require.NotNil(t, proxy.NatTraversal)
	require.Equal(t, 39999, proxy.NatTraversal.BindPort)

	clonedProxy := proxy.Clone().(*v1.XTCPProxyConfig)
	clonedProxy.NatTraversal.BindPort = 30000
	require.Equal(t, 39999, proxy.NatTraversal.BindPort, "fixed port must remain frpc-local across clone")

	// Local BindPort is never included in the NewProxy message sent to frps.
	var registration msg.NewProxy
	proxy.MarshalToMsg(&registration)
	wire, err := json.Marshal(registration)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(wire), "39999") || strings.Contains(string(wire), "bindPort"))
}
