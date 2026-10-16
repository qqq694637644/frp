# XTCP QUIC DATAGRAM on custom frpc (without modifying frps)

This fork adds an **optional local UDP datagram bridge** to XTCP while leaving
the existing NAT hole-punch flow, frps protocol messages, proxy type, visitor
protocol `quic`, and ordinary reliable TCP streams unchanged.

Build **both** frpc binaries from this branch:

```sh
go build -tags 'frpc,noweb' -o frpc ./cmd/frpc
```

The paid third-party **frps stays completely unchanged**. The existing frps
must already support standard XTCP/QUIC traversal with your current setup.
The two frpc instances must both support and enable DATAGRAM.

## Mainland NAT node: XTCP Proxy

Append to the *existing* `frpc.toml` after its existing `serverAddr`,
`serverPort` and authentication configuration:

```toml
[[proxies]]
name = "rsx1_node"
type = "xtcp"
secretKey = "replace-with-existing-xtcp-key"
localIP = "127.0.0.1"
localPort = 9312

[proxies.datagram]
listenAddr = "127.0.0.1:9313"
peerAddr = "127.0.0.1:9314"
```

`9312` remains the normal reliable TCP service (Python RSX1 mux).
`9313` is the **frpc UDP ingress**, and `9314` is the **Python application UDP
socket**. Python must bind UDP `127.0.0.1:9314` and send its datagrams to
`127.0.0.1:9313` *from that same socket*.

## Overseas VPS: XTCP Visitor

```toml
[[visitors]]
name = "rsx1_outside"
type = "xtcp"
serverName = "rsx1_node"
secretKey = "replace-with-existing-xtcp-key"
protocol = "quic"
keepTunnelOpen = true
bindAddr = "127.0.0.1"
bindPort = 6000

[visitors.datagram]
listenAddr = "127.0.0.1:6001"
peerAddr = "127.0.0.1:6002"
```

`6000` is the old TCP visitor; `6001` is the **frpc UDP ingress**;
`6002` is the **Go exit-agent UDP socket**. Go must bind UDP
`127.0.0.1:6002` and send from that socket to `127.0.0.1:6001`.

**Only frpc sees the new `datagram` settings.** These are not fields in the
`NatHoleVisitor` or `NewProxy` protocol sent to the older frps.

The visitor must use `protocol = "quic"` rather than KCP. A QUIC handshake
must negotiate both local and remote DATAGRAM support; otherwise the peer
rejects the tunnel and logs an error. On reconnect the local UDP ports are
rebound. No fallback to TCP stream occurs for UDP.

## Framing and use in RSX1

The local bridge is **transparent**: it sends exactly one local UDP payload as
one QUIC DATAGRAM and reproduces the same bytes as one UDP payload on the peer.
No headers, session IDs or source/destination addresses are added by frpc.
Applications must encode their own session ID and SOCKS5 UDP address
information in these bytes. The current pre-DATAGRAM versions of the Python
NAT node and Go exit agent send UDP through their *TCP* RSX1 mux and therefore
must be adapted to use these local UDP ports before this changes application
traffic. The bridge can already be tested directly with generic UDP sockets.

Maximum single application UDP payload is **1100 bytes**, chosen to avoid
QUIC path MTU fragmentation. Oversized packets are dropped, not reassembled
and not converted to TCP. DATAGRAM is unreliable and unordered; loss,
reordering and congestion still exist. The local bridge only binds to
`127.0.0.1` and accepts packets from exactly the configured `peerAddr`.

Your separate overseas WARP SOCKS5 proxy is an **egress requirement of the Go
application**, not of this frpc transport: both outbound TCP CONNECT and
UDP ASSOCIATE must go via WARP with no direct-connect fallback.
This frpc fork does not change or implement that WARP egress policy.

## Validation

```sh
go test ./pkg/transport/xtcpdatagram ./pkg/config/v1/... ./client/proxy ./client/visitor
go build -tags 'frpc,noweb' -o frpc ./cmd/frpc
```

The package integration test establishes actual QUIC P2P connections on
loopback, negotiates DATAGRAM, transfers UDP in both directions, and proves
that a normal QUIC TCP service stream is still usable over the same session.
It does not substitute for testing through the third-party frps/WARP path.
