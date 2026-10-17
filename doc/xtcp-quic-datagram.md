# 定制 frpc：XTCP QUIC DATAGRAM + 境外 WARP SOCKS5 隐私打洞

本 fork 在 **两端 frpc** 添加 QUIC DATAGRAM，保留现有 frps XTCP 协商消息和 Visitor/Proxy 角色，不要求修改服务商的 frps。已经使用官方 **frps 0.69.0** + 两个定制 frpc + 本地模拟 WARP SOCKS5/STUN，验证 P2P TCP Stream 与双向 QUIC DATAGRAM 均能工作。

> **破坏式更新：对于带 DATAGRAM 的 XTCP Visitor，必须配置强制 WARP SOCKS5 UDP 打洞及相同的控制连接 SOCKS5。** 没有 UDP-over-TCP、native UDP 或其他 Visitor 的回退路径。境内 XTCP Proxy 仍使用普通打洞 UDP。

编译两端的定制客户端：

```sh
go build -tags 'frpc,noweb' -o frpc ./cmd/frpc
```

## 境内 frpc：XTCP Proxy

在现有 `frpc.toml` 里保留服务器地址、认证、STUN 配置；添加：

```toml
transport.wireProtocol = "v1"

[[proxies]]
name = "rsx2_node"
type = "xtcp"
secretKey = "your-existing-xtcp-key"
localIP = "127.0.0.1"
localPort = 9312

[proxies.datagram]
listenAddr = "127.0.0.1:9313"
peerAddr = "127.0.0.1:9314"
```

境内 Python SOCKS5 在 TCP `127.0.0.1:9312` 接收 RSX2；自己的 UDP Socket 绑定 `127.0.0.1:9314`，向本地 frpc `127.0.0.1:9313` 发送封装的应用报文。

## 境外 frpc：XTCP Visitor，强制隐藏原始打洞地址

可通过 x-ui 面板的 **反向 SOCKS5 / WARP** 自动生成并管理自定义 frpc。以下示例必须替换第三方 frps IP、token、XTCP 密钥、STUN 服务器地址、WARP SOCKS5 端口：

```toml
serverAddr = "REPLACE_WITH_FRPS_IP"
serverPort = 7000
auth.method = "token"
auth.token = "REPLACE_WITH_FRPS_TOKEN"
transport.protocol = "tcp"
transport.wireProtocol = "v1"
transport.proxyURL = "socks5://127.0.0.1:40000"
natHoleSTUNServer = "REPLACE_WITH_VERIFIED_STUN_IP:3478"

[[visitors]]
name = "rsx2_outside"
type = "xtcp"
serverName = "rsx2_node"
secretKey = "REPLACE_WITH_XTCP_SECRET"
protocol = "quic"
keepTunnelOpen = true
minRetryInterval = 10
maxRetriesAnHour = 120
bindAddr = "127.0.0.1"
bindPort = 6000

[visitors.datagram]
listenAddr = "127.0.0.1:6001"
peerAddr = "127.0.0.1:6002"

[visitors.natTraversal]
disableAssistedAddrs = true
udpProxyURL = "socks5://127.0.0.1:40000"
```

- `transport.proxyURL` 强制 **到 frps 的 TCP 控制连接** 经过本地 WARP SOCKS5。
- `natTraversal.udpProxyURL` 是本 fork 增加的字段，强制 **STUN、XTCP NAT 打洞及 P2P QUIC** 走同一个 SOCKS5 UDP ASSOCIATE。**仅填 `transport.proxyURL` 不能隐藏原生 UDP 打洞出口。**
- 两个代理字段必须指向相同的本机 SOCKS5 端点，且只允许字面 IPv4 回环地址 `127.0.0.1`；非回环的 UDP 中继地址会拒绝。WARP 不可用时不创建公网原生 UDP 连接。
- 禁止 XTCP `fallbackTo`；辅助候选本机 IP 自动关闭。默认 `wireProtocol="v1"`，与官方 frps 0.69.0 完整本地测试通过。
- 可用 `socks5://USERNAME:PASSWORD@127.0.0.1:40000` 指定账号认证，注意该文件权限（建议仅运行用户可读）。x-ui Web 模板不会自动带出储存的 WARP 密码。

**HardNAT/Mode 2 打洞支持：** 官方 frps 0.69 对 HardNAT Visitor 可能下发 `ListenRandomPorts: 256`，要求接收端打开 256 个额外 UDP 端口。自定义 frpc 将这些端口分别映射到**独立的、本机回环 WARP SOCKS5 UDP ASSOCIATE**，不再因要求额外端口而拒绝，也绝不回退原生公网 UDP。限制最多 256 条关联；如果 WARP 不允许创建所需关联就报错并释放已创建的关联。成功打洞后，立即关闭其余临时关联，仅保留真正承载 QUIC 的关联。

**重要限制：** SOCKS5 UDP 中继不能像原生 UDP Socket 一样设置数据报 IP TTL，因此收到 frps 的非零 TTL 探测提示时仍然通过 SOCKS5 发送，但无法应用该 TTL 优化。**256 条关联只是模拟本地多个 UDP 端口，不保证 WARP NAT 的外部映射端口足够分散或允许对端入站。** 日志中出现 `HardNAT`、`ListenRandomPorts:256`，不代表隧道一定能建立；必须看到 `establishing nat hole connection successful` 和实际传输成功才能视为可用。

建议填写 **数字形式 STUN IP:端口**；使用 STUN 域名会在主机进行 DNS 解析，这段 DNS 不属于 SOCKS5 UDP Relay，可能暴露原始网络 DNS 请求。业务域名则由目标 SOCKS5 代理处理，不在本地解析。

## DATAGRAM 应用接口与边界

境外 Go Agent 在 TCP `127.0.0.1:6000` 连接 Visitor；自己的 UDP Socket 绑定 `127.0.0.1:6002`，向 frpc `127.0.0.1:6001` 发送数据。境内 UDP 端口相反。单个应用数据报作为一条 QUIC DATAGRAM 发送，不经可靠字节流，没有 TCP 回退。

应用层 RSX2 报文：`4-byte session ID (big endian) + RFC1928 SOCKS5 UDP packet`。**上限 1100 字节（包括会话 ID）**，超长直接丢弃、不提供任意 UDP/HTTP3 初始 QUIC 报文支持；HTTP/3 1200 字节 QUIC Initial 通常无法穿过当前应用 UDP 限额。Chromium/Chrome 通过普通 SOCKS5 代理时只代理 TCP，不会直接使用 SOCKS5 UDP ASSOCIATE。

TCP/RSX2 控制流使用每个 SOCKS5 会话独立的 32 帧窗口，接收端完成本地 Socket 写入后按最多 8 帧批量发送 WINDOW 额度，减少控制帧频率和视频突发期间慢客户端队列满立即断流的风险。

## 验证

```sh
go test ./pkg/transport/socks5udp ./pkg/transport/xtcpdatagram ./pkg/nathole ./pkg/config/v1/... ./client/proxy ./client/visitor
go build -tags 'frpc,noweb' -o frpc ./cmd/frpc
./frpc verify -c frpc.toml
```

已在本地模拟环境用**官方 frps 0.69.0** 验证强制 SOCKS5 的控制连接和 UDP STUN/XTCP 打洞、P2P TCP/UDP 都正常收发。另外通过真实 `MakeHole` + 本地模拟 WARP SOCKS5 验证 **Mode 2、TTL=7、256 条关联以及获胜 QUIC 连接的双向 UDP 收发**，并测试代理拒绝关联时清理资源和拒绝创建超过 256 条关联的服务端要求。但线上验收仍应检查三项：

1. 由境内 SOCKS5 发起 TCP 到公网 IP 查询站，确认目标网站看到的是 **WARP IP**，不是 VPS IP；
2. 观察境内对端收到的 XTCP 候选 IP，确认是 **WARP 映射 IP**；不会发送境外本地辅助 IP；
3. VPS 真实物理网卡抓包，核对没有意外的公网 STUN/P2P UDP 和业务目标直连（同时检查 DNS、系统更新等无关流量，以免混淆）。

**不要把「Go Agent WARP 出口正常」误认为「XTCP 打洞 IP 已隐藏」；Web 两项状态也只能测链路与 SOCKS5 协议，不证明公网候选地址。**
