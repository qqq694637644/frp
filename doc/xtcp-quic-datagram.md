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

[proxies.natTraversal]
bindPort = 39999
```

境内 Python SOCKS5 在 TCP `127.0.0.1:9312` 接收 RSX3（默认）或显式兼容 RSX2；自己的 UDP Socket 绑定 `127.0.0.1:9314`，向本地 frpc `127.0.0.1:9313` 发送封装的应用报文。

`proxies.natTraversal.bindPort = 39999` 使境内 XTCP Proxy 的 **STUN、NAT 打洞、后续 QUIC 共用同一个保持打开的 UDP Socket**（绑定 `0.0.0.0:39999`）。未设置或设置为 `0` 时仍使用系统分配的随机 UDP 端口。只能配置在 `[proxies.natTraversal]`，不是 `[visitors.natTraversal]`，也不是 QUIC DATAGRAM 的 `9313` / `9314` 应用端口。

如果使用路由器端口映射，必须为 **UDP 39999 → 境内 Windows 的 LAN IP:39999** 配置转发，并允许 Windows 防火墙入站 UDP 39999。公网 STUN 探测地址中的端口还取决于路由器/上游 NAT：**指定本地端口不能保证外部端口同样为 39999**。检查 STUN 日志 `addresses` 中的映射端口和 `XTCP NAT using fixed local UDP port 39999`；若外部端口仍被改写，需要检查路由器 NAT 和上游 CGNAT。一个端口同一时刻只能供一个 XTCP Proxy 打洞使用，配置冲突会明确报错，不会悄悄回退随机端口。

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
- 可用 `socks5://USERNAME:PASSWORD@127.0.0.1:40000` 指定账号认证，注意该文件权限（建议仅运行用户可读）。单用户 x-ui Web 页面会回显已保存的 WARP 密码，必须保护面板登录与 HTTPS。

**HardNAT/Mode 2 打洞支持：** 官方 frps 0.69 对 HardNAT Visitor 可能下发 `ListenRandomPorts: 256`，要求接收端打开 256 个额外 UDP 端口。自定义 frpc 将这些端口分别映射到**独立的、本机回环 WARP SOCKS5 UDP ASSOCIATE**，不再因要求额外端口而拒绝，也绝不回退原生公网 UDP。限制最多 256 条关联；如果 WARP 不允许创建所需关联就报错并释放已创建的关联。成功打洞后，立即关闭其余临时关联，仅保留真正承载 QUIC 的关联。

**重要限制：** SOCKS5 UDP 中继不能像原生 UDP Socket 一样设置数据报 IP TTL，因此收到 frps 的非零 TTL 探测提示时仍然通过 SOCKS5 发送，但无法应用该 TTL 优化。**256 条关联只是模拟本地多个 UDP 端口，不保证 WARP NAT 的外部映射端口足够分散或允许对端入站。** 日志中出现 `HardNAT`、`ListenRandomPorts:256`，不代表隧道一定能建立；必须看到 `establishing nat hole connection successful` 和实际传输成功才能视为可用。

### 诊断真实 WARP HardNAT 失败

在境外运行**含诊断日志的定制 frpc**，使用 `log.level = "info"` 即可查看：

```text
XTCP WARP NAT diagnostic: sid=... role=receiver mode=2 result=failed elapsed=38s associations=257 localRelayWrites=257 localWriteErrors=0 relayReplies=0 discardedRelayFrames=0 decodedErrors=0 wrongSID=0 matchingSID=0 ignoredSenderProbes=0
```

- `localRelayWrites`：仅说明加了 SOCKS5 UDP 封装的数据已经成功写到**本机回环 WARP 中继**；**不是** WARP 已发送公网、对端已收到的证据。包括多关联和发送探测消息，不包括配置外的原生 UDP。
- `localWriteErrors`：本机回环 SOCKS5 UDP 发送失败次数；这里大于 0 首先检查代理状态和关联生命周期。
- `relayReplies`：所有 SOCKS5 关联收到并接受了**来自指定本机 relay** 的 UDP 封装帧数量。始终为 0 且 `localRelayWrites>0`，应检查 WARP 公网映射、入站 UDP 限制和境内端是否向该映射发出探测，不应继续盲目改 STUN/凭据。
- `discardedRelayFrames`：来源/端口或 SOCKS5 UDP 包头不符而丢弃的帧；这意味着本机收到了 UDP，却无法确认来自指定 relay。
- `decodedErrors`、`wrongSID`：已收到 UDP，但是 NAT 探测包解码/会话匹配失败；此时再核对两端 XTCP secretKey 与 SID。
- `matchingSID`：完整通过解码和 SID 校验的探测包计数；接收到 SID 并不必然意味着后续 QUIC 握手成功。
- `ignoredSenderProbes`：本端为 sender 时按打洞协议忽略的未标记为 response 的探测包数量。

统计只覆盖当次 MakeHole 正在使用的 UDP 关联。随机目标端口发送是异步的，计数为**结束时快照**。这些日志不会打印 SOCKS5 Token、密码或业务负载。打洞成功后还应出现 `XTCP tunnel handshake start`、`XTCP tunnel handshake ready`；如果 `init tunnel session error: dial quic error: ...` 则说明 SID UDP 探测已成功但 QUIC 未完成。要确认业务可用，还需要境内 Python `exit agent connected` 和实际的 TCP/UDP SOCKS5 请求。

建议填写 **数字形式 STUN IP:端口**；使用 STUN 域名会在主机进行 DNS 解析，这段 DNS 不属于 SOCKS5 UDP Relay，可能暴露原始网络 DNS 请求。业务域名则由目标 SOCKS5 代理处理，不在本地解析。

## DATAGRAM 应用接口与边界

境外 Go Agent 在 TCP `127.0.0.1:6000` 连接 Visitor；自己的 UDP Socket 绑定 `127.0.0.1:6002`，向 frpc `127.0.0.1:6001` 发送数据。境内 UDP 端口相反。单个应用数据报作为一条 QUIC DATAGRAM 发送，不经可靠字节流，没有 TCP 回退。

应用层 RSX2 报文：`4-byte session ID (big endian) + RFC1928 SOCKS5 UDP packet`。**上限 1100 字节（包括会话 ID）**，超长直接丢弃、不提供任意 UDP/HTTP3 初始 QUIC 报文支持；HTTP/3 1200 字节 QUIC Initial 通常无法穿过当前应用 UDP 限额。Chromium/Chrome 通过普通 SOCKS5 代理时只代理 TCP，不会直接使用 SOCKS5 UDP ASSOCIATE。

TCP/RSX2 控制流使用每个 SOCKS5 会话独立的 32 帧窗口，接收端完成本地 Socket 写入后按最多 8 帧批量发送 WINDOW 额度，减少控制帧频率和视频突发期间慢客户端队列满立即断流的风险。新版 Go / Python RSX2 sender 采用控制优先、按会话轮询和有界缓冲，并记录 WINDOW/锁等待、慢写和 `drain()` 等指标。

### RSX3 高吞吐升级（参考 Hysteria 2 的每 TCP QUIC Stream）

RSX3 是新的 Go/Python Agent 应用层协议，frps 无需更新、XTCP 协商结构不变。境外 Go Agent 为每条 SOCKS5 TCP CONNECT 新建一个到**本地** frpc XTCP Visitor 的 TCP 连接，这条连接自动映射到同一条 P2P QUIC Connection 的**独立双向 Stream**。短小的 RSX3 Control Stream 只处理会话 OPEN/CANCEL/UDP 事务；QUIC DATAGRAM 仍负责应用层 UDP，不通过 TCP 复用。数据 Stream 使用 Control Epoch + SID + 单次随机 nonce 的 HMAC 验证，拒绝其他会话伪造/重复关联；Go 目标建连仍**只能**经过 WARP SOCKS5。

因为客户端可能 `CloseWrite()` 后继续读取响应，XTCP 原本 `libio.Join` 在任一方向 EOF 时关闭两个 socket 的行为会导致响应被截断。此 fork 为**非额外加密/压缩**的 XTCP 原生 QUIC/TCP 传输实现了双向 Half-Close（`CloseWrite` 发送 FIN 而不取消 QUIC 读取方向），其他类型代理保持旧行为。RSX3 不需要再启用额外的 frpc 传输加密/压缩：QUIC 自身已经通过 TLS 加密。

frpc 对 QUIC 接收窗口设定 8 MiB Stream、20 MiB Connection 上限，并使用保守基础 UDP MTU，降低 SOCKS5/WARP 额外封装下的大包黑洞风险。**这些设置不能解决 WARP 链路本身的 RTT/拥塞问题**，应通过后续 qlog 实际测量。

quic-go 原生 qlog：在境内外 frpc 启动前设置 `QLOGDIR` 环境变量为仅管理员可读目录，重启并执行流量测试，QUIC 关闭后可看到 `*.sqlog`（JSON-seq，包含 RTT、重传、packet loss、拥塞窗口和恢复事件）。例如 VPS：`install -d -m 700 /root/frpc-qlog`，再在 x-ui 实际启动环境里设置 `QLOGDIR=/root/frpc-qlog`；仅在 shell 中 export 不能自动更改已运行的 systemd 服务环境。qlog 不应随意对外分享，它包含连接时序和目标路径元数据。

### XTCP QUIC 双端 Brutal 风格实验发送器（默认关闭）

用于测试高丢包时能否保持预设发送速率，不涉及 KCP，也不发送无界冗余包。参考 Hysteria 2 的 Brutal 设计，但本 fork 独立实现了 5 秒 ACK/loss 采样、保守丢包补偿、token-bucket pacing、最高 **64 Mbps** 的配置限制和 **8 MiB** 的连接发送窗口上限。QUIC 自身的加密、ACK、重传、流控、DATAGRAM 继续生效；**最大带宽是所有发包（含重传）共同遵守的长期 pacing 上限，不是额外可叠加的速率**。网络拥塞下提速并不保证，带宽设得太高仍然可能加剧拥塞。

需要先将 **境内 Windows XTCP Proxy 与境外 VPS XTCP Visitor 的 frpc 都升级到本次构建**。在两端 `frpc.toml` 的**文件根部**、任何 `[[proxies]]` / `[[visitors]]` 表格之前，分别加入：

```toml
# transport.protocol 仍应按原配置；这三个字段只改变 XTCP QUIC
# 的发送侧，不会将 frpc/frps 控制连接改为 KCP 或 UDP。
transport.quic.congestionMode = "brutal"
transport.quic.targetMbps = 16
transport.quic.maxMbps = 24
```

境外 x-ui 反向 SOCKS5 页面可选择「Brutal 风格」，分别填写目标速率 16 Mbps 与最大发包速率 24 Mbps；保存时自动生成上述根部字段。x-ui **只能管理境外 frpc**，所以境内 `frpc.toml` 仍需手动设置这些相同字段。两端的发送方向彼此独立，例如境外参数控制视频下载方向，境内参数控制上传方向。带宽参数可以不同，但建议首轮双方都设置 16/24，再依实验结果逐步调整。

恢复普通控制器：两端删除以上三个字段（或设 `transport.quic.congestionMode = "cubic"` 且不设置目标速率参数），x-ui 同时选「CUBIC / 默认」，然后重新连接。**Brutal 模式的配置验证是严格的**：必须提供合法 1–64 Mbps 数值；境外 Visitor 仍必须配置 `transport.proxyURL` 和相同的 `natTraversal.udpProxyURL` 指向本地 WARP SOCKS5，同时禁用辅助地址与回退；境内 Proxy 固定 `natTraversal.bindPort=39999` 不变；frps v0.69.0 完全不变。若 x-ui 检测到旧版 frpc 忽略 Brutal 配置，它会拒绝应用，而不是悄悄退回 CUBIC。

首轮先使用普通 CUBIC 基线测试 10 MB 下载，再以 Brutal 双端 16/24 运行相同测试，并用两端 `QLOGDIR` 比较 RTT、packet_lost、recovery 和拥塞窗口。不应把本地假 WARP 测试当成真实跨境速度的保证。

部署 RSX3 时需**同时**更新境内 Python `--protocol rsx3`、x-ui Go Exit Agent 选择 `RSX3`，以及最新版两端 frpc。RSX2 只能通过两端显式选择兼容模式启用，版本不匹配时拒绝认证，不会隐式降级。详见 `nat_node/RSX3.md`。

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
