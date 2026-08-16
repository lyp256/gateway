# Gateway 设计文档

## 1. 文档信息

| 项目 | 内容 |
| --- | --- |
| 文档状态 | 开发阶段设计基线 |
| 适用范围 | `gateway` 主进程、eBPF 数据面、DNS 代理、规则管理和 egress 管理 |
| 目标平台 | Linux，内核支持 TC/eBPF、策略路由和 nftables/iptables |
| 当前实现语言 | Go + C/eBPF |
| 主要存储 | BoltDB |

本文以当前代码为基础，同时定义后续完整实现所需的目标架构。文中“当前”表示仓库已有行为，“目标”表示建议实现的最终行为，二者不应混淆。

## 2. 背景与目标

Gateway 位于主机或网关节点的数据路径上，负责根据用户态维护的规则对 IP 数据包设置 `fwmark`。Linux 后续通过 `ip rule`、策略路由表或 nftables/iptables 使用该标记，将流量送往不同出口。

规则来源包括：

1. 显式 IP/CIDR 规则；
2. 域名规则。DNS 代理观察域名解析结果，将 A/AAAA 地址转换为临时 IP 规则；
3. egress 配置。egress 可以是由外部系统管理的手工出口，也可以是 Gateway 自己维护的 HTTP 隧道出口。

核心目标：

- 在策略路由查找前稳定、低开销地完成 IP 匹配和标记；
- 域名规则能够随 DNS 解析结果动态生效，并按 TTL 回收过期地址；
- 规则、DNS、eBPF map、策略路由和隧道状态具有可恢复的一致性；
- 配置修改不需要重启进程；
- 对 IPv4、IPv6、转发流量和主机本地流量定义清晰的支持边界；
- 出现上游 DNS、隧道、内核 map 或网卡异常时可观测、可重试、可降级。

非目标：

- 初期不解析 HTTPS 内容，也不依赖 TLS SNI 作为域名规则的唯一来源；
- 不在 eBPF 中实现 TCP 连接跟踪、DNS 缓存或复杂规则编译；
- 不由 Gateway 接管宿主机全部防火墙策略，只管理带有明确 owner 标识的资源。

## 3. 当前代码盘点

### 3.1 模块结构

| 模块 | 当前职责 | 关键文件 |
| --- | --- | --- |
| eBPF | TC classifier、IPv4 LPM map、ring buffer 事件 | `bpf/src/filter.c`、`bpf/filter.go`、`bpf/generate.go` |
| BPF 控制器 | 加载对象、挂载 TC、读取 ring buffer | `controller/bpf.go` |
| DNS 控制器 | 本地静态解析、上游查询、DNS 结果写入路由表 | `controller/dns.go` |
| DNS 路由索引 | full/domain 两种域名匹配 | `dns/router/*` |
| 上游 DNS | UDP、DoT、DoH、静态解析 | `dns/query/*`、`server/server.go` |
| 持久化 | BoltDB 中保存域名规则、hosts、egress | `dao/*` |
| HTTP API | 路由、域名、hosts、egress 的查询和修改 | `controller/http.go`、`controller/http_handle.go` |
| 隧道 | TUN、转发、策略路由、NAT、HTTP 隧道客户端/服务端 | `tunnel/*`、`tunnel/http/*` |
| DNS 劫持脚本 | 示例 nftables 规则、DNS 代理策略路由 | `config/dns-proxy.conf`、`scripts/*` |

### 3.2 当前数据流

当前已实现的主要闭环如下：

```text
DNS 请求
  -> controller.queryDNS
  -> static 或 UDP/DoT/DoH 上游
  -> controller.dnsToRoute
  -> DNS 域名索引匹配 fwmark
  -> bart 内存路由表 + BPF LPM map
  -> 后续匹配 IPv4 包设置 skb->mark
```

当前 eBPF 程序在 `bpf/src/filter.c` 中：

- 只接受以太网头后的 IPv4；
- 查询 `route_lpm_map`，key 为目的 IPv4 `/32`，value 为 8 位 egress 索引；
- 通过 `egress_map` 解析 egress 规则：`manual` 类型设置 `skb->mark`（兼容原实现），
  `tproxy` 类型在 TC ingress 上调用 `bpf_skc_lookup_tcp` + `bpf_sk_assign` 把 TCP 交给本地透明监听 socket；
- 只对 TCP SYN（`SYN=1, ACK=0`）上报连接事件；
- IPv6、VLAN、IPv4 分片、IPv6 扩展头和 UDP 没有完整处理。

当前控制器在 `controller/bpf.go` 中通过 `HANDLE_MIN_INGRESS` 将程序挂载到 TC ingress，
在策略路由查找前设置 mark 或完成 tproxy socket 分配。

### 3.3 当前已知缺口

1. `bpf.FilterMaps.RouteLpmMap` 只包含 IPv4 map，没有 IPv6 map。
2. `addIRoute` 只接收 IPv4，动态地址没有 TTL、来源和过期回收信息。
3. DNS 服务目前只有普通 UDP listener；透明代理所需的原始目的地址解析辅助函数虽存在，但没有接入完整 listener 生命周期。
4. `config/dns-proxy.conf` 只示例拦截 `8.8.8.8`，不等于拦截所有 DNS 目标。
5. `EventSniffers` 和 sniffers 数据结构是预留代码，当前没有实际事件调用；TC 程序也不应直接依赖不可验证的用户态指针读取。
6. egress API 目前只读写 BoltDB，尚未将配置应用为隧道、路由规则或 NAT 资源。
7. HTTP 隧道客户端目前是独立命令 `cmd/tunnel-client`，与 Gateway 的 egress 配置没有生命周期绑定。
8. `WaitReady` 在 eBPF 加载和 TC 挂载 goroutine 真正成功前即被置为 ready，需要修正启动状态机。
9. 单条规则变更直接先写数据库、再改内存索引；BPF map 更新失败时没有统一的重试和一致性恢复机制。
10. API 当前没有认证、授权和配置版本控制；隧道 token 也支持通过 URL query 传递，存在日志泄漏风险。
11. ring buffer 事件协议没有版本和显式 wire schema；IPv4/IPv6 长度校验需要统一。

## 4. 总体架构

### 4.1 逻辑组件

```text
                         ┌──────────────────────────┐
                         │        管理客户端          │
                         └────────────┬─────────────┘
                                      │ HTTP API
                         ┌────────────▼─────────────┐
                         │       Control Plane        │
                         │ API / 校验 / 持久化 /      │
                         │ 规则编译 / 状态机 / 指标   │
                         └───────┬─────────┬──────────┘
                                 │         │
                   ┌─────────────▼─┐   ┌───▼─────────────┐
                   │ DNS Resolver   │   │ Egress Manager   │
                   │ 劫持/代理/缓存  │   │ 手工/TUN/隧道     │
                   └──────┬────────┘   └───┬─────────────┘
                          │ 动态 IP 规则       │ ip rule/route/NAT
                   ┌──────▼──────────────────▼─────┐
                   │       Rule Compiler             │
                   │  显式规则 + DNS lease -> 快照    │
                   └────────────────┬───────────────┘
                                    │ 原子 map 发布
                   ┌────────────────▼───────────────┐
                   │           eBPF Data Plane        │
                   │ TC ingress / socket / 可选 egress│
                   │ LPM lookup -> skb/sk mark       │
                   └────────────────┬───────────────┘
                                    │ policy routing
             ┌──────────────────────▼─────────────────────┐
             │ LAN / WAN / TUN / 外部出口 / 内核网络栈      │
             └────────────────────────────────────────────┘
```

### 4.2 数据路径

#### 转发流量

```text
网卡 ingress
  -> TC ingress eBPF
  -> 目的地址 LPM 匹配
  -> skb->mark = egress.fwmark
  -> Linux route lookup / ip rule
  -> 对应物理网卡或 TUN
```

TC ingress 是转发流量的默认挂载点，因为标记必须在策略路由查找前生效。TC egress 可以作为补充的观测或出口保护点，但不应作为唯一的分流点。

#### 主机本地生成流量

本地进程生成的包在 OUTPUT/route lookup 路径上不经过目标网卡的 ingress。目标实现提供以下二选一的实现，默认推荐第一种：

1. 使用 cgroup/connect4、connect6 或 socket mark，在连接建立/路由前根据目的地址设置 `sk_mark`；
2. 将编译后的地址集合同步到 nftables `output` mangle set，由 nftables 设置 `meta mark`。

对于未连接 UDP、原始 socket 和内核特殊流量，需要明确归入 nftables 兼容路径或声明不支持，不能假设 TC egress 能重新触发策略路由。

### 4.3 关键原则

- eBPF 只做每包快速查表和轻量事件上报，不访问 BoltDB、不执行 DNS、不创建路由。
- 用户态是规则和生命周期的唯一控制者；内核 map、nftables、ip rule、TUN 都是可重建的运行时资源。
- 运行时资源必须带 Gateway owner 标识，删除时只删除自己创建的对象。
- 所有配置修改都进入同一个 revision/reconcile 流程，避免 API handler 各自修改局部状态。
- 规则没有匹配时保持原始 mark；规则匹配时默认覆盖 mark，覆盖策略必须可配置。

## 5. eBPF 数据面设计

### 5.1 程序挂载

目标挂载矩阵：

| 流量 | 默认挂载 | 作用 |
| --- | --- | --- |
| 转发 IPv4/IPv6 | TC ingress | 在路由查找前设置 mark |
| 主机本地 TCP/UDP | cgroup connect 或 nftables OUTPUT | 在本地路由前设置 mark |
| 出口 TUN/物理网卡 | 可选 TC egress | 防止漏标、统计和调试，不负责首次分流 |

挂载配置应支持指定网卡列表；未指定时应发现实际转发入口，而不是只发现默认路由网卡。TUN、lo 和 Gateway 上游 DNS 出口应通过接口白名单或 mark 排除，避免循环。

运行时挂载管理（当前实现）：

- `GET /api/v1/nics` 枚举系统网卡（索引、类型、MAC、MTU、状态、IP 地址），并以内核 TC filter 为准标注 `tc_gateway_filter` 的实际挂载状态；
- `POST /api/v1/nics/{name}/attach` 将程序挂载到指定网卡的 TC ingress，已挂载时幂等返回；
- `DELETE /api/v1/nics/{name}/attach` 只移除本网关创建的 filter，未挂载时幂等返回；
- `PUT /api/v1/nics/{name}/auto-mount` 设置该网卡是否在程序启动时自动挂载（持久化，loopback 与不存在的网卡拒绝）；
- `GET/PUT /api/v1/bpf/settings` 读取/修改全局“启动时全部挂载”开关（持久化）；
- `GET /api/v1/bpf/status` 返回数据面就绪状态与当前挂载网卡数量，页面据此禁用不可用的挂载按钮。

启动自动挂载优先级：全局“全部挂载”开启时挂载所有可挂载网卡（排除 loopback）；否则挂载勾选了自动挂载的网卡（只保留当前存在且可挂载的，过滤后的空列表回退到默认路由网卡）；未勾选任何网卡时保持原有行为，回退挂载默认路由网卡。自动挂载与全部挂载场景下单项失败仅记录日志并跳过，默认路由回退场景挂载失败仍中止启动。数据面退出前统一解除全部挂载，避免重启后残留旧 filter。

### 5.2 Map 定义

建议的核心 map：

```text
route_v4: LPM_TRIE<key {prefixlen, __u8 addr[4]}, value RouteValue>
route_v6: LPM_TRIE<key {prefixlen, __u8 addr[16]}, value RouteValue>
active_routes: ARRAY_OF_MAPS[1] -> 当前 route_v4/route_v6 快照（可选双缓冲）
config: ARRAY<GlobalConfig>
stats: PERCPU_ARRAY / PERCPU_HASH
events: RINGBUF
```

`RouteValue` 的最小版本建议为：

```c
struct route_value {
    __u32 fwmark;
    __u32 mark_mask;
    __u32 rule_id;
    __u32 generation;
};
```

过期时间不建议让 eBPF 逐包判断；TTL 回收由用户态完成。若后续需要内核保护，可增加 `expires_at_ns`，但必须定义单调时钟、过期包行为和更新成本。

### 5.3 包解析

解析器必须满足 verifier 安全要求，并对以下情况有明确行为：

- Ethernet、单层/多层 VLAN；
- IPv4 IHL、校验边界、分片；
- IPv6 基本头和有限长度的扩展头遍历；
- 非 TCP/UDP 的 IP 协议；
- 不完整包、截断包、未知 EtherType；
- 目的地址为本机、广播、组播或隧道内部地址。

默认只根据目的 IP 设置 mark，不解析 TCP payload，也不在 eBPF 中重组分片。IPv4 和 IPv6 必须使用独立 map，key 的网络字节序在 C 和 Go 之间固定并测试。

### 5.4 标记语义

- `fwmark` 使用 `mark/mask` 语义，默认由 egress 分配不重叠的 mark。
- 未匹配时不修改 `skb->mark`；已存在且属于其他系统的 mark 不应无条件覆盖。
- 目标策略可以选择 `replace` 或 `preserve-if-nonzero`，初期默认 `replace`，并对 owner mask 做隔离。
- `ip rule` 的 mask、优先级、路由表 ID 和 egress fwmark 必须由同一配置校验器生成。

### 5.5 事件协议

ring buffer 只传递需要用户态处理的低频事件，例如 TCP SYN、丢包统计或调试事件。事件统一使用：

```text
version | type | length | timestamp_ns | ifindex | payload
```

要求：

- payload 使用显式固定宽度、网络字节序字段；
- 每个事件先校验 version、length 和 family，再解析地址；
- ring buffer 满时只增加 drop counter，不阻塞数据包；
- 不从 TC 程序读取任意用户指针；
- 域名归因优先依赖 DNS 代理，不依赖未完成的 sniffers 事件。

## 6. 规则模型与编译

### 6.1 egress

egress 是规则引用的稳定目标，API 不应要求用户在每条规则中重复填写 mark。

建议模型：

```json
{
  "name": "proxy-a",
  "type": "manual",
  "fwmark": 4097,
  "markMask": 4294967295,
  "tableId": 2001,
  "priority": 1100,
  "tunnel": {
    "url": "https://tunnel.example/connect",
    "tokenRef": "secret://gateway/tunnel-a"
  },
  "enabled": true
}
```

类型：

- `manual`：Gateway 只负责写 mark，外部系统负责策略路由和出口；
- `http_tunnel`：Gateway 负责连接隧道、TUN、地址、路由规则、NAT 和重连；
- `tproxy`：Gateway 在 TC ingress 上把匹配的 TCP 通过 `bpf_sk_assign` 交给本地透明监听
  socket，`addr`/`port` 留空或为 0 时按包的原目的地址/端口查找。

`fwmark` 必须显式校验冲突；基于设备名 hash 自动生成只能作为兼容默认值，不能作为持久化配置的唯一标识。

### 6.2 域名规则

建议模型：

```json
{
  "id": "rule-domain-001",
  "match": "full",
  "domain": "api.example.com",
  "egress": "proxy-a",
  "priority": 100,
  "enabled": true
}
```

`match`：

- `full`：只匹配完全相同的域名；
- `domain`：匹配自身和所有子域名。

保存和匹配前统一完成：小写化、去掉末尾根域点、IDNA/Punycode 规范化、长度和 label 校验。DNS 查询名也使用相同规范化流程。

域名匹配优先级建议为：更具体的 suffix 优先；相同域名的 full 优先于 domain；再比较显式 priority；最后使用稳定的 rule ID 作为 tie-breaker。

### 6.3 IP/CIDR 规则

建议新增显式 IP 规则：

```json
{
  "id": "rule-cidr-001",
  "cidr": "203.0.113.0/24",
  "egress": "proxy-a",
  "priority": 100,
  "enabled": true
}
```

LPM 负责最长前缀匹配；同一 CIDR 的冲突由 priority 和 rule ID 决定。编译器生成的最终快照只保留每个有效前缀的唯一 `RouteValue`。

### 6.4 DNS 动态 lease

域名规则解析出的地址不能直接视为永久 IP 规则。用户态保存动态 lease：

```text
domain_rule_id
canonical_domain
ip
family
fwmark
first_seen
last_seen
ttl
expires_at
generation
source_dns
```

规则编译器将未过期的显式 CIDR 和动态 lease 聚合成 eBPF route snapshot。多个域名同时引用同一 IP 时，使用规则优先级选出唯一 mark；删除一个 lease 不能误删其他仍有效的引用。

TTL 策略：

- 使用 DNS RR 的 TTL；
- 配置最小和最大 TTL，防止异常的 0 或超大 TTL；
- 到期前可按比例提前刷新；
- 到期后从 lease 集合和 map 删除；
- DNS NXDOMAIN/空应答执行负缓存，但不能凭一次失败立即删除尚未过期的正记录；
- API 删除域名规则时立即删除其全部动态引用。

### 6.5 编译和发布

规则编译器输入：

```text
持久化规则 + egress 状态 + 有效 DNS leases + 运行时 override
```

输出：

```text
RouteSnapshot { generation, v4 entries, v6 entries, counts, checksum }
```

推荐使用双 map/`ARRAY_OF_MAPS` 发布：

1. 在非活动 map 构建完整快照；
2. 校验 entry 数、mark、CIDR、checksum；
3. 原子替换活动 map 引用；
4. 延迟回收旧 map。

如果目标内核或库版本暂时不支持 map swap，第一阶段可以使用 `BatchUpdate` + `BatchDelete`，但必须将短暂不一致记录为 degraded，并由后台 reconcile 最终修复。

## 7. DNS 服务设计

### 7.1 服务边界

DNS 服务承担：

- 接收客户端原始 DNS 请求；
- 识别请求的原始目的地址，支持透明代理返回路径；
- 静态 hosts 优先；
- 本地缓存和负缓存；
- 按顺序或健康状态选择 UDP/DoT/DoH 上游；
- 返回原始 DNS 响应；
- 提取 A/AAAA 和 TTL，提交给规则编译器。

DNS 服务不负责直接操作 eBPF map；它只产生 `DNSObservation`，由 lease manager 和 rule compiler 处理。

### 7.2 透明拦截

目标覆盖：

- 转发的 UDP/53；
- 转发的 TCP/53；
- 本机 OUTPUT 的 UDP/53 和 TCP/53；
- IPv4/IPv6。

UDP listener 需要透明 socket、原始目的地址控制消息和正确的回包源地址；TCP listener 需要读取 `SO_ORIGINAL_DST` 或等价的 TPROXY 原始目的地址。现有 `parseOriginalDstFromCmsgs`、`parseRequestDstFromCmsgs` 等函数可作为底层解析基础，但需要补齐 listener、socket option、生命周期和 IPv6 流程。

nftables 规则必须由 Gateway 以独立 table/chain 管理，并排除：

- Gateway DNS listener 自身的回环流量；
- 上游 DNS socket；
- 已带 DNS-proxy owner mark 的流量；
- 本机本地目的地址。

不能只维护固定的 `8.8.8.8` 集合来宣称“拦截所有 DNS”。对于 DoH/DoT，由于请求内容加密，初期只提供上游客户端能力，不承诺透明识别任意第三方 DoH/DoT 客户端。

### 7.3 DNS 查询流程

```text
收到请求
  -> 校验 question / transport / 原始目的地址
  -> canonicalize name
  -> static hosts
  -> 正/负缓存
  -> 选择健康上游并查询
  -> 复制响应给客户端
  -> 提取 A/AAAA、CNAME 关联名、TTL
  -> DNS lease manager 更新动态地址
  -> 触发 rule compiler
```

上游失败时继续尝试其他健康上游；所有上游失败返回 SERVFAIL。响应中的 CNAME 链需要做大小限制，避免异常响应造成无限归因或内存增长。

### 7.4 DNS 缓存与并发

- 相同 query key 使用 singleflight，避免并发请求击穿上游；
- cache key 至少包括 qname、qtype、qclass、DNSSEC/EDNS 相关影响因素；
- 缓存条目保存过期时间，不复用上游已过期 TTL；
- 限制缓存总条目和单域名地址数量；
- 规则更新、hosts 更新和 DNS lease 更新均使用不可变快照或明确的读写锁；
- DNS 上游请求必须带 context deadline。

## 8. egress 管理

### 8.1 Egress Manager 接口

建议抽象为：

```go
type EgressManager interface {
    Apply(ctx context.Context, spec EgressSpec) error
    Delete(ctx context.Context, name string) error
    Status(name string) EgressStatus
    Close(ctx context.Context) error
}
```

`manual` 实现只校验 mark，不创建网络资源；`http_tunnel` 实现管理完整生命周期。

### 8.2 HTTP 隧道生命周期

```text
Disabled
  -> Starting
  -> Connecting
  -> AllocatingAddress
  -> ConfiguringTUN
  -> ConfiguringRoute/NAT
  -> Ready
  -> Degraded/Reconnecting
  -> Stopping
```

HTTP 隧道 egress 的启动步骤：

1. 校验 URL、认证引用、MTU、设备名、mark 和 route table ID；
2. 建立 HTTP/1.1 raw tunnel 或 HTTP/2 stream tunnel；
3. 校验握手版本、状态、地址和校验和；
4. 创建并配置 TUN；
5. 创建带明确 owner 的 MASQUERADE 规则；
6. 创建 `ip rule fwmark mark/mask lookup table` 和 TUN 默认路由；
7. 启动双向转发；
8. 发布 egress Ready 状态，触发规则快照编译。

任何中途失败都必须按反向顺序清理已经创建的资源。重连时保持逻辑 egress name 和 fwmark 不变，仅替换运行时连接和 TUN 资源。

当前 `tunnel/http/client.go`、`tunnel/tun.go` 已提供不少底层能力，但正式集成时应将其放入 manager，而不是让 API handler 或独立命令分别管理同一 egress。现有设备名 hash 生成 mark/table ID 的逻辑应改为显式配置或持久化分配器。

### 8.3 路由和 NAT 资源

每个 egress 资源需要记录：

```text
owner = gateway
egress_name
generation
fwmark/mask
rule_priority
route_table_id
interface_name
```

删除时通过精确属性匹配删除，不能按整张 table、整条 chain 或模糊接口名清空。程序退出时执行 best-effort 清理，启动时执行 owner 资源审计和孤儿回收；审计失败时进入 degraded，不应删除未知来源资源。

## 9. Control Plane 与一致性

### 9.1 启动顺序

目标顺序：

1. 打开 BoltDB，校验 schema 和数据；
2. 加载并规范化 egress、hosts、显式规则、DNS leases；
3. 创建内存只读快照；
4. 初始化 egress manager；
5. 加载 eBPF 对象、map 和程序；
6. 挂载 ingress/socket/OUTPUT 路径；
7. 编译并发布首个 route snapshot；
8. 启动 DNS listener、HTTP API、reconcile 和 metrics；
9. 所有必需组件成功后才报告 Ready。

当前 `controller.Run` 在 `bpfServer` goroutine 真正完成前即关闭 ready channel，应该改为显式 `Starting/Ready/Degraded/Stopping/Stopped` 状态机。

### 9.2 修改流程

所有规则、hosts 和 egress API 遵循同一流程：

```text
请求
  -> schema 校验 / 规范化 / 冲突检查
  -> BoltDB 原子写入 revision N
  -> 发布内部变更事件
  -> 更新内存快照和运行时资源
  -> 编译 route snapshot
  -> 发布成功：Applied N
```

若运行时应用失败：

- 数据库仍保留 revision N 作为期望状态；
- 状态标记为 `Pending/Degraded`；
- 后台 reconcile 重试；
- API 返回明确的 applied 状态或异步 operation ID；
- 进程重启后从数据库重新应用，不依赖内存状态。

删除操作要按 `rule_id` 或规范化复合 key 定位，不能只按 domain 删除后误删同域名的其他 match 类型。当前 `deleteDomainRule` 只按 domain 调用 `dnsTable.Delete`，目标实现需要修正为删除精确规则并重新编译该域名的有效优先级。

### 9.3 Reconcile

后台 reconcile 周期性校验：

- 数据库期望 revision 与运行时 applied revision；
- BPF map 内容/checksum；
- TC/cgroup/nftables 挂载；
- egress TUN、ip rule、route、NAT；
- DNS listener 和上游健康状态。

reconcile 必须幂等、可中断、限速，并将每次失败的资源、错误和下一次重试时间写入状态。

## 10. 持久化设计

现有 BoltDB 使用 `gateway` bucket 和字符串前缀 key。建议保留兼容读取，同时逐步迁移到显式 bucket：

```text
meta
egresses
domain_rules
cidr_rules
hosts
dns_leases
operations
```

`meta` 保存 schema version、last revision、instance ID。所有持久化对象使用稳定 ID 和 JSON schema version；敏感 token 不直接以明文写入普通配置响应，至少通过 tokenRef 或受限字段返回。

迁移要求：

- 启动时检测旧 `dr:`、`host:`、`tunnel:` key；
- 校验后迁移到新结构；
- 迁移成功写入 version marker；
- 迁移失败拒绝启动并保留原数据；
- 提供只读导出和备份恢复说明。

## 11. HTTP API 设计

保留 `/api/v1`，建议增加以下资源：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/v1/status` | 进程、组件、revision、degraded 原因 |
| GET/PUT/DELETE | `/api/v1/egresses`、`/api/v1/egresses/{name}` | egress 配置和状态 |
| GET/PUT/DELETE | `/api/v1/domains`、`/api/v1/domains/{id}` | 域名规则 |
| GET/PUT/DELETE | `/api/v1/cidrs`、`/api/v1/cidrs/{id}` | 显式 IP/CIDR 规则 |
| GET/PUT/DELETE | `/api/v1/hosts`、`/api/v1/hosts/{host}` | 静态 DNS |
| GET | `/api/v1/routes` | 当前有效 IPv4/IPv6 快照及来源 |
| GET | `/api/v1/dns/cache` | DNS 缓存/lease 摘要 |
| DELETE | `/api/v1/dns/cache/{name}` | 按域名删除 DNS 缓存（忽略大小写与末尾点，同域名的 A/AAAA 等条目一并清除） |
| GET | `/api/v1/operations/{id}` | 异步应用结果 |
| GET | `/metrics` | Prometheus 指标 |

当前 `DomainRule` 直接使用 `egress` 引用，fwmark 由控制器在加载和写入时解析。服务端必须拒绝不存在的 egress、无效域名、非法 CIDR、mark/table 冲突和不允许的系统范围配置。

### 11.1 列表查询约定

所有列表 GET 接口（`/routes`、`/domains`、`/cidrs`、`/hosts`、`/dns/servers`、`/whitelist`、`/dns/cache`、`/egresses`）统一支持以下 query 参数：

| 参数 | 说明 |
| --- | --- |
| `page` | 页码，从 1 开始，默认 1 |
| `per_page` | 每页条数，默认 20，上限 1000 |
| `sort` | 排序字段，按各资源白名单校验；非法字段回退默认排序 |
| `order` | `asc` / `desc`，默认按资源各自的默认方向 |
| `search` | 大小写不敏感的关键字，命中资源的任意可搜索字段 |

响应体保持为纯数组（当前页条目），分页元信息放在响应头：
`X-Total-Count`（过滤后总数）、`X-Page`、`X-Per-Page`。
`/routetree` 是层级结构，只支持 `search` 递归过滤，不做分页与排序。

列表数据的搜索、排序、分页全部在内存中完成：BoltDB 只承担全量遍历（数据规模小且多为内存态），
`controller/query.go` 的通用查询引擎负责关键字过滤、按白名单字段稳定排序和切片分页，
避免为每种资源在存储层实现复杂查询。排序使用稳定排序并以存储顺序作为并列时的固定次序，保证分页结果确定。

API 安全基线：

- 默认只监听 loopback 或 Unix socket；
- 远程管理必须启用 TLS 和认证；
- 写操作需要授权，读写权限分离；
- 配置修改支持 `If-Match`/revision，避免并发覆盖；
- 错误响应不返回 token、完整上游 URL 中的敏感 query 或内核内部细节。

## 12. 可观测性

### 12.1 指标

建议至少提供：

- `gateway_ready`、`gateway_degraded`；
- `gateway_config_revision`、`gateway_applied_revision`；
- `gateway_route_entries{family}`；
- `gateway_route_map_updates_total{result}`；
- `gateway_bpf_packets_total{family,matched}`；
- `gateway_bpf_events_total{type}`、`gateway_bpf_event_drops_total`；
- `gateway_dns_queries_total{transport,upstream,result}`；
- `gateway_dns_query_duration_seconds`；
- `gateway_dns_cache_entries`、`gateway_dns_leases{state}`；
- `gateway_egress_state{egress,state}`、重连次数和最后错误；
- `gateway_reconcile_total{resource,result}`；
- TUN 转发包、字节、丢弃和错误。

指标 label 不使用原始域名、IP、rule ID 等高基数字段。

### 12.2 日志和诊断

日志字段至少包括：`revision`、`generation`、`egress`、`rule_id`、`interface`、`family`、`error`。提供：

- 当前组件状态和最后错误；
- route snapshot checksum；
- BPF 程序/map ID、挂载接口；
- owner 资源审计结果；
- DNS 上游健康列表；
- 单包调试开关和采样率。

## 13. 安全与故障处理

运行所需能力应尽量拆分和最小化，通常涉及 `CAP_NET_ADMIN`、eBPF 加载所需能力、TUN 和 nftables 操作。生产部署应使用 systemd sandbox、受限文件权限和独立运行用户；如果内核版本要求 root，则在部署文档中明确。

安全要求：

- eBPF 所有指针访问先做边界检查；
- DNS 请求、域名和响应大小限额；
- 上游 DoH/DoT 证书校验默认开启，`Insecure` 仅显式配置；
- 隧道 token 不通过 URL query 传输，优先 Authorization header 或受保护 secret；
- API、metrics、pprof 分开暴露并控制访问；
- nftables 和路由资源使用唯一 owner tag；
- 配置恢复前校验 schema、mark、table、接口和权限。

故障策略：

| 故障 | 数据面行为 | 控制面行为 |
| --- | --- | --- |
| DNS 上游全部失败 | 保留未过期动态规则 | 记录失败，指数退避 |
| 单个 DNS lease 过期 | 删除对应动态地址 | 重新编译快照 |
| BPF map 更新失败 | 保留上一版活动快照 | degraded + reconcile |
| egress 断线 | 由配置决定 fail-open 或 fail-closed | 重连，状态可见 |
| TUN/route 创建失败 | 不发布该 egress 的新规则 | 清理半成品并重试 |
| ring buffer 满 | 不影响转发 | 增加 drop 指标 |
| API 进程重启 | map/route 从 DB 重建 | 启动恢复并校验 |

默认推荐 fail-open：出口不可用时不强制丢弃未被策略明确要求阻断的流量；对需要强制代理的规则提供 `failClosed` 配置。

## 14. 测试计划

### 14.1 单元测试

- 域名 canonicalize、full/domain、通配和优先级；
- IPv4/IPv6 CIDR 编译、最长前缀和冲突选择；
- DNS TTL、CNAME、NXDOMAIN、lease 过期和多来源聚合；
- BoltDB 迁移、revision、重启恢复；
- mark/mask、rule priority、table ID 冲突；
- ring buffer 各 family wire decode 和非法长度；
- TUN 转发的分包、MTU 和 IPv4/IPv6 数据。

### 14.2 集成测试

使用 network namespace、veth、TUN 和 mock DNS/tunnel server 验证：

1. IPv4 转发包在 ingress 被设置 mark 并命中预期策略路由；
2. IPv6 转发包路径和 IPv6 route table；
3. 域名 DNS 响应生成 lease，TTL 到期后 map 删除；
4. 相同 IP 被多个域名规则引用时不会提前删除；
5. DNS UDP/TCP 透明代理能按原始目的地址正确回包；
6. 主机本地 TCP、UDP 和未连接 UDP 的标记路径；
7. egress 启动、重连、半失败清理和退出恢复；
8. Gateway 重启后从数据库恢复同一份有效快照；
9. 多次 reconcile 不产生重复 ip rule、route、nft rule；
10. BPF verifier、内核不支持某特性和 ring buffer overflow。

### 14.3 性能和压力

- 固定 map 大小下的每包 LPM 延迟；
- DNS 高并发、singleflight 和缓存命中率；
- 大量域名解析导致的 lease churn；
- route snapshot 全量发布耗时和峰值内存；
- ring buffer 满时转发吞吐不下降；
- 多网卡和多个 egress 并发重连。

## 15. 分阶段实施计划

### Phase 0：契约和基础修复

- 固定 eBPF map、事件 wire schema、mark/mask 语义；
- 修复 ready 状态和 controller 生命周期；
- 增加 API 认证、配置校验和 schema/revision；
- 将规则应用统一收敛到 reconcile；
- 补充当前代码缺少的单元测试。

### Phase 1：可用的 IPv4 静态分流

- 增加 CIDR 规则模型和 API；
- eBPF 改为 TC ingress；
- 实现 route snapshot 和 BPF map 同步；
- 对手工 egress 完成 mark/mask 与策略路由校验；
- 在 namespace 中验证转发路径。

### Phase 2：透明 DNS 和动态域名规则

- 完成 UDP/TCP 透明 DNS listener；
- 接入原始目的地址和 upstream bypass；
- 增加 DNS cache、TTL lease、过期回收和多规则聚合；
- 将 `dnsToRoute` 改为 observation -> lease -> compiler 流程；
- 替换固定 `8.8.8.8` 示例为可配置的全量 DNS 拦截策略。

### Phase 3：egress 生命周期

- 将 HTTP tunnel client 集成到 egress manager；
- 使用显式稳定 fwmark/table ID；
- 管理 TUN、ip rule、route、NAT 和重连；
- 暴露 egress 状态、失败原因和异步 operation。

### Phase 4：IPv6、可靠性和生产化

- IPv6 LPM、透明 IPv6 DNS 和本地 IPv6 标记；
- 双 map 原子发布；
- owner 资源审计、孤儿回收、升级迁移；
- 完成性能压测、权限收敛、systemd/container 部署和故障演练。

## 16. 需要尽早确认的产品决策

以下决策会影响 API 和数据模型，应在 Phase 1 前确定：

1. Gateway 是否只做三层转发，还是必须支持本机所有应用流量；
2. egress 不可用时每条规则默认 fail-open 还是 fail-closed；
3. 是否需要 IPv6 与 IPv4 同期交付；
4. 域名规则是否需要通配符、正则或仅 full/domain；
5. 一个 IP 被多个规则命中时的优先级定义；
6. HTTP 隧道由 Gateway 主进程托管，还是保留独立 tunnel-client 进程并通过 IPC 管理；
7. API 的认证方式、远程管理范围和 token secret 存储方式；
8. 是否需要配置导入/导出、集群同步和高可用。

## 17. 验收标准

完成第一版生产可用实现时，至少满足：

- IPv4 转发数据包在策略路由查找前被正确设置 mark；
- 显式 CIDR 规则可持久化、热更新、重启恢复和删除；
- DNS 代理能处理 UDP/TCP 透明请求，并将响应的 A/AAAA 按 TTL 转为动态规则；
- 动态 IP 到期、规则删除和多规则引用均不会产生脏 map；
- egress 的 mark、策略路由和运行状态可查询，HTTP 隧道失败可重试和清理；
- BPF、DNS、route、egress、reconcile 均有指标和明确错误状态；
- 在 network namespace 集成测试中验证分流结果，而不只验证内存 map 内容；
- API 未授权不能修改规则，敏感 token 不出现在普通日志和响应中。
