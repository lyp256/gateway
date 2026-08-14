#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2   // IPv4
#define AF_INET6 10 // IPv6

// 手动定义缺失的网络基础宏与字节序转换（摆脱系统头文件依赖）
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

#define MAX_HOSTNAME_LEN 253
#define MAX_EGRESS_RULES 256

// egress 规则类型：route_lpm_map 只存 8 位 egress 索引，
// 具体处理方式（打 fwmark 或 tproxy）由 egress_map 决定。
enum egress_rule_type
{
    EGRESS_RULE_NONE = 0,   // 空槽位，未配置
    EGRESS_RULE_FWMARK = 1, // 兼容原模式：直接设置 skb->mark
    EGRESS_RULE_TPROXY = 2, // 通过 bpf_sk_assign 交给本地 tproxy 监听 socket
};

struct egress_rule
{
    __u8 type;
    __u8 pad[3];
    __u32 fwmark;           // FWMARK：要设置的 skb->mark
    __u8 tproxy_addr[4];    // TPROXY：本地监听地址（网络字节序），全 0 表示使用包的原目的地址
    __u8 tproxy_port[2];    // TPROXY：本地监听端口（网络字节序），全 0 表示使用包的原目的端口
    __u8 pad2[2];
};

// 补齐基本的网络协议头结构体
struct ethhdr
{
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int version : 4;
    unsigned int ihl : 4;
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __u32 saddr;
    __u32 daddr;
};

struct ipv6hdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 priority : 4, version : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    __u8 version : 4, priority : 4;
#endif
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u32 saddr[4];
    __u32 daddr[4];
};

struct tcphdr
{
    __be16 source;
    __be16 dest;
    __u32 seq;
    __u32 ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u16 res1 : 4,
        doff : 4,
        fin : 1,
        syn : 1,
        rst : 1,
        psh : 1,
        ack : 1,
        urg : 1,
        ece : 1,
        cwr : 1;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    __u16 doff : 4,
        res1 : 4,
        cwr : 1,
        ece : 1,
        urg : 1,
        ack : 1,
        psh : 1,
        rst : 1,
        syn : 1,
        fin : 1;
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

// 3. 定义 BPF Maps
struct bpf_lpm_trie_key_v4
{
    __u32 prefixlen;
    __u8 data[4];
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct bpf_lpm_trie_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_lpm_map SEC(".maps");

// egress 规则表：key 为 egress 索引（0-255），与 route_lpm_map 的 value 对应。
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_EGRESS_RULES);
    __type(key, __u32);
    __type(value, struct egress_rule);
} egress_map SEC(".maps");

enum event_type
{
    tcp_stream = 1,
    sniffers = 2,

};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_ringbuf SEC(".maps");

// 连接事件 payload 固定大小：family(1) + egress_idx(1) + egress_type(1) + pad(1)
// + fwmark(4) + IPv6 tuple(36) = 44。
#define CONNECT_SIZE 44
struct connect
{
    __u8 family;      // AF_INET 或 AF_INET6
    __u8 egress_idx;  // route_lpm_map 命中的 egress 索引（无命中时为 0）
    __u8 egress_type; // EGRESS_RULE_NONE / EGRESS_RULE_FWMARK / EGRESS_RULE_TPROXY
    __u8 pad;
    __u32 fwmark;     // FWMARK egress 实际写入 skb 的 mark
    struct bpf_sock_tuple tuple;
};

static __always_inline void marshal_connect(void *buf, struct connect *c)
{
    __u8 *ptr = (__u8 *)buf;
    *(__u8 *)ptr = c->family;
    ptr += 1;
    *(__u8 *)ptr = c->egress_idx;
    ptr += 1;
    *(__u8 *)ptr = c->egress_type;
    ptr += 1;
    *(__u8 *)ptr = c->pad;
    ptr += 1;
    *(__u32 *)ptr = c->fwmark;
    ptr += 4;
    switch (c->family)
    {
    case AF_INET:
        *(__be32 *)ptr = c->tuple.ipv4.saddr;
        ptr += 4;
        *(__be32 *)ptr = c->tuple.ipv4.daddr;
        ptr += 4;
        *(__u16 *)ptr = c->tuple.ipv4.sport;
        ptr += 2;
        *(__u16 *)ptr = c->tuple.ipv4.dport;
        break;
    case AF_INET6:
        __builtin_memcpy(ptr, c->tuple.ipv6.saddr, sizeof(c->tuple.ipv6.saddr));
        ptr += 16;
        __builtin_memcpy(ptr, c->tuple.ipv6.daddr, sizeof(c->tuple.ipv6.daddr));
        ptr += 16;
        *(__u16 *)ptr = c->tuple.ipv6.sport;
        ptr += 2;
        *(__u16 *)ptr = c->tuple.ipv6.dport;
        break;
    }
}

#define SNIFFERS_FIXED_SIZE (CONNECT_SIZE + 1)
struct sniffers_request
{
    struct connect connect;
    __u8 hostname_len;
    char *hostname;
};

static __always_inline void marshal_sniffers_request(void *buf, struct sniffers_request *request)
{
    __u8 *ptr = (__u8 *)buf;
    marshal_connect(ptr, &(request->connect));
    ptr += CONNECT_SIZE;

    *(__u8 *)ptr = request->hostname_len;
    ptr += 1;
    bpf_probe_read_user_str(ptr, request->hostname_len, request->hostname);
}

// 异步上报 sniffer 事件
static __always_inline void report_sniffers_event(struct __sk_buff *skb, struct sniffers_request *request)
{
    void *buf = bpf_ringbuf_reserve(&events_ringbuf, SNIFFERS_FIXED_SIZE + request->hostname_len + 1, 0);
    if (buf == NULL)
        return;
    __u8 *ptr = (__u8 *)buf;
    *ptr = sniffers;
    ptr++;
    marshal_sniffers_request(ptr, request);
    bpf_ringbuf_submit(buf, 0);
}

// 异步上报 stream 事件
static __always_inline void report_tcp_stream_event(struct __sk_buff *skb, struct connect *connect)
{
    void *buf = bpf_ringbuf_reserve(&events_ringbuf, CONNECT_SIZE + 1, 0);
    if (buf == NULL)
        return;
    __u8 *ptr = (__u8 *)buf;
    *ptr = tcp_stream;
    ptr++;
    marshal_connect(ptr, connect);
    bpf_ringbuf_submit(buf, 0);
}

// 在 TC ingress 上把匹配 tproxy egress 的 TCP 包交给本地透明监听 socket。
// 使用包的四元组做 socket 查找：新连接命中监听 socket，已建立的连接回绑到
// 已连接 socket，保证同一流的后续包都走 tproxy 路径。
// 查找/分配失败时放行，由内核正常路由决定结果（fail-open）。
static __always_inline int tproxy_assign_tcp(struct __sk_buff *skb,
                                             struct iphdr *iph,
                                             struct tcphdr *th,
                                             struct egress_rule *rule)
{
    struct bpf_sock_tuple tuple = {};

    tuple.ipv4.saddr = iph->saddr;
    tuple.ipv4.daddr = iph->daddr;
    tuple.ipv4.sport = th->source;
    tuple.ipv4.dport = th->dest;
    // egress 配置了固定监听地址/端口时改写查找条件；
    // 否则按原目的地址/端口查找（socket 需以 IP_TRANSPARENT 绑定）。
    __u8 has_addr = rule->tproxy_addr[0] | rule->tproxy_addr[1] |
                    rule->tproxy_addr[2] | rule->tproxy_addr[3];
    if (has_addr)
        __builtin_memcpy(&tuple.ipv4.daddr, rule->tproxy_addr, 4);
    __u8 has_port = rule->tproxy_port[0] | rule->tproxy_port[1];
    if (has_port)
        __builtin_memcpy(&tuple.ipv4.dport, rule->tproxy_port, 2);

    struct bpf_sock *sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4),
                                             BPF_F_CURRENT_NETNS, 0);
    if (!sk)
        return TC_ACT_OK;

    long err = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);
    (void)err;
    return TC_ACT_OK;
}

SEC("classifier")
int tc_gateway_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 解析 IP 头
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // 优先检查 LPM 路由表匹配：value 是 egress 索引，具体行为查 egress_map。
    __u32 dest_ip = iph->daddr;
    struct bpf_lpm_trie_key_v4 lookup_key = {
        .prefixlen = 32};
    __builtin_memcpy(lookup_key.data, &dest_ip, sizeof(lookup_key.data));
    __u8 *route_egress = bpf_map_lookup_elem(&route_lpm_map, &lookup_key);
    struct egress_rule *rule = NULL;
    if (route_egress)
    {
        __u32 rule_idx = *route_egress;
        rule = bpf_map_lookup_elem(&egress_map, &rule_idx);
        // FWMARK 模式兼容原实现：对任意 IP 协议直接设置 skb->mark。
        if (rule && rule->type == EGRESS_RULE_FWMARK)
            skb->mark = rule->fwmark;
    }

    // 如果不是 TCP 协议，直接放行
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 【关键修复】：安全、动态地计算 TCP 头部起始位置
    // iph->ihl 存储的是以 4 字节为单位的 IP 报头长度
    __u32 ip_hlen = iph->ihl * 4;
    if (ip_hlen < 20) // 基础合规性检查
        return TC_ACT_OK;

    // 3. 解析 TCP 头 (使用计算出的动态偏移)
    struct tcphdr *th = (void *)((unsigned char *)iph + ip_hlen);
    if ((void *)(th + 1) > data_end)
        return TC_ACT_OK;

    // TPROXY 模式：每个 TCP 包都尝试把 socket 绑定到 skb，保证整条流被接管。
    if (rule && rule->type == EGRESS_RULE_TPROXY)
        tproxy_assign_tcp(skb, iph, th, rule);

    // 【核心过滤】：只处理 TCP 握手首包 (SYN=1, ACK=0)
    // 后续的所有数据包、ACK包、FIN包直接在此处放行，不触发 ringbuf 上报
    if (!(th->syn == 1 && th->ack == 0))
        return TC_ACT_OK;

    // 4. 构建连接元数据并上报用户态
    struct connect c = {
        .family = AF_INET,
        .egress_idx = route_egress ? *route_egress : 0,
        .egress_type = rule ? rule->type : EGRESS_RULE_NONE,
        .fwmark = skb->mark,
        .tuple.ipv4.saddr = iph->saddr,
        .tuple.ipv4.daddr = iph->daddr,
        .tuple.ipv4.sport = th->source,
        .tuple.ipv4.dport = th->dest,
    };
    report_tcp_stream_event(skb, &c);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
