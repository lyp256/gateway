#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2   // IPv4
#define AF_INET6 10 // IPv6

// 1. 手动定义缺失的网络基础宏与字节序转换（摆脱系统头文件依赖）
#define IPPROTO_TCP 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

#define MAX_HOSTNAME_LEN 253

// 2. 补齐基本的网络协议头结构体
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
    __u8 prefixlen;
    __u32 data;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct bpf_lpm_trie_key_v4);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_lpm_map SEC(".maps");

enum event_type
{
    sniffers = 1,
    tcp_stream = 2,
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_ringbuf SEC(".maps");

#define CONNECT_SIZE 37
struct connect
{
    __u8 family; // AF_INET 或 AF_INET6
    struct bpf_sock_tuple tuple;
};

void marshal_connect(void *buf, struct connect *c)
{
    __u8 *ptr = (__u8 *)buf;
    *(__u8 *)ptr = c->family;
    ptr += 1;

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

#define SNIFFERS_FIXED_SIZE 38
struct sniffers_request
{
    struct connect connect;
    __u8 hostname_len;
    char *hostname;
};

void marshal_sniffers_request(void *buf, struct sniffers_request *request)
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

SEC("classifier")
int tc_gateway_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 1. 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2. 解析 IP 头
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    __u32 dest_ip = iph->daddr;

    // 核心逻辑 A：优先检查 LPM 路由表匹配
    struct bpf_lpm_trie_key_v4 lookup_key = {
        .prefixlen = 32,
        .data = dest_ip};
    __u32 *route_mark = bpf_map_lookup_elem(&route_lpm_map, &lookup_key);
    if (route_mark)
    {
        skb->mark = *route_mark;
        return TC_ACT_OK;
    }

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 3. 解析 TCP 头

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

    struct tcphdr *th = (void *)(iph + 1);
    if ((void *)(th + 1) > data_end)
        return TC_ACT_OK;

    struct connect c = {
        .family = AF_INET,
        .tuple.ipv4.saddr = iph->saddr,
        .tuple.ipv4.daddr = iph->daddr,
        .tuple.ipv4.sport = th->source,
        .tuple.ipv4.dport = th->dest,
    };
    report_tcp_stream_event(skb, &c);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";