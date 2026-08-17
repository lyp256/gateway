package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

const (
	EventTcpStream = 1
	EventSniffers  = 2
)

const (
	// EgressRuleNone 表示 egress_map 中的空槽位。
	EgressRuleNone uint8 = 0
	// EgressRuleFwmark 兼容原模式：命中路由后直接设置 skb->mark。
	EgressRuleFwmark uint8 = 1
	// EgressRuleTproxy 命中路由后通过 bpf_sk_assign 交给本地 tproxy 监听 socket。
	EgressRuleTproxy uint8 = 2

	// MaxEgressRules 与 filter.c 中 egress_map 的容量一致。
	MaxEgressRules = 256

	// DnsRedirectMapKey 是 dns_redirect_map 的单槽 key。
	DnsRedirectMapKey uint32 = 0

	// DnsTproxyFwmark 是 DNS 透明代理 mark，与 filter.c 中 DNS_TPROXY_FWMARK 一致。
	// 控制面据此安装 `ip rule add fwmark <mark> lookup <table>` + local 路由，
	// 把目的地址非本机的 DNS 查询导向本地投递。
	DnsTproxyFwmark = 0x1

	// TcpTproxyFwmark 是 TCP egress tproxy 的透明代理 mark，与 filter.c 中
	// TCP_TPROXY_FWMARK 一致。控制面把它路由到本地透明监听 socket。
	TcpTproxyFwmark = 0x2
)

func ToFilterBpfLpmTrieKeyV4(ip netip.Prefix) FilterBpfLpmTrieKeyV4 {
	return FilterBpfLpmTrieKeyV4{
		Prefixlen: uint32(ip.Bits()),
		Data:      ip.Addr().As4(),
	}
}

// NewFwmarkEgressRule 构造打 fwmark 的 egress 规则（兼容原实现）。
func NewFwmarkEgressRule(mark uint32) FilterEgressRule {
	return FilterEgressRule{Type: EgressRuleFwmark, Fwmark: mark}
}

// EgressRuleTypeString 返回 egress 规则类型的可读名称。
func EgressRuleTypeString(t uint8) string {
	switch t {
	case EgressRuleFwmark:
		return "fwmark"
	case EgressRuleTproxy:
		return "tproxy"
	default:
		return "none"
	}
}

// NewTproxyEgressRule 构造 tproxy egress 规则。
// addr 为零值表示按包的原目的地址查找 socket；port 为 0 表示按包的原目的端口查找。
func NewTproxyEgressRule(addr netip.Addr, port uint16) (FilterEgressRule, error) {
	rule := FilterEgressRule{Type: EgressRuleTproxy}
	if addr.IsValid() {
		if !addr.Is4() {
			return rule, fmt.Errorf("tproxy addr must be IPv4: %s", addr)
		}
		copy(rule.TproxyAddr[:], addr.AsSlice())
	}
	if port != 0 {
		rule.TproxyPort[0] = byte(port >> 8)
		rule.TproxyPort[1] = byte(port)
	}
	return rule, nil
}

// NewDnsRedirectTarget 构造 UDP 53 DNS 重定向目标。
// addr/port 必须指向控制面 DNS server 的本地监听地址，否则返回错误；
// 返回的目标带 Enabled=1，写入 dns_redirect_map 后 BPF 数据面即开始拦截。
func NewDnsRedirectTarget(addr netip.Addr, port uint16) (FilterDnsRedirectTarget, error) {
	target := FilterDnsRedirectTarget{}
	if !addr.Is4() {
		return target, fmt.Errorf("dns redirect addr must be IPv4: %s", addr)
	}
	if port == 0 {
		return target, fmt.Errorf("dns redirect port must not be 0")
	}
	copy(target.Addr[:], addr.AsSlice())
	target.Port[0] = byte(port >> 8)
	target.Port[1] = byte(port)
	target.Enabled = 1
	return target, nil
}

// DisabledDnsRedirectTarget 返回禁用状态的 DNS 重定向目标，
// 写入 dns_redirect_map 后 BPF 数据面停止拦截 UDP 53。
func DisabledDnsRedirectTarget() FilterDnsRedirectTarget {
	return FilterDnsRedirectTarget{}
}

func FromFilterBpfLpmTrieKeyV4(key FilterBpfLpmTrieKeyV4) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4(key.Data), int(key.Prefixlen))
}

type TcpStream struct {
	Src        netip.AddrPort
	Dest       netip.AddrPort
	Mark       uint32 // FWMARK egress 或透明代理本地投递实际写入的 mark
	EgressIdx  uint8  // 命中路由的 egress 索引，对应 route_lpm_map value
	EgressType uint8  // EgressRuleNone / EgressRuleFwmark / EgressRuleTproxy
}

const (
	// TcpStreamBufferSizeV4 是 IPv4 连接事件 payload 大小：
	// family(1) + egress_idx(1) + egress_type(1) + pad(1) + fwmark(4) + IPv4 tuple(12)。
	TcpStreamBufferSizeV4 = 20
	// TcpStreamBufferSizeV6 是 IPv6 连接事件 payload 大小：tuple 部分为 36 字节。
	TcpStreamBufferSizeV6 = 44
)

func ParseTcpStream(buf []byte, v *TcpStream) error {
	if len(buf) < TcpStreamBufferSizeV4 {
		return fmt.Errorf("invalid TCP stream buf: %d bytes, want at least %d", len(buf), TcpStreamBufferSizeV4)
	}
	var (
		saddr, daddr netip.Addr
		sport, dport uint16
	)
	kind := buf[0]
	v.EgressIdx = buf[1]
	v.EgressType = buf[2]
	buf = buf[4:] // family + egress_idx + egress_type + pad
	v.Mark = binary.NativeEndian.Uint32(buf)
	buf = buf[4:]
	switch kind {
	case syscall.AF_INET:
		if len(buf) < 12 {
			return fmt.Errorf("invalid IPv4 TCP stream buf: %d bytes", len(buf))
		}
		saddr = netip.AddrFrom4([4]byte(buf))
		buf = buf[4:]
		daddr = netip.AddrFrom4([4]byte(buf))
		buf = buf[4:]
		sport = binary.BigEndian.Uint16(buf)
		buf = buf[2:]
		dport = binary.BigEndian.Uint16(buf)
	case syscall.AF_INET6:
		if len(buf) < 36 {
			return fmt.Errorf("invalid IPv6 TCP stream buf: %d bytes", len(buf))
		}
		saddr = netip.AddrFrom16([16]byte(buf))
		buf = buf[16:]
		daddr = netip.AddrFrom16([16]byte(buf))
		buf = buf[16:]
		sport = binary.BigEndian.Uint16(buf)
		buf = buf[2:]
		dport = binary.BigEndian.Uint16(buf)
	default:
		return fmt.Errorf("unknown TCP stream family %d", kind)
	}
	v.Src = netip.AddrPortFrom(saddr, sport)
	v.Dest = netip.AddrPortFrom(daddr, dport)
	return nil

}
