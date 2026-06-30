package query

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
)

// 基于 udp 解析 dns
type stdDNS struct {
	client *dns.Client
	addr   string // 上游地址 host:port
}

// newStdDNS 创建一个基于 UDP 的上游解析器。addr 为 host:port。
func NewStdDNS(addr string) DNSQuerier {
	return &stdDNS{
		client: dns.NewClient(),
		addr:   addr,
	}
}

// Query 实现 [DNSQuerier]。
func (s *stdDNS) Query(ctx context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	return s.client.Exchange(ctx, m, "udp", s.addr)
}

// Name 实现 [DNSQuerier]，返回 udp://host:port 形式的标识。
func (s *stdDNS) Name() string {
	return "udp://" + s.addr
}
