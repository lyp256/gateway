package query

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"time"

	"codeberg.org/miekg/dns"
)

// 基于 dot 解析dns
type dot struct {
	client *dns.Client
	addr   string // 上游地址 host:port
}

// newDoT 创建一个基于 DNS-over-TLS 的上游解析器。
// addr 为 host:port，serverName 用于 TLS 校验，insecure 为 true 时跳过证书校验。
func NewDoT(serverName string, port uint16, ip netip.Addr, insecure bool) DNSQuerier {
	portStr := strconv.Itoa(int(port))
	addr := net.JoinHostPort(serverName, portStr)
	if ip.IsValid() {
		addr = net.JoinHostPort(ip.String(), portStr)
	}
	transport := dns.NewTransport()
	transport.TLSConfig = &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
	return &dot{
		client: &dns.Client{Transport: transport},
		addr:   addr,
	}
}

// Query 实现 [DNSQuerier]。
func (d *dot) Query(ctx context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	return d.client.Exchange(ctx, m, "tcp", d.addr)
}

// Name 实现 [DNSQuerier]，返回 tls://host:port 形式的标识。
func (d *dot) Name() string {
	return "tls://" + d.addr
}
