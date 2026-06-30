package query

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"codeberg.org/miekg/dns"
)

const dohContentType = "application/dns-message"

// 基于 doh 解析 dns
type doh struct {
	client *http.Client
	url    string // DoH 查询地址，例如 https://1.1.1.1/dns-query
}

// newDoH 创建一个基于 DNS-over-HTTPS 的上游解析器。
// url 为 DoH 查询地址，例如 https://1.1.1.1/dns-query；insecure 为 true 时跳过证书校验。
func NewDoH(url string, ip netip.Addr, insecure bool) DNSQuerier {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	// ip 有效时，跳过 DNS 解析过程，直接向该 ip 发送请求。
	// 仅替换连接的目标地址，保留原始 host 用于 TLS SNI 与证书校验。
	if ip.IsValid() {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			target := net.JoinHostPort(ip.String(), port)
			return dialer.DialContext(ctx, network, target)
		}
	}

	return &doh{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		url: url,
	}
}

// Query 实现 [DNSQuerier]，使用 RFC 8484 定义的 application/dns-message 方式查询。
func (d *doh) Query(ctx context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	if err := m.Pack(); err != nil {
		return nil, 0, fmt.Errorf("pack dns msg: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(m.Data))
	if err != nil {
		return nil, 0, fmt.Errorf("new doh request: %w", err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("read doh body: %w", err)
	}

	r := new(dns.Msg)
	r.Data = body
	if err := r.Unpack(); err != nil {
		return nil, time.Since(start), fmt.Errorf("unpack doh response: %w", err)
	}
	return r, time.Since(start), nil
}

// Name 实现 [DNSQuerier]，返回 DoH 查询地址作为标识。
func (d *doh) Name() string {
	return d.url
}
