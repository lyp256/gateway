package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/dns/query"
)

// 各类型上游 DNS 的默认端口。
const (
	defaultUDPPort   = 53
	defaultDoTPort   = 853
	defaultHTTPSPort = 443
)

// dnsTestRequest 描述一次上游 DNS 测试请求：上游配置 + 可选的测试域名。
// QName 为空时默认查询 example.com。
type dnsTestRequest struct {
	Type     string     `json:"type"`
	Server   string     `json:"server,omitempty"`
	IP       netip.Addr `json:"ip,omitempty"`
	Insecure bool       `json:"insecure,omitempty"`
	QName    string     `json:"qname,omitempty"`
}

// dnsTestResult 是一次上游 DNS 连通性测试的结果。
type dnsTestResult struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	Latency int64    `json:"latencyMs,omitempty"`
	Answers []string `json:"answers,omitempty"`
}

// probeDNSServer 用给定的配置构造上游解析器，并向其发送一条真实的 A 记录查询，
// 以验证该 DNS 服务器能否正常工作。qname 为测试域名，允许为空（默认 example.com）。
// 测试请求不携带名称，内部使用占位名称通过配置校验。
func probeDNSServer(s dao.DNSServer, qname string) dnsTestResult {
	if s.Name == "" {
		s.Name = "test"
	}
	if err := dao.NormalizeDNSServer(&s); err != nil {
		return dnsTestResult{Message: err.Error()}
	}
	q, err := newQuerier(s)
	if err != nil {
		return dnsTestResult{Message: err.Error()}
	}

	qname = strings.ToLower(strings.TrimSpace(qname))
	if qname == "" {
		qname = "baidu.com"
	}
	if !dnsutil.IsName(qname) {
		return dnsTestResult{Message: fmt.Sprintf("无效的测试域名 %q", qname)}
	}

	msg := dns.NewMsg(qname, dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	resp, _, err := q.Query(ctx, msg)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return dnsTestResult{Message: fmt.Sprintf("查询失败：%v", err), Latency: latency}
	}
	if resp == nil {
		return dnsTestResult{Message: "查询失败：无响应", Latency: latency}
	}

	switch resp.Rcode {
	case dns.RcodeSuccess:
		answers := make([]string, 0, len(resp.Answer))
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				answers = append(answers, a.A.Addr.String())
			case *dns.AAAA:
				answers = append(answers, a.AAAA.Addr.String())
			}
		}
		if len(answers) == 0 {
			return dnsTestResult{OK: true, Message: "查询成功，无地址记录", Latency: latency}
		}
		return dnsTestResult{
			OK:      true,
			Message: fmt.Sprintf("查询成功，%d 条地址记录", len(answers)),
			Latency: latency,
			Answers: answers,
		}
	case dns.RcodeNameError:
		// NXDOMAIN 同样证明服务器正常应答。
		return dnsTestResult{OK: true, Message: "服务器响应正常（NXDOMAIN）", Latency: latency}
	default:
		return dnsTestResult{Message: fmt.Sprintf("查询失败：%s", dnsutil.RcodeToString(resp.Rcode)), Latency: latency}
	}
}

// newQuerier 根据持久化的上游配置创建对应的 [query.DNSQuerier]。
func newQuerier(s dao.DNSServer) (query.DNSQuerier, error) {
	switch s.Type {
	case "udp", "":
		if !s.IP.IsValid() {
			return nil, fmt.Errorf("udp dns server requires a valid ip")
		}
		return query.NewStdDNS(net.JoinHostPort(s.IP.String(), strconv.Itoa(defaultUDPPort))), nil
	case "tls", "dot":
		if s.Server == "" && !s.IP.IsValid() {
			return nil, fmt.Errorf("dot dns server requires domain or ip")
		}
		return query.NewDoT(s.Server, defaultDoTPort, s.IP, s.Insecure), nil
	case "https", "doh":
		if s.Server == "" {
			return nil, fmt.Errorf("doh dns server requires domain")
		}
		url := fmt.Sprintf("https://%s/dns-query", net.JoinHostPort(s.Server, strconv.Itoa(defaultHTTPSPort)))
		return query.NewDoH(url, s.IP, s.Insecure), nil
	default:
		return nil, fmt.Errorf("unsupported dns server type %q", s.Type)
	}
}

// loadDNSServersFromStorage 把持久化的上游 DNS 配置重建为运行时 querier 列表。
// 索引 0 始终是静态本地解析（hosts），之后按存储顺序追加上游。
// 损坏的条目跳过并记录日志，不影响其余上游生效。
func (ctl *controller) loadDNSServersFromStorage() error {
	if ctl.storage == nil {
		return nil
	}
	list, err := ctl.storage.ListDNSServer()
	if err != nil {
		return err
	}
	queriers := make([]query.DNSQuerier, 0, len(list))
	for _, s := range list {
		q, err := newQuerier(s)
		if err != nil {
			slog.Error("invalid dns server entry, skip", "name", s.Name, "err", err)
			continue
		}
		queriers = append(queriers, q)
	}
	ctl.dnsServersMux.Lock()
	next := make([]query.DNSQuerier, 0, len(queriers)+1)
	next = append(next, ctl.dnsServers[0])
	ctl.dnsServers = append(next, queriers...)
	ctl.dnsServersMux.Unlock()
	return nil
}

// setDNSServerRuntime 持久化一条上游 DNS 配置并热更新运行时 querier 列表。
func (ctl *controller) setDNSServerRuntime(s dao.DNSServer) error {
	if err := ctl.storage.SetDNSServer(s); err != nil {
		return err
	}
	return ctl.loadDNSServersFromStorage()
}

// deleteDNSServerRuntime 删除一条上游 DNS 配置并热更新运行时 querier 列表。
func (ctl *controller) deleteDNSServerRuntime(name string) error {
	if err := ctl.storage.DeleteDNSServer(name); err != nil {
		return err
	}
	return ctl.loadDNSServersFromStorage()
}
