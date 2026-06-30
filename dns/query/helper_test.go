package query

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// testAnswerIP 是测试上游 DNS 服务针对 A 查询固定返回的地址。
const testAnswerIP = "9.9.9.9"

// testHandler 是一个简单的 [dns.Handler]，对 A 查询返回固定地址，其余返回空应答。
func testHandler() dns.HandlerFunc {
	return func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		if len(r.Question) > 0 {
			name, qtype := dnsutil.Question(r)
			if qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  name,
						Class: dns.ClassINET,
						TTL:   60,
					},
					A: rdata.A{Addr: netip.MustParseAddr(testAnswerIP)},
				})
			}
		}
		if err := m.Pack(); err == nil {
			_, _ = io.Copy(w, m)
		}
	}
}

// startDNSServer 在本地随机端口上启动一个上游 DNS 服务，返回其监听地址与关闭函数。
// network 取值 "udp" 或 "tcp"。
func startDNSServer(t *testing.T, network string, handler dns.Handler) (addr string, closeFn func()) {
	t.Helper()

	started := make(chan struct{})
	srv := &dns.Server{
		Net:     network,
		Handler: handler,
		NotifyStartedFunc: func(context.Context) {
			close(started)
		},
	}

	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		srv.PacketConn = pc
		addr = pc.LocalAddr().String()
	case "tcp", "tcp-tls":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		srv.Listener = ln
		addr = ln.Addr().String()
	default:
		t.Fatalf("unsupported network %q", network)
	}

	go func() { _ = srv.ListenAndServe() }()
	<-started

	return addr, func() { srv.Shutdown(context.TODO()) }
}

// netipMustParse 解析一个 IP 字符串，失败时终止测试。
func netipMustParse(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return addr
}

// mustParsePort 解析端口字符串，失败时终止测试。
func mustParsePort(t *testing.T, s string) uint16 {
	t.Helper()
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", s, err)
	}
	return uint16(p)
}
