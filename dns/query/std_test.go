package query

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestStdDNS_Query(t *testing.T) {
	addr, closeFn := startDNSServer(t, "udp", testHandler())
	defer closeFn()

	q := NewStdDNS(addr)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	r, rtt, err := q.Query(context.Background(), m)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want RcodeSuccess", r.Rcode)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
	}
	a, ok := r.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", r.Answer[0])
	}
	if a.Addr.String() != testAnswerIP {
		t.Errorf("answer = %s, want %s", a.Addr, testAnswerIP)
	}
	if rtt < 0 {
		t.Errorf("rtt = %v, want >= 0", rtt)
	}
}

func TestStdDNS_Query_Error(t *testing.T) {
	// 指向一个未监听的地址，Exchange 应返回错误。
	q := NewStdDNS("127.0.0.1:1")

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	if _, _, err := q.Query(context.Background(), m); err == nil {
		t.Error("Query() error = nil, want error")
	}
}

func TestStdDNS_Name(t *testing.T) {
	q := NewStdDNS("1.1.1.1:53")
	if got, want := q.Name(), "udp://1.1.1.1:53"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}
