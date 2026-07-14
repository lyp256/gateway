package query

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func newStaticQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn(name), qtype)
	return m
}

func TestStatic_Query(t *testing.T) {
	hosts := map[string]netip.Addr{
		"example.com":       netip.MustParseAddr("1.2.3.4"),
		"v6.example.com":    netip.MustParseAddr("2001:db8::1"),
		"UPPER.Example.COM": netip.MustParseAddr("5.6.7.8"),
	}
	q := NewStatic(hosts, &sync.Mutex{})

	tests := []struct {
		name      string
		msg       *dns.Msg
		wantRcode uint16
		wantAns   int
		checkAddr string
	}{
		{
			name:      "A hit",
			msg:       newStaticQuery("example.com", dns.TypeA),
			wantRcode: dns.RcodeSuccess,
			wantAns:   1,
			checkAddr: "1.2.3.4",
		},
		{
			name:      "A hit case-insensitive",
			msg:       newStaticQuery("upper.example.com", dns.TypeA),
			wantRcode: dns.RcodeSuccess,
			wantAns:   1,
			checkAddr: "5.6.7.8",
		},
		{
			name:      "AAAA hit",
			msg:       newStaticQuery("v6.example.com", dns.TypeAAAA),
			wantRcode: dns.RcodeSuccess,
			wantAns:   1,
			checkAddr: "2001:db8::1",
		},
		{
			name:      "miss returns NXDOMAIN",
			msg:       newStaticQuery("missing.com", dns.TypeA),
			wantRcode: dns.RcodeNameError,
			wantAns:   0,
		},
		{
			name:      "A query on v6-only record returns no answer",
			msg:       newStaticQuery("v6.example.com", dns.TypeA),
			wantRcode: dns.RcodeSuccess,
			wantAns:   0,
		},
		{
			name:      "AAAA query on v4-only record returns no answer",
			msg:       newStaticQuery("example.com", dns.TypeAAAA),
			wantRcode: dns.RcodeSuccess,
			wantAns:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, err := q.Query(context.Background(), tt.msg)
			if err != nil {
				t.Fatalf("Query() error = %v", err)
			}
			if r.Rcode != tt.wantRcode {
				t.Errorf("Rcode = %d, want %d", r.Rcode, tt.wantRcode)
			}
			if len(r.Answer) != tt.wantAns {
				t.Fatalf("len(Answer) = %d, want %d", len(r.Answer), tt.wantAns)
			}
			if tt.checkAddr == "" {
				return
			}
			var got string
			switch rr := r.Answer[0].(type) {
			case *dns.A:
				got = rr.Addr.String()
			case *dns.AAAA:
				got = rr.Addr.String()
			default:
				t.Fatalf("unexpected answer type %T", rr)
			}
			if got != tt.checkAddr {
				t.Errorf("answer addr = %s, want %s", got, tt.checkAddr)
			}
		})
	}
}

func TestStatic_Query_NoQuestion(t *testing.T) {
	q := NewStatic(nil, &sync.Mutex{})
	m := new(dns.Msg)
	r, _, err := q.Query(context.Background(), m)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if r.Rcode != dns.RcodeFormatError {
		t.Errorf("Rcode = %d, want RcodeFormatError", r.Rcode)
	}
}

func TestStatic_Name(t *testing.T) {
	q := NewStatic(nil, &sync.Mutex{})
	if got := q.Name(); got != "static" {
		t.Errorf("Name() = %q, want %q", got, "static")
	}
}
