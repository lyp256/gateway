package controller

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/dns/query"
	"github.com/lyp256/gateway/dns/router"
)

type cacheTestQuerier struct {
	queries int
}

func (q *cacheTestQuerier) Query(_ context.Context, request *dns.Msg) (*dns.Msg, time.Duration, error) {
	q.queries++
	response := new(dns.Msg)
	dnsutil.SetReply(response, request)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	})
	return response, 0, nil
}

func (q *cacheTestQuerier) Name() string { return "test" }

var _ query.DNSQuerier = (*cacheTestQuerier)(nil)

type cacheTestResponseWriter struct {
	data []byte
}

func (w *cacheTestResponseWriter) LocalAddr() net.Addr   { return nil }
func (w *cacheTestResponseWriter) RemoteAddr() net.Addr  { return nil }
func (w *cacheTestResponseWriter) Conn() net.Conn        { return nil }
func (w *cacheTestResponseWriter) Close() error          { return nil }
func (w *cacheTestResponseWriter) Session() *dns.Session { return nil }
func (w *cacheTestResponseWriter) Hijack()               {}
func (w *cacheTestResponseWriter) Write(data []byte) (int, error) {
	w.data = append(w.data, data...)
	return len(data), nil
}

func TestQueryDNSCachesResponse(t *testing.T) {
	upstream := &cacheTestQuerier{}
	ctl := NewController(nil, []query.DNSQuerier{upstream}, chi.NewRouter()).(*controller)
	ctl.dnsTable = router.NewMemoryMap(map[string]uint64{})

	firstRequest := dns.NewMsg("example.com.", dns.TypeA)
	firstRequest.ID = 1
	if ok := ctl.queryDNS(context.Background(), &cacheTestResponseWriter{}, firstRequest); !ok {
		t.Fatal("first DNS query failed")
	}
	secondRequest := dns.NewMsg("example.com.", dns.TypeA)
	secondRequest.ID = 2
	writer := &cacheTestResponseWriter{}
	if ok := ctl.queryDNS(context.Background(), writer, secondRequest); !ok {
		t.Fatal("cached DNS query failed")
	}
	if upstream.queries != 1 {
		t.Fatalf("upstream queries = %d, want 1", upstream.queries)
	}

	if len(writer.data) < 2 {
		t.Fatalf("cached response is too short: %d bytes", len(writer.data))
	}
	response := &dns.Msg{Data: writer.data[2:]}
	if err := response.Unpack(); err != nil {
		t.Fatalf("unpack cached response: %v", err)
	}
	if response.ID != secondRequest.ID {
		t.Fatalf("cached response ID = %d, want %d", response.ID, secondRequest.ID)
	}
	if response.Answer[0].Header().TTL == 0 {
		t.Fatal("cached response has expired TTL")
	}

	entries := ctl.dnsCacheSnapshot()
	if len(entries) != 1 || entries[0].Name != "example.com." || entries[0].Type != "A" {
		t.Fatalf("unexpected cache snapshot: %#v", entries)
	}
}
