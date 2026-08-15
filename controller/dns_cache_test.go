package controller

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/config"
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
	ctl := NewController(nil, chi.NewRouter(), config.Config{}).(*controller)
	ctl.dnsServersMux.Lock()
	ctl.dnsServers = append(ctl.dnsServers, upstream)
	ctl.dnsServersMux.Unlock()
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

func TestDNSCacheKeepsExpiredEntries(t *testing.T) {
	ctl := NewController(nil, chi.NewRouter(), config.Config{}).(*controller)
	ctl.dnsTable = router.NewMemoryMap(map[string]uint64{})

	now := time.Now()
	request := dns.NewMsg("expired.example.", dns.TypeA)
	response := new(dns.Msg)
	dnsutil.SetReply(response, request)
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.Header{Name: "expired.example.", Class: dns.ClassINET, TTL: 60},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.9")},
	})
	stored, err := cloneDNSMessage(response)
	if err != nil {
		t.Fatalf("clone response: %v", err)
	}
	ctl.dnsCache.Add("expired-key", dnsCacheEntry{
		response:     stored,
		cachedAt:     now.Add(-2 * time.Minute),
		lastAccessAt: now.Add(-time.Minute),
		expiresAt:    now.Add(-time.Minute),
	})

	if got, ok := ctl.getCachedDNSResponse("expired-key", request); ok || got != nil {
		t.Fatalf("expired entry served from cache: got=%v ok=%v", got, ok)
	}

	entry, ok := ctl.dnsCache.Peek("expired-key")
	if !ok {
		t.Fatal("expired entry was removed from cache")
	}
	if !entry.lastAccessAt.After(now.Add(-time.Minute)) {
		t.Fatalf("lastAccessAt not updated on access: %v", entry.lastAccessAt)
	}

	entries := ctl.dnsCacheSnapshot()
	if len(entries) != 1 {
		t.Fatalf("cache snapshot entries = %d, want 1", len(entries))
	}
	if !entries[0].Expired || entries[0].TTL != 0 {
		t.Fatalf("unexpected expired snapshot entry: %#v", entries[0])
	}
	if entries[0].Name != "expired.example." || entries[0].Type != "A" {
		t.Fatalf("unexpected expired snapshot entry: %#v", entries[0])
	}
}

func TestDNSCacheSnapshotSortedByLastAccess(t *testing.T) {
	ctl := NewController(nil, chi.NewRouter(), config.Config{}).(*controller)
	ctl.dnsTable = router.NewMemoryMap(map[string]uint64{})

	now := time.Now()
	addEntry := func(key, name string, accessed time.Time) {
		request := dns.NewMsg(name, dns.TypeA)
		response := new(dns.Msg)
		dnsutil.SetReply(response, request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
		})
		stored, err := cloneDNSMessage(response)
		if err != nil {
			t.Fatalf("clone response: %v", err)
		}
		ctl.dnsCache.Add(key, dnsCacheEntry{
			response:     stored,
			cachedAt:     now.Add(-time.Hour),
			lastAccessAt: accessed,
			expiresAt:    now.Add(time.Hour),
		})
	}
	addEntry("old", "old.example.", now.Add(-2*time.Minute))
	addEntry("new", "new.example.", now.Add(-time.Minute))

	entries := ctl.dnsCacheSnapshot()
	if len(entries) != 2 {
		t.Fatalf("cache snapshot entries = %d, want 2", len(entries))
	}
	if entries[0].Name != "new.example." || entries[1].Name != "old.example." {
		t.Fatalf("cache snapshot not sorted by last access: %#v", entries)
	}
}

func TestDNSCacheDeleteAPI(t *testing.T) {
	ctl := newEgressTestController(t)
	c := ctl.(*controller)

	seedCacheEntry := func(name string, qtype uint16, addr string) {
		request := dns.NewMsg(name, qtype)
		key, ok := dnsCacheKey(request)
		if !ok {
			t.Fatalf("cache key missing for %s", name)
		}
		response := new(dns.Msg)
		dnsutil.SetReply(response, request)
		switch qtype {
		case dns.TypeA:
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr(addr)},
			})
		case dns.TypeAAAA:
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
				AAAA: rdata.AAAA{Addr: netip.MustParseAddr(addr)},
			})
		}
		c.cacheDNSResponse(key, response)
	}
	// 同一域名写入两条不同类型，验证按 name 删除会清掉全部类型。
	seedCacheEntry("example.com.", dns.TypeA, "192.0.2.1")
	seedCacheEntry("example.org.", dns.TypeA, "192.0.2.2")
	seedCacheEntry("example.org.", dns.TypeAAAA, "2001:db8::2")
	if got := c.dnsCache.Len(); got != 3 {
		t.Fatalf("cache length = %d, want 3", got)
	}

	// 不带末尾点删除 example.com，example.org 的两条保留。
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/dns/cache/example.com", "", http.StatusNoContent)
	if got := c.dnsCache.Len(); got != 2 {
		t.Fatalf("cache length after delete = %d, want 2", got)
	}

	// 大小写不敏感 + 末尾点，按 name 删除同域名的全部类型。
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/dns/cache/EXAMPLE.ORG.", "", http.StatusNoContent)
	if got := c.dnsCache.Len(); got != 0 {
		t.Fatalf("cache length after delete all = %d, want 0", got)
	}

	// 重复删除返回 404。
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/dns/cache/example.org", "", http.StatusNotFound)
}
