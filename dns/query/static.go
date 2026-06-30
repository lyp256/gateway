package query

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// 基于静态映射解析
type static struct {
	mux sync.Locker
	h   map[string]netip.Addr
}

// NewStatic 基于静态映射创建解析器。传入的 key 应为不含末尾点的域名。
func NewStatic(h map[string]netip.Addr, mux sync.Locker) DNSQuerier {
	return &static{
		mux: mux,
		h:   h,
	}
}

// Query 实现 [DNSQuerier]，仅处理 A/AAAA 查询，命中静态映射时直接返回结果，
// 否则返回 NXDOMAIN，使上层可以回退到其它上游。
func (h *static) Query(_ context.Context, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	r := new(dns.Msg)
	dnsutil.SetReply(r, m)

	if len(m.Question) == 0 {
		r.Rcode = dns.RcodeFormatError
		return r, 0, nil
	}

	name, qtype := dnsutil.Question(m)
	h.mux.Lock()
	canonical := dnsutil.Canonical(name)
	if canonical[len(canonical)-1] == '.' {
		canonical = canonical[:len(canonical)-1]
	}
	addr, ok := h.h[canonical]
	if !ok {
		for host, candidate := range h.h {
			normalizedHost := dnsutil.Canonical(host)
			if normalizedHost[len(normalizedHost)-1] == '.' {
				normalizedHost = normalizedHost[:len(normalizedHost)-1]
			}
			if normalizedHost == canonical {
				addr, ok = candidate, true
				break
			}
		}
	}
	h.mux.Unlock()

	if !ok {
		r.Rcode = dns.RcodeNameError
		return r, 0, nil
	}

	switch qtype {
	case dns.TypeA:
		if addr.Is4() {
			r.Answer = append(r.Answer, &dns.A{
				Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600},
				A:   rdata.A{Addr: addr},
			})
		}
	case dns.TypeAAAA:
		if addr.Is6() {
			r.Answer = append(r.Answer, &dns.AAAA{
				Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600},
				AAAA: rdata.AAAA{Addr: addr},
			})
		}
	}
	return r, 0, nil
}

// Name 实现 [DNSQuerier]，返回固定标识 static。
func (h *static) Name() string {
	return "static"
}
