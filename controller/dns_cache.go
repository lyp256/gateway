package controller

import (
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lyp256/gateway/schema"
)

const dnsCacheSize = 1024

type dnsCacheEntry struct {
	response  *dns.Msg
	cachedAt  time.Time
	expiresAt time.Time
}

func newDNSCache() *lru.Cache[string, dnsCacheEntry] {
	cache, err := lru.New[string, dnsCacheEntry](dnsCacheSize)
	if err != nil {
		panic(err)
	}
	return cache
}

// dnsCacheKey keeps all request options that affect an upstream response while
// excluding the per-request DNS ID.
func dnsCacheKey(request *dns.Msg) (string, bool) {
	if len(request.Question) == 0 {
		return "", false
	}
	keyMsg := request.Copy()
	keyMsg.ID = 0
	keyMsg.Data = nil
	if err := keyMsg.Pack(); err != nil {
		return "", false
	}
	return string(keyMsg.Data), true
}

func dnsCacheTTL(response *dns.Msg) time.Duration {
	var minTTL uint32
	found := false
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			ttl := rr.Header().TTL
			if !found || ttl < minTTL {
				minTTL, found = ttl, true
			}
		}
	}
	if !found || minTTL == 0 {
		return 0
	}
	return time.Duration(minTTL) * time.Second
}

func (ctl *controller) getCachedDNSResponse(key string, request *dns.Msg) (*dns.Msg, bool) {
	entry, ok := ctl.dnsCache.Get(key)
	if !ok {
		return nil, false
	}
	now := time.Now()
	if !now.Before(entry.expiresAt) {
		ctl.dnsCache.Remove(key)
		return nil, false
	}
	response, err := cloneDNSMessage(entry.response)
	if err != nil {
		ctl.dnsCache.Remove(key)
		return nil, false
	}
	response.ID = request.ID
	decrementDNSResponseTTL(response, uint32(now.Sub(entry.cachedAt)/time.Second))
	return response, true
}

func cloneDNSMessage(message *dns.Msg) (*dns.Msg, error) {
	copy := message.Copy()
	copy.Data = nil
	if err := copy.Pack(); err != nil {
		return nil, err
	}
	clone := &dns.Msg{Data: append([]byte(nil), copy.Data...)}
	return clone, clone.Unpack()
}

func decrementDNSResponseTTL(response *dns.Msg, elapsed uint32) {
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			header := rr.Header()
			if header.TTL > elapsed {
				header.TTL -= elapsed
			} else {
				header.TTL = 0
			}
		}
	}
}

func (ctl *controller) cacheDNSResponse(key string, response *dns.Msg) {
	ttl := dnsCacheTTL(response)
	if ttl == 0 {
		return
	}
	stored, err := cloneDNSMessage(response)
	if err != nil {
		return
	}
	now := time.Now()
	ctl.dnsCache.Add(key, dnsCacheEntry{response: stored, cachedAt: now, expiresAt: now.Add(ttl)})
}

func (ctl *controller) dnsCacheSnapshot() []schema.DNSCacheEntry {
	now := time.Now()
	keys := ctl.dnsCache.Keys()
	entries := make([]schema.DNSCacheEntry, 0, len(keys))
	for _, key := range keys {
		entry, ok := ctl.dnsCache.Peek(key)
		if !ok {
			continue
		}
		if !now.Before(entry.expiresAt) {
			ctl.dnsCache.Remove(key)
			continue
		}
		name, qtype := dnsutil.Question(entry.response)
		answers := make([]string, 0, len(entry.response.Answer))
		for _, answer := range entry.response.Answer {
			answers = append(answers, answer.Data().String())
		}
		entries = append(entries, schema.DNSCacheEntry{
			Name:      name,
			Type:      dnsutil.TypeToString(qtype),
			Answers:   answers,
			CachedAt:  entry.cachedAt,
			ExpiresAt: entry.expiresAt,
			TTL:       uint32(time.Until(entry.expiresAt).Seconds()),
		})
	}
	return entries
}
