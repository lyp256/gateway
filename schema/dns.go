package schema

import "time"

// DNSCacheEntry is a currently valid DNS response held in the in-memory cache.
type DNSCacheEntry struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Answers   []string  `json:"answers"`
	CachedAt  time.Time `json:"cachedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	TTL       uint32    `json:"ttl"`
}
