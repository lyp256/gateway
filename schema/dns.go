package schema

import "time"

// DNSCacheEntry is a DNS response held in the in-memory cache. Expired entries
// are kept for browsing until the LRU evicts them or an API operation removes
// them explicitly.
type DNSCacheEntry struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Answers      []string  `json:"answers"`
	CachedAt     time.Time `json:"cachedAt"`
	LastAccessAt time.Time `json:"lastAccessAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	TTL          uint32    `json:"ttl"`
	Expired      bool      `json:"expired"`
}
