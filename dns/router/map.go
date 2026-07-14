package router

import (
	"bytes"
	"slices"
	"strings"
	"sync"

	"github.com/lyp256/gateway/sconv"
)

// NewMemoryMap 创建基于 map 的 dns 路由
// map 传入后不应该在外部使用
func NewMemoryMap(m map[string]uint64) Router {
	if m == nil {
		m = make(map[string]uint64)
	}
	return &memoryMap{m: m, mux: sync.RWMutex{}}
}

type memoryMap struct {
	m   map[string]uint64
	mux sync.RWMutex
}

func (f *memoryMap) Delete(domain string) {
	f.mux.Lock()
	delete(f.m, domain)
	f.mux.Unlock()
}

func (f *memoryMap) Set(domain string, match MatchType, fwmark uint32) {
	dest := RouteDest(uint32(match), fwmark)
	f.mux.Lock()
	if dest != f.m[domain] {
		f.m[domain] = dest
	}
	f.mux.Unlock()
}

func (f *memoryMap) Length() int64 {
	f.mux.RLock()
	c := int64(len(f.m))
	f.mux.RUnlock()
	return c
}
func (f *memoryMap) Match(domain string) (uint32, bool) {
	domain = strings.TrimSuffix(domain, ".")
	parts := splitDomainBytes(sconv.ByteSlice(domain))
	slices.Reverse(parts)
	f.mux.RLock()
	defer f.mux.RUnlock()
	for i := len(parts); i > 0; i-- {
		val, ok := f.m[sconv.String(bytes.Join(parts[:i], []byte{'.'}))]
		flag := MatchType(val >> 32)
		if ok && (flag == MatchSubDomain || len(parts) == i) {
			return uint32(val & 0xffffffff), ok
		}
	}
	return 0, false
}
