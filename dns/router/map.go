package router

import (
	"bytes"
	"slices"
	"strings"
	"sync"

	"github.com/lyp256/gateway/sconv"
)

func NewMemoryMap(m map[string]uint64, l sync.Locker) Router {
	return &memoryMap{m: m, mux: l}
}

type memoryMap struct {
	m   map[string]uint64
	mux sync.Locker
}

func (f *memoryMap) Length() int64 {
	f.mux.Lock()
	c := int64(len(f.m))
	f.mux.Unlock()
	return c
}
func (f *memoryMap) Match(domain string) (uint32, bool) {
	domain = strings.TrimSuffix(domain, ".")
	parts := splitDomainBytes(sconv.ByteSlice(domain))
	slices.Reverse(parts)
	f.mux.Lock()
	defer f.mux.Unlock()
	for i := len(parts); i > 0; i-- {
		val, ok := f.m[sconv.String(bytes.Join(parts[:i], []byte{'.'}))]
		flag := MatchType(val >> 32)
		if ok && (flag == MatchSubDomain || len(parts) == i) {
			return uint32(val & 0xffffffff), ok
		}
	}
	return 0, false
}
