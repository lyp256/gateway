package router

import (
	"bytes"
	"slices"
	"strings"

	"github.com/blevesearch/vellum"
	"github.com/lyp256/gateway/sconv"
)

func NewFST(v *vellum.FST) Router {
	return &fst{v}
}

type fst struct {
	fst *vellum.FST
}

func (f *fst) Length() int64 {
	return int64(f.fst.Len())
}

func (f *fst) Delete(domain string) {
	panic("implement me")
}

func (f *fst) Set(domain string, t MatchType, fw uint32) {
	panic("implement me")
}

func (f *fst) Match(domain string) (uint32, bool) {
	domain = strings.TrimSuffix(domain, ".")
	parts := splitDomainBytes(sconv.ByteSlice(domain))
	slices.Reverse(parts)
	for i := len(parts); i > 0; i-- {
		val, ok, _ := f.fst.Get(bytes.Join(parts[:i], []byte{'.'}))
		flag := MatchType(val >> 32)
		if ok && (flag == MatchSubDomain || len(parts) == i) {
			return uint32(val & 0xffffffff), ok
		}
	}
	return 0, false
}

func ReverseDomainBytes(domain []byte) []byte {
	var (
		dot = []byte{'.'}
	)
	parts := bytes.Split(domain, dot)
	slices.Reverse(parts)
	copy(domain, bytes.Join(parts, dot))
	return domain
}

func ReverseDomainString(domain string) string {
	parts := strings.Split(domain, ".")
	slices.Reverse(parts)
	return strings.Join(parts, ".")
}

func splitDomainBytes(domain []byte) [][]byte {
	parts := make([][]byte, 0, 4)
	last := 0
	for idx := range domain {
		if domain[idx] == '.' {
			parts = append(parts, domain[last:idx])
			last = idx + 1
		}
	}
	parts = append(parts, domain[last:])
	return parts
}
