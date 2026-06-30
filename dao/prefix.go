package dao

import "strings"

const (
	prefixSplit       = ":"
	PrefixDomainRule = "dr:"
	PrifixCidr        = "cidr:"
	PrefixHosts       = "host:"
)

func MarshalKey(prefix, key string) string {
	return prefix + key
}

func ParseKey(s string) (string, string) {
	i := strings.Index(s, prefixSplit)
	if i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

func TrimKeyPrefix(s string) string {
	_, key := ParseKey(s)
	return key
}


