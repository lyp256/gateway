package router

import (
	"encoding/json"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
)

type Router interface {
	Match(domain string) (uint32, bool)
	Length() int64
}

const (
	MatchSubDomain  MatchType = 'S'
	MatchFullDomain MatchType = 'F'
)

// RouteDest 高 32 位为内部使用标志，低 32 位为 fwmark
func RouteDest(flag uint32, fwmark uint32) uint64 {
	return uint64(flag)<<32 + uint64(fwmark)
}

type MatchType byte

func ParseMatchType(s string) MatchType {
	switch s {
	case "domain":
		return MatchSubDomain
	case "full":
		return MatchFullDomain
	default:
		return 0
	}
}

func (m MatchType) String() string {
	switch m {
	case MatchSubDomain:
		return "domain"
	case MatchFullDomain:
		return "full"
	default:
		return ""
	}
}

// MarshalJSON serializes a match type using its public configuration name.
func (m MatchType) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// UnmarshalJSON parses a public configuration name into a match type.
func (m *MatchType) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("router: match type must be a string: %w", err)
	}
	*m = ParseMatchType(value)
	return nil
}

func (c *MatchType) Schema(r huma.Registry) *huma.Schema {
	return &huma.Schema{
		Type:        huma.TypeString,
		Description: "match type",
		Enum:        []any{"full", "domain"},
	}
}
