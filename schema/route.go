package schema

import (
	"net/netip"
)

type RouteTableItem struct {
	CIDR  netip.Prefix `json:"cidr"`
	Value uint32       `json:"value"`
}
