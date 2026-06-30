package query

import (
	"context"
	"time"

	"codeberg.org/miekg/dns"
)

type DNSQuerier interface {
	Query(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error)
	// example： udp://1.2.4.8:53,tls://1.2.4.8:853,https://1.2.4.8:443,static
	Name() string
}
