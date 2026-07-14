package http

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTunnelHandler(t *testing.T) {
	cidr := netip.MustParsePrefix("198.18.1.0/16")
	server, err := NewServer(1500, "gateway", cidr)
	require.NoError(t, err)
	defer server.Close()
}
