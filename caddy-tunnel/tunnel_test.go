package tunnel

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	m := new(tunnelModule)
	err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`tunnel {
	device_name edge-tun
	mtu 1400
	cidr 198.18.20.0/24
}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Device != "edge-tun" || m.MTU != 1400 || m.CIDR != "198.18.20.0/24" {
		t.Fatalf("unexpected configuration: %#v", m)
	}
}

func TestUnmarshalCaddyfileDefaults(t *testing.T) {
	m := new(tunnelModule)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("tunnel")); err != nil {
		t.Fatal(err)
	}
	if m.Device != defaultDevice || m.MTU != defaultMTU || m.CIDR != defaultCIDR {
		t.Fatalf("unexpected defaults: %#v", m)
	}
}

func TestUnmarshalCaddyfileRejectsInvalidOptions(t *testing.T) {
	for _, input := range []string{
		"tunnel {\nmtu 0\n}",
		"tunnel {\ncidr 2001:db8::/64\n}",
		"tunnel {\nunknown value\n}",
	} {
		err := new(tunnelModule).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
		if err == nil {
			t.Fatalf("expected %q to be rejected, got %v", input, err)
		}
	}
}
