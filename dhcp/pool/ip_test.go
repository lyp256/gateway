package pool

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDHCPPoolAllocateRelease(t *testing.T) {
	pool, err := NewDHCPPool(netip.MustParsePrefix("192.168.1.0/30"))
	if err != nil {
		t.Fatalf("NewDHCPPool() error = %v", err)
	}

	first, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() first error = %v", err)
	}
	if want := netip.MustParsePrefix("192.168.1.1/30"); first != want {
		t.Fatalf("Allocate() first = %q, want %q", first, want)
	}

	second, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() second error = %v", err)
	}
	if want := netip.MustParsePrefix("192.168.1.2/30"); second != want {
		t.Fatalf("Allocate() second = %q, want %q", second, want)
	}

	if _, err := pool.Allocate(); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("Allocate() exhausted error = %v, want %v", err, ErrPoolExhausted)
	}

	if err := pool.Release(first.Addr()); err != nil {
		t.Fatalf("Release(%q) error = %v", first, err)
	}

	reused, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() reused error = %v", err)
	}
	if reused != first {
		t.Fatalf("Allocate() reused = %q, want %q", reused, first)
	}
}

func TestDHCPPoolReleaseValidation(t *testing.T) {
	pool, err := NewDHCPPool(netip.MustParsePrefix("10.0.0.0/29"))
	if err != nil {
		t.Fatalf("NewDHCPPool() error = %v", err)
	}

	if err := pool.Release(netip.Addr{}); !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("Release() invalid IP error = %v, want %v", err, ErrInvalidIP)
	}

	if err := pool.Release(netip.MustParseAddr("2001:db8::1")); !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("Release() IPv6 error = %v, want %v", err, ErrInvalidIP)
	}

	if err := pool.Release(netip.MustParseAddr("10.0.0.7")); !errors.Is(err, ErrIPOutOfRange) {
		t.Fatalf("Release() broadcast error = %v, want %v", err, ErrIPOutOfRange)
	}

	if err := pool.Release(netip.MustParseAddr("10.0.0.1")); !errors.Is(err, ErrIPNotAllocated) {
		t.Fatalf("Release() unallocated error = %v, want %v", err, ErrIPNotAllocated)
	}
}

func TestDHCPPoolAllocateSpecificIP(t *testing.T) {
	pool, err := NewDHCPPool(netip.MustParsePrefix("10.0.0.0/29"))
	if err != nil {
		t.Fatalf("NewDHCPPool() error = %v", err)
	}

	ip := netip.MustParseAddr("10.0.0.3")
	allocated, err := pool.IsAllocated(ip)
	if err != nil {
		t.Fatalf("IsAllocated(%q) error = %v", ip, err)
	}
	if allocated {
		t.Fatalf("IsAllocated(%q) = true, want false", ip)
	}

	if _, err := pool.AllocateIP(ip); err != nil {
		t.Fatalf("AllocateIP(%q) error = %v", ip, err)
	}
	allocated, err = pool.IsAllocated(ip)
	if err != nil {
		t.Fatalf("IsAllocated(%q) error = %v", ip, err)
	}
	if !allocated {
		t.Fatalf("IsAllocated(%q) = false, want true", ip)
	}

	if _, err := pool.AllocateIP(ip); !errors.Is(err, ErrIPAlreadyAllocated) {
		t.Fatalf("AllocateIP(%q) duplicate error = %v, want %v", ip, err, ErrIPAlreadyAllocated)
	}

	first, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error = %v", err)
	}
	if want := netip.MustParsePrefix("10.0.0.1/29"); first != want {
		t.Fatalf("Allocate() = %q, want %q", first, want)
	}
}

func TestDHCPPoolSpecificIPValidation(t *testing.T) {
	pool, err := NewDHCPPool(netip.MustParsePrefix("10.0.0.0/29"))
	if err != nil {
		t.Fatalf("NewDHCPPool() error = %v", err)
	}

	for _, ip := range []netip.Addr{
		netip.Addr{},
		netip.MustParseAddr("2001:db8::1"),
	} {
		if _, err := pool.IsAllocated(ip); !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("IsAllocated(%q) error = %v, want %v", ip, err, ErrInvalidIP)
		}
		if _, err := pool.AllocateIP(ip); !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("AllocateIP(%q) error = %v, want %v", ip, err, ErrInvalidIP)
		}
	}

	ip := netip.MustParseAddr("10.0.0.7")
	if _, err := pool.IsAllocated(ip); !errors.Is(err, ErrIPOutOfRange) {
		t.Fatalf("IsAllocated(%q) error = %v, want %v", ip, err, ErrIPOutOfRange)
	}
	if _, err := pool.AllocateIP(ip); !errors.Is(err, ErrIPOutOfRange) {
		t.Fatalf("AllocateIP(%q) error = %v, want %v", ip, err, ErrIPOutOfRange)
	}
}

func TestNewDHCPPoolValidation(t *testing.T) {
	tests := []struct {
		name string
		cidr netip.Prefix
		want error
	}{
		{
			name: "invalid prefix",
			cidr: netip.Prefix{},
			want: ErrInvalidCIDR,
		},
		{
			name: "ipv6 prefix",
			cidr: netip.MustParsePrefix("2001:db8::/64"),
			want: ErrIPv4Only,
		},
		{
			name: "no usable ipv4 hosts",
			cidr: netip.MustParsePrefix("192.168.1.0/31"),
			want: ErrNoUsableAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewDHCPPool(tt.cidr); !errors.Is(err, tt.want) {
				t.Fatalf("NewDHCPPool() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUsableIPv4AddressCount(t *testing.T) {
	count, err := UsableIPv4AddressCount(netip.MustParsePrefix("192.168.1.0/30"))
	if err != nil {
		t.Fatalf("UsableIPv4AddressCount() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("UsableIPv4AddressCount() = %d, want 2", count)
	}

	if _, err := UsableIPv4AddressCount(netip.MustParsePrefix("192.168.1.0/31")); !errors.Is(err, ErrNoUsableAddress) {
		t.Fatalf("UsableIPv4AddressCount() error = %v, want %v", err, ErrNoUsableAddress)
	}
}
