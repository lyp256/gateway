package dao

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizeDNSServer(t *testing.T) {
	tests := []struct {
		name string
		in   DNSServer
		want DNSServer
	}{
		{
			name: "doh canonical",
			in:   DNSServer{Name: "  pub ", Type: "https", Server: "DOH.PUB.", IP: netip.MustParseAddr("1.12.12.12")},
			want: DNSServer{Name: "pub", Type: "doh", Server: "doh.pub", IP: netip.MustParseAddr("1.12.12.12")},
		},
		{
			name: "dot alias",
			in:   DNSServer{Name: "dot", Type: "tls", Server: "dns.example.com"},
			want: DNSServer{Name: "dot", Type: "dot", Server: "dns.example.com"},
		},
		{
			name: "udp empty type",
			in:   DNSServer{Name: "udp", IP: netip.MustParseAddr("223.5.5.5")},
			want: DNSServer{Name: "udp", Type: "udp", IP: netip.MustParseAddr("223.5.5.5")},
		},
		{
			name: "ipv4 mapped unmap",
			in:   DNSServer{Name: "v6", Type: "udp", IP: netip.MustParseAddr("::ffff:1.1.1.1")},
			want: DNSServer{Name: "v6", Type: "udp", IP: netip.MustParseAddr("1.1.1.1")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := NormalizeDNSServer(&tt.in); err != nil {
				t.Fatalf("NormalizeDNSServer: %v", err)
			}
			if tt.in != tt.want {
				t.Fatalf("NormalizeDNSServer = %+v, want %+v", tt.in, tt.want)
			}
		})
	}

	invalid := []DNSServer{
		{Name: "", Type: "udp", IP: netip.MustParseAddr("1.1.1.1")},
		{Name: "bad", Type: "quic", Server: "dns.example.com"},
		{Name: "udp-no-ip", Type: "udp"},
		{Name: "dot-empty", Type: "dot"},
		{Name: "doh-empty", Type: "doh"},
	}
	for _, in := range invalid {
		if err := NormalizeDNSServer(&in); err == nil {
			t.Fatalf("NormalizeDNSServer(%+v) should fail", in)
		}
	}
}

func TestDNSServerCRUD(t *testing.T) {
	d := newTestDao(t)

	primary := DNSServer{Name: "primary", Type: "doh", Server: "doh.pub", IP: netip.MustParseAddr("1.12.12.12")}
	if err := d.SetDNSServer(primary); err != nil {
		t.Fatalf("set dns server: %v", err)
	}
	// 同名覆盖更新。
	primary.Insecure = true
	if err := d.SetDNSServer(primary); err != nil {
		t.Fatalf("update dns server: %v", err)
	}
	if err := d.SetDNSServer(DNSServer{Name: "backup", Type: "udp", IP: netip.MustParseAddr("223.5.5.5")}); err != nil {
		t.Fatalf("set backup dns server: %v", err)
	}

	got, err := d.GetDNSServer("primary")
	if err != nil {
		t.Fatalf("get dns server: %v", err)
	}
	if got.Type != "doh" || !got.Insecure || got.IP != netip.MustParseAddr("1.12.12.12") {
		t.Fatalf("get dns server = %+v", got)
	}

	list, err := d.ListDNSServer()
	if err != nil {
		t.Fatalf("list dns servers: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("dns server count = %d, want 2: %+v", len(list), list)
	}

	if err := d.DeleteDNSServer("backup"); err != nil {
		t.Fatalf("delete dns server: %v", err)
	}
	if err := d.DeleteDNSServer("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("delete missing dns server error = %v, want %v", err, ErrKeyNotFound)
	}
	list, err = d.ListDNSServer()
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(list) != 1 || list[0].Name != "primary" {
		t.Fatalf("dns servers after delete = %+v, want only primary", list)
	}
}

func TestDNSServerInitMarker(t *testing.T) {
	d := newTestDao(t)

	initialized, err := d.DNSServersInitialized()
	if err != nil {
		t.Fatalf("check init marker: %v", err)
	}
	if initialized {
		t.Fatal("init marker should be absent on a fresh database")
	}
	if err := d.MarkDNSServersInitialized(); err != nil {
		t.Fatalf("mark initialized: %v", err)
	}
	initialized, err = d.DNSServersInitialized()
	if err != nil {
		t.Fatalf("check init marker after mark: %v", err)
	}
	if !initialized {
		t.Fatal("init marker should be present after mark")
	}
}
