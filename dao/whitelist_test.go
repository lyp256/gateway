package dao

import (
	"testing"
)

func TestNormalizeWhitelist(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "10.0.0.0/8", want: "10.0.0.0/8"},
		{in: " 203.0.113.5 ", want: "203.0.113.5/32"}, // 单 IP 自动补 /32
		{in: "203.0.113.5/32", want: "203.0.113.5/32"},
		{in: "192.168.1.0/24", want: "192.168.1.0/24"},
	}
	for _, tt := range tests {
		got, err := NormalizeWhitelist(tt.in)
		if err != nil {
			t.Fatalf("NormalizeWhitelist(%q): %v", tt.in, err)
		}
		if got.String() != tt.want {
			t.Fatalf("NormalizeWhitelist(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}

	invalid := []string{"", "not-a-cidr", "2001:db8::/64", "10.0.0.0/33"}
	for _, in := range invalid {
		if _, err := NormalizeWhitelist(in); err == nil {
			t.Fatalf("NormalizeWhitelist(%q) should fail", in)
		}
	}
}

func TestWhitelistCRUD(t *testing.T) {
	d := newTestDao(t)

	// 写入：CIDR 与单 IP 都规范化后落库。
	if err := d.SetWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("set cidr whitelist: %v", err)
	}
	if err := d.SetWhitelist("203.0.113.5"); err != nil {
		t.Fatalf("set ip whitelist: %v", err)
	}
	// 重复写入同一前缀幂等覆盖。
	if err := d.SetWhitelist("10.0.0.0/8"); err != nil {
		t.Fatalf("re-set cidr whitelist: %v", err)
	}

	list, err := d.ListWhitelist()
	if err != nil {
		t.Fatalf("list whitelist: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("whitelist count = %d, want 2: %+v", len(list), list)
	}
	want := map[string]bool{"10.0.0.0/8": true, "203.0.113.5/32": true}
	for _, rule := range list {
		if !want[rule.Cidr] {
			t.Fatalf("unexpected whitelist entry %q in %+v", rule.Cidr, list)
		}
	}

	if err := d.DeleteWhitelist("203.0.113.5"); err != nil {
		t.Fatalf("delete ip whitelist: %v", err)
	}
	list, err = d.ListWhitelist()
	if err != nil {
		t.Fatalf("list whitelist after delete: %v", err)
	}
	if len(list) != 1 || list[0].Cidr != "10.0.0.0/8" {
		t.Fatalf("whitelist after delete = %+v, want only 10.0.0.0/8", list)
	}

	// 删除不存在的条目是幂等操作。
	if err := d.DeleteWhitelist("198.51.100.0/24"); err != nil {
		t.Fatalf("delete missing whitelist: %v", err)
	}
}
