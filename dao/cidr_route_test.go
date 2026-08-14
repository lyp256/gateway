package dao

import (
	"errors"
	"testing"
)

func TestCidrRuleRequiresExistingEgress(t *testing.T) {
	d := newTestDao(t)

	if err := d.SetCidrRule(CidrRule{Cidr: "203.0.113.0/24", Egress: "missing"}); !errors.Is(err, ErrEgressNotFound) {
		t.Fatalf("set cidr rule with missing egress error = %v, want %v", err, ErrEgressNotFound)
	}

	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4097}); err != nil {
		t.Fatalf("create egress: %v", err)
	}

	want := CidrRule{Cidr: "203.0.113.0/24", Egress: "proxy-a"}
	if err := d.SetCidrRule(want); err != nil {
		t.Fatalf("set cidr rule: %v", err)
	}

	got, err := d.GetCidrRule(want.Cidr)
	if err != nil {
		t.Fatalf("get cidr rule: %v", err)
	}
	if got != want {
		t.Fatalf("get cidr rule = %+v, want %+v", got, want)
	}

	list, err := d.ListCidrRule()
	if err != nil {
		t.Fatalf("list cidr rules: %v", err)
	}
	if len(list) != 1 || list[0] != want {
		t.Fatalf("list cidr rules = %+v, want %+v", list, []CidrRule{want})
	}

	if err := d.DeleteCidrRule(want.Cidr); err != nil {
		t.Fatalf("delete cidr rule: %v", err)
	}
	if _, err := d.GetCidrRule(want.Cidr); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("get deleted cidr rule error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestCidrRuleEgressInUse(t *testing.T) {
	d := newTestDao(t)
	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4097}); err != nil {
		t.Fatalf("create egress: %v", err)
	}
	if err := d.SetCidrRule(CidrRule{Cidr: "203.0.113.0/24", Egress: "proxy-a"}); err != nil {
		t.Fatalf("set cidr rule: %v", err)
	}

	if err := d.DeleteEgress("proxy-a"); !errors.Is(err, ErrEgressInUse) {
		t.Fatalf("delete referenced egress error = %v, want %v", err, ErrEgressInUse)
	}
}

func TestNormalizeCidr(t *testing.T) {
	if _, err := NormalizeCidr("203.0.113.0/24"); err != nil {
		t.Fatalf("normalize valid cidr: %v", err)
	}
	if _, err := NormalizeCidr("2001:db8::/64"); err == nil {
		t.Fatal("normalize ipv6 cidr should fail")
	}
	if _, err := NormalizeCidr("203.0.113.1"); err == nil {
		t.Fatal("normalize bare ip should fail")
	}
	if _, err := NormalizeCidr("not-a-cidr"); err == nil {
		t.Fatal("normalize garbage should fail")
	}
}
