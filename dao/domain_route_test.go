package dao

import (
	"errors"
	"testing"

	"github.com/lyp256/gateway/dns/router"
)

func TestDomainRuleRequiresExistingEgress(t *testing.T) {
	d := newTestDao(t)

	if err := d.SetDomainRule(DomainRule{Match: router.MatchFullDomain, Domain: "example.com", Egress: "missing"}); !errors.Is(err, ErrEgressNotFound) {
		t.Fatalf("set domain rule with missing egress error = %v, want %v", err, ErrEgressNotFound)
	}

	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4097}); err != nil {
		t.Fatalf("create egress: %v", err)
	}

	want := DomainRule{Match: router.MatchFullDomain, Domain: "example.com", Egress: "proxy-a"}
	if err := d.SetDomainRule(want); err != nil {
		t.Fatalf("set domain rule: %v", err)
	}

	got, err := d.GetDomainRule(want.Match, want.Domain)
	if err != nil {
		t.Fatalf("get domain rule: %v", err)
	}
	if got != want {
		t.Fatalf("get domain rule = %+v, want %+v", got, want)
	}

	list, err := d.ListDomainRule(nil)
	if err != nil {
		t.Fatalf("list domain rules: %v", err)
	}
	if len(list) != 1 || list[0] != want {
		t.Fatalf("list domain rules = %+v, want %+v", list, []DomainRule{want})
	}
}
