package dao

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/lyp256/gateway/dns/router"
	"go.etcd.io/bbolt"
)

func newTestDao(t *testing.T) *Dao {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "gateway.db"), 0o600, nil)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket(bucketName)
		return err
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return New(db)
}

func TestEgressUniqueness(t *testing.T) {
	d := newTestDao(t)
	first := Egress{Name: "proxy-a", FwMark: 4097}
	if err := d.CreateEgress(first); err != nil {
		t.Fatalf("create first egress: %v", err)
	}

	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4098}); !errors.Is(err, ErrEgressNameExists) {
		t.Fatalf("duplicate name error = %v, want %v", err, ErrEgressNameExists)
	}
	if err := d.CreateEgress(Egress{Name: "proxy-b", FwMark: first.FwMark}); !errors.Is(err, ErrEgressFwMarkExists) {
		t.Fatalf("duplicate fwmark error = %v, want %v", err, ErrEgressFwMarkExists)
	}

	first.Type = EgressHTTPTunnel
	if err := d.UpdateEgress(first); err != nil {
		t.Fatalf("update existing egress: %v", err)
	}
	if err := d.UpdateEgress(Egress{Name: "proxy-missing", FwMark: 4099}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("update missing egress error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestEgressDeleteReferencedByDomainRule(t *testing.T) {
	d := newTestDao(t)
	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4097}); err != nil {
		t.Fatalf("create egress: %v", err)
	}
	dr := DomainRule{Match: router.MatchFullDomain, Domain: "example.com", Egress: "proxy-a"}
	if err := d.SetDomainRule(dr); err != nil {
		t.Fatalf("set domain rule: %v", err)
	}

	if err := d.DeleteEgress("proxy-a"); !errors.Is(err, ErrEgressInUse) {
		t.Fatalf("delete referenced egress error = %v, want %v", err, ErrEgressInUse)
	}

	if err := d.DeleteDomainRule(dr.Match, dr.Domain); err != nil {
		t.Fatalf("delete domain rule: %v", err)
	}
	if err := d.DeleteEgress("proxy-a"); err != nil {
		t.Fatalf("delete egress: %v", err)
	}
	if err := d.DeleteEgress("proxy-a"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("delete missing egress error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestTproxyEgress(t *testing.T) {
	d := newTestDao(t)

	// tproxy 出口不占用 fwmark，多个 tproxy 出口之间不应冲突。
	if err := d.CreateEgress(Egress{Name: "tp-a", Type: EgressTproxy, Tproxy: &EgressTproxyConfig{Port: 12345}}); err != nil {
		t.Fatalf("create tproxy egress: %v", err)
	}
	if err := d.CreateEgress(Egress{Name: "tp-b", Type: EgressTproxy, Tproxy: &EgressTproxyConfig{Addr: "0.0.0.0", Port: 12346}}); err != nil {
		t.Fatalf("create second tproxy egress: %v", err)
	}

	// 空地址应规范化为 0.0.0.0。
	got, err := d.GetEgress("tp-a")
	if err != nil {
		t.Fatalf("get tproxy egress: %v", err)
	}
	if got.Tproxy == nil || got.Tproxy.Addr != "0.0.0.0" || got.Tproxy.Port != 12345 {
		t.Fatalf("tproxy config = %+v, want addr 0.0.0.0 port 12345", got.Tproxy)
	}
	if got.FwMark != 0 {
		t.Fatalf("tproxy egress fwmark = %d, want 0", got.FwMark)
	}

	// 非法地址应被拒绝，未知类型应被拒绝。
	if err := d.CreateEgress(Egress{Name: "tp-bad", Type: EgressTproxy, Tproxy: &EgressTproxyConfig{Addr: "not-an-ip"}}); !errors.Is(err, ErrInvalidEgress) {
		t.Fatalf("invalid tproxy addr error = %v, want %v", err, ErrInvalidEgress)
	}
	if err := d.CreateEgress(Egress{Name: "unknown", Type: "magic"}); !errors.Is(err, ErrInvalidEgress) {
		t.Fatalf("unsupported type error = %v, want %v", err, ErrInvalidEgress)
	}

	// tproxy 与手工出口共存：手工出口仍占用自己的 fwmark。
	if err := d.CreateEgress(Egress{Name: "manual-a", FwMark: 4097}); err != nil {
		t.Fatalf("create manual egress after tproxy: %v", err)
	}
}
