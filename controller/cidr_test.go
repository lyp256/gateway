package controller

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/lyp256/gateway/dao"
	"go.etcd.io/bbolt"
)

func TestLoadCidrRuleMapFromStorage(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "gateway.db"), 0o600, nil)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket([]byte("gateway"))
		return err
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	d := dao.New(db)
	if err := d.CreateEgress(dao.Egress{Name: "proxy-a", FwMark: 4097}); err != nil {
		t.Fatalf("create egress: %v", err)
	}
	if err := d.SetCidrRule(dao.CidrRule{Cidr: "203.0.113.0/24", Egress: "proxy-a"}); err != nil {
		t.Fatalf("set cidr rule: %v", err)
	}
	// 引用了不存在出口的规则应被跳过而不是导致启动失败
	if err := d.SetCidrRule(dao.CidrRule{Cidr: "198.51.100.0/24", Egress: "missing"}); err == nil {
		t.Fatal("set cidr rule with missing egress should fail")
	}

	var table bart.Table[uint32]
	if err := loadCidrRuleMapFromStorage(&table, d); err != nil {
		t.Fatalf("load cidr rule map: %v", err)
	}
	got, ok := table.Lookup(netip.MustParseAddr("203.0.113.8"))
	if !ok || got != 4097 {
		t.Fatalf("loaded route lookup = %d, %v, want 4097, true", got, ok)
	}
	if table.Size4() != 1 {
		t.Fatalf("loaded route table size = %d, want 1", table.Size4())
	}
}
