package server

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/lyp256/gateway/config"
	"github.com/lyp256/gateway/dao"
	"go.etcd.io/bbolt"
)

func newSeedTestDao(t *testing.T) *dao.Dao {
	t.Helper()
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
	return dao.New(db)
}

func TestSeedDNSServersOnce(t *testing.T) {
	d := newSeedTestDao(t)
	servers := []config.DNSServer{
		{Type: "doh", Server: "doh.pub", IP: netip.MustParseAddr("1.12.12.12")},
		{Type: "udp", IP: netip.MustParseAddr("223.5.5.5")},
	}
	if err := seedDNSServers(d, servers); err != nil {
		t.Fatalf("seed dns servers: %v", err)
	}
	// 模拟重启：再次 seed 不应重复写入。
	if err := seedDNSServers(d, servers); err != nil {
		t.Fatalf("re-seed dns servers: %v", err)
	}

	list, err := d.ListDNSServer()
	if err != nil {
		t.Fatalf("list dns servers: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("dns servers count = %d, want 2: %+v", len(list), list)
	}
	names := map[string]bool{}
	for _, s := range list {
		names[s.Name] = true
	}
	if !names["doh.pub"] || !names["223.5.5.5"] {
		t.Fatalf("seeded dns server names = %v, want doh.pub and 223.5.5.5", list)
	}
}

func TestSeedDNSServersDoesNotReseedWhenCleared(t *testing.T) {
	d := newSeedTestDao(t)
	servers := []config.DNSServer{{Type: "udp", IP: netip.MustParseAddr("1.1.1.1")}}
	if err := seedDNSServers(d, servers); err != nil {
		t.Fatalf("seed dns servers: %v", err)
	}
	// 用户通过页面删除全部上游后重启：不应被 config 默认值回填。
	if err := d.DeleteDNSServer("1.1.1.1"); err != nil {
		t.Fatalf("delete dns server: %v", err)
	}
	if err := seedDNSServers(d, servers); err != nil {
		t.Fatalf("re-seed after clear: %v", err)
	}
	list, err := d.ListDNSServer()
	if err != nil {
		t.Fatalf("list dns servers: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("dns servers after clear = %+v, want empty", list)
	}
}
