package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/config"
	"github.com/lyp256/gateway/dao"
	"go.etcd.io/bbolt"
)

func TestWhitelistHTTP(t *testing.T) {
	ctl := newEgressTestController(t)

	// 非法条目：IPv6、无法解析的字符串。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/whitelist", `{"cidr":"2001:db8::/64"}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/whitelist", `{"cidr":"not-a-cidr"}`, http.StatusBadRequest)

	// 合法条目：CIDR 与单 IP（自动补 /32）。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/whitelist", `{"cidr":"10.0.0.0/8"}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/whitelist", `{"cidr":"203.0.113.5"}`, http.StatusOK)

	c := ctl.(*controller)
	c.whitelistMux.RLock()
	got := len(c.sourceWhitelist)
	c.whitelistMux.RUnlock()
	if got != 2 {
		t.Fatalf("in-memory whitelist count = %d, want 2", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/whitelist", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/whitelist status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var rules []dao.WhitelistRule
	if err := json.Unmarshal(res.Body.Bytes(), &rules); err != nil {
		t.Fatalf("decode whitelist response: %v: %s", err, res.Body.String())
	}
	want := map[string]bool{"10.0.0.0/8": true, "203.0.113.5/32": true}
	if len(rules) != len(want) {
		t.Fatalf("whitelist response = %+v, want %v", rules, want)
	}
	for _, rule := range rules {
		if !want[rule.Cidr] {
			t.Fatalf("unexpected whitelist entry %q in %+v", rule.Cidr, rules)
		}
	}

	// 删除：URL 中 CIDR 的 "/" 以 %2F 编码（与 cidr 规则一致）。
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/whitelist/10.0.0.0%2F8", "", http.StatusNoContent)
	c.whitelistMux.RLock()
	got = len(c.sourceWhitelist)
	c.whitelistMux.RUnlock()
	if got != 1 {
		t.Fatalf("in-memory whitelist count after delete = %d, want 1", got)
	}
	for _, p := range c.sourceWhitelist {
		if p.String() != "203.0.113.5/32" {
			t.Fatalf("whitelist after delete = %v, want only 203.0.113.5/32", c.sourceWhitelist)
		}
	}
}

func TestWhitelistPersistence(t *testing.T) {
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

	first := NewController(d, chi.NewRouter(), config.Config{}).(*controller)
	assertEgressStatus(t, first, http.MethodPut, "/api/v1/whitelist", `{"cidr":"192.168.0.0/16"}`, http.StatusOK)

	// 模拟控制面重启：同一数据库重新创建 controller 并加载白名单。
	restarted := NewController(d, chi.NewRouter(), config.Config{}).(*controller)
	if err := restarted.loadWhitelistFromStorage(); err != nil {
		t.Fatalf("load whitelist from storage: %v", err)
	}
	restarted.whitelistMux.RLock()
	defer restarted.whitelistMux.RUnlock()
	if len(restarted.sourceWhitelist) != 1 {
		t.Fatalf("reloaded whitelist = %v, want 1 entry", restarted.sourceWhitelist)
	}
	if got := restarted.sourceWhitelist[0]; got != netip.MustParsePrefix("192.168.0.0/16") {
		t.Fatalf("reloaded whitelist entry = %s, want 192.168.0.0/16", got)
	}
}
