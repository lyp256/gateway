package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/dns/router"
	"go.etcd.io/bbolt"
)

func newEgressTestController(t *testing.T) Controller {
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
	ctl := NewController(dao.New(db), nil, chi.NewRouter()).(*controller)
	ctl.dnsTable = router.NewMemoryMap(nil)
	return ctl
}

func TestEgressHTTPValidation(t *testing.T) {
	ctl := newEgressTestController(t)

	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4097}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4098}`, http.StatusConflict)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-b","type":"manual","fwmark":4097}`, http.StatusConflict)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/egresses/proxy-a", `{"name":"proxy-b","type":"manual","fwmark":4097}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/egresses/proxy-a", `{"name":"proxy-a","type":"manual","fwmark":4098}`, http.StatusOK)
}

func TestDomainRuleEgressValidation(t *testing.T) {
	ctl := newEgressTestController(t)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4097}`, http.StatusOK)

	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/domains", `{"match":"full","domain":"example.com","egress":"missing"}`, http.StatusNotFound)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/domains", `{"match":"full","domain":"example.com","egress":"proxy-a"}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/egresses/proxy-a", "", http.StatusConflict)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/domains status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var domains []map[string]json.RawMessage
	if err := json.Unmarshal(res.Body.Bytes(), &domains); err != nil {
		t.Fatalf("decode domains response: %v: %s", err, res.Body.String())
	}
	if len(domains) != 1 {
		t.Fatalf("domains response count = %d, want 1: %s", len(domains), res.Body.String())
	}
	if got := string(domains[0]["egress"]); got != `"proxy-a"` {
		t.Fatalf("domains response egress = %s, want proxy-a: %s", got, res.Body.String())
	}

	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/domains/full:example.com", "", http.StatusNoContent)
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/egresses/proxy-a", "", http.StatusNoContent)
}

func TestCidrRuleHTTP(t *testing.T) {
	ctl := newEgressTestController(t)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4097}`, http.StatusOK)

	// 不存在的出口应返回 404
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs", `{"cidr":"203.0.113.0/24","egress":"missing"}`, http.StatusNotFound)
	// 非法 CIDR 应返回 400
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs", `{"cidr":"not-a-cidr","egress":"proxy-a"}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs", `{"cidr":"2001:db8::/64","egress":"proxy-a"}`, http.StatusBadRequest)
	// 合法规则应保存并写入路由表
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs", `{"cidr":"203.0.113.0/24","egress":"proxy-a"}`, http.StatusOK)

	got, ok := ctl.(*controller).routeTable.Lookup(netip.MustParseAddr("203.0.113.5"))
	if !ok || got != 0 {
		t.Fatalf("route table lookup = %d, %v, want 0, true", got, ok)
	}

	// 被 CIDR 规则引用的出口不可删除
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/egresses/proxy-a", "", http.StatusConflict)

	// 更新同一 CIDR 的 egress 后应覆盖路由表（value 为该 egress 的索引）
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-b","type":"manual","fwmark":4098}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs", `{"cidr":"203.0.113.0/24","egress":"proxy-b"}`, http.StatusOK)
	got, ok = ctl.(*controller).routeTable.Lookup(netip.MustParseAddr("203.0.113.5"))
	if !ok || got != 1 {
		t.Fatalf("route table lookup after update = %d, %v, want 1, true", got, ok)
	}

	// 删除规则后路由应消失，出口可删除
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/cidrs/203.0.113.0%2F24", "", http.StatusNoContent)
	if _, ok := ctl.(*controller).routeTable.Lookup(netip.MustParseAddr("203.0.113.5")); ok {
		t.Fatal("route table lookup after delete should be missing")
	}
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/egresses/proxy-a", "", http.StatusNoContent)
}

func TestTproxyEgressHTTP(t *testing.T) {
	ctl := newEgressTestController(t)

	// 非法 tproxy 地址应被拒绝
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses",
		`{"name":"tp","type":"tproxy","tproxy":{"addr":"not-an-ip","port":12345}}`, http.StatusBadRequest)
	// 合法 tproxy 出口不占用 fwmark，且允许同时存在多个
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses",
		`{"name":"tp","type":"tproxy","tproxy":{"addr":"0.0.0.0","port":12345}}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses",
		`{"name":"tp2","type":"tproxy","tproxy":{"port":12346}}`, http.StatusOK)

	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/cidrs",
		`{"cidr":"203.0.113.0/24","egress":"tp"}`, http.StatusOK)
	got, ok := ctl.(*controller).routeTable.Lookup(netip.MustParseAddr("203.0.113.5"))
	if !ok || got != 0 {
		t.Fatalf("route table lookup = %d, %v, want 0, true", got, ok)
	}

	// egress 响应应携带运行时索引，供前端把路由 value 对应回出口
	req := httptest.NewRequest(http.MethodGet, "/api/v1/egresses/tp", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/egresses/tp status = %d: %s", res.Code, res.Body.String())
	}
	var tp map[string]json.RawMessage
	if err := json.Unmarshal(res.Body.Bytes(), &tp); err != nil {
		t.Fatalf("decode egress response: %v: %s", err, res.Body.String())
	}
	if got := string(tp["index"]); got != "0" {
		t.Fatalf("egress response index = %s, want 0", got)
	}
}

func TestHostsHTTPResponseUsesFrontendFieldNames(t *testing.T) {
	ctl := newEgressTestController(t)

	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/hosts", `{"name":"internal.example.com","ip":"192.0.2.10"}`, http.StatusOK)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}

	var hosts []map[string]json.RawMessage
	if err := json.Unmarshal(res.Body.Bytes(), &hosts); err != nil {
		t.Fatalf("decode hosts response: %v: %s", err, res.Body.String())
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts response count = %d, want 1: %s", len(hosts), res.Body.String())
	}
	if _, ok := hosts[0]["name"]; !ok {
		t.Fatalf("hosts response is missing lowercase name: %s", res.Body.String())
	}
	if _, ok := hosts[0]["ip"]; !ok {
		t.Fatalf("hosts response is missing lowercase ip: %s", res.Body.String())
	}
}

func assertEgressStatus(t *testing.T, ctl Controller, method, path, body string, want int) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != want {
		t.Fatalf("%s %s status = %d, want %d: %s", method, path, res.Code, want, res.Body.String())
	}
}
