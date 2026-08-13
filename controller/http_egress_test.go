package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/dao"
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
	return NewController(dao.New(db), nil, chi.NewRouter())
}

func TestEgressHTTPValidation(t *testing.T) {
	ctl := newEgressTestController(t)

	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4097}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-a","type":"manual","fwmark":4098}`, http.StatusConflict)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", `{"name":"proxy-b","type":"manual","fwmark":4097}`, http.StatusConflict)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/egresses/proxy-a", `{"name":"proxy-b","type":"manual","fwmark":4097}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/egresses/proxy-a", `{"name":"proxy-a","type":"manual","fwmark":4098}`, http.StatusOK)
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
