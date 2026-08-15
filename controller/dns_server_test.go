package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lyp256/gateway/dao"
)

func TestDNSServerHTTP(t *testing.T) {
	ctl := newEgressTestController(t)
	c := ctl.(*controller)

	// 非法配置：udp 必须带 IP，doh 必须带域名。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers", `{"name":"udp","type":"udp"}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers", `{"name":"doh","type":"doh","server":""}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers", `{"name":"","type":"udp","ip":"1.1.1.1"}`, http.StatusBadRequest)
	// 页面在 IP 为空时发送 null，应作为空 IP 接受。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers",
		`{"name":"dot","type":"dot","server":"dns.example.com","ip":null}`, http.StatusOK)

	// 合法配置写入并热更新运行时 querier（静态 hosts 之后追加）。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers",
		`{"name":"pub","type":"doh","server":"doh.pub","ip":"1.12.12.12"}`, http.StatusOK)
	c.dnsServersMux.RLock()
	got := len(c.dnsServers)
	names := map[string]bool{}
	for _, q := range c.dnsServers[1:] {
		names[q.Name()] = true
	}
	c.dnsServersMux.RUnlock()
	if got != 3 {
		t.Fatalf("runtime dns servers count = %d, want 3 (static + dot + doh)", got)
	}
	if !names["tls://dns.example.com:853"] || !names["https://doh.pub:443/dns-query"] {
		t.Fatalf("runtime dns servers = %v, want dot and doh upstreams", names)
	}

	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/dns/servers",
		`{"name":"backup","type":"udp","ip":"223.5.5.5"}`, http.StatusOK)
	c.dnsServersMux.RLock()
	got = len(c.dnsServers)
	c.dnsServersMux.RUnlock()
	if got != 4 {
		t.Fatalf("runtime dns servers count after add = %d, want 4", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/servers", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/dns/servers status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var servers []dao.DNSServer
	if err := json.Unmarshal(res.Body.Bytes(), &servers); err != nil {
		t.Fatalf("decode dns servers response: %v: %s", err, res.Body.String())
	}
	if len(servers) != 3 {
		t.Fatalf("dns servers response count = %d, want 3: %s", len(servers), res.Body.String())
	}

	// 删除后热更新运行时 querier；删除不存在的返回 404。
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/dns/servers/pub", "", http.StatusNoContent)
	assertEgressStatus(t, ctl, http.MethodDelete, "/api/v1/dns/servers/missing", "", http.StatusNotFound)
	c.dnsServersMux.RLock()
	got = len(c.dnsServers)
	c.dnsServersMux.RUnlock()
	if got != 3 {
		t.Fatalf("runtime dns servers count after delete = %d, want 3", got)
	}
}

func TestDNSServerTestEndpoint(t *testing.T) {
	ctl := newEgressTestController(t)

	// 非法配置无需真实网络即可得到失败结果；接口本身返回 200。
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/servers/test",
		bytes.NewBufferString(`{"type":"udp"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/dns/servers/test status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var result dnsTestResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode test result: %v: %s", err, res.Body.String())
	}
	if result.OK {
		t.Fatalf("invalid config should not pass: %+v", result)
	}
	if result.Message == "" {
		t.Fatal("test result message should not be empty")
	}

	// 配置合法但测试域名非法：同样无需网络即可得到失败结果。
	longName := strings.Repeat("a", 300) + ".com"
	req = httptest.NewRequest(http.MethodPost, "/api/v1/dns/servers/test",
		bytes.NewBufferString(`{"type":"doh","server":"doh.pub","qname":"`+longName+`"}`))
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("POST invalid qname status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode invalid qname result: %v: %s", err, res.Body.String())
	}
	if result.OK {
		t.Fatalf("invalid qname should not pass: %+v", result)
	}
}
