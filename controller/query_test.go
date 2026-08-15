package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/schema"
)

type queryTestItem struct {
	Name  string
	Value uint32
}

func TestQueryListSearchSortPagination(t *testing.T) {
	items := []queryTestItem{
		{Name: "Charlie", Value: 30},
		{Name: "alpha", Value: 10},
		{Name: "Bravo", Value: 20},
		{Name: "charlie", Value: 31},
	}
	spec := listSpec[queryTestItem]{
		Searchable: func(item queryTestItem) []string { return []string{item.Name} },
		Sortable: map[string]func(a, b queryTestItem) int{
			"name":  byString(func(item queryTestItem) string { return item.Name }),
			"value": func(a, b queryTestItem) int { return cmpUint32(a.Value, b.Value) },
		},
		DefaultSort: "name",
	}

	// 搜索不区分大小写。
	page, total, pageNo, perPage := queryList(items, schema.ListParams{Search: "CHAR"}, spec)
	if total != 2 || len(page) != 2 {
		t.Fatalf("search: total=%d page=%d, want 2/2", total, len(page))
	}

	// 默认按 name 升序，忽略未知排序字段。
	page, total, _, _ = queryList(items, schema.ListParams{Sort: "unknown"}, spec)
	if total != 4 || page[0].Name != "alpha" || page[3].Name != "charlie" {
		t.Fatalf("default sort: %+v", page)
	}

	// 显式 desc 排序。
	page, _, _, _ = queryList(items, schema.ListParams{Sort: "name", Order: "desc"}, spec)
	if page[0].Name != "Charlie" || page[1].Name != "charlie" || page[3].Name != "alpha" {
		t.Fatalf("desc sort: %+v", page)
	}

	// 分页切片。
	page, total, pageNo, perPage = queryList(items, schema.ListParams{PerPage: 3, Page: 2}, spec)
	if total != 4 || pageNo != 2 || perPage != 3 || len(page) != 1 || page[0].Name != "charlie" {
		t.Fatalf("page 2: total=%d pageNo=%d perPage=%d page=%+v", total, pageNo, perPage, page)
	}

	// 超出范围返回空页但不丢总数。
	page, total, _, _ = queryList(items, schema.ListParams{PerPage: 3, Page: 9}, spec)
	if total != 4 || len(page) != 0 {
		t.Fatalf("out-of-range page: total=%d page=%d", total, len(page))
	}

	// 非法参数回退默认值，且 perPage 有上限。
	page, _, pageNo, perPage = queryList(items, schema.ListParams{PerPage: 0, Page: 0}, spec)
	if pageNo != 1 || perPage != defaultPerPage || len(page) != 4 {
		t.Fatalf("fallback defaults: pageNo=%d perPage=%d len=%d", pageNo, perPage, len(page))
	}
	_, _, _, perPage = queryList(items, schema.ListParams{PerPage: 99999}, spec)
	if perPage != maxPerPage {
		t.Fatalf("perPage cap = %d, want %d", perPage, maxPerPage)
	}
}

func TestListAPIHeadersAndQuery(t *testing.T) {
	ctl := newEgressTestController(t)
	for _, egress := range []string{
		`{"name":"alpha","type":"manual","fwmark":100}`,
		`{"name":"beta","type":"manual","fwmark":200}`,
		`{"name":"gamma","type":"manual","fwmark":300}`,
	} {
		assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/egresses", egress, http.StatusOK)
	}
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/domains", `{"match":"full","domain":"example.com","egress":"alpha"}`, http.StatusOK)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/domains", `{"match":"domain","domain":"test.org","egress":"beta"}`, http.StatusOK)

	// 分页：第 2 页每页 2 条，按名称升序应只剩 gamma。
	req := httptest.NewRequest(http.MethodGet, "/api/v1/egresses?per_page=2&page=2&sort=name&order=asc", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("X-Total-Count"); got != "3" {
		t.Fatalf("X-Total-Count = %q, want 3", got)
	}
	if got := res.Header().Get("X-Page"); got != "2" {
		t.Fatalf("X-Page = %q, want 2", got)
	}
	if got := res.Header().Get("X-Per-Page"); got != "2" {
		t.Fatalf("X-Per-Page = %q, want 2", got)
	}
	var page []egressResponse
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v: %s", err, res.Body.String())
	}
	if len(page) != 1 || page[0].Name != "gamma" {
		t.Fatalf("page items = %+v, want [gamma]", page)
	}

	// 搜索 + 倒序。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/egresses?search=bet&sort=name&order=desc", nil)
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if got := res.Header().Get("X-Total-Count"); got != "1" {
		t.Fatalf("search X-Total-Count = %q, want 1", got)
	}
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode search page: %v", err)
	}
	if len(page) != 1 || page[0].Name != "beta" {
		t.Fatalf("search items = %+v, want [beta]", page)
	}

	// 倒序分页第一页应为 gamma、beta。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/egresses?per_page=2&sort=name&order=desc", nil)
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode desc page: %v", err)
	}
	if len(page) != 2 || page[0].Name != "gamma" || page[1].Name != "beta" {
		t.Fatalf("desc page items = %+v, want [gamma beta]", page)
	}

	// 存储型列表同样支持搜索与分页：域名按关键字过滤。
	req = httptest.NewRequest(http.MethodGet, "/api/v1/domains?search=org&per_page=1", nil)
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if got := res.Header().Get("X-Total-Count"); got != "1" {
		t.Fatalf("domains search X-Total-Count = %q, want 1", got)
	}
	var domains []dao.DomainRule
	if err := json.Unmarshal(res.Body.Bytes(), &domains); err != nil {
		t.Fatalf("decode domains search: %v", err)
	}
	if len(domains) != 1 || domains[0].Domain != "test.org" {
		t.Fatalf("domains search items = %+v, want [test.org]", domains)
	}
}

func TestFilterRouteTree(t *testing.T) {
	nodes := []bart.DumpListNode[uint8]{
		{CIDR: netip.MustParsePrefix("10.0.0.0/8"), Value: 0, Subnets: []bart.DumpListNode[uint8]{
			{CIDR: netip.MustParsePrefix("10.1.0.0/16"), Value: 1},
			{CIDR: netip.MustParsePrefix("10.2.0.0/16"), Value: 2},
		}},
		{CIDR: netip.MustParsePrefix("192.168.0.0/16"), Value: 3},
	}

	filtered := filterRouteTree(nodes, "10.2")
	if len(filtered) != 1 {
		t.Fatalf("filtered roots = %d, want 1", len(filtered))
	}
	if filtered[0].CIDR.String() != "10.0.0.0/8" || len(filtered[0].Subnets) != 1 || filtered[0].Subnets[0].CIDR.String() != "10.2.0.0/16" {
		t.Fatalf("filtered tree = %+v", filtered)
	}
	if len(filtered[0].Subnets[0].Subnets) != 0 {
		t.Fatalf("pruned leaf should have no subnets: %+v", filtered[0].Subnets[0])
	}

	if filtered := filterRouteTree(nodes, "10.9"); filtered != nil {
		t.Fatalf("no-match filter should be nil, got %+v", filtered)
	}
}

func TestListAPIOpenAPIDocumentsPagination(t *testing.T) {
	ctl := newEgressTestController(t)
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json status = %d: %s", res.Code, res.Body.String())
	}
	var spec map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	body := res.Body.String()
	for _, name := range []string{"page", "per_page", "sort", "order", "search"} {
		if !strings.Contains(body, `"`+name+`"`) {
			t.Fatalf("openapi missing query param %q", name)
		}
	}
	for _, header := range []string{"X-Total-Count", "X-Page", "X-Per-Page"} {
		if !strings.Contains(body, header) {
			t.Fatalf("openapi missing response header %q", header)
		}
	}
}
