package controller

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/lyp256/gateway/schema"
)

const (
	defaultPerPage = 20
	maxPerPage     = 1000
)

// listSpec 描述某个列表的搜索与排序规则，是内存查询引擎的配置。
type listSpec[T any] struct {
	// Searchable 返回一个条目中参与关键字匹配的字符串集合。
	Searchable func(item T) []string
	// Sortable 是排序字段名到比较函数的映射；比较结果 <0 表示 a 排在 b 前。
	Sortable map[string]func(a, b T) int
	// DefaultSort 未指定 sort 参数时使用的字段。
	DefaultSort string
	// DefaultOrder 未指定 order 参数时的方向，asc 或 desc。
	DefaultOrder string
}

// queryList 在内存中完成列表的搜索、排序与分页：
// 先按关键字过滤，再按白名单字段稳定排序，最后切片取当前页。
// 返回当前页条目、过滤后的总数以及实际生效的页码与每页条数。
func queryList[T any](items []T, params schema.ListParams, spec listSpec[T]) (page []T, total, pageNo, perPage int) {
	perPage = params.PerPage
	if perPage <= 0 {
		perPage = defaultPerPage
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	pageNo = params.Page
	if pageNo < 1 {
		pageNo = 1
	}

	filtered := items
	if keyword := strings.ToLower(strings.TrimSpace(params.Search)); keyword != "" && spec.Searchable != nil {
		filtered = make([]T, 0, len(items))
		for _, item := range items {
			if searchable(item, keyword, spec.Searchable) {
				filtered = append(filtered, item)
			}
		}
	}

	sortField := spec.DefaultSort
	if field := strings.ToLower(strings.TrimSpace(params.Sort)); field != "" {
		if _, ok := spec.Sortable[field]; ok {
			sortField = field
		}
	}
	order := strings.ToLower(strings.TrimSpace(params.Order))
	if order == "" {
		order = spec.DefaultOrder
	}
	desc := order == "desc"
	if cmp, ok := spec.Sortable[sortField]; ok {
		slices.SortStableFunc(filtered, func(a, b T) int {
			if desc {
				return -cmp(a, b)
			}
			return cmp(a, b)
		})
	}

	total = len(filtered)
	start := (pageNo - 1) * perPage
	if start > total {
		start = total
	}
	end := min(start+perPage, total)
	page = filtered[start:end]
	if page == nil {
		page = []T{}
	}
	return page, total, pageNo, perPage
}

// searchable 判断关键字是否命中条目任意一个可搜索字段（大小写不敏感）。
func searchable[T any](item T, keyword string, fields func(T) []string) bool {
	for _, field := range fields(item) {
		if strings.Contains(strings.ToLower(field), keyword) {
			return true
		}
	}
	return false
}

// byString 从字段取值函数构造字符串比较器（大小写不敏感）。
func byString[T any](get func(T) string) func(a, b T) int {
	return func(a, b T) int {
		return strings.Compare(strings.ToLower(get(a)), strings.ToLower(get(b)))
	}
}

func cmpUint32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpUint8(a, b uint8) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

func cmpTime(a, b time.Time) int {
	return a.Compare(b)
}

func cmpPrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	if a.Bits() < b.Bits() {
		return -1
	}
	if a.Bits() > b.Bits() {
		return 1
	}
	return 0
}

// cmpCidrString 优先按网段的地址与掩码长度排序，解析失败时回退为字符串比较。
func cmpCidrString(a, b string) int {
	pa, ea := netip.ParsePrefix(a)
	pb, eb := netip.ParsePrefix(b)
	if ea == nil && eb == nil {
		return cmpPrefix(pa, pb)
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}

// cmpAddrString 优先按 IP 地址排序，解析失败时回退为字符串比较。
func cmpAddrString(a, b string) int {
	aa, ea := netip.ParseAddr(a)
	ab, eb := netip.ParseAddr(b)
	if ea == nil && eb == nil {
		return aa.Compare(ab)
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}
