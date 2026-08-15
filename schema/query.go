package schema

// ListParams 是所有列表接口通用的分页、排序与搜索查询参数。
// 查询在内存中完成：bbolt 仅提供全量遍历，复杂的过滤、排序与切片由
// controller 侧的通用查询引擎处理。
type ListParams struct {
	Page    int    `query:"page" minimum:"1" default:"1" doc:"页码，从 1 开始"`
	PerPage int    `query:"per_page" minimum:"1" maximum:"1000" default:"20" doc:"每页条数"`
	Sort    string `query:"sort" doc:"排序字段"`
	Order   string `query:"order" enum:"asc,desc" doc:"排序方向，默认 asc"`
	Search  string `query:"search" doc:"关键字搜索"`
}

// ListOutput 是所有列表接口统一的响应包装。huma 只序列化 Body 字段
// （即列表本身），分页信息通过响应头返回，保持响应体为纯数组。
type ListOutput[T any] struct {
	Body    []T `json:"items"`
	Total   int `header:"X-Total-Count"`
	Page    int `header:"X-Page"`
	PerPage int `header:"X-Per-Page"`
}

// NewListOutput 构造列表响应。
func NewListOutput[T any](items []T, total, page, perPage int) *ListOutput[T] {
	return &ListOutput[T]{
		Body:    items,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}
}
