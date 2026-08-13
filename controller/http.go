package controller

import (
	"net/http"
	"path"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

func (ctl *controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctl.http.ServeHTTP(w, r)
}

func (ctl *controller) registerHttpAPI() {
	ctl.registerWebUI()
	ctl.http.Get("/metrics", ctl.metrics)

	// api doc
	// todo: 使用全局版本管理
	hapi := humachi.New(ctl.http, huma.DefaultConfig("gateway API", "1.0.0"))
	// 路由表相关
	huma.Get(hapi, apiV1("/routetree"), ctl.getRouteTableTree)
	huma.Get(hapi, apiV1("/routes"), ctl.getRouteTables)
	// dns 路由相关
	huma.Get(hapi, apiV1("/domains"), ctl.getDomainRules)
	huma.Put(hapi, apiV1("/domains"), ctl.setDomainRule)
	huma.Delete(hapi, apiV1("/domains/{matchDomain}"), ctl.deleteDomainRule)
	// 静态 dns host 解析
	huma.Get(hapi, apiV1("/hosts"), ctl.getHosts)
	huma.Put(hapi, apiV1("/hosts"), ctl.setHosts)
	huma.Delete(hapi, apiV1("/hosts/{host}"), ctl.deleteHosts)
	// egress 配置
	huma.Get(hapi, apiV1("/egresses"), ctl.getEgresses)
	huma.Get(hapi, apiV1("/egresses/{name}"), ctl.getEgress)
	huma.Post(hapi, apiV1("/egresses"), ctl.createEgress)
	// Retain the previous endpoint for clients creating an egress. Existing
	// names now return a conflict instead of being overwritten.
	huma.Put(hapi, apiV1("/egresses"), ctl.createEgress)
	huma.Put(hapi, apiV1("/egresses/{name}"), ctl.updateEgress)
	huma.Delete(hapi, apiV1("/egresses/{name}"), ctl.deleteEgress)
}

func apiV1(r string) string {
	return path.Join("/api/v1", r)
}
