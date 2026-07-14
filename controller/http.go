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
	ctl.http.Get("/metrics", ctl.metrics)

	// api
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
	// tunnel 配置
	huma.Get(hapi, apiV1("/tunnels"), ctl.getTunnels)
	huma.Get(hapi, apiV1("/tunnels/{name}"), ctl.getTunnel)
	huma.Put(hapi, apiV1("/tunnels"), ctl.setTunnel)
	huma.Delete(hapi, apiV1("/tunnels/{name}"), ctl.deleteTunnel)
}

func apiV1(r string) string {
	return path.Join("/api/v1", r)
}
