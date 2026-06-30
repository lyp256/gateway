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
	huma.Get(hapi, apiV1("/routetree"), ctl.getRouteTableTree)
	huma.Get(hapi, apiV1("/routes"), ctl.getRouteTables)
	huma.Get(hapi, apiV1("/domains"), ctl.getDomainRules)
	huma.Put(hapi, apiV1("/domains"), ctl.setDomainRule)
	huma.Delete(hapi, apiV1("/domains/{matchDomain}"), ctl.deleteDomainRule)
	huma.Get(hapi, apiV1("/hosts"), ctl.getHosts)
	huma.Put(hapi, apiV1("/hosts"), ctl.setHosts)
	huma.Delete(hapi, apiV1("/hosts/{host}"), ctl.deleteHosts)
}

func apiV1(r string) string {
	return path.Join("/api/v1", r)
}
