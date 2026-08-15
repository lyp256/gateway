package controller

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gaissmai/bart"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/dns/router"
	"github.com/lyp256/gateway/schema"
)

// listQuery 是所有列表 handler 共用的查询参数入口。
type listQuery struct {
	schema.ListParams
}

// routeTreeQuery 路由树是层级结构，只支持关键字过滤，不做分页与排序。
type routeTreeQuery struct {
	Search string `query:"search" doc:"按 CIDR 或 egress 索引过滤路由树"`
}

func (ctl *controller) getRouteTableTree(ctx context.Context, in *routeTreeQuery) (*schema.Body[[]bart.DumpListNode[uint8]], error) {
	ctl.routeMux.RLock()
	routes := ctl.routeTable.DumpList4()
	ctl.routeMux.RUnlock()
	if keyword := strings.ToLower(strings.TrimSpace(in.Search)); keyword != "" {
		routes = filterRouteTree(routes, keyword)
	}
	return schema.NewBody(routes), nil
}

// filterRouteTree 递归保留命中的节点及其祖先；未命中的子树会被裁剪。
func filterRouteTree(nodes []bart.DumpListNode[uint8], keyword string) []bart.DumpListNode[uint8] {
	out := make([]bart.DumpListNode[uint8], 0, len(nodes))
	for _, node := range nodes {
		subs := filterRouteTree(node.Subnets, keyword)
		if subs != nil || strings.Contains(strings.ToLower(node.CIDR.String()), keyword) {
			node.Subnets = subs
			out = append(out, node)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (ctl *controller) getRouteTables(ctx context.Context, in *listQuery) (*schema.ListOutput[schema.RouteTableItem], error) {
	res := make([]schema.RouteTableItem, 0, 0)
	ctl.routeMux.RLock()
	ctl.routeTable.AllSorted4()(func(cidr netip.Prefix, v uint8) bool {
		res = append(res, schema.RouteTableItem{
			CIDR:  cidr,
			Value: uint32(v),
		})
		return true
	})
	ctl.routeMux.RUnlock()
	items, total, page, perPage := queryList(res, in.ListParams, listSpec[schema.RouteTableItem]{
		Searchable: func(item schema.RouteTableItem) []string {
			return []string{item.CIDR.String(), strconv.FormatUint(uint64(item.Value), 10)}
		},
		Sortable: map[string]func(a, b schema.RouteTableItem) int{
			"cidr":  func(a, b schema.RouteTableItem) int { return cmpPrefix(a.CIDR, b.CIDR) },
			"value": func(a, b schema.RouteTableItem) int { return cmpUint32(a.Value, b.Value) },
		},
		DefaultSort: "cidr",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) getDomainRules(ctx context.Context, in *listQuery) (*schema.ListOutput[dao.DomainRule], error) {
	list, err := ctl.storage.ListDomainRule(nil)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[dao.DomainRule]{
		Searchable: func(rule dao.DomainRule) []string {
			return []string{rule.Domain, rule.Egress, rule.Match.String()}
		},
		Sortable: map[string]func(a, b dao.DomainRule) int{
			"domain": byString(func(rule dao.DomainRule) string { return rule.Domain }),
			"match":  byString(func(rule dao.DomainRule) string { return rule.Match.String() }),
			"egress": byString(func(rule dao.DomainRule) string { return rule.Egress }),
		},
		DefaultSort: "domain",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) getCidrRules(ctx context.Context, in *listQuery) (*schema.ListOutput[dao.CidrRule], error) {
	list, err := ctl.storage.ListCidrRule()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[dao.CidrRule]{
		Searchable: func(rule dao.CidrRule) []string {
			return []string{rule.Cidr, rule.Egress}
		},
		Sortable: map[string]func(a, b dao.CidrRule) int{
			"cidr":   func(a, b dao.CidrRule) int { return cmpCidrString(a.Cidr, b.Cidr) },
			"egress": byString(func(rule dao.CidrRule) string { return rule.Egress }),
		},
		DefaultSort: "cidr",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) setCidrRule(ctx context.Context, in *schema.Body[dao.CidrRule]) (*schema.Body[dao.CidrRule], error) {
	prefix, err := dao.NormalizeCidr(in.Body.Cidr)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	in.Body.Cidr = prefix.String()
	egress, err := ctl.storage.GetEgress(in.Body.Egress)
	if err != nil {
		return nil, egressError(err)
	}
	if err := ctl.storage.SetCidrRule(in.Body); err != nil {
		if errors.Is(err, dao.ErrEgressNotFound) {
			return nil, huma.NewError(http.StatusNotFound, "egress not found")
		}
		return nil, huma.NewError(500, "create data", err)
	}
	egressIdx, ok := ctl.egressIndex(egress.Name)
	if !ok {
		return nil, huma.NewError(http.StatusInternalServerError, "egress index not found", nil)
	}
	ctl.setCidrRoute(prefix, egressIdx)
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) deleteCidrRule(ctx context.Context, i *struct {
	Cidr string `path:"cidr"`
}) (*struct{}, error) {
	prefix, err := dao.NormalizeCidr(i.Cidr)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	if err := ctl.storage.DeleteCidrRule(prefix.String()); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.deleteCidrRoute(prefix)
	return nil, nil
}

func (ctl *controller) setDomainRule(ctx context.Context, in *schema.Body[dao.DomainRule]) (*schema.Body[dao.DomainRule], error) {
	egress, err := ctl.storage.GetEgress(in.Body.Egress)
	if err != nil {
		return nil, egressError(err)
	}
	err = ctl.storage.SetDomainRule(in.Body)
	if err != nil {
		if errors.Is(err, dao.ErrEgressNotFound) {
			return nil, huma.NewError(http.StatusNotFound, "egress not found")
		}
		return nil, huma.NewError(500, "create data", err)
	}
	egressIdx, ok := ctl.egressIndex(egress.Name)
	if !ok {
		return nil, huma.NewError(http.StatusInternalServerError, "egress index not found", nil)
	}
	ctl.dnsTable.Set(in.Body.Domain, in.Body.Match, uint32(egressIdx))
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) deleteDomainRule(ctx context.Context, i *struct {
	MatchDomain string `path:"matchDomain"`
}) (*struct{}, error) {
	parts := strings.SplitN(i.MatchDomain, ":", 2)
	if len(parts) != 2 {
		return nil, huma.NewError(400, "invalid matchdomain, example full:example.com")
	}
	m := router.ParseMatchType(parts[0])
	if m == 0 {
		return nil, huma.NewError(400, "invalid matchtype")
	}

	err := ctl.storage.DeleteDomainRule(m, parts[1])
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.dnsTable.Delete(parts[1])
	return nil, nil
}

func (ctl *controller) getHosts(ctx context.Context, in *listQuery) (*schema.ListOutput[dao.Host], error) {
	list, err := ctl.storage.ListHost()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[dao.Host]{
		Searchable: func(host dao.Host) []string {
			return []string{host.Name, host.IP.String()}
		},
		Sortable: map[string]func(a, b dao.Host) int{
			"name": byString(func(host dao.Host) string { return host.Name }),
			"ip":   func(a, b dao.Host) int { return a.IP.Compare(b.IP) },
		},
		DefaultSort: "name",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) getWhitelist(ctx context.Context, in *listQuery) (*schema.ListOutput[dao.WhitelistRule], error) {
	list, err := ctl.storage.ListWhitelist()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[dao.WhitelistRule]{
		Searchable: func(rule dao.WhitelistRule) []string {
			return []string{rule.Cidr}
		},
		Sortable: map[string]func(a, b dao.WhitelistRule) int{
			"cidr": func(a, b dao.WhitelistRule) int { return cmpCidrString(a.Cidr, b.Cidr) },
		},
		DefaultSort: "cidr",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) setWhitelistRule(ctx context.Context, in *schema.Body[dao.WhitelistRule]) (*schema.Body[dao.WhitelistRule], error) {
	prefix, err := dao.NormalizeWhitelist(in.Body.Cidr)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	in.Body.Cidr = prefix.String()
	if err := ctl.storage.SetWhitelist(prefix.String()); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "save whitelist", err)
	}
	ctl.setWhitelist(prefix)
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) deleteWhitelistRule(ctx context.Context, i *struct {
	Cidr string `path:"cidr"`
}) (*struct{}, error) {
	prefix, err := dao.NormalizeWhitelist(i.Cidr)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	if err := ctl.storage.DeleteWhitelist(prefix.String()); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.deleteWhitelist(prefix)
	return nil, nil
}

func (ctl *controller) getDNSCache(ctx context.Context, in *listQuery) (*schema.ListOutput[schema.DNSCacheEntry], error) {
	list := ctl.dnsCacheSnapshot()
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[schema.DNSCacheEntry]{
		Searchable: func(entry schema.DNSCacheEntry) []string {
			fields := []string{entry.Name, entry.Type, strings.Join(entry.Answers, " ")}
			if entry.Expired {
				fields = append(fields, "expired", "已过期")
			} else {
				fields = append(fields, "active", "有效")
			}
			return fields
		},
		Sortable: map[string]func(a, b schema.DNSCacheEntry) int{
			"name":         byString(func(entry schema.DNSCacheEntry) string { return entry.Name }),
			"type":         byString(func(entry schema.DNSCacheEntry) string { return entry.Type }),
			"ttl":          func(a, b schema.DNSCacheEntry) int { return cmpUint32(a.TTL, b.TTL) },
			"cachedAt":     func(a, b schema.DNSCacheEntry) int { return cmpTime(a.CachedAt, b.CachedAt) },
			"lastAccessAt": func(a, b schema.DNSCacheEntry) int { return cmpTime(a.LastAccessAt, b.LastAccessAt) },
			"expiresAt":    func(a, b schema.DNSCacheEntry) int { return cmpTime(a.ExpiresAt, b.ExpiresAt) },
		},
		DefaultSort:  "lastAccessAt",
		DefaultOrder: "desc",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) deleteDNSCacheEntry(ctx context.Context, in *struct {
	Name string `path:"name" doc:"缓存条目域名"`
}) (*struct{}, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, huma.NewError(http.StatusBadRequest, "dns cache name is required")
	}
	if !ctl.deleteDNSCacheByName(in.Name) {
		return nil, huma.Error404NotFound("dns cache entry not found")
	}
	return nil, nil
}

func (ctl *controller) setHosts(ctx context.Context, in *schema.Body[dao.Host]) (*schema.Body[dao.Host], error) {
	err := ctl.storage.SetHost(in.Body.Name, in.Body.IP)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.hostsMux.Lock()
	ctl.hosts[in.Body.Name] = in.Body.IP
	ctl.hostsMux.Unlock()
	ctl.dnsCache.Remove(in.Body.Name)
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) deleteHosts(ctx context.Context, in *struct {
	Name string `path:"host_name"`
}) (*struct{}, error) {
	err := ctl.storage.DeleteHost(in.Name)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.hostsMux.Lock()
	delete(ctl.hosts, in.Name)
	ctl.hostsMux.Unlock()
	ctl.dnsCache.Remove(in.Name)
	return nil, nil
}

func (ctl *controller) getDNSServers(ctx context.Context, in *listQuery) (*schema.ListOutput[dao.DNSServer], error) {
	list, err := ctl.storage.ListDNSServer()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(list, in.ListParams, listSpec[dao.DNSServer]{
		Searchable: func(server dao.DNSServer) []string {
			return []string{server.Name, server.Type, server.Server, server.IP.String()}
		},
		Sortable: map[string]func(a, b dao.DNSServer) int{
			"name":   byString(func(server dao.DNSServer) string { return server.Name }),
			"type":   byString(func(server dao.DNSServer) string { return server.Type }),
			"server": byString(func(server dao.DNSServer) string { return server.Server }),
			"ip":     func(a, b dao.DNSServer) int { return cmpAddrString(a.IP.String(), b.IP.String()) },
		},
		DefaultSort: "name",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) setDNSServer(ctx context.Context, in *schema.Body[dao.DNSServer]) (*schema.Body[dao.DNSServer], error) {
	if err := dao.NormalizeDNSServer(&in.Body); err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	if _, err := newQuerier(in.Body); err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	if err := ctl.setDNSServerRuntime(in.Body); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "save dns server", err)
	}
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) testDNSServer(ctx context.Context, in *schema.Body[dnsTestRequest]) (*schema.Body[dnsTestResult], error) {
	req := in.Body
	s := dao.DNSServer{Type: req.Type, Server: req.Server, IP: req.IP, Insecure: req.Insecure}
	return schema.NewBody(probeDNSServer(s, req.QName)), nil
}

func (ctl *controller) deleteDNSServer(ctx context.Context, in *struct {
	Name string `path:"name"`
}) (*struct{}, error) {
	if err := ctl.deleteDNSServerRuntime(in.Name); err != nil {
		if errors.Is(err, dao.ErrKeyNotFound) {
			return nil, huma.Error404NotFound("dns server not found")
		}
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return nil, nil
}

// egressResponse 在持久化 egress 基础上附加运行时索引，供前端把路由表 value 对应回 egress。
type egressResponse struct {
	dao.Egress
	Index uint8 `json:"index"`
}

func (ctl *controller) toEgressResponse(egress dao.Egress) egressResponse {
	idx, _ := ctl.egressIndex(egress.Name)
	return egressResponse{Egress: egress, Index: idx}
}

func (ctl *controller) getEgresses(ctx context.Context, in *listQuery) (*schema.ListOutput[egressResponse], error) {
	list, err := ctl.storage.ListEgress()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	res := make([]egressResponse, 0, len(list))
	for _, egress := range list {
		res = append(res, ctl.toEgressResponse(egress))
	}
	items, total, page, perPage := queryList(res, in.ListParams, listSpec[egressResponse]{
		Searchable: func(egress egressResponse) []string {
			fields := []string{egress.Name, string(egress.Type), strconv.FormatUint(uint64(egress.FwMark), 10)}
			if egress.Tunnel != nil {
				fields = append(fields, egress.Tunnel.Url)
			}
			if egress.Tproxy != nil {
				fields = append(fields, egress.Tproxy.Addr, strconv.FormatUint(uint64(egress.Tproxy.Port), 10))
			}
			return fields
		},
		Sortable: map[string]func(a, b egressResponse) int{
			"name":   byString(func(egress egressResponse) string { return egress.Name }),
			"type":   byString(func(egress egressResponse) string { return string(egress.Type) }),
			"fwmark": func(a, b egressResponse) int { return cmpUint32(a.FwMark, b.FwMark) },
			"index":  func(a, b egressResponse) int { return cmpUint8(a.Index, b.Index) },
		},
		DefaultSort: "name",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

func (ctl *controller) getEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
}) (*schema.Body[egressResponse], error) {
	tun, err := ctl.storage.GetEgress(in.Name)
	if err != nil {
		return nil, egressError(err)
	}
	return schema.NewBody(ctl.toEgressResponse(tun)), nil
}

func (ctl *controller) createEgress(ctx context.Context, in *schema.Body[dao.Egress]) (*schema.Body[egressResponse], error) {
	if in.Body.Name == "" {
		return nil, huma.NewError(http.StatusBadRequest, "egress name is required")
	}
	if err := ctl.storage.CreateEgress(in.Body); err != nil {
		return nil, egressError(err)
	}
	saved, err := ctl.storage.GetEgress(in.Body.Name)
	if err != nil {
		return nil, egressError(err)
	}
	if err := ctl.addEgress(saved); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "apply egress", err)
	}
	return schema.NewBody(ctl.toEgressResponse(saved)), nil
}

func (ctl *controller) updateEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
	Body dao.Egress
}) (*schema.Body[egressResponse], error) {
	if in.Body.Name != in.Name {
		return nil, huma.NewError(http.StatusBadRequest, "egress name cannot be changed")
	}
	if err := ctl.storage.UpdateEgress(in.Body); err != nil {
		return nil, egressError(err)
	}
	saved, err := ctl.storage.GetEgress(in.Body.Name)
	if err != nil {
		return nil, egressError(err)
	}
	if err := ctl.syncEgressRule(saved); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "apply egress", err)
	}
	return schema.NewBody(ctl.toEgressResponse(saved)), nil
}

func egressError(err error) error {
	switch {
	case errors.Is(err, dao.ErrEgressNameExists):
		return huma.Error409Conflict("egress name already exists")
	case errors.Is(err, dao.ErrEgressFwMarkExists):
		return huma.Error409Conflict("egress fwmark already exists")
	case errors.Is(err, dao.ErrEgressInUse):
		return huma.Error409Conflict("egress is referenced by domain rules")
	case errors.Is(err, dao.ErrEgressNotFound):
		return huma.Error404NotFound("egress not found")
	case errors.Is(err, dao.ErrKeyNotFound):
		return huma.Error404NotFound("egress not found")
	case errors.Is(err, dao.ErrInvalidEgress):
		return huma.NewError(http.StatusBadRequest, err.Error())
	default:
		return huma.NewError(http.StatusInternalServerError, "", err)
	}
}

func (ctl *controller) deleteEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
}) (*struct{}, error) {
	if err := ctl.storage.DeleteEgress(in.Name); err != nil {
		return nil, egressError(err)
	}
	ctl.dropEgress(in.Name)
	return nil, nil
}
