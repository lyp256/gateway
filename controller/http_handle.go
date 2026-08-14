package controller

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gaissmai/bart"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/dns/router"
	"github.com/lyp256/gateway/schema"
)

func (ctl *controller) getRouteTableTree(ctx context.Context, _ *struct{}) (*schema.Body[[]bart.DumpListNode[uint8]], error) {
	ctl.routeMux.RLock()
	defer ctl.routeMux.RUnlock()
	routes := ctl.routeTable.DumpList4()
	return schema.NewBody(routes), nil
}

func (ctl *controller) getRouteTables(ctx context.Context, _ *struct{}) (*schema.Body[[]schema.RouteTableItem], error) {
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
	return schema.NewBody(res), nil
}

func (ctl *controller) getDomainRules(ctx context.Context, _ *struct{}) (*schema.Body[[]dao.DomainRule], error) {
	list, err := ctl.storage.ListDomainRule(nil)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(list), nil
}

func (ctl *controller) getCidrRules(ctx context.Context, _ *struct{}) (*schema.Body[[]dao.CidrRule], error) {
	list, err := ctl.storage.ListCidrRule()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(list), nil
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

func (ctl *controller) getHosts(ctx context.Context, _ *struct{}) (*schema.Body[[]dao.Host], error) {
	list, err := ctl.storage.ListHost()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(list), nil
}

func (ctl *controller) getDNSCache(ctx context.Context, _ *struct{}) (*schema.Body[[]schema.DNSCacheEntry], error) {
	return schema.NewBody(ctl.dnsCacheSnapshot()), nil
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

// egressResponse 在持久化 egress 基础上附加运行时索引，供前端把路由表 value 对应回 egress。
type egressResponse struct {
	dao.Egress
	Index uint8 `json:"index"`
}

func (ctl *controller) toEgressResponse(egress dao.Egress) egressResponse {
	idx, _ := ctl.egressIndex(egress.Name)
	return egressResponse{Egress: egress, Index: idx}
}

func (ctl *controller) getEgresses(ctx context.Context, _ *struct{}) (*schema.Body[[]egressResponse], error) {
	list, err := ctl.storage.ListEgress()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	res := make([]egressResponse, 0, len(list))
	for _, egress := range list {
		res = append(res, ctl.toEgressResponse(egress))
	}
	return schema.NewBody(res), nil
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
