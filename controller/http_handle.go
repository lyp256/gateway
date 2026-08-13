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

func (ctl *controller) getRouteTableTree(ctx context.Context, _ *struct{}) (*schema.Body[[]bart.DumpListNode[uint32]], error) {
	routes := ctl.routeTable.DumpList4()
	return schema.NewBody(routes), nil
}

func (ctl *controller) getRouteTables(ctx context.Context, _ *struct{}) (*schema.Body[[]schema.RouteTableItem], error) {
	res := make([]schema.RouteTableItem, 0, 0)
	ctl.routeTable.AllSorted4()(func(cidr netip.Prefix, v uint32) bool {
		res = append(res, schema.RouteTableItem{
			CIDR:  cidr,
			Value: v,
		})
		return true
	})
	return schema.NewBody(res), nil
}

func (ctl *controller) getDomainRules(ctx context.Context, _ *struct{}) (*schema.Body[[]dao.DomainRule], error) {
	list, err := ctl.storage.ListDomainRule(nil)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(list), nil
}

func (ctl *controller) setDomainRule(ctx context.Context, in *schema.Body[dao.DomainRule]) (*schema.Body[dao.DomainRule], error) {
	err := ctl.storage.SetDomainRule(in.Body)
	if err != nil {
		return nil, huma.NewError(500, "create data", err)
	}
	ctl.dnsTable.Set(in.Body.Domain, in.Body.Match, in.Body.Fwmark)
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

func (ctl *controller) setHosts(ctx context.Context, in *schema.Body[dao.Host]) (*schema.Body[dao.Host], error) {
	err := ctl.storage.SetHost(in.Body.Name, in.Body.IP)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.hostsMux.Lock()
	ctl.hosts[in.Body.Name] = in.Body.IP
	ctl.hostsMux.Unlock()
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) deleteHosts(ctx context.Context, in *struct {
	Host string `path:"host"`
}) (*struct{}, error) {
	err := ctl.storage.DeleteHost(in.Host)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	ctl.hostsMux.Lock()
	delete(ctl.hosts, in.Host)
	ctl.hostsMux.Unlock()
	return nil, nil
}

func (ctl *controller) getEgresses(ctx context.Context, _ *struct{}) (*schema.Body[[]dao.Egress], error) {
	list, err := ctl.storage.ListEgress()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(list), nil
}

func (ctl *controller) getEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
}) (*schema.Body[dao.Egress], error) {
	tun, err := ctl.storage.GetEgress(in.Name)
	if err != nil {
		if errors.Is(err, dao.ErrKeyNotFound) {
			return nil, huma.NewError(http.StatusNotFound, "egress not found")
		}
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(tun), nil
}

func (ctl *controller) createEgress(ctx context.Context, in *schema.Body[dao.Egress]) (*schema.Body[dao.Egress], error) {
	if in.Body.Name == "" {
		return nil, huma.NewError(http.StatusBadRequest, "egress name is required")
	}
	if err := ctl.storage.CreateEgress(in.Body); err != nil {
		return nil, egressError(err)
	}
	return schema.NewBody(in.Body), nil
}

func (ctl *controller) updateEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
	Body dao.Egress
}) (*schema.Body[dao.Egress], error) {
	if in.Body.Name != in.Name {
		return nil, huma.NewError(http.StatusBadRequest, "egress name cannot be changed")
	}
	if err := ctl.storage.UpdateEgress(in.Body); err != nil {
		return nil, egressError(err)
	}
	return schema.NewBody(in.Body), nil
}

func egressError(err error) error {
	switch {
	case errors.Is(err, dao.ErrEgressNameExists):
		return huma.Error409Conflict("egress name already exists")
	case errors.Is(err, dao.ErrEgressFwMarkExists):
		return huma.Error409Conflict("egress fwmark already exists")
	case errors.Is(err, dao.ErrKeyNotFound):
		return huma.Error404NotFound("egress not found")
	default:
		return huma.NewError(http.StatusInternalServerError, "", err)
	}
}

func (ctl *controller) deleteEgress(ctx context.Context, in *struct {
	Name string `path:"name"`
}) (*struct{}, error) {
	if err := ctl.storage.DeleteEgress(in.Name); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return nil, nil
}
