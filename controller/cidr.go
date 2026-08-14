package controller

import (
	"log/slog"
	"net/netip"

	"github.com/gaissmai/bart"
	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/dao"
)

// loadCidrRuleMapFromStorage 启动时把持久化的显式 IP/CIDR 规则写入路由表，
// 这些规则不依赖 DNS 解析，直接参与 LPM 匹配。
func loadCidrRuleMapFromStorage(t *bart.Table[uint32], db *dao.Dao) error {
	fwmarkByEgress := make(map[string]uint32)
	if err := db.EgressIterator(func(egress dao.Egress) error {
		fwmarkByEgress[egress.Name] = egress.FwMark
		return nil
	}); err != nil {
		return err
	}
	return db.CidrRuleIterator(func(cr dao.CidrRule) error {
		prefix, err := dao.NormalizeCidr(cr.Cidr)
		if err != nil {
			slog.Error("invalid cidr rule", "cidr", cr.Cidr, "err", err)
			return nil
		}
		fwmark, ok := fwmarkByEgress[cr.Egress]
		if !ok {
			slog.Error("cidr references missing egress", "cidr", cr.Cidr, "egress", cr.Egress)
			return nil
		}
		t.Insert(prefix, fwmark)
		return nil
	})
}

// syncRoutesToBPF 在 eBPF 对象加载完成后，把当前路由表中的 IPv4 路由一次性同步到 BPF LPM map。
func (ctl *controller) syncRoutesToBPF() {
	if ctl.bpf.FilterMaps.RouteLpmMap == nil {
		return
	}
	keys := make([]bpf.FilterBpfLpmTrieKeyV4, 0, ctl.routeTable.Size4())
	values := make([]uint32, 0, cap(keys))
	ctl.routeMux.RLock()
	ctl.routeTable.All4()(func(cidr netip.Prefix, v uint32) bool {
		keys = append(keys, bpf.ToFilterBpfLpmTrieKeyV4(cidr))
		values = append(values, v)
		return true
	})
	ctl.routeMux.RUnlock()
	if len(keys) == 0 {
		return
	}
	updated, err := ctl.bpf.FilterMaps.RouteLpmMap.BatchUpdate(keys, values, nil)
	if err != nil {
		slog.Error("sync cidr route to ebpf failed", "err", err)
		return
	}
	if updated != len(keys) {
		slog.Error("sync cidr route count mismatch", "expect", len(keys), "actual", updated)
	}
}

// setCidrRoute 新增或更新一条显式 IP/CIDR 路由（写入内存路由表与 BPF LPM map）。
func (ctl *controller) setCidrRoute(prefix netip.Prefix, fwmark uint32) {
	prefix = prefix.Masked()
	ctl.routeMux.Lock()
	old, ok := ctl.routeTable.Get(prefix)
	if ok && old == fwmark {
		ctl.routeMux.Unlock()
		return
	}
	ctl.routeTable.Insert(prefix, fwmark)
	ctl.routeMux.Unlock()

	if ctl.bpf.FilterMaps.RouteLpmMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.RouteLpmMap.Put(bpf.ToFilterBpfLpmTrieKeyV4(prefix), fwmark); err != nil {
		slog.Error("update ebpf cidr route failed", "cidr", prefix, "err", err)
	}
}

// deleteCidrRoute 删除一条显式 IP/CIDR 路由。只删除精确前缀，不影响更具体的动态路由。
func (ctl *controller) deleteCidrRoute(prefix netip.Prefix) {
	prefix = prefix.Masked()
	ctl.routeMux.Lock()
	ctl.routeTable.Delete(prefix)
	ctl.routeMux.Unlock()

	if ctl.bpf.FilterMaps.RouteLpmMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.RouteLpmMap.Delete(bpf.ToFilterBpfLpmTrieKeyV4(prefix)); err != nil {
		slog.Error("delete ebpf cidr route failed", "cidr", prefix, "err", err)
	}
}
