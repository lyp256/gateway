package controller

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/dao"
)

// loadEgressRules 启动时枚举持久化 egress，按存储顺序分配运行时索引，
// 并构建 egress_map 的内存镜像。索引只在本进程内有效，删除的索引运行期不复用。
func (ctl *controller) loadEgressRules(db *dao.Dao) error {
	ctl.egressMux.Lock()
	defer ctl.egressMux.Unlock()

	ctl.egressIndexByName = make(map[string]uint8)
	ctl.egressRules = [bpf.MaxEgressRules]bpf.FilterEgressRule{}
	ctl.egressNextIndex = 0

	return db.EgressIterator(func(egress dao.Egress) error {
		idx, err := ctl.allocEgressIndexLocked()
		if err != nil {
			return err
		}
		rule, err := toFilterEgressRule(egress)
		if err != nil {
			return err
		}
		ctl.egressIndexByName[egress.Name] = idx
		ctl.egressRules[idx] = rule
		return nil
	})
}

// addEgress 为新建 egress 分配索引并同步 egress_map。
func (ctl *controller) addEgress(egress dao.Egress) error {
	ctl.egressMux.Lock()
	if _, ok := ctl.egressIndexByName[egress.Name]; ok {
		ctl.egressMux.Unlock()
		return fmt.Errorf("egress %q already indexed", egress.Name)
	}
	idx, err := ctl.allocEgressIndexLocked()
	if err != nil {
		ctl.egressMux.Unlock()
		return err
	}
	rule, err := toFilterEgressRule(egress)
	if err != nil {
		ctl.egressMux.Unlock()
		return err
	}
	ctl.egressIndexByName[egress.Name] = idx
	ctl.egressRules[idx] = rule
	ctl.egressMux.Unlock()

	ctl.putEgressRule(idx, rule)
	return nil
}

// syncEgressRule 更新 egress 规则并同步 egress_map。规则引用的路由仍指向同一索引，
// 因此 fwmark/tproxy 行为变更对所有引用规则即时生效。
func (ctl *controller) syncEgressRule(egress dao.Egress) error {
	ctl.egressMux.Lock()
	idx, ok := ctl.egressIndexByName[egress.Name]
	if !ok {
		ctl.egressMux.Unlock()
		return fmt.Errorf("egress %q not indexed", egress.Name)
	}
	rule, err := toFilterEgressRule(egress)
	if err != nil {
		ctl.egressMux.Unlock()
		return err
	}
	ctl.egressRules[idx] = rule
	ctl.egressMux.Unlock()

	ctl.putEgressRule(idx, rule)
	return nil
}

// dropEgress 释放 egress 索引并清空 egress_map 槽位。
func (ctl *controller) dropEgress(name string) {
	ctl.egressMux.Lock()
	idx, ok := ctl.egressIndexByName[name]
	if !ok {
		ctl.egressMux.Unlock()
		return
	}
	delete(ctl.egressIndexByName, name)
	ctl.egressRules[idx] = bpf.FilterEgressRule{}
	ctl.egressMux.Unlock()

	ctl.putEgressRule(idx, bpf.FilterEgressRule{})
}

// egressIndex 返回 egress 对应的运行时索引。
func (ctl *controller) egressIndex(name string) (uint8, bool) {
	ctl.egressMux.RLock()
	defer ctl.egressMux.RUnlock()
	idx, ok := ctl.egressIndexByName[name]
	return idx, ok
}

// allocEgressIndexLocked 分配下一个可用索引；调用方必须持有 egressMux。
func (ctl *controller) allocEgressIndexLocked() (uint8, error) {
	if int(ctl.egressNextIndex) >= bpf.MaxEgressRules {
		return 0, fmt.Errorf("too many egress rules, max %d", bpf.MaxEgressRules)
	}
	idx := ctl.egressNextIndex
	ctl.egressNextIndex++
	return idx, nil
}

// toFilterEgressRule 把持久化 egress 转换为内核 egress_map 中的规则。
// manual/http_tunnel 都按原 fwmark 模式处理；tproxy 走 bpf_sk_assign。
func toFilterEgressRule(egress dao.Egress) (bpf.FilterEgressRule, error) {
	switch egress.Type {
	case dao.EgressTproxy:
		var addr netip.Addr
		if egress.Tproxy != nil && egress.Tproxy.Addr != "" && egress.Tproxy.Addr != "0.0.0.0" {
			parsed, err := netip.ParseAddr(egress.Tproxy.Addr)
			if err != nil || !parsed.Is4() {
				return bpf.FilterEgressRule{}, fmt.Errorf("invalid tproxy addr %q", egress.Tproxy.Addr)
			}
			addr = parsed
		}
		var port uint16
		if egress.Tproxy != nil {
			port = egress.Tproxy.Port
		}
		return bpf.NewTproxyEgressRule(addr, port)
	default:
		return bpf.NewFwmarkEgressRule(egress.FwMark), nil
	}
}

// putEgressRule 更新 BPF egress_map 中的单个槽位；BPF 未加载时跳过。
func (ctl *controller) putEgressRule(idx uint8, rule bpf.FilterEgressRule) {
	if ctl.bpf.FilterMaps.EgressMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.EgressMap.Put(uint32(idx), rule); err != nil {
		slog.Error("update ebpf egress rule failed", "index", idx, "err", err)
	}
}

// syncEgressMapToBPF 在 BPF 对象加载后把全部 egress 规则一次性写入 egress_map。
func (ctl *controller) syncEgressMapToBPF() {
	if ctl.bpf.FilterMaps.EgressMap == nil {
		return
	}
	ctl.egressMux.RLock()
	defer ctl.egressMux.RUnlock()
	for i, rule := range ctl.egressRules {
		if err := ctl.bpf.FilterMaps.EgressMap.Put(uint32(i), rule); err != nil {
			slog.Error("sync ebpf egress rule failed", "index", i, "err", err)
		}
	}
}
