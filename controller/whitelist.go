package controller

import (
	"log/slog"
	"net/netip"

	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/dao"
)

// loadWhitelistFromStorage 启动时把持久化的源地址白名单载入内存，
// 之后由 bpfServer 一次性全量同步到 src_whitelist_map。
func (ctl *controller) loadWhitelistFromStorage() error {
	if ctl.storage == nil {
		return nil
	}
	ctl.whitelistMux.Lock()
	defer ctl.whitelistMux.Unlock()
	ctl.sourceWhitelist = ctl.sourceWhitelist[:0]
	return ctl.storage.WhitelistIterator(func(rule dao.WhitelistRule) error {
		prefix, err := dao.NormalizeWhitelist(rule.Cidr)
		if err != nil {
			slog.Error("invalid whitelist entry, skip", "cidr", rule.Cidr, "err", err)
			return nil
		}
		ctl.sourceWhitelist = append(ctl.sourceWhitelist, prefix)
		return nil
	})
}

// setWhitelist 新增/更新一条源地址白名单并增量同步 BPF map。
func (ctl *controller) setWhitelist(prefix netip.Prefix) {
	prefix = prefix.Masked()
	ctl.whitelistMux.Lock()
	for _, p := range ctl.sourceWhitelist {
		if p == prefix {
			ctl.whitelistMux.Unlock()
			return
		}
	}
	ctl.sourceWhitelist = append(ctl.sourceWhitelist, prefix)
	ctl.whitelistMux.Unlock()

	if ctl.bpf.FilterMaps.SrcWhitelistMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.SrcWhitelistMap.Put(bpf.ToFilterBpfLpmTrieKeyV4(prefix), uint8(1)); err != nil {
		slog.Error("update ebpf whitelist failed", "cidr", prefix.String(), "err", err)
	}
}

// deleteWhitelist 删除一条源地址白名单并增量同步 BPF map。
func (ctl *controller) deleteWhitelist(prefix netip.Prefix) {
	prefix = prefix.Masked()
	ctl.whitelistMux.Lock()
	for i, p := range ctl.sourceWhitelist {
		if p == prefix {
			ctl.sourceWhitelist = append(ctl.sourceWhitelist[:i], ctl.sourceWhitelist[i+1:]...)
			break
		}
	}
	ctl.whitelistMux.Unlock()

	if ctl.bpf.FilterMaps.SrcWhitelistMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.SrcWhitelistMap.Delete(bpf.ToFilterBpfLpmTrieKeyV4(prefix)); err != nil {
		slog.Error("delete ebpf whitelist failed", "cidr", prefix.String(), "err", err)
	}
}
