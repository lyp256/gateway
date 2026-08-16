package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/schema"
	"github.com/vishvananda/netlink"
)

// errBPFNotReady 表示 eBPF 程序尚未加载完成，暂时不能管理挂载。
var errBPFNotReady = errors.New("eBPF 程序尚未就绪")

// listNics 枚举系统全部网卡，并标注 tc_gateway_filter 的实际挂载状态。
// 挂载状态以内核 filter 为准（即使网关重启后残留的旧挂载也能如实展示），
// 同时合并控制器自身记录的挂载集合，避免 filter 列表读取失败时误报未挂载。
func (ctl *controller) listNics() ([]schema.Nic, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("枚举网卡失败: %w", err)
	}

	ctl.nicMux.RLock()
	attached := make(map[string]struct{}, len(ctl.attachedNics))
	for name := range ctl.attachedNics {
		attached[name] = struct{}{}
	}
	autoMount := make(map[string]struct{}, len(ctl.autoMountNics))
	for name := range ctl.autoMountNics {
		autoMount[name] = struct{}{}
	}
	ctl.nicMux.RUnlock()

	nics := make([]schema.Nic, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		nic := schema.Nic{
			Index: attrs.Index,
			Name:  attrs.Name,
			Type:  link.Type(),
			MTU:   attrs.MTU,
			State: attrs.OperState.String(),
			Flags: linkFlags(attrs.Flags),
		}
		if len(attrs.HardwareAddr) > 0 {
			nic.MAC = attrs.HardwareAddr.String()
		}
		if addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL); err != nil {
			slog.Debug("list nic addresses", "iface", attrs.Name, "err", err)
		} else {
			for _, addr := range addrs {
				nic.Addresses = append(nic.Addresses, addr.IP.String())
			}
		}
		_, tracked := attached[attrs.Name]
		nic.Attached = tracked || linkHasEbpfProg(link, bpf.FilterProgTcGatewayFilter)
		_, nic.AutoMount = autoMount[attrs.Name]
		nics = append(nics, nic)
	}
	sort.Slice(nics, func(i, j int) bool { return nics[i].Index < nics[j].Index })
	return nics, nil
}

// getNic 返回指定网卡的完整信息。
func (ctl *controller) getNic(name string) (schema.Nic, error) {
	nics, err := ctl.listNics()
	if err != nil {
		return schema.Nic{}, err
	}
	for _, nic := range nics {
		if nic.Name == name {
			return nic, nil
		}
	}
	return schema.Nic{}, fmt.Errorf("网卡 %s 不存在", name)
}

// linkFlags 把 net.Flags 转成可读的链路标志列表。
func linkFlags(flags net.Flags) []string {
	var out []string
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		out = append(out, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "pointtopoint")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	if flags&net.FlagRunning != 0 {
		out = append(out, "running")
	}
	return out
}

// linkHasEbpfProg 检查网卡 ingress/egress 上是否已存在指定名称的 TC BPF filter。
// 网卡还没有 clsact qdisc 时 FilterList 会报错，此时按未挂载处理。
func linkHasEbpfProg(link netlink.Link, progName string) bool {
	return linkHasEbpfProgOn(link, netlink.HANDLE_MIN_INGRESS, progName) ||
		linkHasEbpfProgOn(link, netlink.HANDLE_MIN_EGRESS, progName)
}

// linkHasEbpfProgOn 检查网卡指定方向（ingress/egress）上是否存在指定名称的 TC BPF filter。
func linkHasEbpfProgOn(link netlink.Link, parent uint32, progName string) bool {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return false
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if ok && bf.Name == progName {
			return true
		}
	}
	return false
}

// attachNIC 把 tc_gateway_filter 挂载到指定网卡的 TC ingress。
// 已挂载时幂等返回；loopback 与尚未加载完成的场景直接报错。
func (ctl *controller) attachNIC(name string) error {
	ctl.nicMux.Lock()
	defer ctl.nicMux.Unlock()
	if !ctl.bpfReady {
		return errBPFNotReady
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	// loopback 没有 link kind，Type() 通常为空串，按 FlagLoopback 判定最可靠。
	if link.Attrs().Flags&net.FlagLoopback != 0 {
		return errLoopbackUnsupported
	}
	if linkHasEbpfProgOn(link, netlink.HANDLE_MIN_INGRESS, bpf.FilterProgTcGatewayFilter) {
		ctl.attachedNics[name] = struct{}{}
		return nil
	}
	if _, err := mountEbpfProg(link, ctl.bpf.TcGatewayFilter.FD()); err != nil {
		return err
	}
	ctl.attachedNics[name] = struct{}{}
	slog.Info("eBPF attached to nic", "iface", name, "prog", bpf.FilterProgTcGatewayFilter)
	return nil
}

// detachNIC 从指定网卡移除 tc_gateway_filter。
// 未挂载时幂等返回；只清理本网关创建的 filter，不影响其他程序。
func (ctl *controller) detachNIC(name string) error {
	ctl.nicMux.Lock()
	defer ctl.nicMux.Unlock()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := clearEbpfProgFromLink(link, bpf.FilterProgTcGatewayFilter); err != nil {
		return err
	}
	delete(ctl.attachedNics, name)
	slog.Info("eBPF detached from nic", "iface", name, "prog", bpf.FilterProgTcGatewayFilter)
	return nil
}

// detachAllNics 在数据面退出前解除全部挂载，保证重启后不残留旧 filter。
func (ctl *controller) detachAllNics() {
	ctl.nicMux.Lock()
	defer ctl.nicMux.Unlock()
	for name := range ctl.attachedNics {
		link, err := netlink.LinkByName(name)
		if err != nil {
			continue
		}
		if err := clearEbpfProgFromLink(link, bpf.FilterProgTcGatewayFilter); err != nil {
			slog.Error("detach ebpf on shutdown", "iface", name, "err", err)
		}
	}
	ctl.attachedNics = make(map[string]struct{})
}

// nicPath 是网卡操作 API 的路径参数。
type nicPath struct {
	Name string `path:"name" maxLength:"64" doc:"网卡名称"`
}

// getNics 返回系统网卡列表（支持通用的搜索/排序/分页）。
func (ctl *controller) getNics(ctx context.Context, in *listQuery) (*schema.ListOutput[schema.Nic], error) {
	nics, err := ctl.listNics()
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	items, total, page, perPage := queryList(nics, in.ListParams, listSpec[schema.Nic]{
		Searchable: func(nic schema.Nic) []string {
			fields := []string{nic.Name, nic.Type, nic.State, nic.MAC}
			return append(fields, nic.Addresses...)
		},
		Sortable: map[string]func(a, b schema.Nic) int{
			"index":    func(a, b schema.Nic) int { return cmpInt(a.Index, b.Index) },
			"name":     byString(func(nic schema.Nic) string { return nic.Name }),
			"type":     byString(func(nic schema.Nic) string { return nic.Type }),
			"state":    byString(func(nic schema.Nic) string { return nic.State }),
			"attached": func(a, b schema.Nic) int { return cmpBool(a.Attached, b.Attached) },
		},
		DefaultSort: "index",
	})
	return schema.NewListOutput(items, total, page, perPage), nil
}

// attachNic 把 eBPF 程序挂载到指定网卡。
func (ctl *controller) attachNic(ctx context.Context, in *nicPath) (*schema.Body[schema.Nic], error) {
	if err := ctl.attachNIC(in.Name); err != nil {
		return nil, nicError(err)
	}
	nic, err := ctl.getNic(in.Name)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(nic), nil
}

// detachNic 从指定网卡解除 eBPF 程序挂载。
func (ctl *controller) detachNic(ctx context.Context, in *nicPath) (*schema.Body[schema.Nic], error) {
	if err := ctl.detachNIC(in.Name); err != nil {
		return nil, nicError(err)
	}
	nic, err := ctl.getNic(in.Name)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(nic), nil
}

// nicAutoMountBody 是修改网卡“启动自动挂载”开关的请求体。
type nicAutoMountBody struct {
	AutoMount bool `json:"auto_mount" doc:"程序启动时自动挂载 eBPF 到该网卡"`
}

// setNicAutoMount 持久化并更新指定网卡的“启动自动挂载”开关。
func (ctl *controller) setNicAutoMount(ctx context.Context, in *struct {
	Name string `path:"name" maxLength:"64" doc:"网卡名称"`
	Body nicAutoMountBody
}) (*schema.Body[schema.Nic], error) {
	if err := ctl.setNicAutoMountRuntime(in.Name, in.Body.AutoMount); err != nil {
		return nil, nicError(err)
	}
	nic, err := ctl.getNic(in.Name)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "", err)
	}
	return schema.NewBody(nic), nil
}

// loadNicMountSettings 启动时把持久化的网卡自动挂载配置载入内存。
func (ctl *controller) loadNicMountSettings() error {
	if ctl.storage == nil {
		return nil
	}
	ctl.nicMux.Lock()
	defer ctl.nicMux.Unlock()

	enabled, err := ctl.storage.MountAllNicsEnabled()
	if err != nil {
		return err
	}
	ctl.mountAllNics = enabled
	ctl.autoMountNics = make(map[string]struct{})
	return ctl.storage.NicAutoMountIterator(func(name string) error {
		ctl.autoMountNics[name] = struct{}{}
		return nil
	})
}

// setNicAutoMountRuntime 校验网卡并把自动挂载开关同步到数据库与内存。
// loopback 不支持挂载，因此也禁止勾选自动挂载。
func (ctl *controller) setNicAutoMountRuntime(name string, enabled bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if link.Attrs().Flags&net.FlagLoopback != 0 {
		return errLoopbackUnsupported
	}
	if ctl.storage == nil {
		return errors.New("storage not available")
	}
	if err := ctl.storage.SetNicAutoMount(name, enabled); err != nil {
		return err
	}
	ctl.nicMux.Lock()
	if enabled {
		ctl.autoMountNics[name] = struct{}{}
	} else {
		delete(ctl.autoMountNics, name)
	}
	ctl.nicMux.Unlock()
	slog.Info("nic auto mount updated", "iface", name, "enabled", enabled)
	return nil
}

// getBPFSettings 返回 eBPF 网卡挂载的启动策略。
func (ctl *controller) getBPFSettings(ctx context.Context, in *struct{}) (*schema.Body[schema.BPFSettings], error) {
	ctl.nicMux.RLock()
	settings := schema.BPFSettings{MountAll: ctl.mountAllNics}
	ctl.nicMux.RUnlock()
	return schema.NewBody(settings), nil
}

// setBPFSettings 持久化并更新“启动时挂载全部可挂载网卡”全局开关。
func (ctl *controller) setBPFSettings(ctx context.Context, in *schema.Body[schema.BPFSettings]) (*schema.Body[schema.BPFSettings], error) {
	if ctl.storage == nil {
		return nil, huma.NewError(http.StatusInternalServerError, "storage not available", nil)
	}
	if err := ctl.storage.SetMountAllNics(in.Body.MountAll); err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, "save bpf settings", err)
	}
	ctl.nicMux.Lock()
	ctl.mountAllNics = in.Body.MountAll
	ctl.nicMux.Unlock()
	return schema.NewBody(in.Body), nil
}

// getBPFStatus 返回 eBPF 数据面就绪状态与当前挂载网卡数量。
func (ctl *controller) getBPFStatus(ctx context.Context, in *struct{}) (*schema.Body[schema.BPFStatus], error) {
	ctl.nicMux.RLock()
	status := schema.BPFStatus{
		Ready:      ctl.bpfReady,
		Program:    bpf.FilterProgTcGatewayFilter,
		Interfaces: len(ctl.attachedNics),
	}
	ctl.nicMux.RUnlock()
	return schema.NewBody(status), nil
}

// nicError 把网卡管理错误映射成合适的 HTTP 状态码。
func nicError(err error) error {
	if err == nil {
		return nil
	}
	var notFound netlink.LinkNotFoundError
	switch {
	case errors.As(err, &notFound):
		return huma.NewError(http.StatusNotFound, "网卡不存在", err)
	case errors.Is(err, errBPFNotReady):
		return huma.NewError(http.StatusServiceUnavailable, "eBPF 程序尚未就绪", err)
	case errors.Is(err, errLoopbackUnsupported):
		return huma.NewError(http.StatusBadRequest, "loopback 网卡不支持挂载 eBPF", err)
	default:
		return huma.NewError(http.StatusInternalServerError, "网卡操作失败", err)
	}
}

// errLoopbackUnsupported 表示 loopback 网卡不可挂载。
var errLoopbackUnsupported = errors.New("loopback 网卡不支持挂载 eBPF")
