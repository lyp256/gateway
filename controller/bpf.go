package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lyp256/gateway/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (ctl *controller) bpfServer(ctx context.Context) error {
	err := clearEbpfProgByName(bpf.FilterProgTcGatewayFilter)
	if err != nil {
		return err
	}

	// 移除 Linux 内核对 eBPF 锁定内存的默认限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("移除内存锁限制失败:%w", err)
	}

	// 加载编译好的 BPF 资源
	if err := bpf.LoadFilterObjects(&ctl.bpf, nil); err != nil {
		return fmt.Errorf("加载 eBPF 编译对象失败:%w", err)
	}

	// 数据面就绪后开放网卡挂载管理；退出时先解除全部挂载再释放对象，
	// 避免 HTTP 管理接口在对象关闭后拿到已失效的 FD。
	ctl.nicMux.Lock()
	ctl.bpfReady = true
	ctl.nicMux.Unlock()
	defer func() {
		ctl.nicMux.Lock()
		ctl.bpfReady = false
		ctl.nicMux.Unlock()
		removeTproxyRouting()
		ctl.detachAllNics()
		ctl.bpf.Close()
	}()

	// egress 规则先落到 egress_map，路由表里的索引才能被解析。
	ctl.syncEgressMapToBPF()
	// DNS 重定向目标与源地址白名单由控制面配置下发。
	ctl.syncDnsRedirectToBPF()
	ctl.syncWhitelistToBPF()

	// 启动时按自动挂载配置挂载初始网卡；未勾选任何网卡时退化为默认路由网卡。
	mode, initial, strict, err := ctl.initialAttachTargets()
	if err != nil {
		return err
	}
	for _, name := range initial {
		if err := ctl.attachNIC(name); err != nil {
			// 默认路由回退保持原有的严格语义：挂载失败直接中止启动；
			// 自动挂载与全部挂载场景跳过失败项，尽量挂载“能挂载”的网卡。
			if strict {
				return err
			}
			slog.Error("skip ebpf attach at startup", "iface", name, "err", err)
		}
	}
	slog.Info("initial ebpf attach done", "mode", mode.String(), "targets", len(initial))

	// 将持久化的显式 IP/CIDR 规则同步到 eBPF LPM map
	ctl.syncRoutesToBPF()

	// DNS 透明代理策略路由：把带 DNS mark 的查询导向本地投递。
	if err := ensureDnsTproxyRouting(); err != nil {
		return err
	}
	if err := ensureTcpTproxyRouting(); err != nil {
		return err
	}

	return ctl.handleEvent(ctx)
}

// initialAttachMode 表示启动自动挂载的目标来源。
type initialAttachMode int

const (
	// initialAttachDefaultRoute 回退到默认路由网卡，挂载失败时中止启动。
	initialAttachDefaultRoute initialAttachMode = iota
	// initialAttachSelected 挂载勾选了自动挂载的网卡。
	initialAttachSelected
	// initialAttachAll 挂载全部可挂载网卡。
	initialAttachAll
)

func (m initialAttachMode) String() string {
	switch m {
	case initialAttachDefaultRoute:
		return "default-route"
	case initialAttachSelected:
		return "selected"
	case initialAttachAll:
		return "all"
	default:
		return "unknown"
	}
}

// initialAttachTargets 返回启动时需要自动挂载 eBPF 的网卡列表：
// 全局“全部挂载”开启时枚举全部可挂载网卡；否则使用勾选了自动挂载的网卡
// （只保留当前存在且非 loopback 的）；两者都没有有效目标时回退到默认路由网卡。
// strict 为 true 表示该来源挂载失败时应中止启动（仅默认路由回退场景）。
func (ctl *controller) initialAttachTargets() (mode initialAttachMode, targets []string, strict bool, err error) {
	ctl.nicMux.RLock()
	mountAll := ctl.mountAllNics
	autoMount := make([]string, 0, len(ctl.autoMountNics))
	for name := range ctl.autoMountNics {
		autoMount = append(autoMount, name)
	}
	ctl.nicMux.RUnlock()

	if mountAll {
		nics, err := ctl.mountableNics(nil)
		if err != nil {
			return initialAttachAll, nil, false, err
		}
		return initialAttachAll, nics, false, nil
	}

	if len(autoMount) > 0 {
		nics, err := ctl.mountableNics(autoMount)
		if err != nil {
			return initialAttachSelected, nil, false, err
		}
		if len(nics) > 0 {
			return initialAttachSelected, nics, false, nil
		}
		// 勾选的网卡当前都不存在或不可挂载时，退化到默认路由网卡。
	}

	iface, err := getDefaultGatewayInterface()
	if err != nil {
		return initialAttachDefaultRoute, nil, false, err
	}
	return initialAttachDefaultRoute, []string{iface.Attrs().Name}, true, nil
}

// mountableNics 返回按网卡索引升序排列、可挂载 eBPF 的网卡名称。
// names 为空时枚举全部网卡；否则只保留 names 中当前存在且非 loopback 的网卡。
func (ctl *controller) mountableNics(names []string) ([]string, error) {
	nics, err := ctl.listNics()
	if err != nil {
		return nil, err
	}
	var wanted map[string]struct{}
	if names != nil {
		wanted = make(map[string]struct{}, len(names))
		for _, name := range names {
			wanted[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(nics))
	for _, nic := range nics {
		if containsFlag(nic.Flags, "loopback") {
			continue
		}
		if wanted != nil {
			if _, ok := wanted[nic.Name]; !ok {
				continue
			}
		}
		out = append(out, nic.Name)
	}
	return out, nil
}

// containsFlag 判断网卡标志列表是否包含指定标志。
func containsFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

// syncDnsRedirectToBPF 把配置的 DNS 重定向目标写入 dns_redirect_map。
func (ctl *controller) syncDnsRedirectToBPF() {
	if ctl.bpf.FilterMaps.DnsRedirectMap == nil {
		return
	}
	if err := ctl.bpf.FilterMaps.DnsRedirectMap.Put(uint32(bpf.DnsRedirectMapKey), ctl.dnsRedirectTarget); err != nil {
		slog.Error("sync dns redirect target to ebpf failed", "err", err)
		return
	}
	slog.Info("dns redirect target synced", "enabled", ctl.dnsRedirectTarget.Enabled != 0)
}

// syncWhitelistToBPF 把配置的源地址白名单全量同步到 src_whitelist_map，
// 未配置任何前缀时清空 map，即所有流量都不做 ingress 后续处理、直接放行。
func (ctl *controller) syncWhitelistToBPF() {
	if ctl.bpf.FilterMaps.SrcWhitelistMap == nil {
		return
	}
	// 先清空旧条目，保证全量下发语义。
	var key, nextKey bpf.FilterBpfLpmTrieKeyV4
	for ctl.bpf.FilterMaps.SrcWhitelistMap.NextKey(&key, &nextKey) == nil {
		if err := ctl.bpf.FilterMaps.SrcWhitelistMap.Delete(&nextKey); err != nil {
			slog.Error("clear ebpf whitelist entry failed", "err", err)
		}
		key = nextKey
	}
	ctl.whitelistMux.RLock()
	whitelist := make([]netip.Prefix, len(ctl.sourceWhitelist))
	copy(whitelist, ctl.sourceWhitelist)
	ctl.whitelistMux.RUnlock()
	for _, prefix := range whitelist {
		if !prefix.Addr().Is4() {
			slog.Warn("skip non-IPv4 source whitelist prefix", "prefix", prefix.String())
			continue
		}
		if err := ctl.bpf.FilterMaps.SrcWhitelistMap.Put(bpf.ToFilterBpfLpmTrieKeyV4(prefix), uint8(1)); err != nil {
			slog.Error("sync source whitelist entry failed", "prefix", prefix.String(), "err", err)
		}
	}
	slog.Info("source whitelist synced", "count", len(whitelist))
}

func (ctl *controller) handleEvent(ctx context.Context) error {
	rd, err := ringbuf.NewReader(ctl.bpf.EventsRingbuf)
	if err != nil {
		slog.Error("创建 RingBuffer 监听器失败: ", "err", err)
		return err
	}
	defer rd.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return err
			}
			slog.Error("read ringbuf failed", "err", err)
			continue
		}

		if len(record.RawSample) == 0 {
			continue
		}

		switch record.RawSample[0] {
		case bpf.EventTcpStream:
			var conn bpf.TcpStream
			err = bpf.ParseTcpStream(record.RawSample[1:], &conn)
			if err != nil {
				slog.Error("tcp stream event", "err", err)
				continue
			}
			slog.Info("tcp stream event",
				"src", conn.Src.String(),
				"dest", conn.Dest.String(),
				"mark", conn.Mark,
				"egress_index", conn.EgressIdx,
				"egress_type", bpf.EgressRuleTypeString(conn.EgressType),
			)
		}
	}
}

func getDefaultGatewayInterface() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("无法获取路由列表: %v", err)
	}

	// 2. 遍历路由表，寻找默认路由 (Dst 为 nil 或 0.0.0.0/0)
	for _, route := range routes {
		// 默认路由的特点：Dst (目的地址) 为 nil，且 Gateway (网关) 不为 nil
		if defaultRoute(&route) {
			// LinkIndex 是该路由关联的网卡索引
			if route.LinkIndex <= 0 {
				continue
			}
			// 3. 根据网卡索引获取网卡完整信息
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return nil, fmt.Errorf("无法根据索引 %d 找到网卡: %v", route.LinkIndex, err)
			}
			// 找到了默认路由的网卡
			return link, nil
		}
	}
	return nil, fmt.Errorf("未找到默认路由网卡")
}

func defaultRoute(route *netlink.Route) bool {
	if route.Dst == nil && route.Gw != nil {
		return true
	}
	if ones, _ := route.Dst.Mask.Size(); ones == 0 {
		return true
	}
	return false
}

func mountEbpfProg(link netlink.Link, fd int) (func() error, error) {
	// 相当于执行: tc qdisc add dev eth0 clsact
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("link: %s 创建 clsact qdisc 失败:%w", link.Attrs().Name, err)
	}

	// 相当于执行: tc filter add dev eth0 ingress bpf fd <fd> da
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  1,
			Protocol:  unix.ETH_P_IP, // 处理 IP 协议流量
		},
		Fd:           fd,
		Name:         bpf.FilterProgTcGatewayFilter,
		DirectAction: true, // 必须开启 DirectAction
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("link: %s 挂载 eBPF 过滤器到 TC 失败:%w", link.Attrs().Name, err)
	}

	return func() error {
		return netlink.FilterDel(filter)
	}, nil
}

func clearEbpfProgByName(progName string) error {
	// 获取所有网络接口
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}

	var errs []error
	for _, l := range links {
		// loopback 上不会有本网关的挂载，跳过以加快清理。
		if l.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}
		if err := clearEbpfProgFromLink(l, progName); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// clearEbpfProgFromLink 从单个网卡的 ingress/egress 上移除指定名称的 TC BPF filter，
// 同时清理 ingress 与 egress，兼容升级前遗留的挂载；网卡无 clsact qdisc 时视为无需清理。
func clearEbpfProgFromLink(link netlink.Link, progName string) error {
	var errs []error
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			continue
		}
		for _, f := range filters {
			bf, ok := f.(*netlink.BpfFilter)
			if !ok || bf.Id == 0 || bf.Name != progName {
				continue
			}
			if err := netlink.FilterDel(f); err != nil {
				errs = append(errs, fmt.Errorf("link %s 删除 filter %s 失败:%w", link.Attrs().Name, progName, err))
			}
		}
	}
	return errors.Join(errs...)
}

// dnsTproxyRuleTable 是 DNS 透明代理使用的策略路由表，与脚本 scripts/dns-proxy-up.sh 一致。
// eBPF 在 DNS 重定向成功时为 skb 打上 bpf.DnsTproxyFwmark，
// 该表内的 local 路由把目的地址非本机的查询导向本地投递（TPROXY 标准做法）。
const dnsTproxyRuleTable = 100

// tcpTproxyRuleTable 与 DNS 透明代理表分离，避免不同透明代理流量共享 mark。
const tcpTproxyRuleTable = 101

// ensureDnsTproxyRouting 安装 DNS 透明代理所需的 fwmark 策略路由规则与 local 路由。
// 幂等：已存在时跳过，避免重复添加。
func ensureDnsTproxyRouting() error {
	return ensureTproxyRouting(bpf.DnsTproxyFwmark, dnsTproxyRuleTable, "dns")
}

// ensureTcpTproxyRouting 安装 TCP egress tproxy 所需的本地投递路由。
func ensureTcpTproxyRouting() error {
	return ensureTproxyRouting(bpf.TcpTproxyFwmark, tcpTproxyRuleTable, "tcp")
}

func ensureTproxyRouting(mark uint32, table int, kind string) error {
	// ip rule add fwmark <mark> lookup <table>
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list ip rules: %w", err)
	}
	foundRule := false
	for _, r := range rules {
		if r.Family == unix.AF_INET && r.Mark == mark && r.Table == table {
			foundRule = true
			break
		}
	}
	if !foundRule {
		rule := netlink.NewRule()
		rule.Family = unix.AF_INET
		rule.Mark = mark
		fullMask := uint32(0xffffffff)
		rule.Mask = &fullMask
		rule.Table = table
		if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add %s tproxy ip rule: %w", kind, err)
		}
		slog.Info("tproxy ip rule installed", "kind", kind, "mark", mark, "table", table)
	}

	// ip route add local 0.0.0.0/0 dev lo table <table>
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup lo: %w", err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list %s tproxy routes: %w", kind, err)
	}
	foundRoute := false
	for _, rt := range routes {
		if rt.LinkIndex == lo.Attrs().Index && rt.Type == unix.RTN_LOCAL && isDefaultV4Route(rt.Dst) {
			foundRoute = true
			break
		}
	}
	if !foundRoute {
		route := &netlink.Route{
			LinkIndex: lo.Attrs().Index,
			Table:     table,
			Type:      unix.RTN_LOCAL,
			Scope:     netlink.SCOPE_HOST,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add %s tproxy local route: %w", kind, err)
		}
		slog.Info("tproxy local route installed", "kind", kind, "table", table)
	}
	return nil
}

func isDefaultV4Route(ipNet *net.IPNet) bool {
	if ipNet == nil {
		return true
	}
	ones, bits := ipNet.Mask.Size()
	return bits == 32 && ones == 0
}

// removeTproxyRouting 清理 DNS 和 TCP 透明代理安装的规则与路由，服务退出时调用。
func removeTproxyRouting() {
	removeTproxyRoutingFor(bpf.DnsTproxyFwmark, dnsTproxyRuleTable)
	removeTproxyRoutingFor(bpf.TcpTproxyFwmark, tcpTproxyRuleTable)
}

func removeTproxyRoutingFor(mark uint32, table int) {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err == nil {
		for _, r := range rules {
			if r.Family == unix.AF_INET && r.Mark == mark && r.Table == table {
				if err := netlink.RuleDel(&r); err != nil && !errors.Is(err, unix.ENOENT) {
					slog.Error("remove dns tproxy ip rule", "err", err)
				}
			}
		}
	} else {
		slog.Error("list ip rules for cleanup", "err", err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		slog.Error("list dns tproxy routes for cleanup", "err", err)
		return
	}
	for _, rt := range routes {
		if rt.LinkIndex == lo.Attrs().Index && rt.Type == unix.RTN_LOCAL && isDefaultV4Route(rt.Dst) {
			if err := netlink.RouteDel(&rt); err != nil && !errors.Is(err, unix.ENOENT) {
				slog.Error("remove dns tproxy local route", "err", err)
			}
		}
	}
}
