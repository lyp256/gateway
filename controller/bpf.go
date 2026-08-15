package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	defer ctl.bpf.Close()

	// egress 规则先落到 egress_map，路由表里的索引才能被解析。
	ctl.syncEgressMapToBPF()
	// DNS 重定向目标与源地址白名单由控制面配置下发。
	ctl.syncDnsRedirectToBPF()
	ctl.syncWhitelistToBPF()

	if len(ctl.netDevs) == 0 {
		iface, err := getDefaultGatewayInterface()
		if err != nil {
			return err
		}
		clear, err := mountEbpfProg(iface, ctl.bpf.TcGatewayFilter.FD())
		if err != nil {
			return err
		}
		defer clear()
	} else {
		for _, name := range ctl.netDevs {
			iface, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			clear, err := mountEbpfProg(iface, ctl.bpf.TcGatewayFilter.FD())
			if err != nil {
				return err
			}
			defer clear()
		}
	}

	// 将持久化的显式 IP/CIDR 规则同步到 eBPF LPM map
	ctl.syncRoutesToBPF()

	return ctl.handleEvent(ctx)
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

	for _, l := range links {
		// 跳过 lo 等
		if l.Type() == "lo" {
			continue
		}

		// 同时清理 ingress 与 egress，兼容升级前遗留的挂载。
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := netlink.FilterList(l, parent)
			if err != nil {
				slog.Error("list net filter", "err", err)
				continue
			}

			for _, f := range filters {
				bf, ok := f.(*netlink.BpfFilter)
				if !ok || bf.Id == 0 {
					continue
				}

				if bf.Name == progName {
					err = netlink.FilterDel(f)
					if err != nil {
						slog.Error("delete filter", "err", err)
					}
				}
			}
		}
	}
	return nil
}
