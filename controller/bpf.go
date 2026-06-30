package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	return ctl.handleEvent(ctx)
}

func (ctl *controller) handleEvent(ctx context.Context) error {
	rd, err := ringbuf.NewReader(ctl.bpf.EventsRingbuf)
	if err != nil {
		slog.Error("创建 RingBuffer 监听器失败: ", "err", err)
		return err
	}
	defer rd.Close()

	for {
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
			slog.Info("tcp stream event", "src", conn.Src.String(), "dest", conn.Dest.String(), "mark", conn.Mark)
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

	// 相当于执行: tc filter add dev eth0 egress bpf fd <fd> da
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  1,
			Protocol:  unix.ETH_P_IP, // 拦截 IP 协议流量
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

		filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			slog.Error("list net filter", "err", err)
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
	return nil
}
