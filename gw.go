package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lyp256/gw/bpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// 替换为你需要监听的网卡名称（WSL2 默认一般是 eth0）
const targetInterface = "eth0"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 1. 移除 Linux 内核对 eBPF 锁定内存的默认限制
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("移除内存锁限制失败", "err", err)
		os.Exit(1)
	}

	// 2. 加载编译好的 BPF 资源
	objs := bpf.FilterObjects{}
	if err := bpf.LoadFilterObjects(&objs, nil); err != nil {
		slog.Error("加载 eBPF 编译对象失败", "err", err)
		os.Exit(1)
	}
	defer objs.Close()

	slog.Info("eBPF 核心组件加载成功！")

	slog.Info("正在挂载 eBPF 程序到网卡...", "dev", targetInterface)
	link, err := netlink.LinkByName(targetInterface)
	if err != nil {
		slog.Error("获取网卡失败", "dev", targetInterface, "err", err)
		os.Exit(1)
	}

	// 2.1 确保 clsact qdisc 存在
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
		slog.Error("创建 clsact qdisc 失败", "err", err)
		os.Exit(1)
	}

	// 2.2 挂载 BPF Filter 到 egress 方向
	// 相当于执行: tc filter add dev eth0 egress bpf fd <fd> da
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS, // 根据你的日志，挂载到 egress 钩子
			Priority:  1,
			Protocol:  unix.ETH_P_ALL, // 拦截所有协议流量
		},
		Fd:           objs.TcGatewayFilter.FD(),
		Name:         bpf.FilterProgTcGatewayFilter,
		DirectAction: true, // 必须开启 DirectAction
	}
	if err := netlink.FilterAdd(filter); err != nil {
		slog.Error("挂载 eBPF 过滤器到 TC 失败", "err", err)
		os.Exit(1)
	}
	slog.Info("eBPF 程序已成功挂载到 TC egress 钩子！")

	// 程序退出时，自动清理 TC Filter 卸载程序
	defer func() {
		slog.Info("正在清理并卸载 TC 过滤器...")
		if err := netlink.FilterDel(filter); err != nil {
			slog.Error("清理 TC 过滤器失败", "err", err)
		}
	}()

	// 3. 开启协程监听内核 Ring Buffer 事件
	go func() {
		rd, err := ringbuf.NewReader(objs.EventsRingbuf)
		if err != nil {
			log.Fatalf("创建 RingBuffer 监听器失败: %v", err)
		}
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("读取内核数据失败: %v", err)
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
				slog.Info("tcp stream event", "src", conn.Src, "dest", conn.Dest)
			}
		}
	}()

	// 5. 优雅退出信号处理
	<-ctx.Done()
	log.Println("网关服务正在退出...")
}
