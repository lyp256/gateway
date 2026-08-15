package controller

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/VictoriaMetrics/metrics"
	"github.com/gaissmai/bart"
	"github.com/go-chi/chi/v5"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/config"
	"github.com/lyp256/gateway/dao"

	"github.com/lyp256/gateway/dns/query"
	"github.com/lyp256/gateway/dns/router"
)

type Controller interface {
	dns.Handler
	http.Handler
	Run(ctx context.Context) error
	WaitReady(ctx context.Context) error
}

func NewController(storage *dao.Dao, e chi.Router, cfg config.Config) Controller {
	if e == nil {
		e = chi.NewRouter()
	}
	mux := &sync.RWMutex{}
	hosts := make(map[string]netip.Addr)

	c := controller{
		hostsMux:          mux,
		hosts:             hosts,
		dnsServers:        []query.DNSQuerier{query.NewStatic(hosts, mux.RLocker())},
		dnsCache:          newDNSCache(),
		http:              e,
		waitReadCh:        make(chan struct{}),
		storage:           storage,
		egressIndexByName: make(map[string]uint8),
	}
	c.applyConfig(cfg)
	c.initMetrics()
	c.registerHttpAPI()
	return &c
}

type controller struct {
	ctx    context.Context
	cancel context.CancelFunc
	// dns 本地解析 map 锁
	hostsMux *sync.RWMutex
	// 本地 dns map
	hosts map[string]netip.Addr
	// 上游dns 服务
	dnsServersMux sync.RWMutex
	dnsServers    []query.DNSQuerier
	// Recently resolved DNS responses, bounded by dnsCacheSize.
	dnsCache *lru.Cache[string, dnsCacheEntry]
	// ebpf 路由表
	routeTable bart.Table[uint8]
	// 保护 routeTable 的并发读写（DNS 解析与 IP 规则管理可能同时进行）
	routeMux sync.RWMutex
	// dns 路由表
	dnsTable router.Router
	// egress 运行时索引表：name -> 索引（0-255），与 route_lpm_map value / egress_map key 对应
	egressMux         sync.RWMutex
	egressIndexByName map[string]uint8
	egressRules       [bpf.MaxEgressRules]bpf.FilterEgressRule
	egressNextIndex   uint8
	// DNS 重定向目标（控制面配置，启动时同步到 dns_redirect_map）
	dnsRedirectTarget bpf.FilterDnsRedirectTarget
	// 源地址白名单（持久化在数据库，启动加载并同步到 src_whitelist_map，运行时可动态调整）
	whitelistMux    sync.RWMutex
	sourceWhitelist []netip.Prefix

	// 网卡
	netDevs []string

	//bpf 对象
	bpf bpf.FilterObjects

	// 数据库
	storage *dao.Dao

	// http router
	http chi.Router

	// metrics
	metricsSet *metrics.Set

	waitReadCh chan struct{}
	ready      bool
}

// applyConfig 把控制面配置转换成 BPF 运行时参数。
func (c *controller) applyConfig(cfg config.Config) {
	target, err := bpf.NewDnsRedirectTarget(netip.AddrFrom4([4]byte{127, 0, 0, 1}), cfg.DNSPort)
	if err != nil {
		slog.Error("invalid dns redirect target, dns interception disabled",
			"target", fmt.Sprintf("127.0.0.1:%d", cfg.DNSPort), "err", err)
		c.dnsRedirectTarget = bpf.DisabledDnsRedirectTarget()
	} else {
		c.dnsRedirectTarget = target
	}
}

func (ctl *controller) Run(ctx context.Context) error {
	ctl.ctx, ctl.cancel = context.WithCancel(ctx)
	defer ctl.cancel()
	if err := ctl.loadDNSServersFromStorage(); err != nil {
		return err
	}
	err := loadHostsFromStorage(ctl.storage, ctl.hosts)
	if err != nil {
		return err
	}
	if err := ctl.loadEgressRules(ctl.storage); err != nil {
		return err
	}
	routeMap := make(map[string]uint64)
	err = loadDomainRuleMapFromStorage(ctl.storage, routeMap, ctl.egressIndexByName)
	if err != nil {
		return err
	}
	ctl.dnsTable = router.NewMemoryMap(routeMap)
	err = loadCidrRuleMapFromStorage(&ctl.routeTable, ctl.storage, ctl.egressIndexByName)
	if err != nil {
		return err
	}
	if err := ctl.loadWhitelistFromStorage(); err != nil {
		return err
	}

	errCh := make(chan error)
	go func() {
		errCh <- ctl.bpfServer(ctl.ctx)
	}()
	ctl.ready = true
	close(ctl.waitReadCh)
	select {
	case <-ctl.ctx.Done():
		return ctl.ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (ctl *controller) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ctl.waitReadCh:
		if ctl.ready == true {
			return nil
		}
		return fmt.Errorf("server start failed")
	}
}
