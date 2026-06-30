package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/VictoriaMetrics/metrics"
	"github.com/gaissmai/bart"
	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/dao"

	"github.com/lyp256/gateway/dns/query"
	"github.com/lyp256/gateway/dns/router"
)

type Controller interface {
	dns.Handler
	http.Handler
	Run(ctx context.Context) error
	WaitRead(ctx context.Context) error
}

func NewController(storage *dao.Dao, dnsServers []query.DNSQuerier, e chi.Router) Controller {
	if e == nil {
		e = chi.NewRouter()
	}
	mux := &sync.RWMutex{}
	hosts := make(map[string]netip.Addr)

	dnsServers = append([]query.DNSQuerier{query.NewStatic(hosts, mux.RLocker())}, dnsServers...)
	c := controller{
		hostsMux:   mux,
		hosts:      hosts,
		dnsServers: dnsServers,
		http:       e,
		waitReadCh: make(chan struct{}),
		storage:    storage,
	}
	c.initMetrics()
	c.registerHttpAPI()
	return &c
}

type controller struct {
	// dns 本地解析 map 锁
	hostsMux *sync.RWMutex
	// 本地 dns map
	hosts map[string]netip.Addr
	// 上游dns 服务
	dnsServers []query.DNSQuerier
	// ebpf 路由表
	routeTable bart.Table[uint32]
	// dns 路由表
	dnsTable router.Router

	// 网卡
	netDevs []string

	//bpf 对象
	bpf bpf.FilterObjects

	// 数据库
	storage *dao.Dao

	// http router
	http chi.Router

	// metrics
	metricsSet      *metrics.Set
	dnsQueryTotal   *metrics.Counter
	dnsQuerySucceed *metrics.Counter
	dnsQueryFailed  *metrics.Counter

	waitReadCh chan struct{}
	ready      bool
}

type dnsEvent struct {
	name string
	ip   netip.Addr
}

func (ctl *controller) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	err := loadHostsFromStorage(ctl.storage, ctl.hosts)
	if err != nil {
		return err
	}

	routeMap := make(map[string]uint64)
	ctl.dnsTable = router.NewMemoryMap(routeMap, &sync.Mutex{})
	err = loadDomainRuleMapFromStorage(ctl.storage, routeMap)
	if err != nil {
		return err
	}
	errCh := make(chan error)
	go func() {
		errCh <- ctl.bpfServer(ctx)
	}()
	ctl.ready = true
	close(ctl.waitReadCh)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (ctl *controller) WaitRead(ctx context.Context) error {
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
