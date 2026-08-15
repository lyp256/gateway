package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"codeberg.org/miekg/dns"
	"github.com/go-chi/chi/v5"
	"github.com/lyp256/gateway/config"
	"github.com/lyp256/gateway/controller"
	"github.com/lyp256/gateway/dao"
	"go.etcd.io/bbolt"
)

type Server struct {
	c        controller.Controller
	storage  *bbolt.DB
	dnsPort  uint16
	httpPort uint16
}

func NewServer(cfg config.Config) (*Server, error) {
	storageDir := cfg.DBStorage
	if storageDir == "" {
		storageDir = "db"
	}
	if err := os.MkdirAll(storageDir, 0o700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}
	storage, err := bbolt.Open(filepath.Join(storageDir, "gateway.db"), 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("create db failed:%w", err)
	}
	if err := storage.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("gateway"))
		return err
	}); err != nil {
		_ = storage.Close()
		return nil, fmt.Errorf("initialize db failed: %w", err)
	}

	d := dao.New(storage)
	if err := seedDNSServers(d, cfg.DNSServers); err != nil {
		_ = storage.Close()
		return nil, fmt.Errorf("seed dns servers failed: %w", err)
	}

	ctl := controller.NewController(d, chi.NewRouter(), cfg)
	return &Server{
		c:        ctl,
		storage:  storage,
		dnsPort:  cfg.DNSPort,
		httpPort: cfg.HTTPPort,
	}, nil
}

// seedDNSServers 首次启动时把 config 中的上游 DNS 默认值写入数据库，
// 之后运行期以数据库/页面配置为准，config 不再参与。
// 通过 meta 标记区分“尚未初始化”和“用户已清空全部上游”，避免重启时重复回填。
func seedDNSServers(d *dao.Dao, servers []config.DNSServer) error {
	initialized, err := d.DNSServersInitialized()
	if err != nil {
		return err
	}
	if initialized {
		return nil
	}
	taken := map[string]bool{}
	for i, s := range servers {
		item := dao.DNSServer{
			Type:     s.Type,
			Server:   s.Server,
			IP:       s.IP,
			Insecure: s.Insecure,
		}
		item.Name = seedDNSServerName(s, i, taken)
		if err := d.SetDNSServer(item); err != nil {
			return err
		}
	}
	return d.MarkDNSServersInitialized()
}

// seedDNSServerName 为 config 默认上游生成稳定的存储名称：
// 优先用域名，其次 IP，最后 dns-序号；重名时追加 -2、-3 后缀。
func seedDNSServerName(s config.DNSServer, idx int, taken map[string]bool) string {
	base := s.Server
	if base == "" && s.IP.IsValid() {
		base = s.IP.String()
	}
	if base == "" {
		base = fmt.Sprintf("dns-%d", idx+1)
	}
	name := base
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	taken[name] = true
	return name
}

func (s *Server) Run(ctx context.Context) error {
	defer s.storage.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dnsSrv := &dns.Server{
		Net:     "udp",
		Addr:    net.JoinHostPort("", strconv.Itoa(int(s.dnsPort))),
		Handler: s.c,
	}

	httpSrv := http.Server{
		Handler: s.c, Addr: net.JoinHostPort("",
			strconv.Itoa(int(s.httpPort))),
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	errsCh := make(chan []error, 1)
	errsCh <- make([]error, 0, 3)

	go func() {
		defer wg.Done()
		defer cancel()
		slog.Debug("ebpf server start")
		err := s.c.Run(ctx)
		slog.Debug("ebpf server stopped", "err", err)
		if err != nil {
			errs := <-errsCh
			errs = append(errs, err)
			errsCh <- errs
		}
	}()

	if err := s.c.WaitReady(ctx); err != nil {
		return errors.Join(<-errsCh...)
	}

	go func() {
		defer wg.Done()
		defer cancel()
		slog.Debug("dns server start")
		err := dnsSrv.ListenAndServe()

		slog.Debug("dns server stopped", "err", err)
		if err != nil {
			errs := <-errsCh
			errs = append(errs, err)
			errsCh <- errs

		}
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		slog.Debug("http server start")
		err := httpSrv.ListenAndServe()
		slog.Debug("http server stopped", "err", err)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs := <-errsCh
			errs = append(errs, err)
			errsCh <- errs
		}
	}()

	go func() {
		<-ctx.Done()
		slog.Debug("context done server stop", "err", ctx.Err())
		err := httpSrv.Shutdown(context.TODO())
		if err != nil {
			errs := <-errsCh
			errs = append(errs, err)
			errsCh <- errs
		}
		dnsSrv.Shutdown(context.TODO())

	}()

	wg.Wait()
	defer close(errsCh)
	return errors.Join(<-errsCh...)
}
