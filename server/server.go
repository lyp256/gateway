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
	"github.com/lyp256/gateway/dns/query"
	"go.etcd.io/bbolt"
)

// 各类型上游 DNS 的默认端口。
const (
	defaultUDPPort   = 53
	defaultDoTPort   = 853
	defaultHTTPSPort = 443
)

type Server struct {
	c        controller.Controller
	storage  *bbolt.DB
	dnsPort  uint16
	httpPort uint16
}

func NewServer(cfg config.Config) (*Server, error) {
	dnsServers := make([]query.DNSQuerier, 0, len(cfg.DNSServers)+1)
	for i, s := range cfg.DNSServers {
		q, err := newQuerier(s)
		if err != nil {
			return nil, fmt.Errorf("dns server[%d]: %w", i, err)
		}
		dnsServers = append(dnsServers, q)
	}
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

	ctl := controller.NewController(dao.New(storage), dnsServers, chi.NewRouter())
	return &Server{
		c:        ctl,
		storage:  storage,
		dnsPort:  cfg.DNSPort,
		httpPort: cfg.HTTPPort,
	}, nil
}

// newQuerier 根据上游配置创建对应的 [query.DNSQuerier]。
func newQuerier(s config.DNSServer) (query.DNSQuerier, error) {
	switch s.Type {
	case "udp", "":
		if !s.IP.IsValid() {
			return nil, fmt.Errorf("udp dns server requires a valid ip")
		}
		return query.NewStdDNS(net.JoinHostPort(s.IP.String(), strconv.Itoa(defaultUDPPort))), nil
	case "tls", "dot":
		if s.Server == "" && !s.IP.IsValid() {
			return nil, fmt.Errorf("dot dns server requires domain or ip")
		}
		return query.NewDoT(s.Server, defaultDoTPort, s.IP, s.Insecure), nil
	case "https", "doh":
		if s.Server == "" {
			return nil, fmt.Errorf("doh dns server requires domain")
		}
		url := fmt.Sprintf("https://%s/dns-query", net.JoinHostPort(s.Server, strconv.Itoa(defaultHTTPSPort)))
		return query.NewDoH(url, s.IP, s.Insecure), nil
	default:
		return nil, fmt.Errorf("unsupported dns server type %q", s.Type)
	}
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
