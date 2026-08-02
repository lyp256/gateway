package http

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"

	"github.com/lyp256/gateway/dhcp/pool"
	"github.com/lyp256/gateway/tunnel"
	"golang.zx2c4.com/wireguard/tun"
)

func NewServer(mtu uint16, devName string, cidr netip.Prefix) (*TunnelServer, error) {
	if mtu == 0 {
		mtu = 1500
	}
	if devName == "" {
		return nil, fmt.Errorf("device name is empty")
	}

	ippool, err := pool.NewDHCPPool(cidr)
	if err != nil {
		return nil, err
	}
	addr, err := ippool.Allocate()
	if err != nil {
		return nil, err
	}
	device, err := tunnel.CreateTUNDevice(devName, mtu, addr)
	if err != nil {
		return nil, fmt.Errorf("CreateTUNDevice: %w", err)
	}
	h32 := fnv.New32a()
	_, _ = h32.Write([]byte(devName))
	id := h32.Sum32()
	if id < 256 {
		id += 256
	}
	return &TunnelServer{
		mtu:        int(mtu),
		ippool:     ippool,
		device:     device,
		deviceName: devName,
		deviceAddr: addr,
		tableID:    id,
		fwmark:     id,
		peer:       make(map[netip.Addr]io.ReadWriteCloser),
	}, nil
}

type TunnelServer struct {
	mtu        int
	ippool     *pool.DHCPPool
	deviceName string
	device     tun.Device
	deviceAddr netip.Prefix
	tableID    uint32
	fwmark     uint32
	peerMux    sync.RWMutex
	peer       map[netip.Addr]io.ReadWriteCloser
	cancel     context.CancelFunc
}

func (t *TunnelServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var res HandshakeRespone
	addr, err := t.ippool.Allocate()
	if err != nil {
		res.SetStatus(StatusNoIP)
	} else {
		defer t.ippool.Release(addr.Addr())
	}
	res.SetIP(addr)

	conn, err := HTTPServerHandshake(w, r, res)
	if err != nil {
		return
	}
	defer func() {
		_ = conn.Close()
	}()
	t.peerMux.Lock()
	t.peer[addr.Addr()] = conn
	t.peerMux.Unlock()
	defer func() {
		t.peerMux.Lock()
		delete(t.peer, addr.Addr())
		t.peerMux.Unlock()
		_ = conn.Close()
	}()

	err = tunnel.ForwardStreamToTun(r.Context(), t.device, conn)
	slog.Error("server.ForwardStreamToTun", "error", err)
}

func (t *TunnelServer) Run(ctx context.Context) error {
	ctx, t.cancel = context.WithCancel(ctx)
	getter := func(addr netip.Addr) (io.Writer, bool) {
		t.peerMux.RLock()
		conn, ok := t.peer[addr]
		t.peerMux.RUnlock()
		return conn, ok
	}
	return tunnel.ServerForwardTunToStream(ctx, t.device, getter)

}

func (t *TunnelServer) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	var errs []error
	err := t.device.Close()
	if err != nil {
		errs = append(errs, err)
	}
	err = tunnel.DeleteTUNDevice(t.deviceName)
	if err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
