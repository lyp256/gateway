package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/lyp256/gateway/tunnel"
	"golang.zx2c4.com/wireguard/tun"
)

func NewClient(method, url string, header http.Header, deviceName string, mtu uint16) (*TunnelClient, error) {
	// Resources are created by Run so constructing a client does not establish
	// a connection or alter the host network configuration.
	return &TunnelClient{
		method:     method,
		url:        url,
		header:     header,
		deviceName: deviceName,
		mtu:        mtu,
	}, nil

}

type TunnelClient struct {
	method     string
	url        string
	header     http.Header
	deviceName string
	mtu        uint16

	stream            io.ReadWriteCloser
	device            tun.Device
	tableID           uint32
	fwmark            uint32
	masqueradeCreated bool
	routeCreated      bool
	stopOnce          sync.Once
	closeErr          error
}

func (t *TunnelClient) Run(ctx context.Context) error {
	fail := func(operation string, err error) error {
		return errors.Join(fmt.Errorf("%s: %w", operation, err), t.Close())
	}

	stream, res, err := DialHTTPRawTunnel(ctx, t.method, t.url, t.header)
	if err != nil {
		return fmt.Errorf("DialHTTPRawTunnel: %w", err)
	}
	t.stream = stream

	device, err := tunnel.CreateTUNDevice(t.deviceName, t.mtu)
	if err != nil {
		return fail("CreateTUNDevice", err)
	}
	t.device = device

	if err := tunnel.SetAddr(t.deviceName, res.IP(), true); err != nil {
		return fail("SetAddr", err)
	}
	if err := tunnel.CreateMasquerade(t.deviceName); err != nil {
		return fail("CreateMasquerade", err)
	}
	t.masqueradeCreated = true

	id := tunnel.NmaeToHashID(t.deviceName)
	t.tableID = id
	t.fwmark = id
	if err := tunnel.CreateRuleRoute(t.fwmark, t.tableID, t.deviceName); err != nil {
		return fail("CreateRuleRoute", err)
	}
	t.routeCreated = true

	errCh := make(chan error, 2)

	go func() {
		defer t.Close()
		err := tunnel.ForwardStreamToTun(ctx, t.device, t.stream)
		if err != nil {
			errCh <- fmt.Errorf("client.ForwardStreamToTun:%w", err)
			return
		}
		errCh <- nil
	}()
	go func() {
		defer t.Close()
		err := tunnel.ClientForwardTunToStream(ctx, t.device, t.stream)
		if err != nil {
			errCh <- fmt.Errorf("client.ForwardTunToStream:%w", err)
			return
		}
		errCh <- nil
	}()
	return errors.Join(<-errCh, <-errCh)
}

func (t *TunnelClient) Close() error {
	t.stopOnce.Do(func() {
		t.closeErr = t.close()
	})
	return t.closeErr
}

func (t *TunnelClient) close() error {
	var errs []error
	if t.stream != nil {
		if err := t.stream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.device != nil {
		if err := t.device.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.masqueradeCreated {
		err := tunnel.DeleteMasquerade(t.deviceName)
		if err != nil {
			errs = append(errs, err)
		}
		t.masqueradeCreated = false
	}
	if t.routeCreated {
		err := tunnel.DeleteRuleRoute(t.fwmark, t.tableID, t.deviceName)
		if err != nil {
			errs = append(errs, err)
		}
		t.routeCreated = false
	}
	return errors.Join(errs...)
}
