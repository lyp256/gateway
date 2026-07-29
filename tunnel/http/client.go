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

func NewClient(ctx context.Context, method, url string, header http.Header, deviceName string, mtu uint16) (*TunnelClient, error) {
	conn, res, err := DialHTTPRawTunnel(ctx, method, url, header)
	if err != nil {
		return nil, err
	}
	tun, err := tunnel.CreateTUNDevice(deviceName, mtu, res.IP())
	if err != nil {
		return nil, err
	}
	err = tunnel.CreateMasquerade(deviceName)
	if err != nil {
		return nil, err
	}
	id := tunnel.NmaeToHashID(deviceName)
	err = tunnel.CreateRuleRoute(id, id, deviceName)
	if err != nil {
		return nil, err
	}

	return &TunnelClient{
		stream:  conn,
		device:  tun,
		tableID: id,
		fwmark:  id,
	}, nil

}

type TunnelClient struct {
	stream  io.ReadWriteCloser
	device  tun.Device
	tableID uint32
	fwmark  uint32
}

func (t *TunnelClient) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = t.stream.Close()
			_ = t.device.Close()
		})
	}
	go func() {
		defer stop()
		err := tunnel.ClientForwardStreamToTun(ctx, t.device, t.stream)
		if err != nil {
			errCh <- fmt.Errorf("client.ForwardStreamToTun:%w", err)
			return
		}
		errCh <- nil
	}()
	go func() {
		defer stop()
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
	var errs []error
	err := t.stream.Close()
	if err != nil {
		errs = append(errs, err)
	}
	devName, err := t.device.Name()
	if err != nil {
		errs = append(errs, err)
	}
	if devName != "" {
		err = tunnel.DeleteMasquerade(devName)
		if err != nil {
			errs = append(errs, err)
		}
		err = tunnel.DeleteRuleRoute(t.fwmark, t.tableID, devName)
		if err != nil {
			errs = append(errs, err)
		}

		err = tunnel.DeleteTUNDevice(devName)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
