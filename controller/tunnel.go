package controller

import (
	"context"
	"fmt"

	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/tunnel/http"
)

func (ctl *controller) loadTunnelsFromStorage(ctx context.Context, db *dao.Dao) error {
	return db.TunnelIterator(func(tun dao.Tunnel) error {
		ctl.dialTunnel(ctx, tun)
		return nil
	})

}

func (ctl *controller) dialTunnel(ctx context.Context, t dao.Tunnel) {
	ctx, cancel := context.WithCancel(ctx)
	tun := tunIF{
		cancel: cancel,
	}
	cli, err := http.NewClient("POST", t.Url, nil, t.Name, 1350)
	if err != nil {
		tun.lastErr = err
	} else {
		go func() {
			tun.ready = true
			err = cli.Run(ctx)
			tun.lastErr = fmt.Errorf("tun %s client Run:%w", t.Name, err)
			tun.ready = false
		}()
	}
	ctl.tunifMux.Lock()
	ctl.tunifs[t.Name] = &tun
	ctl.tunifMux.Unlock()
}
