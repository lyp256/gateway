package tunnel

import (
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	tunnelHttp "github.com/lyp256/gateway/tunnel/http"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&tunnelModule{})
	httpcaddyfile.RegisterHandlerDirective("tunnel", parseCaddyfileHandler)
	httpcaddyfile.RegisterDirectiveOrder("tunnel", httpcaddyfile.After, "handle")
}

const mtu = 1500

// tunnelModule implements an HTTP tunnel handler
type tunnelModule struct {
	// tun device name
	Device string
	MTU    uint16
	CIDR   string

	server *tunnelHttp.TunnelServer

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*tunnelModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tunnel",
		New: func() caddy.Module { return new(tunnelModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *tunnelModule) Provision(ctx caddy.Context) error {
	if m == nil {
		return nil
	}
	m.logger = ctx.Logger(m)

	cidr, err := netip.ParsePrefix(m.CIDR)
	if err != nil {
		return err
	}

	handeler, err := tunnelHttp.NewServer(m.MTU, m.Device, cidr)
	if err != nil {
		return err
	}
	m.server = handeler

	return nil
}

// Validate implements caddy.Validator.
func (m *tunnelModule) Validate() error {
	if m == nil {
		return nil
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *tunnelModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.server.ServeHTTP(w, r)
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *tunnelModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		opt := d.Val()
		switch opt {

		default:
			return d.ArgErr()
		}
	}
	return nil
}

func (m *tunnelModule) Cleanup() error {
	return m.server.Close()
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	i := new(tunnelModule)
	err := i.UnmarshalCaddyfile(h.Dispenser)
	return i, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*tunnelModule)(nil)
	_ caddy.CleanerUpper          = (*tunnelModule)(nil)
	_ caddy.Validator             = (*tunnelModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*tunnelModule)(nil)
	_ caddyfile.Unmarshaler       = (*tunnelModule)(nil)
)
