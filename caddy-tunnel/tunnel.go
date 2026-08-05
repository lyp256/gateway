// Package tunnel integrates gateway's HTTP tunnel server with Caddy.
package tunnel

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lyp256/gateway/dhcp/pool"
	tunnelHTTP "github.com/lyp256/gateway/tunnel/http"
	"go.uber.org/zap"
)

const (
	defaultMTU    = 1500
	defaultDevice = "tunnel-server"
	defaultCIDR   = "198.18.18.0/24"
)

func init() {
	caddy.RegisterModule(&tunnelModule{})
	httpcaddyfile.RegisterHandlerDirective("tunnel", parseCaddyfileHandler)
	// tunnel terminates a request after upgrading it to the tunnel protocol.
	// It must run before a catch-all handle block.
	httpcaddyfile.RegisterDirectiveOrder("tunnel", httpcaddyfile.Before, "handle")
}

// tunnelModule implements the http.handlers.tunnel Caddy module.
type tunnelModule struct {
	// Device is the name of the server-side TUN device.
	Device string `json:"device_name,omitempty"`
	// MTU is the TUN device MTU.
	MTU uint16 `json:"mtu,omitempty"`
	// CIDR is the IPv4 network from which tunnel client addresses are allocated.
	CIDR string `json:"cidr,omitempty"`
	// auth KEY
	KEY string `json:"key,omitempty"`

	server    *tunnelHTTP.TunnelServer
	logger    *zap.Logger
	closeOnce sync.Once
	closeErr  error
}

// CaddyModule returns the Caddy module information.
func (*tunnelModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tunnel",
		New: func() caddy.Module { return new(tunnelModule) },
	}
}

// Provision creates the TUN device and starts forwarding packets.
func (m *tunnelModule) Provision(ctx caddy.Context) error {
	m.applyDefaults()
	if err := m.Validate(); err != nil {
		return err
	}

	m.logger = ctx.Logger(m)
	cidr, _ := netip.ParsePrefix(m.CIDR) // validated above
	server, err := tunnelHTTP.NewServer(m.MTU, m.Device, cidr, tunnelHTTP.NewKeyAuth(m.KEY))
	if err != nil {
		return fmt.Errorf("create tunnel server: %w", err)
	}
	m.server = server
	go func() {
		if err := server.Run(ctx); err != nil && ctx.Err() == nil {
			m.logger.Error("run tunnel forwarder", zap.Error(err))
		}
	}()
	return nil
}

// Validate verifies the configuration before a TUN device is created.
func (m *tunnelModule) Validate() error {
	if m == nil {
		return fmt.Errorf("tunnel module is nil")
	}
	if m.Device == "" {
		return fmt.Errorf("device_name must not be empty")
	}
	if m.MTU == 0 {
		return fmt.Errorf("mtu must be greater than zero")
	}
	cidr, err := netip.ParsePrefix(m.CIDR)
	if err != nil {
		return fmt.Errorf("parse cidr: %w", err)
	}
	if _, err := pool.UsableIPv4AddressCount(cidr); err != nil {
		return fmt.Errorf("invalid cidr: %w", err)
	}
	return nil
}

// ServeHTTP handles the tunnel HTTP handshake and the subsequent raw stream.
func (m *tunnelModule) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if m.server == nil {
		return fmt.Errorf("tunnel handler is not provisioned")
	}
	m.server.ServeHTTP(w, r)
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	tunnel {
//	    device_name tunnel-server
//	    mtu 1500
//	    cidr 198.18.18.0/24
//	}
func (m *tunnelModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	m.applyDefaults()
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "device_name":
				if !d.AllArgs(&m.Device) {
					return d.ArgErr()
				}
			case "key":
				if !d.AllArgs(&m.KEY) {
					return d.ArgErr()
				}
			case "mtu":
				var value string
				if !d.AllArgs(&value) {
					return d.ArgErr()
				}
				mtu, err := strconv.ParseUint(value, 10, 16)
				if err != nil || mtu == 0 {
					return d.Errf("invalid mtu %q: expected an integer between 1 and 65535", value)
				}
				m.MTU = uint16(mtu)
			case "cidr":
				if !d.AllArgs(&m.CIDR) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized tunnel subdirective %q", d.Val())
			}
		}
	}
	return m.Validate()
}

func (m *tunnelModule) applyDefaults() {
	if m.MTU == 0 {
		m.MTU = defaultMTU
	}
	if m.Device == "" {
		m.Device = defaultDevice
	}
	if m.CIDR == "" {
		m.CIDR = defaultCIDR
	}
}

// Cleanup closes the TUN device and removes its system configuration.
func (m *tunnelModule) Cleanup() error {
	m.closeOnce.Do(func() {
		if m.server != nil {
			m.closeErr = m.server.Close()
		}
	})
	return m.closeErr
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	i := new(tunnelModule)
	return i, i.UnmarshalCaddyfile(h.Dispenser)
}

var (
	_ caddy.Provisioner           = (*tunnelModule)(nil)
	_ caddy.CleanerUpper          = (*tunnelModule)(nil)
	_ caddy.Validator             = (*tunnelModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*tunnelModule)(nil)
	_ caddyfile.Unmarshaler       = (*tunnelModule)(nil)
)
