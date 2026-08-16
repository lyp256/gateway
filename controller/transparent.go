package controller

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/sys/unix"
)

// SetTransparentSocketOptions 为 UDP socket 开启透明代理所需的内核选项：
// IP_TRANSPARENT：允许接收/发送非本机地址的流量（回包源地址可绑定到原始目的地址）；
// IP_RECVORIGDSTADDR：接收路径携带原始目的地址（地址+端口）控制消息。
// 仅 IPv4 socket 上设置 IPv6 选项会返回 ENOPROTOOPT，忽略即可。
func SetTransparentSocketOptions(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = err
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}

const (
	maxDnsReplyConns    = 1024
	dnsReplyConnIdleTTL = 10 * time.Minute
	dnsReplyConnSweep   = 5 * time.Minute
)

type dnsReplyConn struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

// dnsReplyRouter 按原始目的地址维护 IP_TRANSPARENT 回包 socket。
// DNS 查询被 eBPF tproxy 投递时目的地址/端口未改写，回包必须从原始目的
// 地址/端口发出，客户端才会认为应答来自其配置的 DNS server（严格校验
// 源地址/端口的解析器会丢弃源端口不匹配的应答）。
type dnsReplyRouter struct {
	mu        sync.Mutex
	conns     map[netip.AddrPort]*dnsReplyConn
	lastSweep time.Time
}

func newDNSReplyRouter() *dnsReplyRouter {
	return &dnsReplyRouter{
		conns:     make(map[netip.AddrPort]*dnsReplyConn),
		lastSweep: time.Now(),
	}
}

// wrap 返回一个拦截 Write 的 ResponseWriter：
// UDP 查询能拿到原始目的地址时，应答改从绑定原始目的地址/端口的透明 socket 发出；
// 拿不到（TCP、无 OOB 等）时回退到原始写路径。
func (r *dnsReplyRouter) wrap(w dns.ResponseWriter) dns.ResponseWriter {
	return &transparentResponseWriter{ResponseWriter: w, router: r}
}

type transparentResponseWriter struct {
	dns.ResponseWriter
	router *dnsReplyRouter
}

func (tw *transparentResponseWriter) Write(p []byte) (int, error) {
	if n, err, ok := tw.router.tryTransparentWrite(tw.ResponseWriter, p); ok {
		return n, err
	}
	return tw.ResponseWriter.Write(p)
}

func (r *dnsReplyRouter) tryTransparentWrite(w dns.ResponseWriter, p []byte) (int, error, bool) {
	sess := w.Session()
	if sess == nil {
		slog.Debug("transparent dns reply: no session")
		return 0, nil, false
	}
	if sess.Addr == nil {
		slog.Debug("transparent dns reply: no client addr in session")
		return 0, nil, false
	}
	if len(sess.OOB) == 0 {
		slog.Debug("transparent dns reply: empty oob")
		return 0, nil, false
	}
	orig, err := parseRequestDstFromCmsgs(sess.OOB)
	if err != nil {
		slog.Debug("parse original dns dst", "oob_len", len(sess.OOB), "err", err)
		return 0, nil, false
	}
	conn, err := r.connFor(orig)
	if err != nil {
		slog.Debug("open transparent dns reply socket", "orig", orig, "err", err)
		return 0, nil, false
	}
	n, err := conn.WriteToUDP(p, sess.Addr)
	return n, err, true
}

func (r *dnsReplyRouter) connFor(orig netip.AddrPort) (*net.UDPConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.lastSweep) >= dnsReplyConnSweep {
		r.sweepLocked(now)
		r.lastSweep = now
	}
	if c, ok := r.conns[orig]; ok {
		c.lastUsed = now
		return c.conn, nil
	}
	if len(r.conns) >= maxDnsReplyConns {
		r.evictOldestLocked()
	}

	lc := net.ListenConfig{Control: SetTransparentSocketOptions}
	pc, err := lc.ListenPacket(context.Background(), "udp", orig.String())
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
	r.conns[orig] = &dnsReplyConn{conn: uc, lastUsed: now}
	return uc, nil
}

func (r *dnsReplyRouter) sweepLocked(now time.Time) {
	for key, c := range r.conns {
		if now.Sub(c.lastUsed) >= dnsReplyConnIdleTTL {
			_ = c.conn.Close()
			delete(r.conns, key)
		}
	}
}

func (r *dnsReplyRouter) evictOldestLocked() {
	var oldestKey netip.AddrPort
	var oldest time.Time
	first := true
	for key, c := range r.conns {
		if first || c.lastUsed.Before(oldest) {
			oldestKey, oldest, first = key, c.lastUsed, false
		}
	}
	if !first {
		_ = r.conns[oldestKey].conn.Close()
		delete(r.conns, oldestKey)
	}
}
