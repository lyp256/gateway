package controller

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/lyp256/gateway/bpf"
	"github.com/lyp256/gateway/dao"
	"github.com/lyp256/gateway/dns/query"
	"github.com/lyp256/gateway/dns/router"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
)

var ErrNotExistOriginalDst = errors.New("not exist origin dest addr")

func (ctl *controller) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	success := ctl.queryDNS(ctx, w, r)
	d := time.Since(startTime).Seconds()
	if success {
		ctl.dnsQuerySucceedDurationSecond().Update(d)
	} else {
		ctl.dnsQueryFailedDurationSecond().Update(d)

	}

}

// ServeDNS implements [dns.Handler].
//
// 依次尝试从 ctl.dnsServers 中解析 dns：任一上游返回成功且带有应答记录即采用，
// 否则回退到下一个上游。全部上游都失败时返回 SERVFAIL。
func (ctl *controller) queryDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) bool {
	cacheKey, cacheable := dnsCacheKey(r)
	if cacheable {
		if response, ok := ctl.getCachedDNSResponse(cacheKey, r); ok {
			ctl.writeDNSResponse(w, r, response)
			ctl.dnsQuerySucceed().Inc()
			return true
		}
	}

	ctl.dnsServersMux.RLock()
	servers := ctl.dnsServers
	ctl.dnsServersMux.RUnlock()
	for _, srv := range servers {
		resp, _, err := srv.Query(ctx, r)
		if err != nil || resp == nil {
			continue
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			if cacheable {
				ctl.cacheDNSResponse(cacheKey, resp)
			}
			ctl.writeDNSResponse(w, r, resp)
			ctl.dnsQuerySucceed().Inc()
			return true
		}

	}
	ctl.dnsQueryFailed().Inc()
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, r)
	resp.Rcode = dns.RcodeServerFailure
	if err := resp.Pack(); err == nil {
		_, _ = io.Copy(w, resp)
	}
	return false
}

func (ctl *controller) writeDNSResponse(w dns.ResponseWriter, request, response *dns.Msg) {
	nameip := make(map[string][]netip.Addr)
	for _, rr := range response.Answer {
		var value netip.Addr
		header := rr.Header()
		switch record := rr.(type) {
		case *dns.A:
			value = record.A.Addr
		case *dns.AAAA:
			value = record.AAAA.Addr
		}
		if value.IsValid() {
			nameip[header.Name] = append(nameip[header.Name], value)
			slog.Debug("resolve dns", "ip", value, "name", header.Name)
		}
	}
	for name, ips := range nameip {
		ctl.dnsToRoute(name, ips...)
	}
	response.ID = request.ID
	if err := response.Pack(); err == nil {
		_, _ = io.Copy(w, response)
	}
}

func (ctl *controller) proxyDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, server netip.AddrPort) {
	slog.Debug("proxy dns queryt", "server", server)
	resp, _, err := query.NewStdDNS(server.String()).Query(ctx, r)
	if err != nil {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, r)
		resp.Rcode = dns.RcodeServerFailure
		if err := resp.Pack(); err == nil {
			_, _ = io.Copy(w, resp)
		}
		return
	}
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		nameip := make(map[string][]netip.Addr)
		for _, rr := range resp.Answer {
			var val netip.Addr
			header := rr.Header()
			switch r := rr.(type) {
			case *dns.A:
				val, err = netip.ParseAddr(r.A.String())
				if err != nil {
					slog.Warn("ParseAddr A", "err", err)
				}
			case *dns.AAAA:
				val, err = netip.ParseAddr(r.AAAA.String())
				if err != nil {
					slog.Warn("ParseAddr A", "err", err)
				}
			}
			if val.IsValid() {
				nameip[header.Name] = append(nameip[header.Name], val)
				slog.Debug("resolv dns", "ip", val, "name", header.Name)
			}
		}
		for name, ips := range nameip {
			ctl.dnsToRoute(name, ips...)
		}
		if err := resp.Pack(); err == nil {
			_, _ = io.Copy(w, resp)
		}
		return
	}
	if err := resp.Pack(); err == nil {
		_, _ = io.Copy(w, resp)
	}
}

func (ctl *controller) dnsToRoute(name string, ips ...netip.Addr) {
	value, ok := ctl.dnsTable.Match(name)
	if !ok {
		return
	}
	ctl.addIRoute(uint8(value), ips...)
}

func (ctl *controller) addIRoute(egressIdx uint8, ips ...netip.Addr) {

	updateIps := make([]bpf.FilterBpfLpmTrieKeyV4, 0, len(ips))
	values := make([]uint8, 0, len(ips))
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		ctl.routeMux.Lock()
		oldIdx, ok := ctl.routeTable.Lookup(ip)
		if !ok || oldIdx != egressIdx {
			ctl.routeTable.Insert(netip.PrefixFrom(ip, 32), egressIdx)
			updateIps = append(updateIps, bpf.ToFilterBpfLpmTrieKeyV4(netip.PrefixFrom(ip, 32)))
			values = append(values, egressIdx)
			slog.Debug("add route", "ip", ip, "egress_index", egressIdx, "raw", ip.As4())
		}
		ctl.routeMux.Unlock()
	}
	if len(updateIps) == 0 {
		return
	}

	updeted, err := ctl.bpf.FilterMaps.RouteLpmMap.BatchUpdate(updateIps, values, nil)
	if err != nil {
		//TODO 实现淘汰
		slog.Error("update ebpf route failed", "err", err)
		return
	}
	if updeted != len(updateIps) {
		slog.Error("更新路由表数量不匹配", "expect", len(updateIps), "actual", updeted)
	}
}

func loadHostsFromStorage(db *dao.Dao, hosts map[string]netip.Addr) error {
	return db.HostIterator(func(host string, ip netip.Addr) error {
		hosts[host] = ip
		return nil
	})
}

func loadDomainRuleMapFromStorage(db *dao.Dao, routerMap map[string]uint64, egressIndexByName map[string]uint8) error {
	return db.DomainRuleIterator(func(dr dao.DomainRule) error {
		idx, ok := egressIndexByName[dr.Egress]
		if !ok {
			slog.Error("domain references missing egress", "match", dr.Match, "domain", dr.Domain, "egress", dr.Egress)
			return nil
		}
		routerMap[router.ReverseDomainString(dr.Domain)] = router.RouteDest(uint32(dr.Match), uint32(idx))
		return nil
	})
}

func parseOriginalDstFromCmsgs(oob []byte) (netip.AddrPort, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parsing socket control message: %s", err)
	}
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVORIGDSTADDR:
			return parseIPv4OrigDst(msg.Data)
		case msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR:
			return parseIPv6OrigDst(msg.Data)
		}
	}

	return netip.AddrPort{}, ErrNotExistOriginalDst
}

func parseRequestDstFromCmsgs(oob []byte) (netip.AddrPort, error) {
	dest, err := parseOriginalDstFromCmsgs(oob)
	if err == nil && dest.Addr().IsValid() {
		return dest, nil
	}

	addr, addrErr := parseDstAddrFromPktInfo(oob)
	if addrErr != nil {
		if err != nil {
			return netip.AddrPort{}, errors.Join(err, addrErr)
		}
		return netip.AddrPort{}, addrErr
	}
	return netip.AddrPortFrom(addr, 53), nil
}

func parseDstAddrFromPktInfo(oob []byte) (netip.Addr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing socket control message: %s", err)
	}
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_PKTINFO:
			if len(msg.Data) != 12 {
				continue
			}
			return netip.AddrFrom4([4]byte(msg.Data[8:12])), nil
		case msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_PKTINFO:
			if len(msg.Data) != 20 {
				continue
			}
			return netip.AddrFrom16([16]byte(msg.Data[:16])).Unmap(), nil
		}
	}

	return netip.Addr{}, ErrNotExistOriginalDst
}

func parseIPv4OrigDst(data []byte) (netip.AddrPort, error) {
	const rawSockaddrInet4Len = 16
	if len(data) < rawSockaddrInet4Len {
		return netip.AddrPort{}, fmt.Errorf("reading original destination address: short IPv4 sockaddr control message")
	}

	family := binary.NativeEndian.Uint16(data[0:2])
	if family != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("original destination uses unsupported network family %d", family)
	}

	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:])), binary.BigEndian.Uint16(data[2:4])), nil
}

func parseIPv6OrigDst(data []byte) (netip.AddrPort, error) {
	const rawSockaddrInet6Len = 28
	if len(data) < rawSockaddrInet6Len {
		return netip.AddrPort{}, fmt.Errorf("reading original destination address: short IPv6 sockaddr control message")
	}

	family := binary.NativeEndian.Uint16(data[0:2])
	if family != unix.AF_INET6 {
		return netip.AddrPort{}, fmt.Errorf("original destination uses unsupported network family %d", family)
	}
	ip := netip.AddrFrom16([16]byte(data[8:24]))
	zoneID := binary.NativeEndian.Uint32(data[24:28])
	if zoneID != 0 {
		ip.WithZone(strconv.Itoa(int(zoneID)))
	}
	addr := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(data[2:4]))
	return addr, nil
}

func LocalAddr() map[netip.Addr]struct{} {
	m := make(map[netip.Addr]struct{})
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			switch a := addr.(type) {
			case *net.IPNet:
				na, ok := netip.AddrFromSlice(a.IP)
				if ok {
					m[na] = struct{}{}
				}
			}

			a, err := netip.ParseAddr(addr.String())
			if err == nil {
				m[a] = struct{}{}
			}
		}
	}
	return m
}

var (
	lazyDo     = singleflight.Group{}
	localAddrs map[netip.Addr]struct{}
	lastAt     int64
)

const period = int64(5 * time.Second)

// 返回 map 并发使用只读
func lazyLocalAddr() map[netip.Addr]struct{} {
	v, _, _ := lazyDo.Do("localAddrs", func() (any, error) {
		now := time.Now().UnixNano()
		if abs(now-lastAt) > int64(period) || localAddrs == nil {
			lastAt = now
			localAddrs = LocalAddr()
		}
		return localAddrs, nil
	})
	return v.(map[netip.Addr]struct{})
}

func abs(u int64) int64 {
	if u > 0 {
		return u
	}
	return -u
}

func isLocalAddr(addr netip.Addr) bool {
	if addr.As4()[0] == 127 {
		return true
	}
	_, ok := lazyLocalAddr()[addr]
	return ok
}
