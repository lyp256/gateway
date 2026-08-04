package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

func CreateTUNDevice(name string, mtu uint16) (tun.Device, error) {
	dev, err := tun.CreateTUN(name, int(mtu))
	if err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, err
	}
	return dev, nil
}

func SetAddr(name string, addr netip.Prefix, overwrite bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	ip := addr.Addr().As4()
	ipnet := net.IPNet{
		IP:   ip[:],
		Mask: net.CIDRMask(addr.Bits(), len(ip)*8),
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	var exist bool
	for _, addr := range addrs {
		if addr.IPNet.Mask.String() == ipnet.String() {
			exist = true
			continue
		}
		if overwrite {
			err = netlink.AddrDel(link, &addr)
			if err != nil {
				return err
			}
		}
	}
	if exist {
		return netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
	}
	return nil
}

// DeleteTUNDevice removes the network interface named name.
func DeleteTUNDevice(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)

}

func CreateRuleRoute(fwmark uint32, tableID uint32, dev string) error {
	devLink, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("LinkByName: %w", err)
	}

	rule := netlink.NewRule()
	rule.Table = int(tableID)
	rule.Mark = fwmark
	err = netlink.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("RuleAdd: %w", err)
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: devLink.Attrs().Index,
		Table:     int(tableID),
		Dst: &net.IPNet{
			IP:   net.IP{0, 0, 0, 0},
			Mask: net.IPMask{0, 0, 0, 0},
		},
	})

}

// DeleteRuleRoute removes the default route and fwmark rule created by
// CreateRuleRoute.
func DeleteRuleRoute(fwmark uint32, tableID uint32, dev string) error {
	devLink, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}

	routeErr := netlink.RouteDel(&netlink.Route{
		LinkIndex: devLink.Attrs().Index,
		Table:     int(tableID),
		Dst:       &net.IPNet{},
	})
	rule := netlink.NewRule()
	rule.Table = int(tableID)
	rule.Mark = fwmark
	ruleErr := netlink.RuleDel(rule)
	if routeErr != nil || ruleErr != nil {
		return fmt.Errorf("delete route rule for %q: %w", dev, errors.Join(routeErr, ruleErr))
	}
	return nil
}

func CreateMasquerade(dev string) error {
	if strings.TrimSpace(dev) == "" {
		return errors.New("masquerade interface is empty")
	}

	// iptables-nft is commonly installed even on hosts whose packet filter is
	// nftables, so prefer it when available. AppendUnique makes this operation
	// safe to call more than once.
	if err := createMasqueradeByIptables(dev); err == nil {
		return nil
	} else {
		iptablesErr := err
		if err := createMasqueradeByNfttables(dev); err == nil {
			return nil
		} else {
			return fmt.Errorf("create masquerade rule for %q: %w", dev, errors.Join(iptablesErr, err))
		}
	}

}

// DeleteMasquerade removes the IPv4 MASQUERADE rule for dev. It checks both
// the iptables and native nftables backends used by CreateMasquerade.
func DeleteMasquerade(dev string) error {
	if strings.TrimSpace(dev) == "" {
		return errors.New("masquerade interface is empty")
	}

	iptablesErr := deleteMasqueradeByIptables(dev)
	nftablesErr := deleteMasqueradeByNfttables(dev)
	if iptablesErr != nil && nftablesErr != nil {
		return fmt.Errorf("delete masquerade rule for %q: %w", dev, errors.Join(iptablesErr, nftablesErr))
	}
	return nil
}

func createMasqueradeByIptables(dev string) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return ipt.AppendUnique("nat", "POSTROUTING", "-o", dev, "-j", "MASQUERADE")
}

func deleteMasqueradeByIptables(dev string) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}
	return ipt.DeleteIfExists("nat", "POSTROUTING", "-o", dev, "-j", "MASQUERADE")
}

func createMasqueradeByNfttables(dev string) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}

	const tableName = "gateway_nat"
	const chainName = "postrouting"
	var table *nftables.Table

	tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	for _, candidate := range tables {
		if candidate.Name == tableName {
			table = candidate
			break
		}
	}
	if table == nil {
		table = c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   tableName,
		})
	}

	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	var chain *nftables.Chain
	for _, candidate := range chains {
		if candidate.Table.Name == tableName && candidate.Name == chainName {
			chain = candidate
			break
		}
	}
	chainExists := chain != nil
	if !chainExists {
		chain = c.AddChain(&nftables.Chain{
			Name:     chainName,
			Table:    table,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource,
		})
	}

	// nftables interface names are stored as a NUL-padded IFNAMSIZ value.
	if len(dev) >= 16 {
		return fmt.Errorf("interface name %q is too long", dev)
	}
	ifname := make([]byte, 16)
	copy(ifname, dev)
	userData := []byte("gateway:masquerade:" + dev)
	if chainExists {
		rules, err := c.GetRules(table, chain)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, userData) {
				return nil
			}
		}
	}
	c.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userData,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname},
			&expr.Masq{},
		},
	})
	return c.Flush()
}

func deleteMasqueradeByNfttables(dev string) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}

	const tableName = "gateway_nat"
	const chainName = "postrouting"
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	var table *nftables.Table
	for _, candidate := range tables {
		if candidate.Name == tableName {
			table = candidate
			break
		}
	}
	if table == nil {
		return nil
	}

	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	var chain *nftables.Chain
	for _, candidate := range chains {
		if candidate.Table.Name == tableName && candidate.Name == chainName {
			chain = candidate
			break
		}
	}
	if chain == nil {
		return nil
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		return err
	}
	userData := []byte("gateway:masquerade:" + dev)
	for _, rule := range rules {
		if bytes.Equal(rule.UserData, userData) {
			if err := c.DelRule(rule); err != nil {
				return err
			}
		}
	}
	return c.Flush()
}

func NmaeToHashID(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	id := h.Sum32()
	if id < 256 {
		id += 256
	}
	return id
}
