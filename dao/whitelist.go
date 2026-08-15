package dao

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

// WhitelistRule 是一条源地址白名单条目：CIDR 前缀（允许单 IP，统一为 /32）。
type WhitelistRule struct {
	Cidr string `json:"cidr"`
}

// marshalWhitelistKey 组装存储 key：PrefixWhitelist + cidr。
func marshalWhitelistKey(cidr string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixWhitelist, cidr))
}

// NormalizeWhitelist 校验并规范化白名单条目：支持 IPv4 CIDR，
// 也支持不带掩码的单 IP（自动补 /32），与 cidr 规则一致仅限 IPv4。
func NormalizeWhitelist(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty whitelist cidr")
	}
	if !strings.Contains(s, "/") {
		if addr, err := netip.ParseAddr(s); err == nil {
			s = netip.PrefixFrom(addr, 32).String()
		}
	}
	return NormalizeCidr(s)
}

func (d *Dao) SetWhitelist(cidr string) error {
	prefix, err := NormalizeWhitelist(cidr)
	if err != nil {
		return err
	}
	key := marshalWhitelistKey(prefix.String())
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, []byte("1"))
	})
}

func (d *Dao) DeleteWhitelist(cidr string) error {
	prefix, err := NormalizeWhitelist(cidr)
	if err != nil {
		return err
	}
	key := marshalWhitelistKey(prefix.String())
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) WhitelistIterator(fn func(rule WhitelistRule) error) error {
	prefix := sconv.ByteSlice(PrefixWhitelist)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			rule := WhitelistRule{Cidr: TrimKeyPrefix(sconv.String(k))}
			if err := fn(rule); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListWhitelist() ([]WhitelistRule, error) {
	list := []WhitelistRule{}
	err := d.WhitelistIterator(func(rule WhitelistRule) error {
		list = append(list, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}
