package dao

import (
	"bytes"
	"net/netip"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

type Host struct {
	Name string     `json:"name"`
	IP   netip.Addr `json:"ip"`
}

// marshalHostKey 组装存储 key：PrefixHosts + host。
func marshalHostKey(host string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixHosts, host))
}

// parseHostIP 按存储的字节长度解析 IP，与 loadHostsFromStorage 保持一致。
func parseHostIP(v []byte) (netip.Addr, bool) {
	switch len(v) {
	case 4:
		return netip.AddrFrom4([4]byte(v[:4])), true
	case 16:
		return netip.AddrFrom16([16]byte(v[:16])), true
	}
	return netip.Addr{}, false
}

func (d *Dao) SetHost(host string, ip netip.Addr) error {
	key := marshalHostKey(host)
	val := ip.AsSlice()
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, val)
	})
}

func (d *Dao) GetHost(host string) (netip.Addr, error) {
	key := marshalHostKey(host)
	var addr netip.Addr
	err := d.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketName).Get(key)
		if v == nil {
			return ErrKeyNotFound
		}
		addr, _ = parseHostIP(v)
		return nil
	})
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func (d *Dao) DeleteHost(host string) error {
	key := marshalHostKey(host)
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) HostIterator(fn func(host string, ip netip.Addr) error) error {
	prefix := sconv.ByteSlice(PrefixHosts)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			host := TrimKeyPrefix(sconv.String(k))
			ip, ok := parseHostIP(v)
			if !ok {
				continue
			}
			if err := fn(host, ip); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListHost() ([]Host, error) {
	hosts := []Host{}
	err := d.HostIterator(func(host string, ip netip.Addr) error {
		hosts = append(hosts, Host{Name: host, IP: ip})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hosts, nil
}
