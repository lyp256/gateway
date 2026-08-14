package dao

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

var (
	ErrEgressNameExists   = errors.New("egress name already exists")
	ErrEgressFwMarkExists = errors.New("egress fwmark already exists")
	ErrEgressNotFound     = errors.New("egress not found")
	ErrEgressInUse        = errors.New("egress is referenced by rules")
	ErrInvalidEgress      = errors.New("invalid egress")
)

type EgressType string

const (
	// 外部负责处理所有，网关只负责给 ip 报文打 fwmark。
	EgressManual = "manual"
	// HTTP 隧道，网关启动时负责维护 tun 设备以及路由表、策略路由等。
	EgressHTTPTunnel = "http_tunnel"
	// 本地 TPROXY 监听，网关在 TC ingress 上通过 bpf_sk_assign 把 TCP 交给该 socket。
	EgressTproxy = "tproxy"
)

type EgressTunnel struct {
	Url   string `json:"url"`
	Token string `json:"token"`
}

// EgressTproxyConfig 描述本地透明监听 socket 的查找条件。
// Addr 为空或 0.0.0.0 时按包的原目的地址查找；Port 为 0 时按包的原目的端口查找。
type EgressTproxyConfig struct {
	Addr string `json:"addr,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

type Egress struct {
	Name   string              `json:"name"`
	Type   EgressType          `json:"type"`
	FwMark uint32              `json:"fwmark,omitempty"`
	Tunnel *EgressTunnel       `json:"tunnel,omitempty"`
	Tproxy *EgressTproxyConfig `json:"tproxy,omitempty"`
}

// marshalEgressKey 组装存储 key：PrefixTunnel + Egress name。
func marshalEgressKey(name string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixEgress, name))
}

func (d *Dao) CreateEgress(egress Egress) error {
	return d.storeEgress(egress, false)
}

func (d *Dao) UpdateEgress(egress Egress) error {
	return d.storeEgress(egress, true)
}

func (d *Dao) storeEgress(egress Egress, mustExist bool) error {
	if err := validateEgress(&egress); err != nil {
		return err
	}
	key := marshalEgressKey(egress.Name)
	value, err := json.Marshal(egress)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if existing := bucket.Get(key); existing != nil && !mustExist {
			return ErrEgressNameExists
		} else if existing == nil && mustExist {
			return ErrKeyNotFound
		}

		prefix := sconv.ByteSlice(PrefixEgress)
		cursor := bucket.Cursor()
		for otherKey, otherValue := cursor.Seek(prefix); otherKey != nil && bytes.HasPrefix(otherKey, prefix); otherKey, otherValue = cursor.Next() {
			if bytes.Equal(otherKey, key) {
				continue
			}
			var other Egress
			if err := json.Unmarshal(otherValue, &other); err != nil {
				return err
			}
			if other.FwMark != 0 && egress.FwMark != 0 && other.FwMark == egress.FwMark {
				return fmt.Errorf("%w: %s", ErrEgressFwMarkExists, other.Name)
			}
		}

		return bucket.Put(key, value)
	})
}

// validateEgress 规范化并校验 egress 配置。
// tproxy 出口不占用 fwmark（统一置 0），避免与手工出口的 mark 冲突。
func validateEgress(egress *Egress) error {
	switch egress.Type {
	case EgressTproxy:
		egress.FwMark = 0
		if egress.Tproxy == nil {
			egress.Tproxy = &EgressTproxyConfig{}
		}
		if egress.Tproxy.Addr == "" {
			egress.Tproxy.Addr = "0.0.0.0"
		}
		addr, err := netip.ParseAddr(egress.Tproxy.Addr)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("%w: invalid tproxy addr %q: must be an IPv4 address", ErrInvalidEgress, egress.Tproxy.Addr)
		}
		egress.Tproxy.Addr = addr.String()
	case "", EgressManual, EgressHTTPTunnel:
		egress.Tproxy = nil
	default:
		return fmt.Errorf("%w: unsupported egress type %q", ErrInvalidEgress, egress.Type)
	}
	return nil
}

func (d *Dao) GetEgress(name string) (Egress, error) {
	key := marshalEgressKey(name)
	var tun Egress
	err := d.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket(bucketName).Get(key)
		if value == nil {
			return ErrEgressNotFound
		}
		return json.Unmarshal(value, &tun)
	})
	if err != nil {
		return tun, err
	}
	return tun, nil
}

func (d *Dao) DeleteEgress(name string) error {
	key := marshalEgressKey(name)
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket.Get(key) == nil {
			return ErrKeyNotFound
		}
		for _, prefix := range []string{PrefixDomainRule, PrifixCidr} {
			keyPrefix := sconv.ByteSlice(prefix)
			cursor := bucket.Cursor()
			for ruleKey, ruleValue := cursor.Seek(keyPrefix); ruleKey != nil && bytes.HasPrefix(ruleKey, keyPrefix); ruleKey, ruleValue = cursor.Next() {
				if string(ruleValue) == name {
					return fmt.Errorf("%w: %s", ErrEgressInUse, name)
				}
			}
		}
		return bucket.Delete(key)
	})
}

func (d *Dao) EgressIterator(fn func(egress Egress) error) error {
	prefix := sconv.ByteSlice(PrefixEgress)
	return d.db.View(func(tx *bbolt.Tx) error {
		cursor := tx.Bucket(bucketName).Cursor()
		for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
			var egress Egress
			if err := json.Unmarshal(value, &egress); err != nil {
				return err
			}
			if err := fn(egress); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListEgress() ([]Egress, error) {
	egresses := []Egress{}
	err := d.EgressIterator(func(egress Egress) error {
		egresses = append(egresses, egress)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return egresses, nil
}
