package dao

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

var (
	ErrEgressNameExists   = errors.New("egress name already exists")
	ErrEgressFwMarkExists = errors.New("egress fwmark already exists")
)

type EgressType string

const (
	// 外部负责处理所有，网关只负责给 ip 报文打 fwmark。
	EgressManual = "manual"
	// HTTP 隧道，网关启动时负责维护 tun 设备以及路由表、策略路由等。
	EgressHTTPTunnel = "http_tunnel"
)

type EgressTunnel struct {
	Url   string `json:"url"`
	Token string `json:"token"`
}

type Egress struct {
	Name   string        `json:"name"`
	Type   EgressType    `json:"type"`
	FwMark uint32        `json:"fwmark"`
	Tunnel *EgressTunnel `json:"tunnel,omitempty"`
}

// marshalEgressKey 组装存储 key：PrefixTunnel + Egress name。
func marshalEgressKey(name string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixTunnel, name))
}

func (d *Dao) CreateEgress(egress Egress) error {
	return d.storeEgress(egress, false)
}

func (d *Dao) UpdateEgress(egress Egress) error {
	return d.storeEgress(egress, true)
}

func (d *Dao) storeEgress(egress Egress, mustExist bool) error {
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

		prefix := sconv.ByteSlice(PrefixTunnel)
		cursor := bucket.Cursor()
		for otherKey, otherValue := cursor.Seek(prefix); otherKey != nil && bytes.HasPrefix(otherKey, prefix); otherKey, otherValue = cursor.Next() {
			if bytes.Equal(otherKey, key) {
				continue
			}
			var other Egress
			if err := json.Unmarshal(otherValue, &other); err != nil {
				return err
			}
			if other.FwMark == egress.FwMark {
				return fmt.Errorf("%w: %s", ErrEgressFwMarkExists, other.Name)
			}
		}

		return bucket.Put(key, value)
	})
}

func (d *Dao) GetEgress(name string) (Egress, error) {
	key := marshalEgressKey(name)
	var tun Egress
	err := d.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket(bucketName).Get(key)
		if value == nil {
			return ErrKeyNotFound
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
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) EgressIterator(fn func(egress Egress) error) error {
	prefix := sconv.ByteSlice(PrefixTunnel)
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
