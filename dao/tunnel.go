package dao

import (
	"bytes"
	"encoding/json"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

type Tunnel struct {
	Name   string `json:"name"`
	Url    string `json:"url"`
	Token  string `json:"token"`
	FwMark uint32 `json:"fwmark"`
}

// marshalTunnelKey 组装存储 key：PrefixTunnels + Tunnel name。
func marshalTunnelKey(name string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixTunnel, name))
}

func (d *Dao) SetTunnel(Tunnel Tunnel) error {
	key := marshalTunnelKey(Tunnel.Name)
	value, err := json.Marshal(Tunnel)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, value)
	})
}

func (d *Dao) GetTunnel(name string) (Tunnel, error) {
	key := marshalTunnelKey(name)
	var tun Tunnel
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

func (d *Dao) DeleteTunnel(name string) error {
	key := marshalTunnelKey(name)
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) TunnelIterator(fn func(Tunnel Tunnel) error) error {
	prefix := sconv.ByteSlice(PrefixTunnel)
	return d.db.View(func(tx *bbolt.Tx) error {
		cursor := tx.Bucket(bucketName).Cursor()
		for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
			var Tunnel Tunnel
			if err := json.Unmarshal(value, &Tunnel); err != nil {
				return err
			}
			if err := fn(Tunnel); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListTunnel() ([]Tunnel, error) {
	Tunnels := []Tunnel{}
	err := d.TunnelIterator(func(Tunnel Tunnel) error {
		Tunnels = append(Tunnels, Tunnel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Tunnels, nil
}
