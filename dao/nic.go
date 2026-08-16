package dao

import (
	"bytes"
	"errors"
	"strings"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

// mountAllNicsMetaKey 是“启动时挂载全部可挂载网卡”全局开关的存储 key。
var mountAllNicsMetaKey = []byte(MarshalKey(PrefixMeta, "nic-mount-all"))

// marshalNicMountKey 组装存储 key：PrefixNicMount + 网卡名称。
func marshalNicMountKey(name string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixNicMount, name))
}

// SetNicAutoMount 持久化指定网卡的自动挂载开关（程序启动时生效）。
// 关闭不存在的开关是幂等操作，不返回错误。
func (d *Dao) SetNicAutoMount(name string, enabled bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("nic name is required")
	}
	key := marshalNicMountKey(name)
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if enabled {
			return bucket.Put(key, []byte("1"))
		}
		return bucket.Delete(key)
	})
}

// NicAutoMountIterator 遍历全部勾选了自动挂载的网卡名称。
func (d *Dao) NicAutoMountIterator(fn func(name string) error) error {
	prefix := sconv.ByteSlice(PrefixNicMount)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if err := fn(TrimKeyPrefix(sconv.String(k))); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListNicAutoMount 返回全部勾选了自动挂载的网卡名称。
func (d *Dao) ListNicAutoMount() ([]string, error) {
	var names []string
	err := d.NicAutoMountIterator(func(name string) error {
		names = append(names, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return names, nil
}

// SetMountAllNics 持久化“启动时挂载全部可挂载网卡”全局开关。
func (d *Dao) SetMountAllNics(enabled bool) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if enabled {
			return bucket.Put(mountAllNicsMetaKey, []byte("1"))
		}
		return bucket.Delete(mountAllNicsMetaKey)
	})
}

// MountAllNicsEnabled 返回“启动时挂载全部可挂载网卡”全局开关，未配置时为 false。
func (d *Dao) MountAllNicsEnabled() (bool, error) {
	var enabled bool
	err := d.db.View(func(tx *bbolt.Tx) error {
		enabled = tx.Bucket(bucketName).Get(mountAllNicsMetaKey) != nil
		return nil
	})
	return enabled, err
}
