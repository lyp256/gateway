package dao

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

type CidrRule struct {
	Cidr   string `json:"cidr"`
	Egress string `json:"egress"`
}

// marshalCidrRuleKey 组装存储 key：PrefixCidr + cidr。
func marshalCidrRuleKey(cidr string) []byte {
	return sconv.ByteSlice(MarshalKey(PrifixCidr, cidr))
}

func (d *Dao) SetCidrRule(cr CidrRule) error {
	key := marshalCidrRuleKey(cr.Cidr)
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket.Get(marshalEgressKey(cr.Egress)) == nil {
			return fmt.Errorf("%w: %s", ErrEgressNotFound, cr.Egress)
		}
		return bucket.Put(key, []byte(cr.Egress))
	})
}

func (d *Dao) GetCidrRule(cidr string) (CidrRule, error) {
	key := marshalCidrRuleKey(cidr)
	cr := CidrRule{Cidr: cidr}
	err := d.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketName).Get(key)
		if v == nil {
			return ErrKeyNotFound
		}
		cr.Egress = string(v)
		return nil
	})
	if err != nil {
		return CidrRule{}, err
	}
	return cr, nil
}

func (d *Dao) DeleteCidrRule(cidr string) error {
	key := marshalCidrRuleKey(cidr)
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) CidrRuleIterator(fn func(cr CidrRule) error) error {
	prefix := sconv.ByteSlice(PrifixCidr)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			cr := CidrRule{
				Cidr: TrimKeyPrefix(sconv.String(k)),
			}
			cr.Egress = string(v)
			if err := fn(cr); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListCidrRule() ([]CidrRule, error) {
	var list []CidrRule
	err := d.CidrRuleIterator(func(cr CidrRule) error {
		list = append(list, cr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// NormalizeCidr 校验并规范化 CIDR：仅支持 IPv4 且必须携带前缀长度。
func NormalizeCidr(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid cidr %q", s)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("only IPv4 cidr is supported, got %q", s)
	}
	return prefix.Masked(), nil
}
