package dao

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/lyp256/gateway/dns/router"
	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

type DomainRule struct {
	Match  router.MatchType `json:"match"`
	Domain string           `json:"domain"`
	Fwmark uint32           `json:"fwmark"`
}

func ParseDomainRuleKey[T string | []byte](key T) (uint32, T) {
	if len(key) == 0 {
		return 0, key
	}
	switch key[0] {
	case 'S', 'F':
		return uint32(key[0]), key[1:]
	}
	return 0, key
}

// marshalDomainRuleKey 组装存储 key：PrefixDomainRule + 匹配前缀 + domain。
func marshalDomainRuleKey(match router.MatchType, domain string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixDomainRule, string(match)+domain))
}

func (d *Dao) SetDomainRule(dr DomainRule) error {
	key := marshalDomainRuleKey(dr.Match, dr.Domain)
	return d.db.Update(func(tx *bbolt.Tx) error {
		val := make([]byte, 4)
		binary.BigEndian.PutUint32(val, dr.Fwmark)
		return tx.Bucket(bucketName).Put(key, val)
	})
}

func (d *Dao) GetDomainRule(match router.MatchType, domain string) (DomainRule, error) {
	key := marshalDomainRuleKey(match, domain)
	dr := DomainRule{Match: match, Domain: domain}
	err := d.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketName).Get(key)
		if v == nil {
			return ErrKeyNotFound
		}
		if len(v) != 4 {
			return fmt.Errorf("invalid value")
		}
		dr.Fwmark = binary.BigEndian.Uint32(v)
		return nil
	})
	if err != nil {
		return DomainRule{}, err
	}
	return dr, nil
}

func (d *Dao) DeleteDomainRule(match router.MatchType, domain string) error {
	key := marshalDomainRuleKey(match, domain)
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete(key)
	})
}

func (d *Dao) DomainRuleIterator(fn func(dr DomainRule) error) error {
	prefix := sconv.ByteSlice(PrefixDomainRule)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			match, domain := ParseDomainRuleKey(TrimKeyPrefix(sconv.String(k)))
			dr := DomainRule{
				Match:  router.MatchType(match),
				Domain: domain,
			}
			if len(v) != 4 {
				return fmt.Errorf("invalid value")
			}
			dr.Fwmark = binary.BigEndian.Uint32(v)
			if err := fn(dr); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListDomainRule(match *router.MatchType) ([]DomainRule, error) {
	var list []DomainRule
	err := d.DomainRuleIterator(func(dr DomainRule) error {
		if match != nil && *match != dr.Match {
			return nil
		}
		list = append(list, dr)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}
