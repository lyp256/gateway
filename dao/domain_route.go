package dao

import (
	"bytes"
	"fmt"

	"github.com/lyp256/gateway/dns/router"
	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

type DomainRule struct {
	Match  router.MatchType `json:"match"`
	Domain string           `json:"domain"`
	Egress string           `json:"egress"`
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
		bucket := tx.Bucket(bucketName)
		if bucket.Get(marshalEgressKey(dr.Egress)) == nil {
			return fmt.Errorf("%w: %s", ErrEgressNotFound, dr.Egress)
		}
		return bucket.Put(key, []byte(dr.Egress))
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
		dr.Egress = string(v)
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
			dr.Egress = string(v)
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
