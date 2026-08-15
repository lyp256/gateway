package dao

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lyp256/gateway/sconv"
	"go.etcd.io/bbolt"
)

// DNSServer 是一条持久化的上游 DNS 服务配置。
// Name 作为存储与页面管理的唯一标识；Type 统一为 udp/dot/doh。
type DNSServer struct {
	Name     string     `json:"name"`
	Type     string     `json:"type"`
	Server   string     `json:"server,omitempty"`
	IP       netip.Addr `json:"ip,omitempty"`
	Insecure bool       `json:"insecure,omitempty"`
}

// marshalDNSServerKey 组装存储 key：PrefixDNSServer + name。
func marshalDNSServerKey(name string) []byte {
	return sconv.ByteSlice(MarshalKey(PrefixDNSServer, name))
}

// NormalizeDNSServer 校验并规范化上游 DNS 配置：
// 名称必填；类型收敛为 udp/dot/doh；域名去空格、小写并去掉末尾点；
// IP 按类型做必填校验（udp 必须，dot/doh 可选）。
func NormalizeDNSServer(s *DNSServer) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return fmt.Errorf("dns server name is required")
	}
	switch s.Type {
	case "":
		s.Type = "udp"
	case "udp", "dot", "doh":
	case "tls":
		s.Type = "dot"
	case "https":
		s.Type = "doh"
	default:
		return fmt.Errorf("unsupported dns server type %q", s.Type)
	}
	s.Server = strings.TrimSpace(s.Server)
	s.Server = strings.ToLower(strings.TrimSuffix(s.Server, "."))
	if s.IP.IsValid() {
		s.IP = s.IP.Unmap()
	}
	switch s.Type {
	case "udp":
		if !s.IP.IsValid() {
			return fmt.Errorf("udp dns server requires a valid ip")
		}
	case "dot":
		if s.Server == "" && !s.IP.IsValid() {
			return fmt.Errorf("dot dns server requires a domain or ip")
		}
	case "doh":
		if s.Server == "" {
			return fmt.Errorf("doh dns server requires a domain")
		}
	}
	return nil
}

func (d *Dao) SetDNSServer(s DNSServer) error {
	if err := NormalizeDNSServer(&s); err != nil {
		return err
	}
	key := marshalDNSServerKey(s.Name)
	value, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, value)
	})
}

func (d *Dao) GetDNSServer(name string) (DNSServer, error) {
	key := marshalDNSServerKey(name)
	var s DNSServer
	err := d.db.View(func(tx *bbolt.Tx) error {
		value := tx.Bucket(bucketName).Get(key)
		if value == nil {
			return ErrKeyNotFound
		}
		return json.Unmarshal(value, &s)
	})
	if err != nil {
		return DNSServer{}, err
	}
	return s, nil
}

func (d *Dao) DeleteDNSServer(name string) error {
	key := marshalDNSServerKey(name)
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket.Get(key) == nil {
			return ErrKeyNotFound
		}
		return bucket.Delete(key)
	})
}

func (d *Dao) DNSServerIterator(fn func(s DNSServer) error) error {
	prefix := sconv.ByteSlice(PrefixDNSServer)
	return d.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var s DNSServer
			if err := json.Unmarshal(v, &s); err != nil {
				return err
			}
			if err := fn(s); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dao) ListDNSServer() ([]DNSServer, error) {
	list := []DNSServer{}
	err := d.DNSServerIterator(func(s DNSServer) error {
		list = append(list, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// DNSServersInitialized 返回数据库是否已完成上游 DNS 的首次初始化。
// 首次启动时由 server 从 config 默认值写入；之后以页面/数据库配置为准。
func (d *Dao) DNSServersInitialized() (bool, error) {
	key := sconv.ByteSlice(MarshalKey(PrefixMeta, "dns-servers-initialized"))
	var initialized bool
	err := d.db.View(func(tx *bbolt.Tx) error {
		initialized = tx.Bucket(bucketName).Get(key) != nil
		return nil
	})
	return initialized, err
}

// MarkDNSServersInitialized 记录上游 DNS 已完成首次初始化。
func (d *Dao) MarkDNSServersInitialized() error {
	key := sconv.ByteSlice(MarshalKey(PrefixMeta, "dns-servers-initialized"))
	return d.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, []byte("1"))
	})
}
