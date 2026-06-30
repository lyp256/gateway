package query

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// testTLSConfig 生成一张用于测试的自签名证书，SAN 中包含 serverName 与 127.0.0.1，
// 返回服务端 TLS 配置。
func testTLSConfig(t *testing.T, serverName string) *tls.Config {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{serverName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// startDoTServer 在本地随机端口启动一个 DNS-over-TLS 上游服务。
func startDoTServer(t *testing.T, handler dns.Handler, tlsCfg *tls.Config) (addr string, closeFn func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}

	started := make(chan struct{})
	srv := &dns.Server{
		Net:      "tcp",
		Listener: ln,
		Handler:  handler,
		NotifyStartedFunc: func(context.Context) {
			close(started)
		},
	}
	go func() { _ = srv.ListenAndServe() }()
	<-started

	return ln.Addr().String(), func() { srv.Shutdown(context.TODO()) }
}

func TestDoT_Query_Insecure(t *testing.T) {
	tlsCfg := testTLSConfig(t, "dns.example.com")
	addr, closeFn := startDoTServer(t, testHandler(), tlsCfg)
	defer closeFn()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	ip := netipMustParse(t, host)
	port := mustParsePort(t, portStr)

	// insecure=true 跳过证书校验，serverName 仅用于 SNI。
	q := NewDoT("dns.example.com", port, ip, true)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	r, _, err := q.Query(m)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.Addr.String() != testAnswerIP {
		t.Errorf("answer = %v, want %s", r.Answer[0], testAnswerIP)
	}
}

func TestDoT_Query_CertVerifyFails(t *testing.T) {
	tlsCfg := testTLSConfig(t, "dns.example.com")
	addr, closeFn := startDoTServer(t, testHandler(), tlsCfg)
	defer closeFn()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	ip := netipMustParse(t, host)
	port := mustParsePort(t, portStr)

	// insecure=false 且 serverName 与证书不匹配（wrong.example.com 不在 SAN 中），应校验失败。
	q := NewDoT("wrong.example.com", port, ip, false)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	if _, _, err := q.Query(m); err == nil {
		t.Error("Query() error = nil, want TLS verification error")
	}
}

func TestDoT_Name(t *testing.T) {
	// ip 无效时使用 serverName 构造地址。
	q := NewDoT("dns.example.com", 853, netip.Addr{}, false)
	if got, want := q.Name(), "tls://dns.example.com:853"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}
