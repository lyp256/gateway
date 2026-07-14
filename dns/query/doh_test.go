package query

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// dohTestHandler 返回一个 RFC 8484 的 DoH HTTP 处理器，对 A 查询返回固定地址。
func dohTestHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != dohContentType {
			t.Errorf("Content-Type = %q, want %q", ct, dohContentType)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		req.Data = body
		if err := req.Unpack(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := new(dns.Msg)
		dnsutil.SetReply(resp, req)
		if len(req.Question) > 0 {
			name, qtype := dnsutil.Question(req)
			if qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  name,
						Class: dns.ClassINET,
						TTL:   60,
					},
					A: rdata.A{Addr: netip.MustParseAddr(testAnswerIP)},
				})
			}
		}

		if err := resp.Pack(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(resp.Data)
	}
}

func TestDoH_Query(t *testing.T) {
	srv := httptest.NewTLSServer(dohTestHandler(t))
	defer srv.Close()

	// 使用测试服务器的自签名证书，因此需要 insecure=true。
	q := NewDoH(srv.URL, netip.Addr{}, true)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	r, rtt, err := q.Query(context.Background(), m)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.Addr.String() != testAnswerIP {
		t.Errorf("answer = %v, want %s", r.Answer[0], testAnswerIP)
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want > 0", rtt)
	}
}

func TestDoH_Query_Non200(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	q := NewDoH(srv.URL, netip.Addr{}, true)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	if _, _, err := q.Query(context.Background(), m); err == nil {
		t.Error("Query() error = nil, want error for non-200 status")
	}
}

func TestDoH_Query_CertVerifyFails(t *testing.T) {
	srv := httptest.NewTLSServer(dohTestHandler(t))
	defer srv.Close()

	// insecure=false，测试服务器证书未受信任，应校验失败。
	q := NewDoH(srv.URL, netip.Addr{}, false)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeA)

	if _, _, err := q.Query(context.Background(), m); err == nil {
		t.Error("Query() error = nil, want TLS verification error")
	}
}

func TestDoH_Name(t *testing.T) {
	url := "https://1.1.1.1/dns-query"
	q := NewDoH(url, netip.Addr{}, false)
	if got := q.Name(); got != url {
		t.Errorf("Name() = %q, want %q", got, url)
	}
}
