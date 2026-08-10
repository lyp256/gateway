package http

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"golang.org/x/net/http2"
)

const (
	StatusOK byte = iota
	StatusInvalidParams
	StatusUnauthorized
	StatusNoIP
)

var ErrInvalidCRC32Sum = errors.New("invalid crc32 sum")

// HandshakeRespone 握手包
// 结构如下
//
//	┌───────────┬───────────┬───────────┬──────────┐
//	│  1 byte   │  4 byte   │  1 byte   │  4 byte  │
//	├───────────┼───────────┼───────────┼──────────┤
//	│  状态     │ ipv4 地址 │  ip 前缀   │ crc32 sum│
//	└───────────┴───────────┴───────────┴──────────┘
type HandshakeRespone [10]byte

func (h *HandshakeRespone) SetIP(ip netip.Prefix) {
	ip4 := ip.Addr().As4()
	copy(h[1:5], ip4[:])
	h[5] = byte(ip.Bits())
}

func (h *HandshakeRespone) IP() netip.Prefix {
	addr := netip.AddrFrom4([4]byte(h[1:5]))
	return netip.PrefixFrom(addr, int(h[5]))
}

func (h *HandshakeRespone) SetStatus(s byte) {
	h[0] = s
}

func (h *HandshakeRespone) Status() byte {
	return h[0]
}

func (h *HandshakeRespone) Sum() {
	n := len(h)
	ha := crc32.NewIEEE()
	_, _ = ha.Write(h[:n-4])
	binary.BigEndian.PutUint32(h[n-4:], ha.Sum32())
}

func (h *HandshakeRespone) Verify() error {
	n := len(h)
	ha := crc32.NewIEEE()
	_, _ = ha.Write(h[:n-4])
	if ha.Sum32() != binary.BigEndian.Uint32(h[n-4:]) {
		return ErrInvalidCRC32Sum
	}
	return nil
}

// DialHTTPRawTunnel 基于 http 1.1 的 底层连接(TCP/TLS) tunnel
func DialHTTPRawTunnel(ctx context.Context, method string, url string, header http.Header) (io.ReadWriteCloser, *HandshakeRespone, error) {
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("http.NewRequest:%w", err)
	}
	addr := serverAddr(request.URL)
	var conn net.Conn
	switch request.URL.Scheme {
	case "http":
		conn, err = net.Dial("tcp", addr)
	case "https":
		conn, err = tls.Dial("tcp", addr, nil)
	default:
		return nil, nil, fmt.Errorf("unsupport scheme '%s'", request.URL.Scheme)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("net.Dial:%w", err)
	}
	request.Header = header
	err = request.Write(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("request.Write:%w", err)
	}
	var res HandshakeRespone
	buf := res[:]
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("io.ReadFull:%w", err)
	}
	if len(buf) != n {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("invalid handshak message")
	}
	err = res.Verify()
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("invalid handshak message:%w", err)
	}
	if res.Status() != StatusOK {
		_ = conn.Close()
		return nil, &res, fmt.Errorf("server error status:%d", res.Status())
	}

	return conn, &res, nil
}

// DialHTTPStreamTunnel 基于 http 2/3 的 stream  tunnel, stream 开销大于 raw tunnel
func DialHTTPStreamTunnel(ctx context.Context, client *http.Client, method string, url string, header http.Header) (io.ReadWriteCloser, *HandshakeRespone, error) {
	bodyR, bodyW := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, method, url, bodyR)
	if err != nil {
		_ = bodyR.Close()
		_ = bodyW.Close()
		return nil, nil, err
	}
	request.Header = header
	response, err := client.Do(request)
	if err != nil {
		_ = bodyR.Close()
		_ = bodyW.Close()
		return nil, nil, err
	}
	stream := &h2Stream{
		writer: bodyW,
		reader: io.NopCloser(response.Body),
	}
	var res HandshakeRespone
	buf := res[:]
	n, err := io.ReadFull(stream, buf)
	if err != nil {
		_ = stream.Close()
		return nil, nil, err
	}
	if len(buf) != n {
		_ = stream.Close()
		return nil, nil, fmt.Errorf("invalid handshak message")
	}
	err = res.Verify()
	if err != nil {
		_ = stream.Close()
		return nil, nil, fmt.Errorf("invalid handshak message:%w", err)
	}
	if res.Status() != StatusOK {
		_ = stream.Close()
		return nil, &res, fmt.Errorf("server error status:%d", res.Status())
	}
	return stream, &res, nil

}

var H2CClient = &http.Client{
	Transport: &http2.Transport{
		// AllowHTTP 允许非 TLS 的 HTTP/2 连接
		AllowHTTP: true,
		// DialTLS 覆盖默认的 TLS 拨号，直接建立明文 TCP 连接
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	},
}

func HTTPServerHandshake(w http.ResponseWriter, r *http.Request, res HandshakeRespone) (io.ReadWriteCloser, error) {
	rc := http.NewResponseController(w)
	err := rc.EnableFullDuplex()
	if err != nil {
		return nil, err
	}

	var conn io.ReadWriteCloser
	switch r.ProtoMajor {
	case 1:
		conn, _, err = rc.Hijack()
		if err != nil {
			return nil, err
		}
	case 2, 3:
		conn = &h2Stream{
			flusher: rc.Flush,
			writer:  nopWriteCloser{Writer: w},
			reader:  r.Body,
		}
	default:
		return nil, http.ErrNotSupported
	}
	res.Sum()
	_, err = conn.Write(res[:])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if res.Status() != StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("failed by status")
	}
	return conn, nil
}

type h2Stream struct {
	flusher func() error
	writer  io.WriteCloser
	reader  io.ReadCloser
}

func (h *h2Stream) Read(p []byte) (n int, err error) {
	return h.reader.Read(p)
}

func (h *h2Stream) Write(p []byte) (n int, err error) {
	n, err = h.writer.Write(p)
	if err != nil {
		return
	}
	if h.flusher != nil {
		_ = h.flusher()
	}
	return
}

func (h *h2Stream) Close() error {
	errs := make([]error, 0, 2)
	err := h.reader.Close()
	if err != nil {
		errs = append(errs, err)
	}
	err = h.writer.Close()
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func serverAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}

	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}
