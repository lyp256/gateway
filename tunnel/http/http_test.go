package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

var defAddr = netip.MustParsePrefix("192.168.1.1/24")

func runTUNServer(t *testing.T) (string, func(), error) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		err := rc.EnableFullDuplex()
		if err != nil {
			return
		}
		var res HandshakeRespone
		res.SetStatus(StatusOK)
		res.SetIP(defAddr)
		conn, err := HTTPServerHandshake(w, r, res)
		buf := make([]byte, 1500)
		if err != nil {
			return
		}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	})
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", nil, err
	}

	addr := listener.Addr().(*net.TCPAddr)

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Addr:      ":18800",
		Handler:   http.DefaultServeMux,
		Protocols: protocols,
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("runTUNServer: ListenAndServe %s", err)
		}
	}()
	return fmt.Sprintf("http://127.0.0.1:%d", addr.Port), func() {
		_ = server.Shutdown(context.Background())
		_ = listener.Close()

	}, nil
}

func TestStream(t *testing.T) {
	url, clear, err := runTUNServer(t)
	require.NoError(t, err)
	defer clear()

	const testData = "foobar"
	t.Run("DialHTTPRawTunnel", func(t *testing.T) {
		conn, res, err := DialHTTPRawTunnel(context.Background(), http.MethodPost, url, nil)
		require.NoError(t, err)
		defer conn.Close()
		require.Equal(t, defAddr, res.IP())
		n, err := conn.Write([]byte(testData))
		require.NoError(t, err)
		require.Equal(t, len(testData), n)
		buf := make([]byte, len(testData))
		n, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		require.Equal(t, len(buf), n)
		require.Equal(t, testData, string(buf))
	})

	t.Run("DialHTTPStreamTunnel", func(t *testing.T) {
		conn, res, err := DialHTTPStreamTunnel(context.Background(), H2CClient, http.MethodPost, url, nil)
		require.NoError(t, err)
		defer conn.Close()
		require.Equal(t, defAddr, res.IP())
		n, err := conn.Write([]byte(testData))
		require.NoError(t, err)
		require.Equal(t, len(testData), n)
		buf := make([]byte, len(testData))
		n, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		require.Equal(t, len(buf), n)
		require.Equal(t, testData, string(buf))
	})

}
