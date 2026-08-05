package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lyp256/gateway/pprof"
	tunnelHttp "github.com/lyp256/gateway/tunnel/http"
	"github.com/spf13/pflag"
)

func init() {
	pprof.DebugServerWithENV()
}

func main() {
	u := pflag.StringP("url", "", "", "")
	method := pflag.StringP("method", "", "POST", "http method")
	h := pflag.StringArrayP("header", "", nil, "http header key:value ")
	devName := pflag.StringP("device-name", "", "tun-http", "tunnel device name")
	pflag.Parse()
	header := make(http.Header)
	for _, item := range *h {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) == 2 {
			header.Set(parts[0], parts[1])
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	client, err := tunnelHttp.NewClient(*method, *u, header, *devName, 1350)
	if err != nil {
		slog.Error("create tunnel client", "error", err)
		os.Exit(1)
	}
	err = client.Run(ctx)
	if err != nil {
		slog.Error("run tunnel client", "error", err)
		os.Exit(1)
	}
}
