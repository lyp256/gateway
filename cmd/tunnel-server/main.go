package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	tunnelHttp "github.com/lyp256/gateway/tunnel/http"
)

func main() {
	mtu := pflag.Uint16P("mtu", "", 1500, "tunnel device mtu")
	port := pflag.Uint16P("port", "", 80, "tunnel server http port")
	devName := pflag.StringP("device-name", "n", "tunnel-server", "tunnel device name")
	cidrNet := pflag.IPNetP("cidr", "", net.IPNet{
		IP:   net.IPv4(198, 18, 18, 0),
		Mask: net.CIDRMask(24, 32),
	}, "runnel cidr")
	pflag.Parse()
	ones, _ := cidrNet.Mask.Size()
	cidr := netip.PrefixFrom(netip.AddrFrom4([4]byte(cidrNet.IP.To4())), ones)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	handler, err := tunnelHttp.NewServer(*mtu, *devName, cidr)
	if err != nil {
		slog.Error("create tunnel server", "error", err)
		os.Exit(1)
	}
	go func() {
		err = handler.Run(ctx)
		if err != nil {
			slog.Error(" handler.Run", "error", err)
			os.Exit(1)
		}
	}()

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *port),
		Handler:   handler,
		Protocols: protocols,
	}
	err = server.ListenAndServe()
	if err != nil {
		slog.Error(" handler.Run", "error", err)
		os.Exit(1)
	}
}
