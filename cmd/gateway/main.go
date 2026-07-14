package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/lyp256/gateway/config"
	"github.com/lyp256/gateway/server"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cfg := config.GetConfig()
	level, err := config.LogLevel(cfg.LogLevel)
	if err != nil {
		slog.Error("parse level", "err", err)
		return
	}
	slog.SetLogLoggerLevel(level)

	s, err := server.NewServer(cfg)
	if err != nil {
		slog.Error("server", "err", err)
		return

	}
	func() {
		defer cancel()
		err = s.Run(ctx)
		slog.Error("server exited", "err", err)
	}()
}
