package config

import (
	"fmt"
	"log/slog"
	"strings"
)

var defaultConfig = Config{
	LogLevel:  "debug",
	DNSPort:   5453,
	HTTPPort:  80,
	DBStorage: "db",
	// Keep the original marks as defaults while allowing deployments to avoid
	// collisions with their existing policy-routing rules.
	DNSTproxyFwmark: 0x1,
	TCPTproxyFwmark: 0x2,
}

type Config struct {
	// log level
	LogLevel string
	// http 服务监听
	HTTPPort uint16
	// dns 服务监听地址
	DNSPort uint16
	// DNS/TCP 透明代理使用的策略路由 mark。
	DNSTproxyFwmark uint32
	TCPTproxyFwmark uint32
	// 存储目录
	DBStorage string
}

func GetConfig() Config {
	return defaultConfig
}

func LogLevel(l string) (slog.Level, error) {
	switch strings.ToLower(l) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "err", "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level: %s", l)

	}
}
