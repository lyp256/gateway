package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
)

var defaultConfig = Config{
	LogLevel:  "debug",
	DNSPort:   5453,
	HTTPPort:  80,
	Hosts:     map[string]netip.Addr{},
	DBStorage: "db",
	DNSServers: []DNSServer{
		{
			Type:   "doh",
			Server: "doh.pub",
			IP:     netip.MustParseAddr("1.12.12.12"),
		},
	},
}

type Config struct {
	// log level
	LogLevel string
	// http 服务监听
	HTTPPort uint16
	// dns 服务监听地址
	DNSPort uint16
	// 存储目录
	DBStorage string

	// 上游dns 地址
	DNSServers []DNSServer
	// 静态解析
	Hosts map[string]netip.Addr
}

type DNSServer struct {
	Type     string
	IP       netip.Addr
	Server   string
	Insecure bool
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
