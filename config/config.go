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
