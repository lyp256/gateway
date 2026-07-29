package pprof

import (
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
)

func DebugServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		slog.Error("debug server ListenAndServe ", "error", err)
	}
}

func DebugServerWithENV() {
	addr := os.Getenv("DEBUG_ADDR")
	if addr == "" {
		return
	}
	slog.Debug("start debug server", "addr", addr)
	go DebugServer(addr)
}
