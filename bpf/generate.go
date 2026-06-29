package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -go-package bpf Filter src/filter.c
