package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	AF_INET  = 2  // IPv4
	AF_INET6 = 10 // IPv6
)

const (
	EventSniffers  = 1
	EventTcpStream = 2
)

func ToFilterBpfLpmTrieKeyV4(ip netip.Prefix) FilterBpfLpmTrieKeyV4 {
	buf := ip.Addr().As4()
	return FilterBpfLpmTrieKeyV4{
		Prefixlen: uint8(ip.Bits()),
		Data:      binary.BigEndian.Uint32(buf[:]),
	}
}

func FromFilterBpfLpmTrieKeyV4(key FilterBpfLpmTrieKeyV4) netip.Prefix {
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], key.Data)
	return netip.PrefixFrom(netip.AddrFrom4(ip), int(key.Prefixlen))
}

type TcpStream struct {
	Src  netip.AddrPort
	Dest netip.AddrPort
}

const TcpStreamBufferSize = 37

func ParseTcpStream(buf []byte, v *TcpStream) error {
	if len(buf) < TcpStreamBufferSize {
		return fmt.Errorf("invalid TCP stream buf")
	}
	var (
		saddr, daddr netip.Addr
		sport, dport uint16
	)
	kind := buf[0]
	buf = buf[1:]
	switch kind {
	case AF_INET:
		saddr = netip.AddrFrom4([4]byte(buf))
		buf = buf[4:]
		daddr = netip.AddrFrom4([4]byte(buf))
		buf = buf[4:]
		sport = binary.BigEndian.Uint16(buf)
		buf = buf[2:]
		dport = binary.BigEndian.Uint16(buf)
	case AF_INET6:
		saddr = netip.AddrFrom16([16]byte(buf))
		buf = buf[16:]
		daddr = netip.AddrFrom16([16]byte(buf))
		buf = buf[16:]
		sport = binary.BigEndian.Uint16(buf)
		buf = buf[2:]
		dport = binary.BigEndian.Uint16(buf)
	}
	v.Src = netip.AddrPortFrom(saddr, sport)
	v.Dest = netip.AddrPortFrom(daddr, dport)
	return nil

}
