package bpf

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func TestNewTproxyEgressRule(t *testing.T) {
	rule, err := NewTproxyEgressRule(netip.MustParseAddr("127.0.0.1"), 12345)
	if err != nil {
		t.Fatalf("new tproxy rule: %v", err)
	}
	if rule.Type != EgressRuleTproxy {
		t.Fatalf("rule type = %d, want %d", rule.Type, EgressRuleTproxy)
	}
	if rule.TproxyAddr != [4]uint8{127, 0, 0, 1} {
		t.Fatalf("tproxy addr = %v, want [127 0 0 1]", rule.TproxyAddr)
	}
	if rule.TproxyPort != [2]uint8{0x30, 0x39} { // 12345 = 0x3039，网络字节序
		t.Fatalf("tproxy port = %v, want [0x30 0x39]", rule.TproxyPort)
	}

	// 全零 addr/port 表示按包原目的地址/端口查找。
	rule, err = NewTproxyEgressRule(netip.Addr{}, 0)
	if err != nil {
		t.Fatalf("new wildcard tproxy rule: %v", err)
	}
	if rule.TproxyAddr != [4]uint8{} || rule.TproxyPort != [2]uint8{} {
		t.Fatalf("wildcard tproxy rule = %v:%v, want all zero", rule.TproxyAddr, rule.TproxyPort)
	}

	if _, err := NewTproxyEgressRule(netip.MustParseAddr("::1"), 80); err == nil {
		t.Fatal("IPv6 tproxy addr should be rejected")
	}
}

func TestNewFwmarkEgressRule(t *testing.T) {
	rule := NewFwmarkEgressRule(4097)
	if rule.Type != EgressRuleFwmark || rule.Fwmark != 4097 {
		t.Fatalf("fwmark rule = %+v, want type %d fwmark 4097", rule, EgressRuleFwmark)
	}
}

func TestNewTproxyConfig(t *testing.T) {
	config, err := NewTproxyConfig(0x101, 0x102)
	if err != nil {
		t.Fatalf("new tproxy config: %v", err)
	}
	if config.DnsFwmark != 0x101 || config.TcpFwmark != 0x102 {
		t.Fatalf("tproxy config = %+v, want dns 0x101 tcp 0x102", config)
	}

	if _, err := NewTproxyConfig(0, 0x102); err == nil {
		t.Fatal("zero DNS mark should be rejected")
	}
	if _, err := NewTproxyConfig(0x101, 0); err == nil {
		t.Fatal("zero TCP mark should be rejected")
	}
	if _, err := NewTproxyConfig(0x101, 0x101); err == nil {
		t.Fatal("duplicate marks should be rejected")
	}
}

func TestNewDnsRedirectTarget(t *testing.T) {
	target, err := NewDnsRedirectTarget(netip.MustParseAddr("127.0.0.1"), 5453)
	if err != nil {
		t.Fatalf("new dns redirect target: %v", err)
	}
	if target.Addr != [4]uint8{127, 0, 0, 1} {
		t.Fatalf("dns redirect addr = %v, want [127 0 0 1]", target.Addr)
	}
	if target.Port != [2]uint8{0x15, 0x4d} { // 5453 = 0x154d，网络字节序
		t.Fatalf("dns redirect port = %v, want [0x15 0x4d]", target.Port)
	}
	if target.Enabled != 1 {
		t.Fatalf("dns redirect enabled = %d, want 1", target.Enabled)
	}

	// IPv6 地址不支持（当前数据面仅处理 IPv4）。
	if _, err := NewDnsRedirectTarget(netip.MustParseAddr("::1"), 5453); err == nil {
		t.Fatal("IPv6 dns redirect addr should be rejected")
	}
	// 端口 0 无意义。
	if _, err := NewDnsRedirectTarget(netip.MustParseAddr("127.0.0.1"), 0); err == nil {
		t.Fatal("zero dns redirect port should be rejected")
	}

	if got := DisabledDnsRedirectTarget(); got.Enabled != 0 {
		t.Fatalf("disabled target enabled = %d, want 0", got.Enabled)
	}
}

func TestParseTcpStreamIPv4(t *testing.T) {
	buf := make([]byte, TcpStreamBufferSizeV4)
	buf[0] = syscall.AF_INET
	buf[1] = 3 // egress index
	buf[2] = EgressRuleTproxy
	buf[3] = 0 // pad
	binary.NativeEndian.PutUint32(buf[4:8], 4097)
	copy(buf[8:12], []byte{192, 0, 2, 1})
	copy(buf[12:16], []byte{198, 51, 100, 7})
	binary.BigEndian.PutUint16(buf[16:18], 12345)
	binary.BigEndian.PutUint16(buf[18:20], 443)

	var stream TcpStream
	if err := ParseTcpStream(buf, &stream); err != nil {
		t.Fatalf("parse tcp stream: %v", err)
	}
	if stream.Src.String() != "192.0.2.1:12345" || stream.Dest.String() != "198.51.100.7:443" {
		t.Fatalf("parsed addr = %s -> %s", stream.Src, stream.Dest)
	}
	if stream.Mark != 4097 || stream.EgressIdx != 3 || stream.EgressType != EgressRuleTproxy {
		t.Fatalf("parsed meta = mark %d idx %d type %d", stream.Mark, stream.EgressIdx, stream.EgressType)
	}
}

func TestParseTcpStreamIPv6(t *testing.T) {
	buf := make([]byte, TcpStreamBufferSizeV6)
	buf[0] = syscall.AF_INET6
	buf[1] = 7 // egress index
	buf[2] = EgressRuleFwmark
	buf[3] = 0 // pad
	binary.NativeEndian.PutUint32(buf[4:8], 8194)
	copy(buf[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(buf[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	binary.BigEndian.PutUint16(buf[40:42], 12345)
	binary.BigEndian.PutUint16(buf[42:44], 53)

	var stream TcpStream
	if err := ParseTcpStream(buf, &stream); err != nil {
		t.Fatalf("parse tcp stream: %v", err)
	}
	if stream.Src.String() != "[2001:db8::1]:12345" || stream.Dest.String() != "[2001:db8::2]:53" {
		t.Fatalf("parsed addr = %s -> %s", stream.Src, stream.Dest)
	}
	if stream.Mark != 8194 || stream.EgressIdx != 7 || stream.EgressType != EgressRuleFwmark {
		t.Fatalf("parsed meta = mark %d idx %d type %d", stream.Mark, stream.EgressIdx, stream.EgressType)
	}
}

func TestParseTcpStreamInvalid(t *testing.T) {
	var stream TcpStream
	if err := ParseTcpStream([]byte{0, 1, 2, 3}, &stream); err == nil {
		t.Fatal("short buffer should fail")
	}
	bad := make([]byte, TcpStreamBufferSizeV4)
	bad[0] = 99 // unknown family
	if err := ParseTcpStream(bad, &stream); err == nil {
		t.Fatal("unknown family should fail")
	}
}
