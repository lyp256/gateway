package controller

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func BenchmarkLocalAddr(b *testing.B) {

	for i := 0; i < b.N; i++ {
		LocalAddr()
	}

}
func BenchmarkLazyLocalAddr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lazyLocalAddr()
	}

}

func TestParseIPv4OrigDst(t *testing.T) {
	data := []byte{
		0x02, 0x00,
		0x00, 0x35,
		0x08, 0x08, 0x08, 0x08,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	got, err := parseIPv4OrigDst(data)
	if err != nil {
		t.Fatalf("parseIPv4OrigDst returned error: %v", err)
	}

	want := netip.MustParseAddrPort("8.8.8.8:53")
	if got != want {
		t.Fatalf("parseIPv4OrigDst = %v, want %v", got, want)
	}
}

func TestParseRequestDstFromPktInfo(t *testing.T) {
	oob := makeIPv4PktInfoOOB([4]byte{8, 8, 8, 8})

	got, err := parseRequestDstFromCmsgs(oob)
	if err != nil {
		t.Fatalf("parseRequestDstFromCmsgs returned error: %v", err)
	}

	want := netip.MustParseAddrPort("8.8.8.8:53")
	if got != want {
		t.Fatalf("parseRequestDstFromCmsgs = %v, want %v", got, want)
	}
}

func makeIPv4PktInfoOOB(dst [4]byte) []byte {
	oob := make([]byte, unix.CmsgSpace(12))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(12))
	copy(oob[unix.CmsgSpace(0)+8:], dst[:])
	return oob
}
