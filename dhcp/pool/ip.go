package pool

import (
	"errors"
	"math/bits"
	"net/netip"
	"sync"
)

var (
	ErrInvalidCIDR        = errors.New("invalid CIDR")
	ErrIPv4Only           = errors.New("DHCP pool only supports IPv4 CIDR")
	ErrNoUsableAddress    = errors.New("CIDR has no usable IP addresses")
	ErrPoolExhausted      = errors.New("IP address pool exhausted")
	ErrInvalidIP          = errors.New("invalid IPv4 address")
	ErrIPOutOfRange       = errors.New("IP out of pool range")
	ErrIPNotAllocated     = errors.New("IP is not allocated")
	ErrIPAlreadyAllocated = errors.New("IP is already allocated")
)

type DHCPPool struct {
	mu       sync.Mutex
	maskbits int
	baseIP   uint32   // 起始 IP 的整数形式
	totalIPs int      // 总 IP 数量
	bitmap   []uint64 // 位图，每位代表一个 IP 是否被占用
}

func UsableIPv4AddressCount(cidr netip.Prefix) (int, error) {
	if !cidr.IsValid() {
		return 0, ErrInvalidCIDR
	}

	cidr = cidr.Masked()
	if !cidr.Addr().Is4() {
		return 0, ErrIPv4Only
	}

	hostBits := 32 - cidr.Bits()
	if hostBits <= 1 {
		return 0, ErrNoUsableAddress
	}

	return 1<<hostBits - 2, nil
}

// NewDHCPPool 根据 CIDR 初始化 IP 池
func NewDHCPPool(cidr netip.Prefix) (*DHCPPool, error) {
	cidr = cidr.Masked()
	usableCount, err := UsableIPv4AddressCount(cidr)
	if err != nil {
		return nil, err
	}

	firstIP := cidr.Addr().Next()
	total := int(usableCount)

	baseIP := addrToUint32(firstIP)
	// 每个 uint64 可以表示 64 个 IP
	bitmapSize := (total + 63) / 64

	return &DHCPPool{
		baseIP:   baseIP,
		totalIPs: total,
		maskbits: cidr.Bits(),
		bitmap:   make([]uint64, bitmapSize),
	}, nil
}

// Allocate 申请一个空闲 IP (类似 DHCP Request)
func (p *DHCPPool) Allocate() (netip.Prefix, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, bucket := range p.bitmap {
		// 如果 bucket 全是 1 (^bucket == 0)，说明这 64 个 IP 全被占满了
		if ^bucket == 0 {
			continue
		}

		// 寻找第一个为 0 的位 (取反后寻找第一个 1)
		trailingZeros := bits.TrailingZeros64(^bucket)
		offset := i*64 + trailingZeros

		if offset >= p.totalIPs {
			break
		}

		// 将该位置为 1 (标记为已分配)
		p.bitmap[i] |= uint64(1) << trailingZeros

		// 算出实际 IP 并返回
		allocatedIP := uint32ToIP(p.baseIP + uint32(offset))
		return netip.PrefixFrom(allocatedIP, p.maskbits), nil
	}
	return netip.Prefix{}, ErrPoolExhausted
}

// Release 释放/归还 IP (类似 DHCP Release)
func (p *DHCPPool) Release(ip netip.Addr) error {
	bucketIndex, bitIndex, err := p.ipPosition(ip)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	mask := uint64(1) << bitIndex
	if p.bitmap[bucketIndex]&mask == 0 {
		return ErrIPNotAllocated
	}

	// 将对应位清零 (与非操作)
	p.bitmap[bucketIndex] &^= mask
	return nil
}

// IsAllocated reports whether ip has been allocated from this pool.
func (p *DHCPPool) IsAllocated(ip netip.Addr) (bool, error) {
	bucketIndex, bitIndex, err := p.ipPosition(ip)
	if err != nil {
		return false, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.bitmap[bucketIndex]&(uint64(1)<<bitIndex) != 0, nil
}

// AllocateIP allocates the specified available IP address from this pool.
func (p *DHCPPool) AllocateIP(ip netip.Addr) (netip.Prefix, error) {
	bucketIndex, bitIndex, err := p.ipPosition(ip)
	if err != nil {
		return netip.Prefix{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	mask := uint64(1) << bitIndex
	if p.bitmap[bucketIndex]&mask != 0 {
		return netip.Prefix{}, ErrIPAlreadyAllocated
	}

	p.bitmap[bucketIndex] |= mask
	return netip.PrefixFrom(ip, p.maskbits), nil
}

func (p *DHCPPool) ipPosition(ip netip.Addr) (bucketIndex, bitIndex int, err error) {
	if !ip.IsValid() || !ip.Is4() {
		return 0, 0, ErrInvalidIP
	}

	ipInt := addrToUint32(ip)
	if ipInt < p.baseIP || ipInt >= p.baseIP+uint32(p.totalIPs) {
		return 0, 0, ErrIPOutOfRange
	}

	offset := int(ipInt - p.baseIP)
	return offset / 64, offset % 64, nil
}

// 工具函数：IPv4 转 uint32
func addrToUint32(ip netip.Addr) uint32 {
	bytes := ip.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// 工具函数：uint32 转 IPv4
func uint32ToIP(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}
