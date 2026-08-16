package schema

// Nic 描述一块系统网卡及其 eBPF 程序挂载状态。
type Nic struct {
	// Index 是内核网卡索引（ifindex）。
	Index int `json:"index"`
	// Name 是网卡名称，作为挂载/解除挂载 API 的标识。
	Name string `json:"name"`
	// Type 是 netlink 报告的网卡类型，例如 device/bridge/veth/loopback。
	Type string `json:"type"`
	// MAC 是网卡硬件地址，虚拟网卡可能为空。
	MAC string `json:"mac,omitempty"`
	// MTU 是当前 MTU。
	MTU int `json:"mtu"`
	// State 是内核操作状态（up/down/unknown 等）。
	State string `json:"state"`
	// Flags 是可读的链路标志列表。
	Flags []string `json:"flags,omitempty"`
	// Addresses 是网卡绑定的 IP 地址列表。
	Addresses []string `json:"addresses,omitempty"`
	// Attached 表示 tc_gateway_filter 是否已挂载到该网卡。
	Attached bool `json:"attached"`
	// AutoMount 表示程序启动时是否自动将 eBPF 挂载到该网卡。
	AutoMount bool `json:"auto_mount"`
}

// BPFStatus 描述 eBPF 数据面运行状态，供页面展示挂载能力。
type BPFStatus struct {
	// Ready 表示 eBPF 程序已加载完成，可以执行挂载/解除挂载。
	Ready bool `json:"ready"`
	// Program 是数据面程序名（tc_gateway_filter）。
	Program string `json:"program"`
	// Interfaces 是当前已挂载程序的网卡数量。
	Interfaces int `json:"interfaces"`
}

// BPFSettings 描述 eBPF 网卡挂载的启动策略。
type BPFSettings struct {
	// MountAll 启用后程序启动时自动挂载所有可挂载网卡。
	MountAll bool `json:"mount_all"`
}
