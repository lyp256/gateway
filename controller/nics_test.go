package controller

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lyp256/gateway/schema"
)

func TestNicsHTTP(t *testing.T) {
	ctl := newEgressTestController(t)

	// eBPF 未就绪时挂载请求应返回 503。
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/nics/eth0/attach", "", http.StatusServiceUnavailable)

	// 标记数据面就绪后，loopback 与不存在的网卡分别返回 400/404。
	ctl.(*controller).nicMux.Lock()
	ctl.(*controller).bpfReady = true
	ctl.(*controller).nicMux.Unlock()
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/nics/lo/attach", "", http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPost, "/api/v1/nics/definitely-not-exist/attach", "", http.StatusNotFound)

	// 网卡列表应至少包含 loopback，并携带挂载状态字段。
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/nics?per_page=1000", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/nics status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var nics []schema.Nic
	if err := json.Unmarshal(res.Body.Bytes(), &nics); err != nil {
		t.Fatalf("decode nics response: %v: %s", err, res.Body.String())
	}
	found := false
	for _, nic := range nics {
		if nic.Name == "lo" {
			found = true
			if nic.Index <= 0 || nic.Type == "" || nic.MTU <= 0 {
				t.Fatalf("loopback nic missing basic fields: %+v", nic)
			}
		}
	}
	if !found {
		t.Fatalf("loopback nic not found in %+v", nics)
	}

	// BPF 状态接口返回当前就绪状态与程序名。
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/bpf/status", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/bpf/status status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var status schema.BPFStatus
	if err := json.Unmarshal(res.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode bpf status: %v: %s", err, res.Body.String())
	}
	if !status.Ready || status.Program == "" {
		t.Fatalf("unexpected bpf status: %+v", status)
	}
}

func TestLinkFlags(t *testing.T) {
	got := linkFlags(net.FlagUp | net.FlagRunning)
	want := map[string]bool{"up": true, "running": true}
	if len(got) != len(want) {
		t.Fatalf("linkFlags = %v, want %v", got, want)
	}
	for _, flag := range got {
		if !want[flag] {
			t.Fatalf("unexpected flag %q in %v", flag, got)
		}
	}
}

func TestNicAutoMountHTTP(t *testing.T) {
	ctl := newEgressTestController(t)

	// loopback 与不存在的网卡不能勾选自动挂载。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/nics/lo/auto-mount", `{"auto_mount":true}`, http.StatusBadRequest)
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/nics/definitely-not-exist/auto-mount", `{"auto_mount":true}`, http.StatusNotFound)

	// 全局“全部挂载”默认关闭。
	res := httptest.NewRecorder()
	ctl.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/bpf/settings", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/bpf/settings status = %d, want %d: %s", res.Code, http.StatusOK, res.Body.String())
	}
	var settings schema.BPFSettings
	if err := json.Unmarshal(res.Body.Bytes(), &settings); err != nil {
		t.Fatalf("decode bpf settings: %v: %s", err, res.Body.String())
	}
	if settings.MountAll {
		t.Fatalf("mount_all should default to false: %+v", settings)
	}

	// 开启全局全部挂载并确认内存与数据库都已更新。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/bpf/settings", `{"mount_all":true}`, http.StatusOK)
	c := ctl.(*controller)
	c.nicMux.RLock()
	mountAll := c.mountAllNics
	c.nicMux.RUnlock()
	if !mountAll {
		t.Fatal("in-memory mount_all should be true")
	}
	persisted, err := c.storage.MountAllNicsEnabled()
	if err != nil {
		t.Fatalf("read persisted mount_all: %v", err)
	}
	if !persisted {
		t.Fatal("persisted mount_all should be true")
	}

	// 非 loopback 网卡存在时验证自动挂载开关的完整读写路径；
	// 无可用网卡的环境下跳过成功路径，只保留校验与持久化断言。
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/nics?per_page=1000", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/nics status = %d: %s", res.Code, res.Body.String())
	}
	var nics []schema.Nic
	if err := json.Unmarshal(res.Body.Bytes(), &nics); err != nil {
		t.Fatalf("decode nics response: %v: %s", err, res.Body.String())
	}
	var target string
	for _, nic := range nics {
		if !containsFlag(nic.Flags, "loopback") {
			target = nic.Name
			break
		}
	}
	if target == "" {
		t.Skip("no non-loopback nic available, skip success path")
	}

	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/nics/"+target+"/auto-mount", `{"auto_mount":true}`, http.StatusOK)
	c.nicMux.RLock()
	_, auto := c.autoMountNics[target]
	c.nicMux.RUnlock()
	if !auto {
		t.Fatalf("nic %s should be marked auto mount", target)
	}
	autoNames, err := c.storage.ListNicAutoMount()
	if err != nil {
		t.Fatalf("list persisted auto mount: %v", err)
	}
	if len(autoNames) != 1 || autoNames[0] != target {
		t.Fatalf("persisted auto mount = %+v, want [%s]", autoNames, target)
	}

	// 列表接口应如实返回 auto_mount 状态。
	res = httptest.NewRecorder()
	ctl.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/nics?per_page=1000", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/nics status = %d: %s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &nics); err != nil {
		t.Fatalf("decode nics response: %v: %s", err, res.Body.String())
	}
	found := false
	for _, nic := range nics {
		if nic.Name == target {
			found = true
			if !nic.AutoMount {
				t.Fatalf("nic %s should report auto_mount true: %+v", target, nic)
			}
		}
	}
	if !found {
		t.Fatalf("nic %s not found in %+v", target, nics)
	}

	// 关闭自动挂载。
	assertEgressStatus(t, ctl, http.MethodPut, "/api/v1/nics/"+target+"/auto-mount", `{"auto_mount":false}`, http.StatusOK)
	c.nicMux.RLock()
	_, auto = c.autoMountNics[target]
	c.nicMux.RUnlock()
	if auto {
		t.Fatalf("nic %s should no longer be auto mount", target)
	}
}

func TestInitialAttachTargets(t *testing.T) {
	ctl := newEgressTestController(t).(*controller)

	// 全部挂载优先：目标为全部可挂载网卡且不包含 loopback。
	ctl.nicMux.Lock()
	ctl.mountAllNics = true
	ctl.autoMountNics = map[string]struct{}{"lo": {}}
	ctl.nicMux.Unlock()

	mode, targets, strict, err := ctl.initialAttachTargets()
	if err != nil {
		t.Fatalf("initialAttachTargets (all): %v", err)
	}
	if mode != initialAttachAll || strict {
		t.Fatalf("initialAttachTargets (all) mode = %v strict = %v, want all/false", mode, strict)
	}
	for _, name := range targets {
		if name == "lo" {
			t.Fatalf("all attach targets should exclude loopback: %+v", targets)
		}
	}

	// 勾选自动挂载的网卡优先于默认路由；不存在的网卡会被过滤。
	allNics, err := ctl.listNics()
	if err != nil {
		t.Fatalf("list nics: %v", err)
	}
	var existing string
	for _, nic := range allNics {
		if !containsFlag(nic.Flags, "loopback") {
			existing = nic.Name
			break
		}
	}
	if existing == "" {
		t.Skip("no non-loopback nic available, skip selected mode assertions")
	}

	ctl.nicMux.Lock()
	ctl.mountAllNics = false
	ctl.autoMountNics = map[string]struct{}{existing: {}, "definitely-not-exist": {}}
	ctl.nicMux.Unlock()

	mode, targets, strict, err = ctl.initialAttachTargets()
	if err != nil {
		t.Fatalf("initialAttachTargets (selected): %v", err)
	}
	if mode != initialAttachSelected || strict {
		t.Fatalf("initialAttachTargets (selected) mode = %v strict = %v, want selected/false", mode, strict)
	}
	if len(targets) != 1 || targets[0] != existing {
		t.Fatalf("initialAttachTargets (selected) = %+v, want [%s]", targets, existing)
	}

	// 勾选的网卡全部不可挂载时退化到默认路由网卡（严格模式）。
	ctl.nicMux.Lock()
	ctl.autoMountNics = map[string]struct{}{"definitely-not-exist": {}}
	ctl.nicMux.Unlock()

	mode, targets, strict, err = ctl.initialAttachTargets()
	if err != nil {
		t.Fatalf("initialAttachTargets (fallback): %v", err)
	}
	if mode != initialAttachDefaultRoute || !strict || len(targets) != 1 {
		t.Fatalf("initialAttachTargets (fallback) mode = %v strict = %v targets = %+v, want default-route/true/[default]", mode, strict, targets)
	}
}
