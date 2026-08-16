package dao

import (
	"testing"
)

func TestNicAutoMountCRUD(t *testing.T) {
	d := newTestDao(t)

	enabled, err := d.MountAllNicsEnabled()
	if err != nil {
		t.Fatalf("mount all nics default: %v", err)
	}
	if enabled {
		t.Fatal("mount all nics should default to false")
	}

	if err := d.SetMountAllNics(true); err != nil {
		t.Fatalf("enable mount all nics: %v", err)
	}
	enabled, err = d.MountAllNicsEnabled()
	if err != nil {
		t.Fatalf("mount all nics after enable: %v", err)
	}
	if !enabled {
		t.Fatal("mount all nics should be true after enable")
	}
	if err := d.SetMountAllNics(false); err != nil {
		t.Fatalf("disable mount all nics: %v", err)
	}
	enabled, err = d.MountAllNicsEnabled()
	if err != nil {
		t.Fatalf("mount all nics after disable: %v", err)
	}
	if enabled {
		t.Fatal("mount all nics should be false after disable")
	}
}

func TestNicAutoMountNames(t *testing.T) {
	d := newTestDao(t)

	if err := d.SetNicAutoMount("eth0", true); err != nil {
		t.Fatalf("set eth0 auto mount: %v", err)
	}
	if err := d.SetNicAutoMount(" eth1 ", true); err != nil {
		t.Fatalf("set eth1 auto mount: %v", err)
	}
	if err := d.SetNicAutoMount("  ", true); err == nil {
		t.Fatal("set auto mount with empty name should fail")
	}

	list, err := d.ListNicAutoMount()
	if err != nil {
		t.Fatalf("list auto mount: %v", err)
	}
	want := map[string]bool{"eth0": true, "eth1": true}
	if len(list) != len(want) {
		t.Fatalf("auto mount count = %d, want %d: %+v", len(list), len(want), list)
	}
	for _, name := range list {
		if !want[name] {
			t.Fatalf("unexpected auto mount nic %q in %+v", name, list)
		}
	}

	// 关闭不存在的开关幂等。
	if err := d.SetNicAutoMount("missing", false); err != nil {
		t.Fatalf("disable missing auto mount: %v", err)
	}
	if err := d.SetNicAutoMount("eth0", false); err != nil {
		t.Fatalf("disable eth0 auto mount: %v", err)
	}
	list, err = d.ListNicAutoMount()
	if err != nil {
		t.Fatalf("list auto mount after disable: %v", err)
	}
	if len(list) != 1 || list[0] != "eth1" {
		t.Fatalf("auto mount after disable = %+v, want [eth1]", list)
	}
}
