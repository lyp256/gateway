package dao

import (
	"errors"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

func newTestDao(t *testing.T) *Dao {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "gateway.db"), 0o600, nil)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket(bucketName)
		return err
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return New(db)
}

func TestEgressUniqueness(t *testing.T) {
	d := newTestDao(t)
	first := Egress{Name: "proxy-a", FwMark: 4097}
	if err := d.CreateEgress(first); err != nil {
		t.Fatalf("create first egress: %v", err)
	}

	if err := d.CreateEgress(Egress{Name: "proxy-a", FwMark: 4098}); !errors.Is(err, ErrEgressNameExists) {
		t.Fatalf("duplicate name error = %v, want %v", err, ErrEgressNameExists)
	}
	if err := d.CreateEgress(Egress{Name: "proxy-b", FwMark: first.FwMark}); !errors.Is(err, ErrEgressFwMarkExists) {
		t.Fatalf("duplicate fwmark error = %v, want %v", err, ErrEgressFwMarkExists)
	}

	first.Type = EgressHTTPTunnel
	if err := d.UpdateEgress(first); err != nil {
		t.Fatalf("update existing egress: %v", err)
	}
	if err := d.UpdateEgress(Egress{Name: "proxy-missing", FwMark: 4099}); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("update missing egress error = %v, want %v", err, ErrKeyNotFound)
	}
}
