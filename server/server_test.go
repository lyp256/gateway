package server

import (
	"path/filepath"
	"testing"

	"github.com/lyp256/gateway/dao"
	"go.etcd.io/bbolt"
)

func newSeedTestDao(t *testing.T) *dao.Dao {
	t.Helper()
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "gateway.db"), 0o600, nil)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket([]byte("gateway"))
		return err
	}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return dao.New(db)
}
