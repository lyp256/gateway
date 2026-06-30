package dao

import (
	"errors"

	"go.etcd.io/bbolt"
)

var bucketName = []byte("gateway")

var ErrKeyNotFound = errors.New("key not found")

func New(db *bbolt.DB) *Dao {
	return &Dao{db: db}
}

type Dao struct {
	db *bbolt.DB
}
