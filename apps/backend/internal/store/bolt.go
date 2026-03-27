package store

import (
	"go.etcd.io/bbolt"
)

type BoltStore struct {
	walPath string
	db      *bbolt.DB
}

func NewBoltStore(path string) *BoltStore {
	return &BoltStore{walPath: path}
}

func (s *BoltStore) Init() error {
	var err error
	s.db, err = bbolt.Open(s.walPath, 0600, nil)
	if err != nil {
		return err
	}

	// Create WAL bucket
	return s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("wal_entries"))
		return err
	})
}

func (s *BoltStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
