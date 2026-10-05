package federation

import bolt "go.etcd.io/bbolt"

// ledgerDB keeps domain decisions inside one atomic storage transaction.
// Get/Stats/Cursor retain bbolt's shape; SQL implementations retain any read
// error and refuse commit, so a failed query can never mean authoritative absence.
type ledgerDB interface {
	View(func(ledgerTx) error) error
	Update(func(ledgerTx) error) error
	Close() error
}
type ledgerTx interface {
	Bucket([]byte) ledgerBucket
	CreateBucketIfNotExists([]byte) (ledgerBucket, error)
}
type ledgerBucket interface {
	ForEach(func([]byte, []byte) error) error
	Get([]byte) []byte
	Put([]byte, []byte) error
	Delete([]byte) error
	Stats() ledgerStats
	Cursor() ledgerCursor
}
type ledgerStats struct{ KeyN int }
type ledgerCursor interface {
	First() ([]byte, []byte)
	Next() ([]byte, []byte)
	Seek([]byte) ([]byte, []byte)
	Delete() error
}
type localLedger struct{ db *bolt.DB }
type localTx struct{ tx *bolt.Tx }
type localBucket struct{ b *bolt.Bucket }

func (d *localLedger) View(f func(ledgerTx) error) error {
	return d.db.View(func(tx *bolt.Tx) error { return f(localTx{tx}) })
}
func (d *localLedger) Update(f func(ledgerTx) error) error {
	return d.db.Update(func(tx *bolt.Tx) error { return f(localTx{tx}) })
}
func (d *localLedger) Close() error            { return d.db.Close() }
func (t localTx) Bucket(k []byte) ledgerBucket { return localBucket{t.tx.Bucket(k)} }
func (t localTx) CreateBucketIfNotExists(k []byte) (ledgerBucket, error) {
	b, e := t.tx.CreateBucketIfNotExists(k)
	return localBucket{b}, e
}
func (b localBucket) Get(k []byte) []byte   { return b.b.Get(k) }
func (b localBucket) Put(k, v []byte) error { return b.b.Put(k, v) }
func (b localBucket) Delete(k []byte) error { return b.b.Delete(k) }
func (b localBucket) Stats() ledgerStats    { return ledgerStats{b.b.Stats().KeyN} }
func (b localBucket) Cursor() ledgerCursor  { return b.b.Cursor() }

func (b localBucket) ForEach(f func([]byte, []byte) error) error { return b.b.ForEach(f) }
