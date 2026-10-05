package federation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	bolt "go.etcd.io/bbolt"
)

// PostgresStorage is shared IAM state. Every transaction locks its namespace's
// control row and checks the externally configured recovery epoch. It never
// retries a domain decision automatically after an uncertain commit.
type PostgresStorage struct {
	db               *sql.DB
	namespace, epoch string
}
type PostgresStorageConfig struct{ DSNFile, Namespace, RecoveryEpoch string }

var storageName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func OpenPostgresStorage(ctx context.Context, c PostgresStorageConfig) (*PostgresStorage, error) {
	raw, e := privateDocument(c.DSNFile)
	if e != nil {
		return nil, ErrInvalid
	}
	return openPostgresStorage(ctx, strings.TrimSpace(string(raw)), c.Namespace, c.RecoveryEpoch, true)
}
func openPostgresStorage(ctx context.Context, dsn, namespace, epoch string, requireTLS bool) (*PostgresStorage, error) {
	if ctx == nil || !storageName.MatchString(namespace) || !storageName.MatchString(epoch) {
		return nil, ErrInvalid
	}
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		return nil, ErrInvalid
	}
	if requireTLS && (cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName == "" || len(cfg.Fallbacks) > 0) {
		return nil, ErrInvalid
	}
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	s := &PostgresStorage{db, namespace, epoch}
	if e = s.Check(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *PostgresStorage) Close() error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	return s.db.Close()
}
func (s *PostgresStorage) Check(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrUnavailable
	}
	var epoch string
	var version int
	if e := s.db.QueryRowContext(ctx, `SELECT epoch,version FROM iam_federation_control WHERE namespace=$1`, s.namespace).Scan(&epoch, &version); e != nil {
		return ErrUnavailable
	}
	if epoch != s.epoch || version != 1 {
		return ErrDenied
	}
	return nil
}
func openLedger(path string, s *PostgresStorage, name string) (ledgerDB, error) {
	if s != nil {
		if path != "" {
			return nil, ErrInvalid
		}
		return &postgresLedger{s: s, name: name}, nil
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: privateLedgerFile})
	if e != nil {
		return nil, e
	}
	return &localLedger{db}, nil
}

type postgresLedger struct {
	s      *PostgresStorage
	name   string
	closed atomic.Bool
}

func (d *postgresLedger) Close() error                        { d.closed.Store(true); return nil } // Pool lifetime belongs to the composition root.
func (d *postgresLedger) View(f func(ledgerTx) error) error   { return d.transaction(false, f) }
func (d *postgresLedger) Update(f func(ledgerTx) error) error { return d.transaction(true, f) }
func (d *postgresLedger) transaction(write bool, f func(ledgerTx) error) error {
	if d.closed.Load() {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, e := d.s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	lock := "FOR SHARE"
	if write {
		lock = "FOR UPDATE"
	}
	var epoch string
	var version int
	e = tx.QueryRowContext(ctx, `SELECT epoch,version FROM iam_federation_control WHERE namespace=$1 `+lock, d.s.namespace).Scan(&epoch, &version)
	if e != nil {
		return ErrUnavailable
	}
	if epoch != d.s.epoch || version != 1 {
		return ErrDenied
	}
	t := &postgresTx{tx: tx, ctx: ctx, namespace: d.s.namespace, ledger: d.name, write: write}
	e = f(t)
	if t.err != nil {
		return ErrUnavailable
	}
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return ErrUnavailable
	}
	return nil
}

type postgresTx struct {
	tx                *sql.Tx
	ctx               context.Context
	namespace, ledger string
	write             bool
	err               error
}

func (t *postgresTx) Bucket(k []byte) ledgerBucket                           { return &postgresBucket{t, string(k)} }
func (t *postgresTx) CreateBucketIfNotExists(k []byte) (ledgerBucket, error) { return t.Bucket(k), nil }
func (t *postgresTx) fail(e error) {
	if e != nil && t.err == nil {
		t.err = e
	}
}

type postgresBucket struct {
	t    *postgresTx
	name string
}

func (b *postgresBucket) Get(k []byte) []byte {
	var v []byte
	e := b.t.tx.QueryRowContext(b.t.ctx, `SELECT value FROM iam_federation_records WHERE namespace=$1 AND ledger=$2 AND bucket=$3 AND key=$4`, b.t.namespace, b.t.ledger, b.name, k).Scan(&v)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	b.t.fail(e)
	return v
}
func (b *postgresBucket) Put(k, v []byte) error {
	if !b.t.write || len(k) == 0 || v == nil {
		return ErrInvalid
	}
	_, e := b.t.tx.ExecContext(b.t.ctx, `INSERT INTO iam_federation_records(namespace,ledger,bucket,key,value) VALUES($1,$2,$3,$4,$5) ON CONFLICT(namespace,ledger,bucket,key) DO UPDATE SET value=EXCLUDED.value`, b.t.namespace, b.t.ledger, b.name, k, v)
	b.t.fail(e)
	return e
}
func (b *postgresBucket) Delete(k []byte) error {
	if !b.t.write {
		return ErrDenied
	}
	_, e := b.t.tx.ExecContext(b.t.ctx, `DELETE FROM iam_federation_records WHERE namespace=$1 AND ledger=$2 AND bucket=$3 AND key=$4`, b.t.namespace, b.t.ledger, b.name, k)
	b.t.fail(e)
	return e
}
func (b *postgresBucket) Stats() ledgerStats {
	var n int
	e := b.t.tx.QueryRowContext(b.t.ctx, `SELECT count(*) FROM iam_federation_records WHERE namespace=$1 AND ledger=$2 AND bucket=$3`, b.t.namespace, b.t.ledger, b.name).Scan(&n)
	b.t.fail(e)
	return ledgerStats{n}
}
func (b *postgresBucket) Cursor() ledgerCursor { return &postgresCursor{b: b} }

const postgresCursorPageSize = 256

type postgresCursorEntry struct{ key, value []byte }
type postgresCursor struct {
	b     *postgresBucket
	key   []byte
	ended bool
	page  []postgresCursorEntry
}

func (c *postgresCursor) read(op string, k []byte) ([]byte, []byte) {
	b := c.b
	query := `SELECT key,value FROM iam_federation_records WHERE namespace=$1 AND ledger=$2 AND bucket=$3`
	args := []any{b.t.namespace, b.t.ledger, b.name}
	if op != "" {
		query += " AND key " + op + " $4"
		args = append(args, k)
	}
	query += fmt.Sprintf(" ORDER BY key LIMIT %d", postgresCursorPageSize)
	rows, err := b.t.tx.QueryContext(b.t.ctx, query, args...)
	if err != nil {
		b.t.fail(err)
		c.ended = true
		return nil, nil
	}
	c.page = nil
	for rows.Next() {
		var e postgresCursorEntry
		if err = rows.Scan(&e.key, &e.value); err != nil {
			break
		}
		c.page = append(c.page, e)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		b.t.fail(err)
		c.page = nil
		c.ended = true
		return nil, nil
	}
	return c.take()
}
func (c *postgresCursor) take() ([]byte, []byte) {
	if len(c.page) == 0 {
		c.ended = true
		return nil, nil
	}
	e := c.page[0]
	c.page[0] = postgresCursorEntry{}
	c.page = c.page[1:]
	c.key = e.key
	return e.key, e.value
}
func (c *postgresCursor) First() ([]byte, []byte)        { c.ended = false; return c.read("", nil) }
func (c *postgresCursor) Seek(k []byte) ([]byte, []byte) { c.ended = false; return c.read(">=", k) }
func (c *postgresCursor) Next() ([]byte, []byte) {
	if c.ended {
		return nil, nil
	}
	if len(c.page) > 0 {
		return c.take()
	}
	if c.key == nil {
		return c.First()
	}
	return c.read(">", c.key)
}
func (c *postgresCursor) Delete() error {
	if c.key == nil || c.ended {
		return ErrInvalid
	}
	return c.b.Delete(c.key)
}

func (b *postgresBucket) ForEach(f func([]byte, []byte) error) error {
	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if e := f(k, v); e != nil {
			return e
		}
	}
	return b.t.err
}
