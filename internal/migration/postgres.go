package migration

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_n05_ledger.sql
var n05Schema string

// N05Schema is reviewed, immutable SQL for an externally controlled migration
// runner. Constructing a store NEVER upgrades a database implicitly.
func N05Schema() string { return n05Schema }

var (
	ErrMigrationConflict = errors.New("migration: concurrent revision, reassignment or duplicate external binding")
	ErrImmutableLedger   = errors.New("migration: durable ledger cannot delete history")
	ErrCutoverNotApproved = errors.New("migration: N05 never performs protected issuer cutover")
)

// PostgresStore is the durable PostgreSQL 17 RecordStore. Its append-only
// database history is inserted by triggers in the SAME transaction as changes.
// It uses versioned FOR UPDATE row locking; no last-writer-wins or email
// matching. It does NOT make CP CanonicalIdentity/issuer-trust decisions.
type PostgresStore struct { pool *pgxpool.Pool }

func NewPostgresStore(ctx context.Context, pool *pgxpool.Pool) (*PostgresStore, error) {
	if ctx == nil || pool == nil {
		return nil, errors.New("migration: explicit PostgreSQL pool required")
	}
	var table *string
	if err := pool.QueryRow(ctx, "SELECT to_regclass('iam_migration.record')::text").Scan(&table); err != nil || table == nil {
		return nil, errors.New("migration: reviewed N05 ledger schema is unavailable")
	}
	return &PostgresStore{pool: pool}, nil
}

const n05Columns = `revision, migration_id, migration_batch_id, canonical_identity_id,
source_provider, source_issuer, source_subject, target_provider, target_issuer, target_subject,
identity_class, credential_strategy, migration_state, verification_state, cutover_state,
source_snapshot_reference, attempt_count, last_error_code,
created_at, started_at, verified_at, cutover_at, retired_at`

func scanN05(row pgx.Row) (*Record, error) {
	r := new(Record)
	err := row.Scan(&r.Revision, &r.MigrationID, &r.MigrationBatchID,
		&r.CanonicalIdentityID, &r.Source.Provider, &r.Source.Issuer, &r.Source.Subject,
		&r.Target.Provider, &r.Target.Issuer, &r.Target.Subject,
		&r.IdentityClass, &r.CredentialStrategy, &r.MigrationState,
		&r.VerificationState, &r.CutoverState, &r.SourceSnapshotReference,
		&r.AttemptCount, &r.LastErrorCode,
		&r.CreatedAt, &r.StartedAt, &r.VerifiedAt, &r.CutoverAt, &r.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) { return nil, ErrNotFound }
	if err != nil { return nil, fmt.Errorf("migration: database read unavailable: %w", err) }
	if err := r.ValidateStructural(); err != nil {
		return nil, fmt.Errorf("migration: invalid durable row: %w", err)
	}
	return r, nil
}

func n05Args(r *Record) []any {
	return []any{
		r.MigrationID, r.MigrationBatchID, r.CanonicalIdentityID,
		r.Source.Provider, r.Source.Issuer, r.Source.Subject,
		r.Target.Provider, r.Target.Issuer, r.Target.Subject,
		r.IdentityClass, r.CredentialStrategy, r.MigrationState,
		r.VerificationState, r.CutoverState, r.SourceSnapshotReference,
		r.AttemptCount, r.LastErrorCode, r.CreatedAt, r.StartedAt,
		r.VerifiedAt, r.CutoverAt, r.RetiredAt,
	}
}

func immutableN05(existing, next *Record) bool {
	return existing.MigrationID == next.MigrationID &&
		existing.MigrationBatchID == next.MigrationBatchID &&
		existing.CanonicalIdentityID == next.CanonicalIdentityID &&
		existing.Source == next.Source &&
		existing.IdentityClass == next.IdentityClass &&
		existing.CredentialStrategy == next.CredentialStrategy &&
		existing.CreatedAt.Equal(next.CreatedAt)
}
func sameTargetN05(a, b ProviderBinding) bool { return a == b }
func emptyTargetN05(p ProviderBinding) bool {
	return p == (ProviderBinding{})
}

// Put is transactional and revision-checked. Version 0 means a new record;
// an existing record with the same ID/source but a different version DENIES.
// A target binding can only be added once, while PROVISIONING, never moved to
// a different CP person or target issuer to "fix" a failed import.
func (s *PostgresStore) Put(ctx context.Context, r *Record) error {
	if s == nil || s.pool == nil || ctx == nil || r == nil {
		return errors.New("migration: PostgreSQL store/record required")
	}
	if err := r.ValidateStructural(); err != nil { return err }
	if len(r.MigrationID) > 160 || len(r.CanonicalIdentityID) > 160 ||
		len(r.MigrationBatchID) > 160 || len(r.Source.Issuer) > 2048 ||
		len(r.Source.Subject) > 512 || len(r.Source.Provider) > 40 {
		return errors.New("migration: bounded ledger identifiers required")
	}
	// N05 preserves current ADR-IAM-0033 Keycloak enterprise federation and
	// does not authorize M18 production trust or retirement, even if a
	// caller has mistakenly supplied the test-only AllowAllPolicyGate.
	if r.MigrationState == StateCutover || r.MigrationState == StateLegacyRetired {
		return ErrCutoverNotApproved
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil { return fmt.Errorf("migration: start ledger transaction: %w", err) }
	defer tx.Rollback(ctx)
	old, err := scanN05(tx.QueryRow(ctx, "SELECT "+n05Columns+
		" FROM iam_migration.record WHERE migration_id=$1 FOR UPDATE", r.MigrationID))
	if errors.Is(err, ErrNotFound) {
		if r.Revision != 0 || r.MigrationState != StateDiscovered {
			return ErrMigrationConflict
		}
		args := n05Args(r)
		_, err = tx.Exec(ctx, `INSERT INTO iam_migration.record (
migration_id, migration_batch_id, canonical_identity_id,
source_provider, source_issuer, source_subject, target_provider, target_issuer, target_subject,
identity_class, credential_strategy, migration_state, verification_state, cutover_state,
source_snapshot_reference, attempt_count, last_error_code, created_at,
started_at, verified_at, cutover_at, retired_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`, args...)
		if err != nil { return n05WriteError(err) }
		if err := tx.Commit(ctx); err != nil { return n05WriteError(err) }
		r.Revision = 1
		return nil
	}
	if err != nil { return err }
	if old.Revision != r.Revision || !immutableN05(old, r) ||
		(!emptyTargetN05(old.Target) && !sameTargetN05(old.Target, r.Target)) {
		return ErrMigrationConflict
	}
	if !sameTargetN05(old.Target, r.Target) &&
		(r.MigrationState != StateProvisioning || old.MigrationState != StateProvisioning ||
		 emptyTargetN05(r.Target)) {
		return ErrMigrationConflict
	}
	if old.MigrationState != r.MigrationState && !CanTransition(old.MigrationState, r.MigrationState) {
		return ErrMigrationConflict
	}
	if reflect.DeepEqual(old, r) { return nil }
	args := []any{
		r.Target.Provider, r.Target.Issuer, r.Target.Subject,
		r.MigrationState, r.VerificationState, r.CutoverState,
		r.SourceSnapshotReference, r.AttemptCount, r.LastErrorCode,
		r.StartedAt, r.VerifiedAt, r.CutoverAt, r.RetiredAt,
		r.MigrationID, r.Revision,
	}
	var newRevision int64
	err = tx.QueryRow(ctx, `UPDATE iam_migration.record SET
target_provider=$1, target_issuer=$2, target_subject=$3,
migration_state=$4, verification_state=$5, cutover_state=$6,
source_snapshot_reference=$7, attempt_count=$8, last_error_code=$9,
started_at=$10, verified_at=$11, cutover_at=$12, retired_at=$13,
revision=revision+1
WHERE migration_id=$14 AND revision=$15 RETURNING revision`, args...).Scan(&newRevision)
	if errors.Is(err, pgx.ErrNoRows) { return ErrMigrationConflict }
	if err != nil { return n05WriteError(err) }
	if err := tx.Commit(ctx); err != nil { return n05WriteError(err) }
	r.Revision = newRevision
	return nil
}

func n05WriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23514" ||
		pg.Code == "40001" || pg.Code == "23503" || pg.Code == "P0001") {
		return ErrMigrationConflict
	}
	return fmt.Errorf("migration: durable ledger unavailable: %w", err)
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*Record, error) {
	if s == nil || s.pool == nil || ctx == nil { return nil, errors.New("migration: PostgreSQL required") }
	return scanN05(s.pool.QueryRow(ctx, "SELECT "+n05Columns+
		" FROM iam_migration.record WHERE migration_id=$1", id))
}

func (s *PostgresStore) list(ctx context.Context, filter, value string) ([]*Record, error) {
	if s == nil || s.pool == nil || ctx == nil { return nil, errors.New("migration: PostgreSQL required") }
	statement := "SELECT "+n05Columns+" FROM iam_migration.record "
	var args []any
	switch filter {
	case "": // all rows
	case "migration_state", "identity_class":
		statement += "WHERE " + filter + "=$1 "
		args = []any{value}
	default:
		return nil, errors.New("migration: invalid ledger filter")
	}
	statement += "ORDER BY migration_id LIMIT 10001"
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil { return nil, fmt.Errorf("migration: ledger list unavailable: %w", err) }
	defer rows.Close()
	result := make([]*Record, 0)
	for rows.Next() {
		r, err := scanN05(rows)
		if err != nil { return nil, err }
		result = append(result, r)
		if len(result) > 10000 { return nil, errors.New("migration: pagination required; refusing silent truncation") }
	}
	if err := rows.Err(); err != nil { return nil, err }
	return result, nil
}
func (s *PostgresStore) List(ctx context.Context) ([]*Record, error) {
	return s.list(ctx, "", "")
}
func (s *PostgresStore) ListByState(ctx context.Context, state MigrationState) ([]*Record, error) {
	if !state.Valid() { return nil, errors.New("migration: invalid state") }
	return s.list(ctx, "migration_state", string(state))
}
func (s *PostgresStore) ListByClass(ctx context.Context, class IdentityClass) ([]*Record, error) {
	if !class.Valid() { return nil, errors.New("migration: invalid class") }
	return s.list(ctx, "identity_class", string(class))
}
func (s *PostgresStore) Delete(context.Context, string) error { return ErrImmutableLedger }

// History is a provider-independent audit of every persisted revision.
// No actor claim is asserted without separately verified IAM audit evidence.
type History struct {
	EventID int64
	Revision int64
	FromState *MigrationState
	ToState MigrationState
	EventType string
	At time.Time
}
func (s *PostgresStore) History(ctx context.Context, id string) ([]History, error) {
	rows, err := s.pool.Query(ctx, `SELECT event_id, revision, from_state,
to_state, event_type, occurred_at FROM iam_migration.history
WHERE migration_id=$1 ORDER BY revision LIMIT 10001`, id)
	if err != nil { return nil, err }
	defer rows.Close()
	var events []History
	for rows.Next() {
		var h History
		if err := rows.Scan(&h.EventID, &h.Revision, &h.FromState,
			&h.ToState, &h.EventType, &h.At); err != nil { return nil, err }
		events = append(events,h)
		if len(events)>10000 { return nil, errors.New("migration: history pagination required") }
	}
	return events,rows.Err()
}
var _ RecordStore = (*PostgresStore)(nil)
