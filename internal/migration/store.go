package migration

import (
	"context"
	"fmt"
)

// RecordStore is a persistence port for migration ledger rows (ADR-0022 §9).
// Implementations MUST NOT accept or store credential material.
type RecordStore interface {
	Put(ctx context.Context, r *Record) error
	Get(ctx context.Context, migrationID string) (*Record, error)
	List(ctx context.Context) ([]*Record, error)
	ListByState(ctx context.Context, state MigrationState) ([]*Record, error)
	ListByClass(ctx context.Context, class IdentityClass) ([]*Record, error)
	Delete(ctx context.Context, migrationID string) error
}

// ErrNotFound is returned when a migration_id is unknown.
var ErrNotFound = fmt.Errorf("migration: record not found")
