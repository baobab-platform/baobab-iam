package migration

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is an in-process RecordStore for tests and non-durable pilots.
// It is not a production ledger backend.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[string]*Record
}

// NewMemoryStore returns an empty in-memory ledger.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: make(map[string]*Record)}
}

// Put validates and upserts a record by MigrationID.
func (s *MemoryStore) Put(ctx context.Context, r *Record) error {
	_ = ctx
	if r == nil {
		return fmt.Errorf("migration: nil record")
	}
	if err := r.ValidateStructural(); err != nil {
		return err
	}
	// Defensive copy so callers cannot mutate stored state without Put.
	cp := *r
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[r.MigrationID] = &cp
	return nil
}

// Get returns a copy of the record or ErrNotFound.
func (s *MemoryStore) Get(ctx context.Context, migrationID string) (*Record, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[migrationID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

// List returns copies of all records (order not guaranteed).
func (s *MemoryStore) List(ctx context.Context) ([]*Record, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0, len(s.byID))
	for _, r := range s.byID {
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}

// ListByState filters by MigrationState.
func (s *MemoryStore) ListByState(ctx context.Context, state MigrationState) ([]*Record, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0)
	for _, r := range all {
		if r.MigrationState == state {
			out = append(out, r)
		}
	}
	return out, nil
}

// ListByClass filters by IdentityClass.
func (s *MemoryStore) ListByClass(ctx context.Context, class IdentityClass) ([]*Record, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*Record, 0)
	for _, r := range all {
		if r.IdentityClass == class {
			out = append(out, r)
		}
	}
	return out, nil
}

// Delete removes a record. Missing IDs are not an error (idempotent).
func (s *MemoryStore) Delete(ctx context.Context, migrationID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, migrationID)
	return nil
}
