package migration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Service applies ledger transitions against a RecordStore.
// It does not talk to Kratos, Hydra, or CP — only enforces ADR-0022 state rules
// and an optional PolicyGate (Phase C defaults to denying production cutover).
type Service struct {
	Store RecordStore
	// Policy is consulted on every ApplyTransition. If nil, PhaseCPolicyGate is used.
	Policy PolicyGate
	Now    func() time.Time // optional clock; defaults to time.Now UTC
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Register creates a new DISCOVERED row after structural validation.
// Store errors other than ErrNotFound fail closed (not treated as "absent").
func (s *Service) Register(ctx context.Context, r *Record) error {
	if s == nil || s.Store == nil {
		return fmt.Errorf("migration: service or store is nil")
	}
	if r.MigrationState == "" {
		r.MigrationState = StateDiscovered
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now()
	}
	if err := r.ValidateStructural(); err != nil {
		return err
	}
	_, err := s.Store.Get(ctx, r.MigrationID)
	switch {
	case err == nil:
		return fmt.Errorf("migration: migration_id %q already exists", r.MigrationID)
	case errors.Is(err, ErrNotFound):
		// proceed
	default:
		return fmt.Errorf("migration: store get %s: %w", r.MigrationID, err)
	}
	return s.Store.Put(ctx, r)
}

// ApplyTransition loads a row, applies a legal state transition, and persists it.
func (s *Service) ApplyTransition(ctx context.Context, migrationID string, to MigrationState) (*Record, error) {
	if s == nil || s.Store == nil {
		return nil, fmt.Errorf("migration: service or store is nil")
	}
	r, err := s.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}
	policy := s.Policy
	if policy == nil {
		policy = PhaseCPolicyGate{}
	}
	if err := policy.AllowTransition(ctx, migrationID, r.MigrationState, to); err != nil {
		return nil, err
	}
	if err := r.Transition(to); err != nil {
		return nil, err
	}
	s.stamp(r, to)
	if err := s.Store.Put(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Service) stamp(r *Record, to MigrationState) {
	n := s.now()
	switch to {
	case StateProvisioning, StateReady:
		if r.StartedAt == nil {
			r.StartedAt = &n
		}
	case StateVerified:
		r.VerifiedAt = &n
	case StateCutover:
		r.CutoverAt = &n
	case StateLegacyRetired:
		r.RetiredAt = &n
	}
}

// SetTargetBinding attaches target issuer/subject (after successful provision).
func (s *Service) SetTargetBinding(ctx context.Context, migrationID string, target ProviderBinding) (*Record, error) {
	if s == nil || s.Store == nil {
		return nil, fmt.Errorf("migration: service or store is nil")
	}
	target.Provider = strings.TrimSpace(target.Provider)
	target.Issuer = strings.TrimSpace(target.Issuer)
	target.Subject = strings.TrimSpace(target.Subject)
	if target.Issuer == "" || target.Subject == "" || target.Provider == "" {
		return nil, fmt.Errorf("migration: target provider, issuer, and subject are required")
	}
	r, err := s.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}
	r.Target = target
	if err := r.ValidateStructural(); err != nil {
		return nil, err
	}
	if err := s.Store.Put(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}
