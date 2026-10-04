package migration

import (
	"context"
	"fmt"
)

// VerificationStage advances ledger rows from CREDENTIAL_READY into the
// verification/policy-approval states defined by ADR-IAM-0022 §10 and the
// migration ledger gate. It does not touch provider state or issue cutover.
type VerificationStage struct {
	Service *Service
}

// NewVerificationStage returns a helper bound to svc.
func NewVerificationStage(svc *Service) (*VerificationStage, error) {
	if svc == nil || svc.Store == nil {
		return nil, fmt.Errorf("migration: Service with Store is required")
	}
	return &VerificationStage{Service: svc}, nil
}

// VerificationResult is the row after a verification transition.
type VerificationResult struct {
	Record *Record
	Outcome string
	AlreadyVerified bool
}

// Apply advances CREDENTIAL_READY → VERIFICATION_PENDING when the provider has
// completed credential-side evidence and the row is eligible for verification.
func (v *VerificationStage) Apply(ctx context.Context, migrationID string) (*VerificationResult, error) {
	if v == nil || v.Service == nil {
		return nil, fmt.Errorf("migration: VerificationStage is nil")
	}
	r, err := v.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}

	switch r.MigrationState {
	case StateVerified, StateCutoverReady, StateCutover, StateLegacyRetired:
		return &VerificationResult{Record: r, Outcome: "already_verified", AlreadyVerified: true}, nil
	case StateCredentialReady, StateVerificationPending:
		// continue
	default:
		return nil, fmt.Errorf("migration: verification stage requires CREDENTIAL_READY or VERIFICATION_PENDING, got %s", r.MigrationState)
	}

	if r.MigrationState == StateVerificationPending {
		return &VerificationResult{Record: r, Outcome: "verification_pending"}, nil
	}

	out, err := v.Service.ApplyTransition(ctx, migrationID, StateVerificationPending)
	if err != nil {
		return nil, err
	}
	return &VerificationResult{Record: out, Outcome: "verification_pending"}, nil
}

// MarkVerified moves VERIFICATION_PENDING → VERIFIED after external acceptance or
// a provider-side verification check has passed. The ledger itself stores only the
// outcome state and proof references; it does not embed provider proof material.
func (v *VerificationStage) MarkVerified(ctx context.Context, migrationID string) (*VerificationResult, error) {
	if v == nil || v.Service == nil {
		return nil, fmt.Errorf("migration: VerificationStage is nil")
	}
	r, err := v.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}

	switch r.MigrationState {
	case StateVerified, StateCutoverReady, StateCutover, StateLegacyRetired:
		return &VerificationResult{Record: r, Outcome: "already_verified", AlreadyVerified: true}, nil
	case StateVerificationPending:
		out, err := v.Service.ApplyTransition(ctx, migrationID, StateVerified)
		if err != nil {
			return nil, err
		}
		return &VerificationResult{Record: out, Outcome: "verified"}, nil
	default:
		return nil, fmt.Errorf("migration: MarkVerified requires VERIFICATION_PENDING, got %s", r.MigrationState)
	}
}
