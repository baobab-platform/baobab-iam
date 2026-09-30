// Target path: baobab-iam/internal/migration/credential.go
//
// CredentialStage advances ledger rows from PROVISIONED into CREDENTIAL_*
// according to CredentialStrategy (ADR-IAM-0022 §16–20).
//
// Hard rules:
//   - No password hashes, TOTP secrets, passkeys, or client secrets are
//     accepted or stored on the ledger (ADR-0022 §9).
//   - Identity provisioned ≠ credential ready (ADR-0022 §15).
//   - DIRECT_IMPORT cannot complete in this helper without provider-side
//     import APIs; it stops at CREDENTIAL_PENDING (or fails closed).
package migration

import (
	"context"
	"fmt"
)

// CredentialStage applies strategy-driven transitions after PROVISIONED.
type CredentialStage struct {
	Service *Service
}

// NewCredentialStage returns a helper bound to svc.
func NewCredentialStage(svc *Service) (*CredentialStage, error) {
	if svc == nil || svc.Store == nil {
		return nil, fmt.Errorf("migration: Service with Store is required")
	}
	return &CredentialStage{Service: svc}, nil
}

// CredentialResult is the row after Apply.
type CredentialResult struct {
	Record *Record
	// Outcome is a machine-readable summary (no secrets).
	Outcome string
	// AlreadyReady is true when the row was already ≥ CREDENTIAL_READY.
	AlreadyReady bool
}

// Apply advances migrationID from PROVISIONED (or CREDENTIAL_PENDING) according
// to its CredentialStrategy:
//
//	NO_CREDENTIAL_REQUIRED → CREDENTIAL_READY (workloads, service accounts)
//	FIRST_LOGIN_MIGRATION / CONTROLLED_RE_ENROLMENT / FEDERATED_REBIND /
//	PASSKEY_RE_ENROLMENT / MFA_RE_ENROLMENT → CREDENTIAL_PENDING
//	  (user or federation action is external; ledger only records pending)
//	DIRECT_IMPORT → CREDENTIAL_PENDING
//	  (import material must be applied via IdentityProvisioner credentials
//	   APIs — never via ledger fields; Phase C does not complete import here)
//
// Rows already at CREDENTIAL_READY or later return AlreadyReady.
func (c *CredentialStage) Apply(ctx context.Context, migrationID string) (*CredentialResult, error) {
	if c == nil || c.Service == nil {
		return nil, fmt.Errorf("migration: CredentialStage is nil")
	}
	r, err := c.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}
	if !r.CredentialStrategy.Valid() {
		return nil, fmt.Errorf("migration: invalid credential_strategy %q", r.CredentialStrategy)
	}

	switch r.MigrationState {
	case StateCredentialReady, StateVerificationPending, StateVerified,
		StateCutoverReady, StateCutover, StateLegacyRetired:
		return &CredentialResult{Record: r, Outcome: "already_credential_ready", AlreadyReady: true}, nil
	case StateProvisioned, StateCredentialPending:
		// continue
	default:
		return nil, fmt.Errorf("migration: credential stage requires PROVISIONED or CREDENTIAL_PENDING, got %s", r.MigrationState)
	}

	switch r.CredentialStrategy {
	case StrategyNoCredentialRequired:
		return c.toReady(ctx, migrationID, r, "no_credential_required")
	case StrategyFirstLoginMigration, StrategyControlledReEnrolment,
		StrategyFederatedRebind, StrategyPasskeyReEnrolment, StrategyMFAReEnrolment:
		return c.toPending(ctx, migrationID, r, "awaiting_external_credential_action")
	case StrategyDirectImport:
		// Refuse to accept secret material on the ledger. Leave PENDING so an
		// operator/automation can call provider import APIs out-of-band.
		return c.toPending(ctx, migrationID, r, "direct_import_pending_provider_side")
	default:
		return nil, fmt.Errorf("migration: unhandled credential_strategy %q", r.CredentialStrategy)
	}
}

// MarkReady moves CREDENTIAL_PENDING → CREDENTIAL_READY when an external
// process has finished credential work. Callers MUST NOT pass secrets here;
// proof lives in the provider, not the ledger.
func (c *CredentialStage) MarkReady(ctx context.Context, migrationID string) (*CredentialResult, error) {
	if c == nil || c.Service == nil {
		return nil, fmt.Errorf("migration: CredentialStage is nil")
	}
	r, err := c.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}
	switch r.MigrationState {
	case StateCredentialReady, StateVerificationPending, StateVerified,
		StateCutoverReady, StateCutover, StateLegacyRetired:
		return &CredentialResult{Record: r, Outcome: "already_credential_ready", AlreadyReady: true}, nil
	case StateCredentialPending:
		out, err := c.Service.ApplyTransition(ctx, migrationID, StateCredentialReady)
		if err != nil {
			return nil, err
		}
		return &CredentialResult{Record: out, Outcome: "marked_ready_external_proof"}, nil
	case StateProvisioned:
		if r.CredentialStrategy == StrategyNoCredentialRequired {
			return c.toReady(ctx, migrationID, r, "no_credential_required")
		}
		return nil, fmt.Errorf("migration: MarkReady from PROVISIONED only for NO_CREDENTIAL_REQUIRED; got %s", r.CredentialStrategy)
	default:
		return nil, fmt.Errorf("migration: MarkReady requires CREDENTIAL_PENDING (or PROVISIONED+NO_CREDENTIAL_REQUIRED), got %s", r.MigrationState)
	}
}

func (c *CredentialStage) toPending(ctx context.Context, migrationID string, r *Record, outcome string) (*CredentialResult, error) {
	if r.MigrationState == StateCredentialPending {
		return &CredentialResult{Record: r, Outcome: outcome}, nil
	}
	out, err := c.Service.ApplyTransition(ctx, migrationID, StateCredentialPending)
	if err != nil {
		return nil, err
	}
	return &CredentialResult{Record: out, Outcome: outcome}, nil
}

func (c *CredentialStage) toReady(ctx context.Context, migrationID string, r *Record, outcome string) (*CredentialResult, error) {
	if r.MigrationState == StateProvisioned {
		out, err := c.Service.ApplyTransition(ctx, migrationID, StateCredentialReady)
		if err != nil {
			return nil, err
		}
		return &CredentialResult{Record: out, Outcome: outcome}, nil
	}
	if r.MigrationState == StateCredentialPending {
		out, err := c.Service.ApplyTransition(ctx, migrationID, StateCredentialReady)
		if err != nil {
			return nil, err
		}
		return &CredentialResult{Record: out, Outcome: outcome}, nil
	}
	return &CredentialResult{Record: r, Outcome: outcome, AlreadyReady: true}, nil
}

// RejectCredentialMaterial is a deliberate API that always fails. It documents
// that credential secrets must not enter the migration ledger.
func RejectCredentialMaterial(_ context.Context, _ string, materialKind string) error {
	return fmt.Errorf("migration: refusing to store credential material %q on ledger (ADR-0022 §9)", materialKind)
}
