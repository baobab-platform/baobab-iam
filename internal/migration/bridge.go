// Target path: baobab-iam/internal/migration/bridge.go
//
// ProvisionBridge advances ledger rows from DISCOVERED through PROVISIONED
// by calling provider-neutral IdentityProvisioner / WorkloadProvisioner
// (ADR-IAM-0020, ADR-IAM-0022). Phase C uses offline fakes; live Ory adapters
// are injected later without changing this orchestration.
//
// Explicitly does not:
//   - advance past PROVISIONED into credential/verification/cutover
//   - store client secrets, password hashes, or TOTP on the ledger
//   - authorize production CUTOVER (PolicyGate still applies on transitions)
package migration

import (
	"context"
	"fmt"
	"strings"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// ProvisionBridge orchestrates ledger state + target provider provisioning.
// Zero-value is not usable; construct with NewProvisionBridge.
type ProvisionBridge struct {
	Service *Service
	// Human provisions Kratos (or equivalent) identities. Required for HUMAN*
	// classes when Provision is called.
	Human provider.IdentityProvisioner
	// Workload provisions Hydra (or equivalent) OAuth clients. Required for
	// WORKLOAD / SERVICE_INTEGRATION classes.
	Workload provider.WorkloadProvisioner
	// TargetIssuer is written onto Target.Issuer and passed to provisioners
	// as the deployment public issuer (e.g. http://127.0.0.1:4444).
	TargetIssuer string
	// TargetProvider is stored on Target.Provider (default "ory").
	TargetProvider string
	// DefaultWorkloadScopes applied when provisioning WORKLOAD rows.
	DefaultWorkloadScopes []string
}

// NewProvisionBridge validates required fields and applies defaults.
func NewProvisionBridge(svc *Service, targetIssuer string, human provider.IdentityProvisioner, workload provider.WorkloadProvisioner) (*ProvisionBridge, error) {
	if svc == nil || svc.Store == nil {
		return nil, fmt.Errorf("migration: Service with Store is required")
	}
	if strings.TrimSpace(targetIssuer) == "" {
		return nil, fmt.Errorf("migration: TargetIssuer is required")
	}
	return &ProvisionBridge{
		Service:               svc,
		Human:                 human,
		Workload:              workload,
		TargetIssuer:          strings.TrimRight(targetIssuer, "/"),
		TargetProvider:        "ory",
		DefaultWorkloadScopes: provider.NormalizeAllowedScopes([]string{"actor-type-workload", "context-resolve"}),
	}, nil
}

// ProvisionResult is the ledger row after a successful or failed bridge attempt.
type ProvisionResult struct {
	Record *Record
	// ProviderSubject is the target subject (Kratos id or Hydra client id).
	ProviderSubject string
	// AlreadyProvisioned is true when the row was already ≥ PROVISIONED.
	AlreadyProvisioned bool
}

// Provision advances one row DISCOVERED → … → PROVISIONED.
//
// Allowed starting states: DISCOVERED, VALIDATED, READY, PROVISIONING
// (resume after retry). Rows in PROVISIONED or later are returned unchanged.
//
// ORPHAN_CANDIDATE and BREAK_GLASS are refused (manual procedures).
func (b *ProvisionBridge) Provision(ctx context.Context, migrationID string) (*ProvisionResult, error) {
	if b == nil || b.Service == nil {
		return nil, fmt.Errorf("migration: ProvisionBridge is nil")
	}
	r, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}

	switch r.IdentityClass {
	case ClassOrphanCandidate:
		return nil, fmt.Errorf("migration: refuse to provision ORPHAN_CANDIDATE %q (manual review)", migrationID)
	case ClassBreakGlass:
		return nil, fmt.Errorf("migration: refuse to auto-provision BREAK_GLASS %q", migrationID)
	}

	// Already past provision stage — idempotent success.
	if !targetOptional(r.MigrationState) && r.MigrationState != StateProvisioning {
		if r.MigrationState == StateProvisioned ||
			r.MigrationState == StateCredentialPending ||
			r.MigrationState == StateCredentialReady ||
			r.MigrationState == StateVerificationPending ||
			r.MigrationState == StateVerified ||
			r.MigrationState == StateCutoverReady ||
			r.MigrationState == StateCutover ||
			r.MigrationState == StateLegacyRetired {
			return &ProvisionResult{Record: r, ProviderSubject: r.Target.Subject, AlreadyProvisioned: true}, nil
		}
	}

	// Walk pre-provision states.
	if err := b.advanceTo(ctx, migrationID, r, StateValidated); err != nil {
		return nil, err
	}
	if err := b.advanceTo(ctx, migrationID, r, StateReady); err != nil {
		return nil, err
	}
	if err := b.advanceTo(ctx, migrationID, r, StateProvisioning); err != nil {
		return nil, err
	}

	r, err = b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return nil, err
	}

	target, provErr := b.provisionTarget(ctx, r)
	if provErr != nil {
		_ = b.fail(ctx, migrationID, "provision_failed")
		return nil, fmt.Errorf("migration: provision %s: %w", migrationID, provErr)
	}

	if _, err := b.Service.SetTargetBinding(ctx, migrationID, target); err != nil {
		_ = b.fail(ctx, migrationID, "set_target_failed")
		return nil, err
	}
	out, err := b.Service.ApplyTransition(ctx, migrationID, StateProvisioned)
	if err != nil {
		return nil, err
	}
	return &ProvisionResult{Record: out, ProviderSubject: target.Subject}, nil
}

// advanceTo moves to `to` when current state is strictly before it on the happy path.
// Always reloads from the store so callers can pass a stale snapshot safely.
func (b *ProvisionBridge) advanceTo(ctx context.Context, migrationID string, _ *Record, to MigrationState) error {
	r, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return err
	}
	if r.MigrationState == to || stateOrder(r.MigrationState) >= stateOrder(to) {
		return nil
	}
	for stateOrder(r.MigrationState) < stateOrder(to) {
		next := nextHappy(r.MigrationState)
		if next == "" {
			return fmt.Errorf("migration: cannot advance from %s toward %s", r.MigrationState, to)
		}
		r, err = b.Service.ApplyTransition(ctx, migrationID, next)
		if err != nil {
			return err
		}
	}
	return nil
}

func stateOrder(s MigrationState) int {
	switch s {
	case StateDiscovered:
		return 0
	case StateValidated:
		return 1
	case StateReady:
		return 2
	case StateProvisioning:
		return 3
	case StateProvisioned:
		return 4
	default:
		return 100
	}
}

func nextHappy(from MigrationState) MigrationState {
	switch from {
	case StateDiscovered:
		return StateValidated
	case StateValidated:
		return StateReady
	case StateReady:
		return StateProvisioning
	case StateProvisioning:
		return StateProvisioned
	default:
		return ""
	}
}

func (b *ProvisionBridge) provisionTarget(ctx context.Context, r *Record) (ProviderBinding, error) {
	switch r.IdentityClass {
	case ClassHuman, ClassPrivilegedHuman, ClassFederatedHuman, ClassTestOrNonProd:
		return b.provisionHuman(ctx, r)
	case ClassWorkload, ClassServiceIntegration:
		return b.provisionWorkload(ctx, r)
	default:
		return ProviderBinding{}, fmt.Errorf("migration: unsupported identity_class %q for auto-provision", r.IdentityClass)
	}
}

func (b *ProvisionBridge) provisionHuman(ctx context.Context, r *Record) (ProviderBinding, error) {
	if b.Human == nil {
		return ProviderBinding{}, fmt.Errorf("migration: IdentityProvisioner is not configured")
	}
	spec := provider.IdentityProvisioningSpec{
		Traits: map[string]any{
			"migration_source_subject": r.Source.Subject,
			"migration_id":             r.MigrationID,
		},
		MigrationID: r.MigrationID,
		Metadata: map[string]string{
			"gate":                  "IAM-M5",
			"canonical_identity_id": r.CanonicalIdentityID,
			"source_issuer":         r.Source.Issuer,
		},
	}
	id, err := b.Human.ProvisionIdentity(ctx, spec)
	if err != nil {
		return ProviderBinding{}, err
	}
	if id == nil || id.Subject == "" {
		return ProviderBinding{}, fmt.Errorf("migration: provisioner returned empty subject")
	}
	issuer := id.Issuer
	if issuer == "" {
		issuer = b.TargetIssuer
	}
	return ProviderBinding{
		Provider: b.targetProviderName(id.Provider),
		Issuer:   issuer,
		Subject:  id.Subject,
	}, nil
}

func (b *ProvisionBridge) provisionWorkload(ctx context.Context, r *Record) (ProviderBinding, error) {
	if b.Workload == nil {
		return ProviderBinding{}, fmt.Errorf("migration: WorkloadProvisioner is not configured")
	}
	logicalID := r.Source.Subject
	scopes := b.DefaultWorkloadScopes
	if len(scopes) == 0 {
		scopes = provider.NormalizeAllowedScopes([]string{"actor-type-workload", "context-resolve"})
	}
	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: logicalID,
		DisplayName:     logicalID,
		AllowedScopes:   scopes,
		AuthMethod:      provider.WorkloadAuthClientSecret,
		Metadata: map[string]string{
			"gate":          "IAM-M5",
			"migration_id":  r.MigrationID,
			"source_issuer": r.Source.Issuer,
		},
	}
	w, err := b.Workload.ProvisionWorkload(ctx, spec)
	if err != nil {
		return ProviderBinding{}, err
	}
	if w == nil {
		return ProviderBinding{}, fmt.Errorf("migration: workload provisioner returned nil")
	}
	subject := w.ProviderClientID
	if subject == "" {
		subject = w.LogicalClientID
	}
	if subject == "" {
		return ProviderBinding{}, fmt.Errorf("migration: workload provisioner returned empty client id")
	}
	issuer := w.Issuer
	if issuer == "" {
		issuer = b.TargetIssuer
	}
	return ProviderBinding{
		Provider: b.targetProviderName(w.Provider),
		Issuer:   issuer,
		Subject:  subject,
	}, nil
}

func (b *ProvisionBridge) targetProviderName(fromProvisioner string) string {
	if fromProvisioner != "" {
		return fromProvisioner
	}
	if b.TargetProvider != "" {
		return b.TargetProvider
	}
	return "ory"
}

func (b *ProvisionBridge) fail(ctx context.Context, migrationID, code string) error {
	r, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return err
	}
	to := StateFailedRetryable
	if !CanTransition(r.MigrationState, to) {
		to = StateFailedManualReview
	}
	if CanTransition(r.MigrationState, to) {
		if _, err := b.Service.ApplyTransition(ctx, migrationID, to); err != nil {
			r.LastErrorCode = code
			_ = b.Service.Store.Put(ctx, r)
			return err
		}
	}
	r2, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return err
	}
	r2.LastErrorCode = code
	return b.Service.Store.Put(ctx, r2)
}
