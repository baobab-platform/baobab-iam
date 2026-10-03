// Target path: baobab-iam/internal/migration/bridge.go
//
// ProvisionBridge advances ledger rows from DISCOVERED through PROVISIONED
// by calling provider-neutral IdentityProvisioner / WorkloadProvisioner /
// FederatedWorkloadProvisioner (ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022).
//
// Workload policy (post EA-04 / Shared federated_workload_token):
//   - Default WORKLOAD / SERVICE_INTEGRATION path is federated JWT-bearer
//     (RFC 7523). No static OAuth client secret is generated or stored.
//   - Client-secret Hydra clients are M4-C only and require an explicit
//     allow-list entry on the bridge (Shared-authorized secret clients).
//   - AllowedScopes / audiences for federated trust MUST be supplied by the
//     operator from the Shared workload registry — the bridge does not invent
//     platform scopes.
//
// Explicitly does not:
//   - advance past PROVISIONED into credential/verification/cutover
//   - store client secrets, private JWKs, password hashes, or TOTP on the ledger
//   - authorize production CUTOVER (PolicyGate still applies on transitions)
//   - mark Shared workload lifecycle ACTIVE (provider evidence only)
package migration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// WorkloadCredentialProfile selects the M4 provider path for a logical client.
type WorkloadCredentialProfile string

const (
	// WorkloadProfileFederated is Shared credential_type=federated_workload_token
	// (ADR-IAM-0021). Default for WORKLOAD / SERVICE_INTEGRATION rows.
	WorkloadProfileFederated WorkloadCredentialProfile = "federated_workload_token"
	// WorkloadProfileClientSecret is the limited M4-C confidential-client path.
	// Only logical IDs present in ProvisionBridge.ClientSecretAllowList may use it.
	WorkloadProfileClientSecret WorkloadCredentialProfile = "client_secret"
)

// FederatedTrustTemplate supplies Shared-aligned trust inputs for M4-F.
// Scopes and audiences are keyed by logical client id and MUST mirror Shared.
// AssertionJWK must be public material only (validated by FederatedWorkloadTrustSpec).
type FederatedTrustTemplate struct {
	AssertionIssuer string
	// AssertionSubjectFor returns the exact JWT subject Hydra will trust.
	// If nil, defaults to "system:serviceaccount:baobab:" + logicalClientID.
	AssertionSubjectFor func(logicalClientID string) string
	AssertionJWK        map[string]any
	// TrustTTL bounds provider-side trust. Default 24h when zero.
	TrustTTL time.Duration
	// ScopesByLogicalID is required for each federated logical client.
	ScopesByLogicalID map[string][]string
	// AudiencesByLogicalID is required for each federated logical client.
	AudiencesByLogicalID map[string][]string
}

// ProvisionBridge orchestrates ledger state + target provider provisioning.
// Zero-value is not usable; construct with NewProvisionBridge.
type ProvisionBridge struct {
	Service *Service
	// Human provisions Kratos (or equivalent) identities.
	Human provider.IdentityProvisioner
	// Workload provisions confidential OAuth clients (M4-C only).
	Workload provider.WorkloadProvisioner
	// Federated provisions RFC 7523 trust (M4-F default for platform workloads).
	Federated provider.FederatedWorkloadProvisioner
	// TargetIssuer is the deployment public issuer (e.g. Hydra public URL).
	TargetIssuer string
	// TargetProvider is stored on Target.Provider (default "ory").
	TargetProvider string
	// DefaultWorkloadProfile selects M4-F vs M4-C when not overridden by allow-list.
	// Empty means WorkloadProfileFederated.
	DefaultWorkloadProfile WorkloadCredentialProfile
	// ClientSecretAllowList lists logical client ids permitted to use M4-C
	// client_secret. Empty means no client-secret path (fail closed).
	ClientSecretAllowList map[string]struct{}
	// FederatedTrust supplies Shared-aligned scopes/audiences/issuer for M4-F.
	FederatedTrust *FederatedTrustTemplate
	// Now is injectable for tests.
	Now func() time.Time
}

// NewProvisionBridge returns a bridge with federated-first defaults.
func NewProvisionBridge(svc *Service) *ProvisionBridge {
	return &ProvisionBridge{
		Service:                 svc,
		TargetProvider:          "ory",
		DefaultWorkloadProfile:  WorkloadProfileFederated,
		ClientSecretAllowList:   map[string]struct{}{},
	}
}

// WithFederated configures the M4-F path.
func (b *ProvisionBridge) WithFederated(f provider.FederatedWorkloadProvisioner, trust *FederatedTrustTemplate) *ProvisionBridge {
	b.Federated = f
	b.FederatedTrust = trust
	return b
}

// WithHuman configures the human identity provisioner.
func (b *ProvisionBridge) WithHuman(h provider.IdentityProvisioner) *ProvisionBridge {
	b.Human = h
	return b
}

// WithWorkload configures the M4-C confidential-client provisioner.
func (b *ProvisionBridge) WithWorkload(w provider.WorkloadProvisioner) *ProvisionBridge {
	b.Workload = w
	return b
}

// AllowClientSecret permits the given logical client ids to use M4-C.
func (b *ProvisionBridge) AllowClientSecret(ids ...string) *ProvisionBridge {
	if b.ClientSecretAllowList == nil {
		b.ClientSecretAllowList = map[string]struct{}{}
	}
	for _, id := range ids {
		b.ClientSecretAllowList[id] = struct{}{}
	}
	return b
}

func (b *ProvisionBridge) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now().UTC()
}

func (b *ProvisionBridge) targetProvider() string {
	if b.TargetProvider != "" {
		return b.TargetProvider
	}
	return "ory"
}

// resolveWorkloadProfile chooses M4-F (default) or M4-C (allow-list only).
func (b *ProvisionBridge) resolveWorkloadProfile(logicalClientID string) WorkloadCredentialProfile {
	if b.ClientSecretAllowList != nil {
		if _, ok := b.ClientSecretAllowList[logicalClientID]; ok {
			return WorkloadProfileClientSecret
		}
	}
	if b.DefaultWorkloadProfile != "" {
		return b.DefaultWorkloadProfile
	}
	return WorkloadProfileFederated
}

// ProvisionResult is returned after a successful (or already-done) provision.
type ProvisionResult struct {
	Record *Record
	// ProviderSubject is the target subject (Kratos id or Hydra client id).
	ProviderSubject string
	// WorkloadProfile records which M4 path was used (empty for humans).
	WorkloadProfile WorkloadCredentialProfile
	// AlreadyProvisioned is true when the row was already ≥ PROVISIONED.
	AlreadyProvisioned bool
}

// Provision advances one row DISCOVERED → … → PROVISIONED.
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

	target, profile, provErr := b.provisionTarget(ctx, r)
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
	return &ProvisionResult{Record: out, ProviderSubject: target.Subject, WorkloadProfile: profile}, nil
}

func (b *ProvisionBridge) advanceTo(ctx context.Context, migrationID string, r *Record, next MigrationState) error {
	if r.MigrationState == next {
		return nil
	}
	// Only advance forward from earlier states; skip if already past.
	order := []MigrationState{
		StateDiscovered, StateValidated, StateReady, StateProvisioning, StateProvisioned,
	}
	curIdx, nextIdx := -1, -1
	for i, s := range order {
		if s == r.MigrationState {
			curIdx = i
		}
		if s == next {
			nextIdx = i
		}
	}
	if curIdx >= 0 && nextIdx >= 0 && curIdx >= nextIdx {
		return nil
	}
	_, err := b.Service.ApplyTransition(ctx, migrationID, next)
	return err
}

func (b *ProvisionBridge) provisionTarget(ctx context.Context, r *Record) (ProviderBinding, WorkloadCredentialProfile, error) {
	switch r.IdentityClass {
	case ClassHuman, ClassPrivilegedHuman, ClassFederatedHuman, ClassTestOrNonProd:
		return b.provisionHuman(ctx, r)
	case ClassWorkload, ClassServiceIntegration:
		return b.provisionWorkload(ctx, r)
	default:
		return ProviderBinding{}, "", fmt.Errorf("unsupported identity class %q", r.IdentityClass)
	}
}

func (b *ProvisionBridge) provisionHuman(ctx context.Context, r *Record) (ProviderBinding, WorkloadCredentialProfile, error) {
	if b.Human == nil {
		return ProviderBinding{}, "", fmt.Errorf("human identity provisioner not configured")
	}
	spec := provider.IdentitySpec{
		LogicalID:   r.CanonicalIdentityID,
		DisplayName: r.CanonicalIdentityID,
		Traits:      map[string]any{},
	}
	res, err := b.Human.ProvisionIdentity(ctx, spec)
	if err != nil {
		return ProviderBinding{}, "", err
	}
	return ProviderBinding{
		Provider: b.targetProvider(),
		Issuer:   b.TargetIssuer,
		Subject:  res.ProviderSubjectID,
	}, "", nil
}

func (b *ProvisionBridge) provisionWorkload(ctx context.Context, r *Record) (ProviderBinding, WorkloadCredentialProfile, error) {
	logicalID := r.CanonicalIdentityID
	if logicalID == "" {
		logicalID = r.Source.Subject
	}
	profile := b.resolveWorkloadProfile(logicalID)
	switch profile {
	case WorkloadProfileClientSecret:
		return b.provisionWorkloadClientSecret(ctx, r, logicalID)
	default:
		return b.provisionWorkloadFederated(ctx, r, logicalID)
	}
}

func (b *ProvisionBridge) provisionWorkloadClientSecret(ctx context.Context, r *Record, logicalID string) (ProviderBinding, WorkloadCredentialProfile, error) {
	if b.Workload == nil {
		return ProviderBinding{}, WorkloadProfileClientSecret, fmt.Errorf("workload provisioner not configured")
	}
	spec := provider.WorkloadClientSpec{
		LogicalClientID: logicalID,
	}
	res, err := b.Workload.ProvisionWorkload(ctx, spec)
	if err != nil {
		return ProviderBinding{}, WorkloadProfileClientSecret, err
	}
	// Secrets returned only on operator channel — never on ledger.
	return ProviderBinding{
		Provider: b.targetProvider(),
		Issuer:   b.TargetIssuer,
		Subject:  res.ProviderClientID,
	}, WorkloadProfileClientSecret, nil
}

func (b *ProvisionBridge) provisionWorkloadFederated(ctx context.Context, r *Record, logicalID string) (ProviderBinding, WorkloadCredentialProfile, error) {
	if b.Federated == nil {
		return ProviderBinding{}, WorkloadProfileFederated, fmt.Errorf("federated workload provisioner not configured")
	}
	trust := provider.FederatedWorkloadTrustSpec{
		LogicalClientID: logicalID,
	}
	if b.FederatedTrust != nil {
		trust.AssertionIssuer = b.FederatedTrust.AssertionIssuer
		if b.FederatedTrust.AssertionSubjectFor != nil {
			trust.AssertionSubject = b.FederatedTrust.AssertionSubjectFor(logicalID)
		} else {
			trust.AssertionSubject = "system:serviceaccount:baobab:" + logicalID
		}
		if scopes, ok := b.FederatedTrust.ScopesByLogicalID[logicalID]; ok {
			trust.AllowedScopes = scopes
		}
		if auds, ok := b.FederatedTrust.AudiencesByLogicalID[logicalID]; ok && len(auds) > 0 {
			trust.Audience = auds[0]
		}
		trust.AssertionJWK = b.FederatedTrust.AssertionJWK
		if b.FederatedTrust.TrustTTL > 0 {
			trust.TrustTTL = b.FederatedTrust.TrustTTL
		}
	} else {
		trust.AssertionSubject = "system:serviceaccount:baobab:" + logicalID
	}
	if len(trust.AllowedScopes) == 0 {
		return ProviderBinding{}, WorkloadProfileFederated, fmt.Errorf("federated trust requires AllowedScopes from Shared registry for %q", logicalID)
	}
	if strings.TrimSpace(trust.Audience) == "" {
		return ProviderBinding{}, WorkloadProfileFederated, fmt.Errorf("federated trust requires Audience from Shared registry for %q", logicalID)
	}
	res, err := b.Federated.ProvisionFederatedWorkload(ctx, trust)
	if err != nil {
		return ProviderBinding{}, WorkloadProfileFederated, err
	}
	return ProviderBinding{
		Provider: b.targetProvider(),
		Issuer:   b.TargetIssuer,
		Subject:  res.ProviderClientID,
	}, WorkloadProfileFederated, nil
}

func (b *ProvisionBridge) fail(ctx context.Context, migrationID, code string) error {
	r, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return err
	}
	r.LastErrorCode = code
	r.MigrationState = StateFailedRetryable
	return b.Service.Store.Put(ctx, r)
}
