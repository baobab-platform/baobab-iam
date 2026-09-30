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
	// ClientSecretScopesByLogicalID supplies scopes for allow-listed M4-C clients.
	// Required for each allow-listed id at provision time.
	ClientSecretScopesByLogicalID map[string][]string
	// FederatedTrust holds Shared-aligned trust template for M4-F.
	FederatedTrust FederatedTrustTemplate
}

// NewProvisionBridge validates required fields and applies federated-first defaults.
func NewProvisionBridge(svc *Service, targetIssuer string, human provider.IdentityProvisioner, workload provider.WorkloadProvisioner) (*ProvisionBridge, error) {
	if svc == nil || svc.Store == nil {
		return nil, fmt.Errorf("migration: Service with Store is required")
	}
	if strings.TrimSpace(targetIssuer) == "" {
		return nil, fmt.Errorf("migration: TargetIssuer is required")
	}
	return &ProvisionBridge{
		Service:                svc,
		Human:                  human,
		Workload:               workload,
		TargetIssuer:           strings.TrimRight(targetIssuer, "/"),
		TargetProvider:         "ory",
		DefaultWorkloadProfile: WorkloadProfileFederated,
	}, nil
}

// WithFederated attaches the M4-F provisioner and Shared-aligned trust template.
func (b *ProvisionBridge) WithFederated(fed provider.FederatedWorkloadProvisioner, trust FederatedTrustTemplate) *ProvisionBridge {
	b.Federated = fed
	b.FederatedTrust = trust
	return b
}

// AllowClientSecret marks a logical client id as Shared-authorized for M4-C.
func (b *ProvisionBridge) AllowClientSecret(logicalClientID string, scopes []string) *ProvisionBridge {
	if b.ClientSecretAllowList == nil {
		b.ClientSecretAllowList = make(map[string]struct{})
	}
	if b.ClientSecretScopesByLogicalID == nil {
		b.ClientSecretScopesByLogicalID = make(map[string][]string)
	}
	b.ClientSecretAllowList[logicalClientID] = struct{}{}
	b.ClientSecretScopesByLogicalID[logicalClientID] = append([]string(nil), scopes...)
	return b
}

// ProvisionResult is the ledger row after a successful or failed bridge attempt.
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

func (b *ProvisionBridge) provisionTarget(ctx context.Context, r *Record) (ProviderBinding, WorkloadCredentialProfile, error) {
	switch r.IdentityClass {
	case ClassHuman, ClassPrivilegedHuman, ClassFederatedHuman, ClassTestOrNonProd:
		binding, err := b.provisionHuman(ctx, r)
		return binding, "", err
	case ClassWorkload, ClassServiceIntegration:
		return b.provisionWorkload(ctx, r)
	default:
		return ProviderBinding{}, "", fmt.Errorf("migration: unsupported identity_class %q for auto-provision", r.IdentityClass)
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

// resolveWorkloadProfile chooses M4-F (default) vs M4-C (explicit allow-list).
func (b *ProvisionBridge) resolveWorkloadProfile(logicalID string) WorkloadCredentialProfile {
	if _, ok := b.ClientSecretAllowList[logicalID]; ok {
		return WorkloadProfileClientSecret
	}
	return WorkloadProfileFederated
}

func (b *ProvisionBridge) provisionWorkload(ctx context.Context, r *Record) (ProviderBinding, WorkloadCredentialProfile, error) {
	logicalID := r.Source.Subject
	if logicalID == "" {
		return ProviderBinding{}, "", fmt.Errorf("migration: workload source subject (logical client id) is required")
	}
	profile := b.resolveWorkloadProfile(logicalID)
	switch profile {
	case WorkloadProfileClientSecret:
		binding, err := b.provisionWorkloadClientSecret(ctx, r, logicalID)
		return binding, WorkloadProfileClientSecret, err
	default:
		binding, err := b.provisionWorkloadFederated(ctx, r, logicalID)
		return binding, WorkloadProfileFederated, err
	}
}

func (b *ProvisionBridge) provisionWorkloadClientSecret(ctx context.Context, r *Record, logicalID string) (ProviderBinding, error) {
	if b.Workload == nil {
		return ProviderBinding{}, fmt.Errorf("migration: WorkloadProvisioner is not configured for M4-C client_secret path")
	}
	if _, ok := b.ClientSecretAllowList[logicalID]; !ok {
		return ProviderBinding{}, fmt.Errorf("migration: logical client %q is not on ClientSecretAllowList (ADR-0021: federated default; M4-C requires explicit allow)", logicalID)
	}
	scopes := provider.NormalizeAllowedScopes(b.ClientSecretScopesByLogicalID[logicalID])
	if len(scopes) == 0 {
		return ProviderBinding{}, fmt.Errorf("migration: Shared-authorized scopes required for M4-C client %q (no hardcoded defaults)", logicalID)
	}
	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: logicalID,
		DisplayName:     logicalID,
		AllowedScopes:   scopes,
		AuthMethod:      provider.WorkloadAuthClientSecret,
		Metadata: map[string]string{
			"gate":                   "IAM-M5",
			"migration_id":           r.MigrationID,
			"source_issuer":          r.Source.Issuer,
			"baobab_credential_type": "client_secret",
			"m4_path":                "M4-C",
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

func (b *ProvisionBridge) provisionWorkloadFederated(ctx context.Context, r *Record, logicalID string) (ProviderBinding, error) {
	if b.Federated == nil {
		return ProviderBinding{}, fmt.Errorf("migration: FederatedWorkloadProvisioner is required for federated_workload_token path (ADR-0021); attach WithFederated or allow-list M4-C client_secret explicitly")
	}
	tpl := b.FederatedTrust
	if strings.TrimSpace(tpl.AssertionIssuer) == "" {
		return ProviderBinding{}, fmt.Errorf("migration: FederatedTrust.AssertionIssuer is required (platform projected-token issuer)")
	}
	if len(tpl.AssertionJWK) == 0 {
		return ProviderBinding{}, fmt.Errorf("migration: FederatedTrust.AssertionJWK public key is required")
	}
	scopes := provider.NormalizeAllowedScopes(tpl.ScopesByLogicalID[logicalID])
	if len(scopes) == 0 {
		return ProviderBinding{}, fmt.Errorf("migration: Shared registry scopes missing for federated client %q (ScopesByLogicalID)", logicalID)
	}
	audiences := append([]string(nil), tpl.AudiencesByLogicalID[logicalID]...)
	if len(audiences) == 0 {
		return ProviderBinding{}, fmt.Errorf("migration: Shared registry audiences missing for federated client %q (AudiencesByLogicalID)", logicalID)
	}
	subject := "system:serviceaccount:baobab:" + logicalID
	if tpl.AssertionSubjectFor != nil {
		subject = tpl.AssertionSubjectFor(logicalID)
	}
	ttl := tpl.TrustTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	jwk := make(map[string]any, len(tpl.AssertionJWK))
	for k, v := range tpl.AssertionJWK {
		jwk[k] = v
	}
	spec := provider.FederatedWorkloadTrustSpec{
		LogicalClientID:   logicalID,
		DisplayName:       logicalID,
		AllowedScopes:     scopes,
		IntendedAudiences: audiences,
		AssertionIssuer:   tpl.AssertionIssuer,
		AssertionSubject:  subject,
		AssertionJWK:      jwk,
		TrustExpiresAt:    time.Now().UTC().Add(ttl),
		Metadata: map[string]string{
			"gate":                   "IAM-M5",
			"migration_id":           r.MigrationID,
			"source_issuer":          r.Source.Issuer,
			"baobab_credential_type": "federated_workload_token",
			"m4_path":                "M4-F",
		},
	}
	if err := spec.Validate(); err != nil {
		return ProviderBinding{}, err
	}
	trust, err := b.Federated.ProvisionFederatedWorkload(ctx, spec)
	if err != nil {
		return ProviderBinding{}, err
	}
	if trust == nil {
		return ProviderBinding{}, fmt.Errorf("migration: federated provisioner returned nil")
	}
	clientID := trust.ProviderClientID
	if clientID == "" {
		clientID = trust.LogicalClientID
	}
	if clientID == "" {
		return ProviderBinding{}, fmt.Errorf("migration: federated provisioner returned empty client id")
	}
	issuer := trust.Issuer
	if issuer == "" {
		issuer = b.TargetIssuer
	}
	return ProviderBinding{
		Provider: b.targetProviderName(trust.Provider),
		Issuer:   issuer,
		Subject:  clientID,
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
