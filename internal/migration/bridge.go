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
	// AllowedScopesByClient maps logical client id -> scopes from Shared registry.
	AllowedScopesByClient map[string][]string
	// AudienceByClient maps logical client id -> audience (resource server).
	AudienceByClient map[string]string
	// AssertionJWK is the public JWK for the platform assertion issuer.
	// Private material must never reach the bridge or ledger.
	AssertionJWK map[string]interface{}
}

// ProvisionBridge advances DISCOVERED ledger rows to PROVISIONED.
type ProvisionBridge struct {
	Service *Service
	// Identity provisioner (human / service accounts via Kratos path).
	Identities provider.IdentityProvisioner
	// Classic confidential-client path (M4-C only).
	Workloads provider.WorkloadProvisioner
	// Federated JWT-bearer path (M4-F default).
	Federated provider.FederatedWorkloadProvisioner
	// ClientSecretAllowList limits which logical client IDs may use client_secret.
	// Empty = federated-only for all workloads.
	ClientSecretAllowList map[string]struct{}
	// FederatedTrust supplies Shared-aligned scopes/audiences/issuer for M4-F.
	FederatedTrust *FederatedTrustTemplate
	// Now is injectable for tests.
	Now func() time.Time
}

func (b *ProvisionBridge) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now().UTC()
}

// resolveWorkloadProfile chooses M4-F (default) or M4-C (allow-list only).
func (b *ProvisionBridge) resolveWorkloadProfile(logicalClientID string) WorkloadCredentialProfile {
	if b.ClientSecretAllowList != nil {
		if _, ok := b.ClientSecretAllowList[logicalClientID]; ok {
			return WorkloadProfileClientSecret
		}
	}
	return WorkloadProfileFederated
}

// Provision advances a single ledger row from DISCOVERED to PROVISIONED.
// It is idempotent for already-PROVISIONED rows.
func (b *ProvisionBridge) Provision(ctx context.Context, migrationID string) error {
	if b.Service == nil || b.Service.Store == nil {
		return fmt.Errorf("provision bridge: service/store required")
	}
	r, err := b.Service.Store.Get(ctx, migrationID)
	if err != nil {
		return err
	}
	if r.State == StateProvisioned || r.State == StateCredentialIssued || r.State == StateCredentialVerified || r.State == StateReady || r.State == StateCutover {
		return nil
	}
	if r.State != StateDiscovered {
		return fmt.Errorf("provision bridge: expected DISCOVERED, got %s", r.State)
	}

	switch r.SubjectKind {
	case SubjectKindHuman, SubjectKindServiceAccount:
		return b.provisionIdentity(ctx, r)
	case SubjectKindWorkload, SubjectKindServiceIntegration:
		return b.provisionWorkload(ctx, r)
	default:
		return fmt.Errorf("provision bridge: unsupported subject kind %q", r.SubjectKind)
	}
}

func (b *ProvisionBridge) provisionIdentity(ctx context.Context, r *LedgerRecord) error {
	if b.Identities == nil {
		return b.fail(ctx, r.MigrationID, "IDENTITY_PROVISIONER_MISSING", fmt.Errorf("identity provisioner not configured"))
	}
	spec := provider.IdentitySpec{
		LogicalID:   r.LogicalSubjectID,
		DisplayName: r.LogicalSubjectID,
		Traits:      map[string]interface{}{},
	}
	if r.SourceEmail != "" {
		spec.Traits["email"] = r.SourceEmail
	}
	res, err := b.Identities.ProvisionIdentity(ctx, spec)
	if err != nil {
		return b.fail(ctx, r.MigrationID, "IDENTITY_PROVISION_FAILED", err)
	}
	r.TargetSubjectID = res.ProviderSubjectID
	r.State = StateProvisioned
	r.LastErrorCode = ""
	r.UpdatedAt = b.now()
	return b.Service.Store.Put(ctx, r)
}

func (b *ProvisionBridge) provisionWorkload(ctx context.Context, r *LedgerRecord) error {
	logicalID := r.LogicalSubjectID
	if logicalID == "" {
		logicalID = r.SourceClientID
	}
	profile := b.resolveWorkloadProfile(logicalID)
	switch profile {
	case WorkloadProfileClientSecret:
		return b.provisionWorkloadClientSecret(ctx, r, logicalID)
	default:
		return b.provisionWorkloadFederated(ctx, r, logicalID)
	}
}

func (b *ProvisionBridge) provisionWorkloadClientSecret(ctx context.Context, r *LedgerRecord, logicalID string) error {
	if b.Workloads == nil {
		return b.fail(ctx, r.MigrationID, "WORKLOAD_PROVISIONER_MISSING", fmt.Errorf("workload provisioner not configured"))
	}
	spec := provider.WorkloadClientSpec{
		LogicalClientID: logicalID,
		// Scopes/audiences MUST come from Shared; do not invent defaults here.
		// Caller/CLI is expected to have already resolved them when building the ledger row.
		AllowedScopes: r.AllowedScopes,
		Audience:      r.Audience,
	}
	res, err := b.Workloads.ProvisionWorkload(ctx, spec)
	if err != nil {
		return b.fail(ctx, r.MigrationID, "WORKLOAD_PROVISION_FAILED", err)
	}
	// Secrets are returned only to the operator channel (CLI stdout / secret manager).
	// They must never be written to the ledger.
	r.TargetClientID = res.ProviderClientID
	r.LifecycleStatus = "PROVISIONED"
	r.State = StateProvisioned
	r.LastErrorCode = ""
	r.UpdatedAt = b.now()
	return b.Service.Store.Put(ctx, r)
}

func (b *ProvisionBridge) provisionWorkloadFederated(ctx context.Context, r *LedgerRecord, logicalID string) error {
	if b.Federated == nil {
		return b.fail(ctx, r.MigrationID, "FEDERATED_PROVISIONER_MISSING", fmt.Errorf("federated workload provisioner not configured"))
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
		if scopes, ok := b.FederatedTrust.AllowedScopesByClient[logicalID]; ok {
			trust.AllowedScopes = scopes
		} else if len(r.AllowedScopes) > 0 {
			trust.AllowedScopes = r.AllowedScopes
		}
		if aud, ok := b.FederatedTrust.AudienceByClient[logicalID]; ok {
			trust.Audience = aud
		} else if r.Audience != "" {
			trust.Audience = r.Audience
		}
		trust.AssertionJWK = b.FederatedTrust.AssertionJWK
	} else {
		// Minimal path: scopes/audience from ledger row only (must be Shared-sourced).
		trust.AllowedScopes = r.AllowedScopes
		trust.Audience = r.Audience
		trust.AssertionSubject = "system:serviceaccount:baobab:" + logicalID
	}
	if len(trust.AllowedScopes) == 0 {
		return b.fail(ctx, r.MigrationID, "FEDERATED_SCOPES_REQUIRED", fmt.Errorf("federated trust requires AllowedScopes from Shared registry"))
	}
	if strings.TrimSpace(trust.Audience) == "" {
		return b.fail(ctx, r.MigrationID, "FEDERATED_AUDIENCE_REQUIRED", fmt.Errorf("federated trust requires Audience from Shared registry"))
	}
	res, err := b.Federated.ProvisionFederatedWorkload(ctx, trust)
	if err != nil {
		return b.fail(ctx, r.MigrationID, "FEDERATED_PROVISION_FAILED", err)
	}
	r.TargetClientID = res.ProviderClientID
	r.LifecycleStatus = "PROVISIONED"
	r.State = StateProvisioned
	r.LastErrorCode = ""
	r.UpdatedAt = b.now()
	return b.Service.Store.Put(ctx, r)
}

func (b *ProvisionBridge) fail(ctx context.Context, migrationID, code string, err error) error {
	r, getErr := b.Service.Store.Get(ctx, migrationID)
	if getErr != nil {
		return fmt.Errorf("%s: %w (also failed to load ledger: %v)", code, err, getErr)
	}
	r.LastErrorCode = code
	r.UpdatedAt = b.now()
	_ = b.Service.Store.Put(ctx, r)
	// Best-effort: re-read and ensure code is persisted even if concurrent writers race.
	r2, err2 := b.Service.Store.Get(ctx, migrationID)
	if err2 != nil {
		return err
	}
	r2.LastErrorCode = code
	return b.Service.Store.Put(ctx, r2)
}
