// Package provider defines the provider-neutral Identity Provider Contract
// and Adapter Architecture for Baobab IAM (ADR-IAM-0020).
//
// Target path: baobab-iam/internal/provider/provider.go
//
// Rules:
//
//   - Baobab owns identity meaning; the configured provider owns mechanics.
//   - Standards (OIDC, OAuth, JWKS, PKCE, client credentials) stay direct —
//     do not wrap them in proprietary Baobab endpoints.
//   - Business semantics (Tenant, LegalEntity, Market, Capability, domain
//     authorization) never appear in these interfaces.
//   - Callers should depend on the smallest capability interfaces they need,
//     not on the full IdentityProvider union.
package provider

import (
	"context"
	"time"
)

// ---------------------------------------------------------------------------
// Core identity keys (provider-independent)
// ---------------------------------------------------------------------------

// ExternalSubject is the stable, standards-based identity key.
// Canonical resolution remains: issuer + subject → ExternalIdentity → CanonicalIdentity.
type ExternalSubject struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// String returns a debug-friendly representation. Do not use as a storage key
// without canonicalising issuer URLs.
func (s ExternalSubject) String() string {
	return s.Issuer + "|" + s.Subject
}

// ProviderIdentityStatus is the lifecycle state as reported by the provider.
type ProviderIdentityStatus string

const (
	IdentityStatusActive   ProviderIdentityStatus = "active"
	IdentityStatusDisabled ProviderIdentityStatus = "disabled"
	IdentityStatusUnknown  ProviderIdentityStatus = "unknown"
)

// ProviderIdentity is the minimal normalized view of a human identity
// as seen by the configured identity provider. Attributes are opaque
// provider metadata and MUST NOT become Baobab business state.
type ProviderIdentity struct {
	Provider   string                 `json:"provider"` // e.g. "ory", "keycloak"
	Issuer     string                 `json:"issuer"`
	Subject    string                 `json:"subject"`
	Status     ProviderIdentityStatus `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	Attributes map[string]any         `json:"attributes,omitempty"`
}

// ExternalSubject returns the stable key for this identity.
func (p *ProviderIdentity) ExternalSubject() ExternalSubject {
	return ExternalSubject{Issuer: p.Issuer, Subject: p.Subject}
}

// ---------------------------------------------------------------------------
// Workload identity
// ---------------------------------------------------------------------------

// WorkloadAuthenticationMethod describes how a workload client authenticates.
type WorkloadAuthenticationMethod string

const (
	WorkloadAuthClientSecret  WorkloadAuthenticationMethod = "client_secret"
	WorkloadAuthPrivateKeyJWT WorkloadAuthenticationMethod = "private_key_jwt"
)

// WorkloadProvisioningSpec is the input for creating or updating a workload client.
type WorkloadProvisioningSpec struct {
	// LogicalClientID is the Baobab-stable identifier (e.g. "baobab-trade-workload").
	LogicalClientID string `json:"logical_client_id"`

	// DisplayName is human-readable; may appear in admin UIs.
	DisplayName string `json:"display_name,omitempty"`

	// AllowedScopes that this workload is allowed to request.
	AllowedScopes []string `json:"allowed_scopes"`

	// Audiences / resource indicators if required by the token profile.
	Audiences []string `json:"audiences,omitempty"`

	// AuthMethod for the client.
	AuthMethod WorkloadAuthenticationMethod `json:"auth_method"`

	// Metadata that the adapter may persist with the provider client.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ProviderWorkload is the normalized result of provisioning a workload.
type ProviderWorkload struct {
	Provider         string                       `json:"provider"`
	LogicalClientID  string                       `json:"logical_client_id"`
	ProviderClientID string                       `json:"provider_client_id"` // IdP-native ID
	Issuer           string                       `json:"issuer"`
	AuthMethod       WorkloadAuthenticationMethod `json:"auth_method"`
	// ClientSecret is returned only on create/rotate when AuthMethod == client_secret.
	// Callers MUST treat it as sensitive and never log it.
	ClientSecret string            `json:"-"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ProviderWorkloadReference identifies an existing workload for lifecycle ops.
type ProviderWorkloadReference struct {
	LogicalClientID  string `json:"logical_client_id"`
	ProviderClientID string `json:"provider_client_id,omitempty"`
}

// ---------------------------------------------------------------------------
// Human identity provisioning
// ---------------------------------------------------------------------------

// IdentityProvisioningSpec describes a human identity to create or import.
type IdentityProvisioningSpec struct {
	// Traits are the identity schema fields (email, name, …).
	// MUST NOT contain tenant, LegalEntity, purchase limits, etc.
	Traits map[string]any `json:"traits"`

	// Credentials, when present, enable import of existing password hashes,
	// TOTP, WebAuthn, etc. Format is provider-specific but documented per adapter.
	Credentials *ImportedCredentials `json:"credentials,omitempty"`

	// MigrationID correlates this provision with a migration batch/record.
	MigrationID string `json:"migration_id,omitempty"`

	// Metadata for reconciliation tracking (opaque to the provider domain model).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ImportedCredentials carries material that can be imported without forcing
// an immediate password reset. Adapters map these onto provider import APIs.
type ImportedCredentials struct {
	PasswordHash *PasswordHashImport `json:"password_hash,omitempty"`
	TOTP         *TOTPImport         `json:"totp,omitempty"`
	WebAuthn     []WebAuthnImport    `json:"webauthn,omitempty"`
}

// PasswordHashImport holds a pre-hashed password for migration.
type PasswordHashImport struct {
	Algorithm string `json:"algorithm"` // bcrypt, argon2id, pbkdf2, scrypt, …
	Hash      string `json:"hash"`
}

// TOTPImport holds a TOTP shared secret for migration.
type TOTPImport struct {
	Secret string `json:"secret"`
}

// WebAuthnImport holds a provider-specific WebAuthn/passkey credential payload.
type WebAuthnImport struct {
	CredentialJSON []byte `json:"credential_json"`
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

// ReconciliationResult reports the outcome of comparing provider state
// with expected Baobab state within the provider boundary only.
type ReconciliationResult struct {
	Subject          ExternalSubject        `json:"subject"`
	ProviderIdentity *ProviderIdentity      `json:"provider_identity,omitempty"`
	Status           ProviderIdentityStatus `json:"status"`
	Changed          bool                   `json:"changed"`
	ActionsTaken     []string               `json:"actions_taken,omitempty"`
	Notes            string                 `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
// Capability discovery
// ---------------------------------------------------------------------------

// ProviderCapabilities declares what the concrete adapter supports.
// Missing required capabilities MUST fail deployment validation.
type ProviderCapabilities struct {
	Provider string `json:"provider"`

	HumanIdentity     bool   `json:"human_identity"`
	SessionRevocation bool   `json:"session_revocation"`
	WorkloadIdentity  bool   `json:"workload_identity"`
	PasswordImport    bool   `json:"password_import"`
	TOTPImport        bool   `json:"totp_import"`
	PasskeyImport     bool   `json:"passkey_import"`
	EnterpriseSSO     string `json:"enterprise_sso"` // "supported" | "deployment-dependent" | "unsupported"
	SCIM              string `json:"scim"`
}

// ProviderInfo returns static/runtime information about the configured provider.
type ProviderInfo struct {
	Name         string               `json:"name"`
	Version      string               `json:"version,omitempty"`
	Issuer       string               `json:"issuer"`
	Capabilities ProviderCapabilities `json:"capabilities"`
}

// ---------------------------------------------------------------------------
// Capability-oriented interfaces
// ---------------------------------------------------------------------------

// ProviderInfoSource is implemented by every adapter.
type ProviderInfoSource interface {
	ProviderInfo(ctx context.Context) (ProviderInfo, error)
}

// IdentityReader reads a human identity from the provider.
type IdentityReader interface {
	GetIdentity(ctx context.Context, subject ExternalSubject) (*ProviderIdentity, error)
}

// IdentityProvisioner creates or imports human identities.
type IdentityProvisioner interface {
	ProvisionIdentity(ctx context.Context, spec IdentityProvisioningSpec) (*ProviderIdentity, error)
}

// IdentityLifecycleManager enables/disables human identities.
type IdentityLifecycleManager interface {
	DisableIdentity(ctx context.Context, subject ExternalSubject) error
	EnableIdentity(ctx context.Context, subject ExternalSubject) error
}

// SessionRevoker invalidates provider-side sessions for a subject.
// This is the technical half of the Baobab “kill switch”; CP membership
// revocation remains a separate concern.
type SessionRevoker interface {
	RevokeSessions(ctx context.Context, subject ExternalSubject) error
}

// WorkloadProvisioner manages OAuth clients used for machine identities.
type WorkloadProvisioner interface {
	ProvisionWorkload(ctx context.Context, spec WorkloadProvisioningSpec) (*ProviderWorkload, error)
	DisableWorkload(ctx context.Context, ref ProviderWorkloadReference) error
	RotateWorkloadCredentials(ctx context.Context, ref ProviderWorkloadReference) (*ProviderWorkload, error)
}

// IdentityReconciler compares provider state with expected Baobab state
// and reports / applies corrective actions within the provider boundary.
type IdentityReconciler interface {
	ReconcileIdentity(ctx context.Context, subject ExternalSubject) (*ReconciliationResult, error)
}

// ---------------------------------------------------------------------------
// Composed full adapter (optional convenience)
// ---------------------------------------------------------------------------

// IdentityProvider is the union of all capabilities. Prefer depending on the
// smaller interfaces above so adapters that lack a capability are not forced
// to implement stubs.
type IdentityProvider interface {
	ProviderInfoSource
	IdentityReader
	IdentityProvisioner
	IdentityLifecycleManager
	SessionRevoker
	WorkloadProvisioner
	IdentityReconciler
}
