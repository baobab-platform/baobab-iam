// Package ory implements the provider-neutral IdentityProvider interfaces
// against Ory Kratos (human identity) and Ory Hydra (OAuth/OIDC + workloads).
//
// Target path: baobab-iam/internal/provider/ory/adapter.go
//
// Architectural constraints (ADR-IAM-0019 / 0020 / 0021):
//
//   - Standards (OIDC discovery, token endpoint, JWKS, PKCE, client credentials)
//     remain direct; this adapter does NOT proxy ordinary token validation.
//   - Business semantics (Tenant, LegalEntity, Market, Capability, domain auth)
//     stay in baobab-cp and domain engines — never here.
//   - Public vs admin planes: only admin APIs are called from this package.
//   - Kratos and Hydra are separate runtimes with separate databases; this
//     adapter coordinates them at the Baobab boundary.
package ory

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// Config holds connection and operational settings for the Ory adapter.
// Secrets must come from the platform secret store; never from Git.
type Config struct {
	// KratosAdminURL is the private admin API base (e.g. http://kratos-admin:4434).
	// MUST NOT be internet-reachable.
	KratosAdminURL string

	// HydraAdminURL is the private admin API base (e.g. http://hydra-admin:4445).
	// MUST NOT be internet-reachable.
	HydraAdminURL string

	// PublicIssuer is the issuer value that appears in tokens and ExternalSubject.
	// Typically the public Hydra issuer URL.
	PublicIssuer string

	// HTTPClient is optional; if nil a default client with sensible timeouts is used.
	HTTPClient *http.Client

	// RequestTimeout bounds individual admin API calls.
	RequestTimeout time.Duration
}

// Adapter is the concrete Ory implementation of the provider interfaces.
// It composes Kratos (human identity) and Hydra (OAuth clients / workloads).
type Adapter struct {
	cfg    Config
	kratos *kratosClient
	hydra  *hydraClient
	http   *http.Client
}

// NewAdapter validates config and returns a ready Adapter.
// It does not perform network I/O; call ProviderInfo or a readiness probe
// to verify connectivity.
func NewAdapter(cfg Config) (*Adapter, error) {
	if cfg.KratosAdminURL == "" {
		return nil, fmt.Errorf("ory: KratosAdminURL is required")
	}
	if cfg.HydraAdminURL == "" {
		return nil, fmt.Errorf("ory: HydraAdminURL is required")
	}
	if cfg.PublicIssuer == "" {
		return nil, fmt.Errorf("ory: PublicIssuer is required")
	}

	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
			// Transport should be configured by the caller for mTLS / custom CA
			// when required by the deployment.
		}
	}

	a := &Adapter{
		cfg:  cfg,
		http: httpClient,
	}
	a.kratos = newKratosClient(cfg.KratosAdminURL, httpClient)
	a.hydra = newHydraClient(cfg.HydraAdminURL, httpClient)
	return a, nil
}

// ---------------------------------------------------------------------------
// ProviderInfoSource
// ---------------------------------------------------------------------------

// ProviderInfo returns static/runtime metadata and declared capabilities.
func (a *Adapter) ProviderInfo(ctx context.Context) (provider.ProviderInfo, error) {
	caps := a.capabilities()
	return provider.ProviderInfo{
		Name:         "ory",
		Version:      "", // optionally filled by probing /version or build info
		Issuer:       a.cfg.PublicIssuer,
		Capabilities: caps,
	}, nil
}

// ---------------------------------------------------------------------------
// IdentityReader
// ---------------------------------------------------------------------------

// GetIdentity loads a human identity from Kratos by issuer+subject.
// Subject is the Kratos identity ID (UUID) when the issuer is this deployment.
func (a *Adapter) GetIdentity(ctx context.Context, subject provider.ExternalSubject) (*provider.ProviderIdentity, error) {
	if err := a.requireIssuer(subject); err != nil {
		return nil, err
	}
	return a.kratos.getIdentity(ctx, subject.Subject)
}

// ---------------------------------------------------------------------------
// IdentityProvisioner
// ---------------------------------------------------------------------------

// ProvisionIdentity creates or imports a human identity in Kratos.
// On success the returned ProviderIdentity.Subject is the Kratos identity ID
// and Issuer is the configured PublicIssuer.
func (a *Adapter) ProvisionIdentity(ctx context.Context, spec provider.IdentityProvisioningSpec) (*provider.ProviderIdentity, error) {
	return a.kratos.provisionIdentity(ctx, a.cfg.PublicIssuer, spec)
}

// ---------------------------------------------------------------------------
// IdentityLifecycleManager
// ---------------------------------------------------------------------------

// DisableIdentity marks the Kratos identity inactive so it can no longer
// authenticate. Pair with RevokeSessions for a full kill-switch.
func (a *Adapter) DisableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	return a.kratos.setIdentityActive(ctx, subject.Subject, false)
}

// EnableIdentity re-activates a previously disabled Kratos identity.
func (a *Adapter) EnableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	return a.kratos.setIdentityActive(ctx, subject.Subject, true)
}

// ---------------------------------------------------------------------------
// SessionRevoker
// ---------------------------------------------------------------------------

// RevokeSessions invalidates all Kratos sessions for the subject.
// This is the technical half of the Baobab kill-switch; CP membership
// revocation remains a separate concern.
func (a *Adapter) RevokeSessions(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	return a.kratos.revokeSessions(ctx, subject.Subject)
}

// ---------------------------------------------------------------------------
// WorkloadProvisioner
// ---------------------------------------------------------------------------

// ProvisionWorkload creates (or updates) a Hydra OAuth2 client for a
// machine/workload identity. LogicalClientID is the Baobab-stable name.
func (a *Adapter) ProvisionWorkload(ctx context.Context, spec provider.WorkloadProvisioningSpec) (*provider.ProviderWorkload, error) {
	return a.hydra.provisionClient(ctx, a.cfg.PublicIssuer, spec)
}

// DisableWorkload deactivates or deletes the Hydra client corresponding
// to the workload reference.
func (a *Adapter) DisableWorkload(ctx context.Context, ref provider.ProviderWorkloadReference) error {
	return a.hydra.disableClient(ctx, ref)
}

// RotateWorkloadCredentials rotates the client secret (or signing material)
// for the given workload and returns the updated ProviderWorkload.
// The previous secret is invalidated.
func (a *Adapter) RotateWorkloadCredentials(ctx context.Context, ref provider.ProviderWorkloadReference) (*provider.ProviderWorkload, error) {
	return a.hydra.rotateClientCredentials(ctx, a.cfg.PublicIssuer, ref)
}

// ---------------------------------------------------------------------------
// IdentityReconciler
// ---------------------------------------------------------------------------

// ReconcileIdentity compares provider state with expected Baobab state and
// reports (and optionally applies) corrective actions within the provider
// boundary. It does not touch CanonicalIdentity or CP memberships.
func (a *Adapter) ReconcileIdentity(ctx context.Context, subject provider.ExternalSubject) (*provider.ReconciliationResult, error) {
	if err := a.requireIssuer(subject); err != nil {
		return nil, err
	}

	id, err := a.kratos.getIdentity(ctx, subject.Subject)
	if err != nil {
		if provider.IsNotFound(err) {
			return &provider.ReconciliationResult{
				Subject: subject,
				Status:  provider.IdentityStatusUnknown,
				Changed: false,
				Notes:   "identity not found in provider",
			}, nil
		}
		return nil, err
	}

	return &provider.ReconciliationResult{
		Subject:          subject,
		ProviderIdentity: id,
		Status:           id.Status,
		Changed:          false,
		Notes:            "provider state observed; no automatic mutation in base reconcile",
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// requireIssuer ensures the ExternalSubject.Issuer matches this deployment.
// Mismatched issuers are rejected so we never mutate the wrong provider.
func (a *Adapter) requireIssuer(subject provider.ExternalSubject) error {
	if subject.Issuer == "" || subject.Subject == "" {
		return &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  "issuer and subject are required",
			Provider: "ory",
		}
	}
	if subject.Issuer != a.cfg.PublicIssuer {
		return &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  fmt.Sprintf("issuer mismatch: got %q, want %q", subject.Issuer, a.cfg.PublicIssuer),
			Provider: "ory",
		}
	}
	return nil
}

// Compile-time assertion that Adapter implements the full IdentityProvider.
var _ provider.IdentityProvider = (*Adapter)(nil)
