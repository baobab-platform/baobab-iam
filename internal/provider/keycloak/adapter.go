// Package keycloak provides a temporary dual-run adapter that implements
// the same provider-neutral interfaces against the existing Keycloak
// deployment. It exists only for the migration window (ADR-IAM-0019 phases
// dual-run / cutover) and MUST be removed after Keycloak retirement
// (Gate IAM-M19).
//
// Target path: baobab-iam/internal/provider/keycloak/adapter.go
//
// This skeleton is intentionally incomplete: it demonstrates the interface
// surface and issuer isolation. Fill Admin API calls against the pinned
// Keycloak version only if dual-run is required in production; otherwise
// prefer a one-way migration via the Ory adapter and migration tooling.
package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// Config holds connection settings for the Keycloak dual-run adapter.
type Config struct {
	// AdminURL is the Keycloak admin base (e.g. https://iam.example/admin).
	AdminURL string

	// Realm is the Baobab realm name.
	Realm string

	// PublicIssuer is the issuer value that appears in tokens
	// (e.g. https://iam.example/realms/baobab).
	PublicIssuer string

	// HTTPClient is optional.
	HTTPClient *http.Client

	// RequestTimeout bounds individual admin API calls.
	RequestTimeout time.Duration

	// ClientID / ClientSecret for the admin service account used by this adapter.
	// Prefer client-credentials or a short-lived token source in production.
	AdminClientID     string
	AdminClientSecret string
}

// Adapter is a partial Keycloak implementation of the provider interfaces.
// Methods that are not required for dual-run validation return
// provider.ErrUnsupported.
type Adapter struct {
	cfg  Config
	http *http.Client
}

// NewAdapter validates config and returns a Keycloak adapter.
func NewAdapter(cfg Config) (*Adapter, error) {
	if cfg.AdminURL == "" || cfg.Realm == "" || cfg.PublicIssuer == "" {
		return nil, fmt.Errorf("keycloak: AdminURL, Realm and PublicIssuer are required")
	}
	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Adapter{cfg: cfg, http: httpClient}, nil
}

// ---------------------------------------------------------------------------
// ProviderInfoSource
// ---------------------------------------------------------------------------

func (a *Adapter) ProviderInfo(ctx context.Context) (provider.ProviderInfo, error) {
	return provider.ProviderInfo{
		Name:    "keycloak",
		Issuer:  a.cfg.PublicIssuer,
		Version: "", // optionally probe server info
		Capabilities: provider.ProviderCapabilities{
			Provider:          "keycloak",
			HumanIdentity:     false, // adapter methods are ErrUnsupported stubs
			SessionRevocation: false,
			WorkloadIdentity:  false,
			PasswordImport:    false, // dual-run does not re-import into Keycloak
			TOTPImport:        false,
			PasskeyImport:     false,
			EnterpriseSSO:     "deployment-dependent",
			SCIM:              "unsupported",
		},
	}, nil
}

// ---------------------------------------------------------------------------
// IdentityReader
// ---------------------------------------------------------------------------

func (a *Adapter) GetIdentity(ctx context.Context, subject provider.ExternalSubject) (*provider.ProviderIdentity, error) {
	if err := a.requireIssuer(subject); err != nil {
		return nil, err
	}
	// TODO: GET /admin/realms/{realm}/users/{id} and map to ProviderIdentity.
	return nil, provider.NewUnsupported("keycloak", "GetIdentity (implement for dual-run if needed)")
}

// ---------------------------------------------------------------------------
// IdentityProvisioner — not used for dual-run into Keycloak
// ---------------------------------------------------------------------------

func (a *Adapter) ProvisionIdentity(ctx context.Context, spec provider.IdentityProvisioningSpec) (*provider.ProviderIdentity, error) {
	return nil, provider.NewUnsupported("keycloak", "ProvisionIdentity (migration direction is Keycloak → Ory only)")
}

// ---------------------------------------------------------------------------
// IdentityLifecycleManager
// ---------------------------------------------------------------------------

func (a *Adapter) DisableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	// TODO: PUT user enabled=false
	return provider.NewUnsupported("keycloak", "DisableIdentity (implement for dual-run kill-switch if needed)")
}

func (a *Adapter) EnableIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	return provider.NewUnsupported("keycloak", "EnableIdentity")
}

// ---------------------------------------------------------------------------
// SessionRevoker
// ---------------------------------------------------------------------------

func (a *Adapter) RevokeSessions(ctx context.Context, subject provider.ExternalSubject) error {
	if err := a.requireIssuer(subject); err != nil {
		return err
	}
	// TODO: POST /admin/realms/{realm}/users/{id}/logout
	return provider.NewUnsupported("keycloak", "RevokeSessions")
}

// ---------------------------------------------------------------------------
// WorkloadProvisioner
// ---------------------------------------------------------------------------

func (a *Adapter) ProvisionWorkload(ctx context.Context, spec provider.WorkloadProvisioningSpec) (*provider.ProviderWorkload, error) {
	return nil, provider.NewUnsupported("keycloak", "ProvisionWorkload (workloads migrate to Hydra first)")
}

func (a *Adapter) DisableWorkload(ctx context.Context, ref provider.ProviderWorkloadReference) error {
	return provider.NewUnsupported("keycloak", "DisableWorkload")
}

func (a *Adapter) RotateWorkloadCredentials(ctx context.Context, ref provider.ProviderWorkloadReference) (*provider.ProviderWorkload, error) {
	return nil, provider.NewUnsupported("keycloak", "RotateWorkloadCredentials")
}

// ---------------------------------------------------------------------------
// WorkloadLifecycleManager (stubs during dual-run; Ory is the target path)
// ---------------------------------------------------------------------------

func (a *Adapter) SuspendWorkload(ctx context.Context, ref provider.ProviderWorkloadReference) error {
	return provider.NewUnsupported("keycloak", "SuspendWorkload")
}

func (a *Adapter) RevokeWorkload(ctx context.Context, ref provider.ProviderWorkloadReference) error {
	return provider.NewUnsupported("keycloak", "RevokeWorkload")
}

// ---------------------------------------------------------------------------
// IdentityReconciler
// ---------------------------------------------------------------------------

func (a *Adapter) ReconcileIdentity(ctx context.Context, subject provider.ExternalSubject) (*provider.ReconciliationResult, error) {
	if err := a.requireIssuer(subject); err != nil {
		return nil, err
	}
	return nil, provider.NewUnsupported("keycloak", "ReconcileIdentity")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (a *Adapter) requireIssuer(subject provider.ExternalSubject) error {
	issuer := strings.TrimSpace(subject.Issuer)
	subjectID := strings.TrimSpace(subject.Subject)
	if issuer == "" || subjectID == "" {
		return &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  "issuer and subject are required",
			Provider: "keycloak",
		}
	}
	if issuer != a.cfg.PublicIssuer {
		return &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  fmt.Sprintf("issuer mismatch: got %q, want %q", issuer, a.cfg.PublicIssuer),
			Provider: "keycloak",
		}
	}
	return nil
}

// Compile-time assertion that Adapter implements the full IdentityProvider.
// Methods that return ErrUnsupported still satisfy the interface.
var _ provider.IdentityProvider = (*Adapter)(nil)

var _ provider.WorkloadLifecycleManager = (*Adapter)(nil)
