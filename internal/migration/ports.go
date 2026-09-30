// Target path: baobab-iam/internal/migration/ports.go
//
// Phase C ports for Gate IAM-M5 (ADR-IAM-0022). These interfaces define
// boundaries between the ledger domain and external systems. Phase C does
// not wire production Keycloak discovery, CP RPCs, or dual-issuer cutover.
//
// See docs/governance/gate-iam-m5-phase-c-design.md §7.
package migration

import "context"

// SourceBinding is a discovered source-side identity binding before ledger
// registration. It carries no credential material (ADR-0022 §9).
type SourceBinding struct {
	// Provider is the source system name (e.g. "keycloak").
	Provider string
	// Issuer is the OIDC issuer URL of the source IdP.
	Issuer string
	// Subject is the stable subject within that issuer.
	Subject string
	// SuggestedClass is an optional classifier hint from discovery; the
	// register path may override after policy review.
	SuggestedClass IdentityClass
	// SnapshotReference is a redacted pointer to an export/batch artifact.
	// MUST NOT embed passwords, TOTP, or client secrets.
	SnapshotReference string
}

// DiscoveryPort lists source bindings eligible for migration planning.
// Greenfield / Phase C may use FixtureDiscovery; live Keycloak Admin export
// is a later implementation and is not required to exercise the ledger.
type DiscoveryPort interface {
	// ListSourceBindings returns candidate source bindings for a batch.
	// batchID is an opaque cohort identifier for correlation only.
	ListSourceBindings(ctx context.Context, batchID string) ([]SourceBinding, error)
}

// CanonicalResolver maps a source issuer+subject to a CP CanonicalIdentity id.
// Implementations MUST refuse email-only matching (ADR-0022 §7).
type CanonicalResolver interface {
	// ResolveCanonical returns the CP canonical / Principal id for the source
	// binding. If no mapping exists, return ("", ErrNoCanonicalMapping) so the
	// caller can classify the row as ORPHAN_CANDIDATE.
	ResolveCanonical(ctx context.Context, source ProviderBinding) (canonicalID string, err error)
}

// ErrNoCanonicalMapping means CP has no Principal for this source binding.
// Callers SHOULD register an ORPHAN_CANDIDATE row for manual review rather
// than inventing a CanonicalIdentity from email.
var ErrNoCanonicalMapping = errNoCanonicalMapping{}

type errNoCanonicalMapping struct{}

func (errNoCanonicalMapping) Error() string {
	return "migration: no canonical identity mapping for source issuer+subject (ADR-0022 §7)"
}

// PolicyGate decides whether a state transition is authorized beyond the
// pure state-machine edges in state.go. Phase C default denies production
// cutover transitions even when the edge is legal in the graph.
type PolicyGate interface {
	// AllowTransition reports whether moving migrationID from→to is permitted.
	// A nil PolicyGate on Service is treated as PhaseCPolicyGate.
	AllowTransition(ctx context.Context, migrationID string, from, to MigrationState) error
}
