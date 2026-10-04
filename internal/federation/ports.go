package federation

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnsupported = errors.New("federation: authority or protocol unsupported")
	ErrUnverified  = errors.New("federation: evidence unverified")
	ErrDenied      = errors.New("federation: consumption denied")
	ErrUnavailable = errors.New("federation: authority unavailable")
	ErrInvalid     = errors.New("federation: invalid contract")
)

// Scope is trusted composition/context configuration, not token-derived tenancy.
// PlatformAuthority must independently authorize this caller's scoped use.
type Scope struct{ OrganisationID, EstateID string }

// TrustSnapshot is an authoritative approved revision, not a caller-supplied
// ACTIVE claim. Revision and snapshot ID bind all IAM governance receipts.
type TrustSnapshot struct {
	Trust            Trust
	ApprovedRevision uint64
	SnapshotID       string
	ValidUntil       time.Time
}

// ReferenceExpectation is an internal port query, not a new Shared entity or
// public reference type. Kind identifies the target's purpose at this boundary.
type ReferenceExpectation struct {
	ID, Kind, TrustID, SnapshotID                   string
	TrustRevision                                   uint64
	ProviderID, EngineInstanceID                    string
	Scope                                           Scope
	EventID, Issuer, Subject, Level, EvidenceDigest string
}
type ApprovedReference struct {
	Expectation          ReferenceExpectation
	Status               string
	NonSecret            bool
	ValidFrom, ExpiresAt time.Time
}

// GovernanceAuthority resolves approved IAM trust policy and typed non-secret
// reference targets. Implementations must authenticate their authority source,
// resolve CP ExternalReferences, and verify immutable approval/evidence records.
// A raw ref_ identifier, successful fetch, or caller boolean is not approval.
// Reads must be current and snapshot coherent; failures must not mean not-found.
type GovernanceAuthority interface {
	Trust(context.Context, string) (TrustSnapshot, error)
	Reference(context.Context, ReferenceExpectation) (ApprovedReference, error)
}

// PlatformSnapshot reflects CP's independently governed provider/instance/scope
// association and approval of the exact deployed runtime artifact/profile.
// No grants or business roles are copied into the federation result.
type PlatformSnapshot struct {
	ProviderID, EngineInstanceID                                             string
	Scope                                                                    Scope
	ProviderStatus, InstanceStatus, BindingStatus                            string
	RuntimeCapability, SupportStatus, ArtifactDigest, DeployedArtifactDigest string
	ProfileRevision                                                          uint64
	EvidenceExpiresAt                                                        time.Time
}
type PlatformAuthority interface {
	FederationBinding(context.Context, Binding, Scope) (PlatformSnapshot, error)
}

// EventVerifier performs actual protocol/signature/audience/time/replay checks,
// using approved configuration and trust material. It returns normalized
// evidence bound to the requested immutable event reference. No product parser
// may substitute for this verifier. An unsupported adapter returns ErrUnsupported.
// Claiming an event consumes no canonical identity or business permission.
type EventVerifier interface {
	Verify(context.Context, string, TrustSnapshot) (ExternalPrincipal, Assurance, error)
}

type CanonicalIdentity struct {
	Issuer, Subject, PrincipalID, ExternalIdentityID, MappingReference string
	PrincipalStatus, ExternalIdentityStatus, ActorType, MappingBasis   string
	ValidUntil                                                         time.Time
}
type CanonicalAuthority interface {
	Resolve(context.Context, string, string) (CanonicalIdentity, error)
}

// Authorities are supplied only by the trusted composition root. There is no
// permissive/default implementation, fixture-backed production authority, HTTP
// endpoint, or concrete provider auto-selection in this increment.
type Authorities struct {
	Governance GovernanceAuthority
	Platform   PlatformAuthority
	Events     EventVerifier
	Canonical  CanonicalAuthority
}
