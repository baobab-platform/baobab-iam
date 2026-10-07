package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

// SharedCommit is the accepted immutable MP2-A/B contract revision. The lock,
// fixture provenance manifest and this constant are checked together in CI.
const SharedCommit = "e5faaaf8f596ccb6a81cf7fa3bff5e7343da1917"

type Policy struct {
	Scope                Scope
	MaxEventLifetime     time.Duration
	MaxAuthenticationAge time.Duration
	MaxDecisionLifetime  time.Duration
	Now                  func() time.Time
}
type Consumer struct {
	authorities Authorities
	policy      Policy
}
type Decision struct {
	PrincipalID           string
	ExternalIdentityID    string
	AuthenticationEventID string
	AssuranceLevel        string
	ExpiresAt             time.Time
}

// New requires explicit authoritative implementations and governed time/scope
// policy. Factory aliases and provider names are deliberately absent.
func New(a Authorities, p Policy) (*Consumer, error) {
	if absent(a.Governance) || absent(a.Platform) || absent(a.Events) || absent(a.Canonical) || p.Now == nil || !validScope(p.Scope) || p.MaxEventLifetime <= 0 || p.MaxAuthenticationAge <= 0 || p.MaxDecisionLifetime <= 0 {
		return nil, ErrInvalid
	}
	return &Consumer{a, p}, nil
}
func absent(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func authorityError(err error) error {
	switch {
	case errors.Is(err, ErrUnsupported):
		return ErrUnsupported
	case errors.Is(err, ErrUnverified):
		return ErrUnverified
	case errors.Is(err, ErrDenied):
		return ErrDenied
	default:
		return ErrUnavailable
	}
}
func minimum(values ...time.Time) time.Time {
	result := values[0]
	for _, v := range values[1:] {
		if v.Before(result) {
			result = v
		}
	}
	return result
}

// Consume accepts only opaque trust/event IDs. It reloads trusted policy and
// invokes a configured verifier instead of trusting caller-supplied evidence.
// A successful result proves this bounded identity/assurance consumption only;
// it is not estate admission, business authorization, workload activation or
// automatic provider selection. Private authority sources must implement live
// approval/revocation semantics before wiring this into a public login route.
func (c *Consumer) Consume(ctx context.Context, trustID, eventID string) (Decision, error) {
	deny := func(err error) (Decision, error) { return Decision{}, err }
	if c == nil || c.policy.Now == nil || absent(c.authorities.Governance) || absent(c.authorities.Platform) || absent(c.authorities.Events) || absent(c.authorities.Canonical) || ctx == nil || !uuidPattern.MatchString(trustID) || !uuidPattern.MatchString(eventID) {
		return deny(ErrInvalid)
	}
	if ctx.Err() != nil {
		return deny(ErrUnavailable)
	}
	now := c.policy.Now()
	if now.IsZero() {
		return deny(ErrInvalid)
	}
	snapshot, err := c.authorities.Governance.Trust(ctx, trustID)
	if err != nil {
		return deny(authorityError(err))
	}
	t := snapshot.Trust
	if t.ID != trustID || snapshot.SnapshotID == "" || snapshot.ApprovedRevision != t.Revision || t.Revision < 1 || t.UpdatedAt.After(now) || !now.Before(snapshot.ValidUntil) {
		return deny(ErrUnverified)
	}
	if t.Status != "ACTIVE" {
		return deny(ErrDenied)
	}
	if !member(t.OrganisationIDs, c.policy.Scope.OrganisationID) || !member(t.EstateIDs, c.policy.Scope.EstateID) || !validBinding(t.ProviderBinding) {
		return deny(ErrDenied)
	}
	expires := minimum(snapshot.ValidUntil, now.Add(c.policy.MaxDecisionLifetime))
	// Purpose and approval revision come from this trusted snapshot, not a
	// provider-native key or caller field. Receipt queries expose no credentials.
	base := ReferenceExpectation{TrustID: t.ID, SnapshotID: snapshot.SnapshotID, TrustRevision: t.Revision, ProviderID: t.ProviderBinding.ProviderID, EngineInstanceID: t.ProviderBinding.EngineInstanceID, Scope: c.policy.Scope}
	check := func(want ReferenceExpectation) error {
		if !validRef(want.ID) {
			return ErrInvalid
		}
		receipt, e := c.authorities.Governance.Reference(ctx, want)
		if e != nil {
			return authorityError(e)
		}
		if receipt.Expectation != want || receipt.Status != "APPROVED" || !receipt.NonSecret || !fresh(receipt.ValidFrom, receipt.ExpiresAt, now) {
			return ErrUnverified
		}
		expires = minimum(expires, receipt.ExpiresAt)
		return nil
	}
	for _, ref := range []struct{ id, kind string }{
		{t.ProviderBinding.ConfigurationReference, "federation_configuration"},
		{t.ProviderBinding.TrustMaterialReference, "federation_trust_material"},
		{t.AssurancePolicyReference, "assurance_policy"},
		{t.AttributeMappingReference, "attribute_mapping"},
		{t.ProvisioningPolicyReference, "provisioning_policy"},
		{t.ActivationEvidenceReference, "federation_activation"},
	} {
		want := base
		want.ID = ref.id
		want.Kind = ref.kind
		if e := check(want); e != nil {
			return deny(e)
		}
	}
	facet := RuntimeOIDCFederation
	if t.Protocol == "SAML2" {
		facet = RuntimeSAMLFederation
	}
	platform, e := c.authorities.Platform.FederationBinding(ctx, t.ProviderBinding, c.policy.Scope, facet)
	if e != nil {
		return deny(authorityError(e))
	}
	if platform.ProviderID != t.ProviderBinding.ProviderID || platform.EngineInstanceID != t.ProviderBinding.EngineInstanceID || platform.Scope != c.policy.Scope || platform.ProviderStatus != "ACTIVE" || platform.InstanceStatus != "ACTIVE" || platform.BindingStatus != "ACTIVE" {
		return deny(ErrDenied)
	}
	if platform.SupportStatus != "VERIFIED" || platform.RuntimeCapability != facet || platform.ProfileRevision < 1 || !digestPattern.MatchString(platform.ArtifactDigest) || platform.ArtifactDigest != platform.DeployedArtifactDigest || !now.Before(platform.EvidenceExpiresAt) {
		return deny(ErrUnverified)
	}
	expires = minimum(expires, platform.EvidenceExpiresAt)
	principal, assurance, e := c.authorities.Events.Verify(ctx, eventID, snapshot)
	if e != nil {
		return deny(authorityError(e))
	}
	if principal.AuthenticationEventID != eventID || ValidateBundle(Bundle{t, principal, assurance}) != nil {
		return deny(ErrInvalid)
	}
	if !fresh(principal.ObservedAt, principal.ExpiresAt, now) || !fresh(assurance.EvaluatedAt, assurance.ExpiresAt, now) || principal.ExpiresAt.Sub(principal.ObservedAt) > c.policy.MaxEventLifetime {
		return deny(ErrDenied)
	}
	authenticated := time.Time{}
	if assurance.UpstreamEvidence.OIDC != nil {
		authenticated = assurance.UpstreamEvidence.OIDC.AuthenticatedAt
		if assurance.UpstreamEvidence.OIDC.StepUpAt != nil {
			authenticated = *assurance.UpstreamEvidence.OIDC.StepUpAt
		}
	} else {
		authenticated = assurance.UpstreamEvidence.SAML.AuthenticatedAt
	}
	if now.Sub(authenticated) > c.policy.MaxAuthenticationAge {
		return deny(ErrDenied)
	}
	expires = minimum(expires, authenticated.Add(c.policy.MaxAuthenticationAge))
	if assurance.MappingStatus != "MAPPED" {
		return deny(ErrUnverified)
	}
	// Hash the normalized evidence, not raw assertions/secrets. This binds the
	// approved mapping decision to exact acr/amr/AuthnContext and timestamps.
	encoded, e := json.Marshal(assurance.UpstreamEvidence)
	if e != nil {
		return deny(ErrInvalid)
	}
	sum := sha256.Sum256(encoded)
	want := base
	want.ID = assurance.MappingEvidenceReference
	want.Kind = "assurance_mapping_decision"
	want.EventID = eventID
	want.Issuer = principal.Issuer
	want.Subject = principal.Subject
	want.Level = assurance.Level
	want.EvidenceDigest = "sha256:" + hex.EncodeToString(sum[:])
	if e := check(want); e != nil {
		return deny(e)
	}
	canonical, e := c.authorities.Canonical.Resolve(ctx, principal.Issuer, principal.Subject)
	if e != nil {
		return deny(authorityError(e))
	}
	if canonical.Issuer != principal.Issuer || canonical.Subject != principal.Subject || canonical.MappingBasis != "ISSUER_SUBJECT" || canonical.PrincipalStatus != "ACTIVE" || canonical.ExternalIdentityStatus != "ACTIVE" || canonical.ActorType != "human" || !uuidPattern.MatchString(canonical.PrincipalID) || !uuidPattern.MatchString(canonical.ExternalIdentityID) || !validRef(canonical.MappingReference) || !now.Before(canonical.ValidUntil) {
		return deny(ErrUnverified)
	}

	mappingWant := base
	mappingWant.ID = canonical.MappingReference
	mappingWant.Kind = "canonical_identity_mapping"
	mappingWant.Issuer = principal.Issuer
	mappingWant.Subject = principal.Subject
	mappingWant.PrincipalID = canonical.PrincipalID
	mappingWant.ExternalIdentityID = canonical.ExternalIdentityID
	if e := check(mappingWant); e != nil {
		return deny(e)
	}
	// RESOLVED in adapter evidence is an assertion to cross-check, never authority.
	r := principal.Resolution
	if r.Status == "RESOLVED" && (r.PrincipalID != canonical.PrincipalID || r.ExternalIdentityID != canonical.ExternalIdentityID || r.MappingReference != canonical.MappingReference) {
		return deny(ErrDenied)
	}
	expires = minimum(expires, canonical.ValidUntil, principal.ExpiresAt, assurance.ExpiresAt)
	// Recheck the approved trust revision after remote reads to reject observed
	// concurrent suspension/revocation/config changes. Atomic consumption/replay
	// and current CP authorization still belong to the authoritative adapters.
	latest, e := c.authorities.Governance.Trust(ctx, trustID)
	if e != nil {
		return deny(authorityError(e))
	}
	if latest.Trust.ID != t.ID || latest.Trust.Status != "ACTIVE" || latest.Trust.Revision != t.Revision || latest.ApprovedRevision != snapshot.ApprovedRevision || latest.SnapshotID != snapshot.SnapshotID || !reflect.DeepEqual(latest.Trust, t) {
		return deny(ErrDenied)
	}
	started := now
	now = c.policy.Now()
	if now.Before(started) {
		return deny(ErrDenied)
	}
	if ctx.Err() != nil || now.IsZero() || !now.Before(expires) || !now.Before(latest.ValidUntil) {
		return deny(ErrDenied)
	}
	expires = minimum(expires, latest.ValidUntil)
	return Decision{canonical.PrincipalID, canonical.ExternalIdentityID, eventID, assurance.Level, expires}, nil
}
