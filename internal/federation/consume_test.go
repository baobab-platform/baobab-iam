package federation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeAuthority struct {
	bundle          Bundle
	snapshot        TrustSnapshot
	platform        PlatformSnapshot
	canonical       CanonicalIdentity
	err             error
	trustCalls      int
	revokeOnRecheck bool
	changeOnRecheck bool
	mutateReceipt   func(*ApprovedReference)
	eventErr        error
	canonicalErr    error
	clock           time.Time
}

func (f *fakeAuthority) Trust(ctx context.Context, id string) (TrustSnapshot, error) {
	f.trustCalls++
	s := f.snapshot
	if f.trustCalls > 1 && f.revokeOnRecheck {
		s.Trust.Status = "SUSPENDED"
	}
	if f.trustCalls > 1 && f.changeOnRecheck {
		s.Trust.UpstreamIssuer = "https://changed.example.test"
	}
	return s, f.err
}
func (f *fakeAuthority) Reference(ctx context.Context, w ReferenceExpectation) (ApprovedReference, error) {
	r := ApprovedReference{Expectation: w, Status: "APPROVED", NonSecret: true, ValidFrom: f.clock.Add(-time.Minute), ExpiresAt: f.clock.Add(5 * time.Minute)}
	if f.mutateReceipt != nil {
		f.mutateReceipt(&r)
	}
	return r, f.err
}
func (f *fakeAuthority) FederationBinding(context.Context, Binding, Scope) (PlatformSnapshot, error) {
	return f.platform, f.err
}
func (f *fakeAuthority) Verify(context.Context, string, TrustSnapshot) (ExternalPrincipal, Assurance, error) {
	return f.bundle.ExternalPrincipal, f.bundle.Assurance, f.eventErr
}
func (f *fakeAuthority) Resolve(context.Context, string, string) (CanonicalIdentity, error) {
	return f.canonical, f.canonicalErr
}

func fixture(t *testing.T, protocol string) Bundle {
	t.Helper()
	data, err := os.ReadFile("testdata/federation-" + protocol + ".json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func setup(t *testing.T, protocol string) (*Consumer, *fakeAuthority) {
	t.Helper()
	b := fixture(t, protocol)
	at := b.ExternalPrincipal.ObservedAt
	b.Trust.Status = "ACTIVE"
	b.Trust.ActivatedAt = &at
	b.Trust.ActivationEvidenceReference = "ref_ciactivation"
	b.Assurance.MappingStatus = "MAPPED"
	b.Assurance.Level = "BAOBAB-A1"
	b.Assurance.MappingEvidenceReference = "ref_cidecision"
	scope := Scope{"org_cisynthetic", "estate_ci"}
	f := &fakeAuthority{bundle: b, clock: at.Add(time.Minute)}
	f.snapshot = TrustSnapshot{Trust: b.Trust, ApprovedRevision: 1, SnapshotID: "approved-snapshot", ValidUntil: at.Add(10 * time.Minute)}
	facet := "OIDC_FEDERATION"
	if protocol == "saml2" {
		facet = "SAML_FEDERATION"
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	f.platform = PlatformSnapshot{ProviderID: b.ExternalPrincipal.ProviderID, EngineInstanceID: b.ExternalPrincipal.EngineInstanceID, Scope: scope, ProviderStatus: "ACTIVE", InstanceStatus: "ACTIVE", BindingStatus: "ACTIVE", RuntimeCapability: facet, SupportStatus: "VERIFIED", ArtifactDigest: digest, DeployedArtifactDigest: digest, ProfileRevision: 1, EvidenceExpiresAt: at.Add(8 * time.Minute)}
	f.canonical = CanonicalIdentity{Issuer: b.ExternalPrincipal.Issuer, Subject: b.ExternalPrincipal.Subject, PrincipalID: "33333333-3333-4333-8333-333333333333", ExternalIdentityID: "44444444-4444-4444-8444-444444444444", MappingReference: "ref_cimapping", PrincipalStatus: "ACTIVE", ExternalIdentityStatus: "ACTIVE", ActorType: "human", MappingBasis: "ISSUER_SUBJECT", ValidUntil: at.Add(8 * time.Minute)}
	c, err := New(Authorities{f, f, f, f}, Policy{Scope: scope, MaxEventLifetime: 15 * time.Minute, MaxAuthenticationAge: 5 * time.Minute, MaxDecisionLifetime: time.Minute, Now: func() time.Time { return f.clock }})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func run(c *Consumer, f *fakeAuthority) (Decision, error) {
	return c.Consume(context.Background(), f.bundle.Trust.ID, f.bundle.ExternalPrincipal.AuthenticationEventID)
}
func denied(t *testing.T, c *Consumer, f *fakeAuthority) {
	t.Helper()
	d, err := run(c, f)
	if err == nil || d != (Decision{}) {
		t.Fatalf("expected empty denied decision; error=%v", err)
	}
}

func TestOIDCAndSAMLConsumption(t *testing.T) {
	for _, protocol := range []string{"oidc", "saml2"} {
		t.Run(protocol, func(t *testing.T) {
			c, f := setup(t, protocol)
			d, err := run(c, f)
			if err != nil {
				t.Fatal(err)
			}
			if d.PrincipalID != f.canonical.PrincipalID || d.AssuranceLevel != "BAOBAB-A1" || !d.ExpiresAt.Equal(f.clock.Add(time.Minute)) || f.trustCalls != 2 {
				t.Fatal("unexpected consumption result")
			}
		})
	}
}
func TestPinnedFixturesDoNotAuthorize(t *testing.T) {
	for _, protocol := range []string{"oidc", "saml2"} {
		c, f := setup(t, protocol)
		f.snapshot.Trust = fixture(t, protocol).Trust
		denied(t, c, f)
	}
}
func TestNonactiveTrustDenial(t *testing.T) {
	for _, status := range []string{"REQUESTED", "CONFIGURING", "VERIFYING", "SUSPENDED", "ROTATING", "REVOKED", " ACTIVE ", ""} {
		t.Run(status, func(t *testing.T) { c, f := setup(t, "oidc"); f.snapshot.Trust.Status = status; denied(t, c, f) })
	}
}
func TestUnavailableAndUnsupportedAuthorities(t *testing.T) {
	for _, e := range []error{ErrUnsupported, ErrUnverified, ErrDenied, errors.New("secret-value-must-not-leak")} {
		c, f := setup(t, "oidc")
		f.err = e
		_, err := run(c, f)
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatal("authority error was swallowed or leaked")
		}
		if errors.Is(e, ErrUnsupported) && !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported outcome lost")
		}
	}
	c, f := setup(t, "oidc")
	f.eventErr = ErrUnsupported
	denied(t, c, f)
	c, f = setup(t, "oidc")
	f.canonicalErr = errors.New("database timeout secret")
	denied(t, c, f)
}
func TestReferenceApprovalAndExactCoverage(t *testing.T) {
	mutations := []func(*ApprovedReference){
		func(r *ApprovedReference) {
			if r.Expectation.Kind == "canonical_identity_mapping" {
				r.Expectation.PrincipalID = "55555555-5555-4555-8555-555555555555"
			}
		},
		func(r *ApprovedReference) {
			if r.Expectation.Kind == "canonical_identity_mapping" {
				r.Expectation.ExternalIdentityID = "55555555-5555-4555-8555-555555555555"
			}
		},
		func(r *ApprovedReference) { r.Status = "UNVERIFIED" }, func(r *ApprovedReference) { r.NonSecret = false },
		func(r *ApprovedReference) { r.Expectation.Kind = "wrong_type" }, func(r *ApprovedReference) { r.Expectation.ID = "ref_ciother" },
		func(r *ApprovedReference) { r.Expectation.ProviderID = "provider_ciother" }, func(r *ApprovedReference) { r.Expectation.EngineInstanceID = "ei_ciother" },
		func(r *ApprovedReference) { r.Expectation.Scope.EstateID = "other_estate" }, func(r *ApprovedReference) { r.Expectation.TrustRevision = 2 },
		func(r *ApprovedReference) { r.Expectation.SnapshotID = "old-snapshot" }, func(r *ApprovedReference) { r.ExpiresAt = r.ValidFrom },
		func(r *ApprovedReference) { r.ValidFrom = r.ExpiresAt },
		func(r *ApprovedReference) {
			if r.Expectation.Kind == "assurance_mapping_decision" {
				r.Expectation.Subject = "another"
			}
		},
		func(r *ApprovedReference) {
			if r.Expectation.Kind == "assurance_mapping_decision" {
				r.Expectation.Level = "BAOBAB-A3"
			}
		},
		func(r *ApprovedReference) {
			if r.Expectation.Kind == "assurance_mapping_decision" {
				r.Expectation.EvidenceDigest = "sha256:" + strings.Repeat("b", 64)
			}
		},
	}
	for i, mutate := range mutations {
		c, f := setup(t, "oidc")
		f.mutateReceipt = mutate
		t.Run(string(rune('a'+i)), func(t *testing.T) { denied(t, c, f) })
	}
}
func TestPlatformSupportAndArtifactDenials(t *testing.T) {
	mutations := []func(*PlatformSnapshot){
		func(p *PlatformSnapshot) { p.ProviderStatus = "SUSPENDED" }, func(p *PlatformSnapshot) { p.InstanceStatus = "DRAINING" }, func(p *PlatformSnapshot) { p.BindingStatus = "REVOKED" },
		func(p *PlatformSnapshot) { p.Scope.OrganisationID = "org_other" }, func(p *PlatformSnapshot) { p.ProviderID = "provider_other" },
		func(p *PlatformSnapshot) { p.SupportStatus = "UNVERIFIED" }, func(p *PlatformSnapshot) { p.SupportStatus = "DEPLOYMENT_DEPENDENT" }, func(p *PlatformSnapshot) { p.SupportStatus = "UNSUPPORTED" },
		func(p *PlatformSnapshot) { p.RuntimeCapability = "HUMAN_AUTHENTICATION" }, func(p *PlatformSnapshot) { p.ProfileRevision = 0 },
		func(p *PlatformSnapshot) { p.DeployedArtifactDigest = "sha256:" + strings.Repeat("b", 64) }, func(p *PlatformSnapshot) { p.ArtifactDigest = "latest" }, func(p *PlatformSnapshot) { p.EvidenceExpiresAt = time.Time{} },
	}
	for _, mutate := range mutations {
		c, f := setup(t, "oidc")
		mutate(&f.platform)
		denied(t, c, f)
	}
}
func TestCanonicalAuthorityCannotUseEmailOrInventPrincipal(t *testing.T) {
	mutations := []func(*CanonicalIdentity){
		func(p *CanonicalIdentity) { p.Issuer = "https://other.example.test" }, func(p *CanonicalIdentity) { p.Subject = "another" }, func(p *CanonicalIdentity) { p.MappingBasis = "EMAIL" },
		func(p *CanonicalIdentity) { p.PrincipalID = "orphan:pending-review" }, func(p *CanonicalIdentity) { p.ActorType = "workload" }, func(p *CanonicalIdentity) { p.PrincipalStatus = "SUSPENDED" },
		func(p *CanonicalIdentity) { p.ExternalIdentityStatus = "REVOKED" }, func(p *CanonicalIdentity) { p.MappingReference = "" }, func(p *CanonicalIdentity) { p.ValidUntil = time.Time{} },
	}
	for _, mutate := range mutations {
		c, f := setup(t, "oidc")
		mutate(&f.canonical)
		denied(t, c, f)
	}
	c, f := setup(t, "oidc")
	at := f.bundle.ExternalPrincipal.ObservedAt
	f.bundle.ExternalPrincipal.Resolution = Resolution{"RESOLVED", "55555555-5555-4555-8555-555555555555", f.canonical.ExternalIdentityID, f.canonical.MappingReference, "ISSUER_SUBJECT", &at}
	denied(t, c, f)
}
func TestAssuranceProvenanceAndNoAutomaticMFA(t *testing.T) {
	mutations := []func(*Bundle){
		func(b *Bundle) { b.Assurance.Subject = "other" }, func(b *Bundle) { b.Assurance.Issuer = "https://other.example.test" }, func(b *Bundle) { b.Assurance.AuthenticationEventID = "55555555-5555-4555-8555-555555555555" },
		func(b *Bundle) { b.Assurance.Level = "BAOBAB-A4" }, func(b *Bundle) { b.Assurance.Level = "BAOBAB-A3 " }, func(b *Bundle) {
			b.Assurance.MappingStatus = "UNKNOWN"
			b.Assurance.Level = ""
			b.Assurance.MappingEvidenceReference = ""
		},
		func(b *Bundle) { b.Assurance.UpstreamEvidence.OIDC.Issuer = "https://other.example.test" }, func(b *Bundle) { b.ExternalPrincipal.Subject = " padded " },
	}
	for _, mutate := range mutations {
		c, f := setup(t, "oidc")
		mutate(&f.bundle)
		denied(t, c, f)
	}
}
func TestExpiryClockAndConcurrentRevocation(t *testing.T) {
	c, f := setup(t, "oidc")
	f.clock = f.bundle.ExternalPrincipal.ExpiresAt
	denied(t, c, f)
	c, f = setup(t, "oidc")
	f.clock = f.clock.Add(5 * time.Minute)
	denied(t, c, f)
	c, f = setup(t, "oidc")
	f.revokeOnRecheck = true
	denied(t, c, f)
	c, f = setup(t, "oidc")
	f.changeOnRecheck = true
	denied(t, c, f)
	c, f = setup(t, "oidc")
	f.snapshot.ApprovedRevision = 2
	denied(t, c, f)
	c, f = setup(t, "oidc")
	calls := 0
	c.policy.Now = func() time.Time {
		calls++
		if calls > 1 {
			return f.clock.Add(-time.Minute)
		}
		return f.clock
	}
	denied(t, c, f)
	c, f = setup(t, "oidc")
	calls = 0
	c.policy.Now = func() time.Time {
		calls++
		if calls > 1 {
			return f.clock.Add(10 * time.Minute)
		}
		return f.clock
	}
	denied(t, c, f)
}
func TestConstructorAndCancelledContext(t *testing.T) {
	zero := &Consumer{}
	if _, err := zero.Consume(context.Background(), "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("zero consumer accepted")
	}
	c, f := setup(t, "oidc")
	var missing *fakeAuthority
	if _, err := New(Authorities{missing, f, f, f}, c.policy); err == nil {
		t.Fatal("typed nil authority accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Consume(ctx, f.bundle.Trust.ID, f.bundle.ExternalPrincipal.AuthenticationEventID); err == nil {
		t.Fatal("cancelled context accepted")
	}
}
func TestStrictWireDecode(t *testing.T) {
	data, err := os.ReadFile("testdata/federation-oidc.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		[]byte(strings.Replace(string(data), `"status": "UNRESOLVED"`, `"status": "UNRESOLVED", "principal_id": ""`, 1)),
		[]byte(strings.Replace(string(data), `"mapping_status": "UNKNOWN"`, `"mapping_status": "UNKNOWN", "level": ""`, 1)),
		append(append([]byte{}, data...), []byte(" {}")...),
		[]byte(strings.Replace(string(data), `"protocol": "OIDC"`, `"protocol": "OIDC", "protocol": "SAML2"`, 1)),
		[]byte(strings.Replace(string(data), `"revision": 1`, `"revision": 1, "client_secret": "secret-value"`, 1)),
		[]byte(strings.Replace(string(data), `"status": "VERIFYING"`, `"status": null`, 1)),
	}
	for _, input := range cases {
		if _, err := DecodeBundle(input); err == nil {
			t.Fatal("invalid wire record accepted")
		}
	}
	b := fixture(t, "oidc")
	b.Assurance.MappingStatus = "UNKNOWN"
	b.Assurance.Level = "BAOBAB-A3"
	input, _ := json.Marshal(b)
	if _, err := DecodeBundle(input); err == nil {
		t.Fatal("unknown assurance promoted")
	}
}
