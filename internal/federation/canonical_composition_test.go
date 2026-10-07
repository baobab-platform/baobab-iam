package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Only the remote CP boundary is simulated here. Governance, immutable target
// storage, maker/checker ledgers, trust transitions, signed OIDC verification,
// durable event consumption and replay fences are executable production code.
// CP's repository integration tests separately prove the attestation query.
type composedCP struct {
	mu          sync.RWMutex
	targets     map[ReferenceExpectation]string
	unavailable bool
}

func (c *composedCP) TargetRegistration(_ context.Context, w ReferenceExpectation) (TargetRegistration, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.unavailable {
		return TargetRegistration{}, ErrUnavailable
	}
	d, ok := c.targets[w]
	if !ok {
		return TargetRegistration{}, ErrUnverified
	}
	return TargetRegistration{Digest: d}, nil
}
func (c *composedCP) put(w ReferenceExpectation, d string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targets[w] = d
}

type composedAccess struct{}

func (composedAccess) AuthorizeAuthorityRequest(ctx context.Context, r *http.Request, _ string, _ ReferenceExpectation) (context.Context, error) {
	if r.Header.Get("Authorization") != "Bearer isolated-service-token" {
		return nil, ErrDenied
	}
	return ctx, nil
}

type composedActorKey struct{}
type composedActors struct{ now time.Time }

func (a composedActors) AuthorizeApproval(ctx context.Context, _ string, _ ReferenceExpectation) (ApprovalActor, error) {
	p, _ := ctx.Value(composedActorKey{}).(string)
	if p == "" {
		return ApprovalActor{}, ErrDenied
	}
	return ApprovalActor{PrincipalID: p, ValidUntil: a.now.Add(time.Hour)}, nil
}
func composedActor(p string) context.Context {
	return context.WithValue(context.Background(), composedActorKey{}, p)
}

var composedMaker = composedActor("77777777-7777-4777-8777-777777777777")
var composedChecker = composedActor("88888888-8888-4888-8888-888888888888")

type canonicalComposition struct {
	g        *GovernanceComposition
	cp       *composedCP
	consumer *Consumer
	events   *OIDCEvents
	want     ReferenceExpectation
	receipt  ApprovedReference
	facts    *fakeAuthority
	eventID  string
}

func newCanonicalComposition(t *testing.T, approveMapping bool) *canonicalComposition {
	t.Helper()
	events, policy, s, key, _ := oidcSetup(t)
	t.Cleanup(func() { events.Close() })
	_, facts := setup(t, "oidc")
	facts.canonical.Subject = "issuer-local-human-123"
	cp := &composedCP{targets: map[ReferenceExpectation]string{}}
	dir := t.TempDir()
	g, err := OpenGovernanceComposition(GovernanceCompositionConfig{NativeTargetLedgerPath: filepath.Join(dir, "native.db"), ApprovalLedgerPath: filepath.Join(dir, "approvals.db"), TrustLedgerPath: filepath.Join(dir, "trusts.db"), Registration: cp, Canonical: facts, ApprovalAuthority: composedActors{policy.clock}, Now: func() time.Time { return policy.clock }})
	if err != nil {
		t.Fatalf("composition error: %v", err)
	}
	t.Cleanup(func() { g.Close() })
	seq := 0
	approve := func(w ReferenceExpectation) {
		t.Helper()
		seq++
		r := ApprovedReference{Expectation: w, Status: "APPROVED", NonSecret: true, ValidFrom: policy.clock.Add(-time.Minute), ExpiresAt: policy.clock.Add(20 * time.Minute)}
		p, err := g.Approvals.Propose(composedMaker, fmt.Sprintf("99999999-9999-4999-8999-%012d", seq), r)
		if err != nil {
			t.Fatalf("composition error: %v", err)
		}
		if _, err = g.Approvals.Decide(composedChecker, p.ID, p.TargetDigest, true); err != nil {
			t.Fatalf("composition error: %v", err)
		}
	}
	base := ReferenceExpectation{TrustID: s.Trust.ID, ProviderID: s.Trust.ProviderBinding.ProviderID, EngineInstanceID: s.Trust.ProviderBinding.EngineInstanceID, Scope: facts.platform.Scope}
	for i, status := range []string{"REQUESTED", "CONFIGURING", "VERIFYING", "ACTIVE"} {
		s.Trust.Status = status
		s.Trust.UpdatedAt = policy.clock
		s.Trust.Revision = uint64(i + 1)
		s.ApprovedRevision = s.Trust.Revision
		s.SnapshotID = fmt.Sprintf("snapshot-%d", i+1)
		s.Trust.ActivatedAt = nil
		s.Trust.ActivationEvidenceReference = ""
		activation := fmt.Sprintf("ref_activation%d", i+1)
		if status == "ACTIVE" {
			s.Trust.ActivatedAt = &policy.clock
			s.Trust.ActivationEvidenceReference = activation
		}
		base.TrustRevision = s.Trust.Revision
		base.SnapshotID = s.SnapshotID
		w := base
		w.ID = activation
		w.Kind = "federation_activation"
		d, err := g.NativeTargets.RegisterTrustSnapshotTarget(context.Background(), w, s)
		if err != nil {
			t.Fatalf("register trust %s: %v valid=%v expectation=%v", status, err, ValidateTrust(s.Trust), validExpectation(w))
		}
		cp.put(w, d)
		approve(w)
		if status == "ACTIVE" {
			for _, item := range []struct{ id, kind string }{{s.Trust.ProviderBinding.ConfigurationReference, "federation_configuration"}, {s.Trust.ProviderBinding.TrustMaterialReference, "federation_trust_material"}, {s.Trust.AssurancePolicyReference, "assurance_policy"}, {s.Trust.AttributeMappingReference, "attribute_mapping"}, {s.Trust.ProvisioningPolicyReference, "provisioning_policy"}} {
				rw := base
				rw.ID = item.id
				rw.Kind = item.kind
				d, err := g.NativeTargets.RegisterNonSecretTarget(context.Background(), rw, []byte(`{"reviewed":"test-policy"}`))
				if err != nil {
					t.Fatalf("composition error: %v", err)
				}
				cp.put(rw, d)
				approve(rw)
			}
		}
		p, err := g.Trusts.Propose(composedMaker, fmt.Sprintf("66666666-6666-4666-8666-%012d", i+1), s, w)
		if err != nil {
			t.Fatalf("composition error: %v", err)
		}
		if _, err = g.Trusts.Decide(composedChecker, p.ID, p.TargetDigest, true); err != nil {
			t.Fatalf("composition error: %v", err)
		}
	}
	policy.config.SnapshotID = s.SnapshotID
	policy.config.Revision = s.ApprovedRevision
	r, err := events.Begin(context.Background(), s, secretDigest(browserSecret))
	if err != nil {
		t.Fatalf("composition error: %v", err)
	}
	if err = events.Complete(context.Background(), r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(policy, s, r)), s); err != nil {
		t.Fatalf("composition error: %v", err)
	}
	var event storedEvent
	if err = events.db.View(func(tx ledgerTx) error { return decodeAuthority(tx.Bucket(eventsBucket).Get([]byte(r.ID)), &event) }); err != nil {
		t.Fatalf("composition error: %v", err)
	}
	evidence, _ := json.Marshal(event.Bundle.Assurance.UpstreamEvidence)
	aw := base
	aw.ID = event.Bundle.Assurance.MappingEvidenceReference
	aw.Kind = "assurance_mapping_decision"
	aw.EventID = r.ID
	aw.Issuer = event.Bundle.ExternalPrincipal.Issuer
	aw.Subject = event.Bundle.ExternalPrincipal.Subject
	aw.Level = event.Bundle.Assurance.Level
	aw.EvidenceDigest = nativeTargetDigest(evidence)
	d, err := g.NativeTargets.RegisterNonSecretTarget(context.Background(), aw, evidence)
	if err != nil {
		t.Fatalf("composition error: %v", err)
	}
	cp.put(aw, d)
	approve(aw)
	w := base
	w.ID = facts.canonical.MappingReference
	w.Kind = "canonical_identity_mapping"
	w.Issuer = facts.canonical.Issuer
	w.Subject = facts.canonical.Subject
	w.PrincipalID = facts.canonical.PrincipalID
	w.ExternalIdentityID = facts.canonical.ExternalIdentityID
	mapping, _ := json.Marshal(struct{ Issuer, Subject, PrincipalID, ExternalIdentityID string }{w.Issuer, w.Subject, w.PrincipalID, w.ExternalIdentityID})
	cp.put(w, nativeTargetDigest(mapping))
	if approveMapping {
		approve(w)
	}
	sources, err := g.AuthoritySources(composedAccess{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAuthorityHandler(sources)
	if err != nil {
		t.Fatal(err)
	}
	remote, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) })
	remote.tokens = &testAuthorityToken{value: "isolated-service-token"}
	c, err := New(Authorities{Governance: remote, Platform: facts, Events: events, Canonical: facts}, Policy{Scope: facts.platform.Scope, MaxEventLifetime: 10 * time.Minute, MaxAuthenticationAge: 5 * time.Minute, MaxDecisionLifetime: time.Minute, Now: func() time.Time { return policy.clock }})
	if err != nil {
		t.Fatalf("composition error: %v", err)
	}
	return &canonicalComposition{g: g, cp: cp, consumer: c, events: events, want: w, receipt: ApprovedReference{Expectation: w, Status: "APPROVED", NonSecret: true, ValidFrom: policy.clock.Add(-time.Minute), ExpiresAt: policy.clock.Add(20 * time.Minute)}, facts: facts, eventID: r.ID}
}
func TestCanonicalMappingActualGovernanceComposition(t *testing.T) {
	f := newCanonicalComposition(t, true)
	d, err := f.consumer.Consume(context.Background(), f.want.TrustID, f.eventID)
	if err != nil || d.PrincipalID != f.want.PrincipalID {
		t.Fatal(d, err)
	}
	if _, err = f.consumer.Consume(context.Background(), f.want.TrustID, f.eventID); err == nil {
		t.Fatal("replay accepted")
	}
	if _, err = f.g.NativeTargets.NativeTargetContent(context.Background(), f.want); err == nil {
		t.Fatal("CP mapping copied into IAM native authority")
	}
}
func TestCanonicalMappingCompositionDenials(t *testing.T) {
	for _, mode := range []string{"missing approval", "reference", "revision", "revoked mapping", "principal", "tenant", "CP unavailable", "digest changed", "expired approval"} {
		t.Run(mode, func(t *testing.T) {
			f := newCanonicalComposition(t, mode != "missing approval")
			switch mode {
			case "reference":
				f.facts.canonical.MappingReference = "ref_substituted"
			case "revision":
				f.cp.mu.Lock()
				delete(f.cp.targets, f.want)
				changed := f.want
				changed.TrustRevision++
				f.cp.targets[changed] = "sha256:" + fmt.Sprintf("%064d", 1)
				f.cp.mu.Unlock()
			case "revoked mapping":
				f.cp.mu.Lock()
				delete(f.cp.targets, f.want)
				f.cp.mu.Unlock()
			case "principal":
				f.facts.canonical.PrincipalID = "55555555-5555-4555-8555-555555555555"
			case "tenant":
				f.consumer.policy.Scope.OrganisationID = "org_wrong"
			case "CP unavailable":
				f.cp.mu.Lock()
				f.cp.unavailable = true
				f.cp.mu.Unlock()
			case "digest changed":
				f.cp.put(f.want, "sha256:"+fmt.Sprintf("%064d", 1))
			case "expired approval":
				f.g.Approvals.now = func() time.Time { return f.receipt.ExpiresAt }
			}
			if d, err := f.consumer.Consume(context.Background(), f.want.TrustID, f.eventID); err == nil || d != (Decision{}) {
				t.Fatal("accepted", d, err)
			}
		})
	}
}
func TestCanonicalMappingConcurrentApprovalAndConsumption(t *testing.T) {
	f := newCanonicalComposition(t, false)
	p, err := f.g.Approvals.Propose(composedMaker, proposalID, f.receipt)
	if err != nil {
		t.Fatalf("composition error: %v", err)
	}
	var wg sync.WaitGroup
	outcomes := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.g.Approvals.Decide(composedChecker, p.ID, p.TargetDigest, true)
			outcomes <- err
		}()
	}
	wg.Wait()
	close(outcomes)
	success := 0
	for err := range outcomes {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("approval winners", success)
	}
	outcomes = make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.consumer.Consume(context.Background(), f.want.TrustID, f.eventID)
			outcomes <- err
		}()
	}
	wg.Wait()
	close(outcomes)
	success = 0
	for err := range outcomes {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("consumption winners", success)
	}
}
