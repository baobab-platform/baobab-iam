package federation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

type trustFixture struct {
	*approvalFixture
	references *fakeAuthority
}

func (f *trustFixture) Reference(ctx context.Context, w ReferenceExpectation) (ApprovedReference, error) {
	r, err := f.references.Reference(ctx, w)
	r.ExpiresAt = f.clock.Add(30 * time.Minute)
	return r, err
}
func trustSetup(t *testing.T) (*TrustLedger, *trustFixture, TrustSnapshot, ReferenceExpectation, string) {
	t.Helper()
	_, f := setup(t, "oidc")
	a := &trustFixture{&approvalFixture{actor: "33333333-3333-4333-8333-333333333333", clock: f.clock}, f}
	s := f.snapshot
	s.Trust.Status = "REQUESTED"
	s.Trust.ActivatedAt = nil
	s.Trust.ActivationEvidenceReference = ""
	w := ReferenceExpectation{ID: "ref_ciactivation", Kind: "federation_activation", TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, TrustRevision: s.ApprovedRevision, ProviderID: s.Trust.ProviderBinding.ProviderID, EngineInstanceID: s.Trust.ProviderBinding.EngineInstanceID, Scope: f.platform.Scope}
	path := filepath.Join(t.TempDir(), "trusts.db")
	l, err := OpenTrustLedger(path, a, a, a, func() time.Time { return a.clock })
	if err != nil {
		t.Fatal(err)
	}
	return l, a, s, w, path
}
func trustCommit(t *testing.T, l *TrustLedger, a *trustFixture, s TrustSnapshot, w ReferenceExpectation, n int) {
	t.Helper()
	a.actor = "33333333-3333-4333-8333-333333333333"
	a.digest = TrustSnapshotDigest(s)
	p, err := l.Propose(context.Background(), fmt.Sprintf("55555555-5555-4555-8555-%012d", n), s, w)
	if err != nil {
		t.Fatal(err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	if _, err = l.Decide(context.Background(), p.ID, p.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
}
func advanceTrust(s *TrustSnapshot, w *ReferenceExpectation, status string, clock time.Time) {
	s.Trust.Revision++
	s.ApprovedRevision = s.Trust.Revision
	s.SnapshotID = fmt.Sprintf("revision-%d", s.Trust.Revision)
	s.Trust.Status = status
	s.Trust.UpdatedAt = clock
	w.TrustRevision = s.ApprovedRevision
	w.SnapshotID = s.SnapshotID
	if status == "ACTIVE" {
		s.Trust.ActivatedAt = &clock
		s.Trust.ActivationEvidenceReference = w.ID
	}
}
func TestTrustLifecycleApprovalRestartContainment(t *testing.T) {
	l, a, s, w, path := trustSetup(t)
	ctx := context.Background()
	a.digest = TrustSnapshotDigest(s)
	p, err := l.Propose(ctx, proposalID, s, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); !errors.Is(err, ErrDenied) {
		t.Fatal("self approval", err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	for i, status := range []string{"CONFIGURING", "VERIFYING", "ACTIVE"} {
		advanceTrust(&s, &w, status, a.clock)
		trustCommit(t, l, a, s, w, i+2)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenTrustLedger(path, a, a, a, func() time.Time { return a.clock })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got, err := l.Trust(ctx, s.Trust.ID); err != nil || !sameSnapshot(got, s) {
		t.Fatal("restart", err)
	}
	if err = l.Contain(ctx, s.Trust.ID, s.ApprovedRevision, "SUSPENDED"); err != nil {
		t.Fatal(err)
	}
	suspended, err := l.Trust(ctx, s.Trust.ID)
	if err != nil || suspended.Trust.Status != "SUSPENDED" {
		t.Fatal(err)
	}
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err == nil {
		t.Fatal("replayed approval")
	}
	s = suspended
	w.SnapshotID = s.SnapshotID
	w.TrustRevision = s.ApprovedRevision
	advanceTrust(&s, &w, "ACTIVE", a.clock)
	a.digest = TrustSnapshotDigest(s)
	if _, err = l.Propose(ctx, "66666666-6666-4666-8666-666666666666", s, w); err == nil {
		t.Fatal("skipped reverification")
	}
	if err = l.Contain(ctx, s.Trust.ID, suspended.ApprovedRevision, "REVOKED"); err != nil {
		t.Fatal(err)
	}
	revoked, err := l.Trust(ctx, s.Trust.ID)
	if err != nil || revoked.Trust.Status != "REVOKED" {
		t.Fatal(err)
	}
	current, err := l.read(ctx, s.Trust.ID)
	if err != nil || current.Maker != p.Maker || current.Checker == "" || current.ContainmentActor == "" {
		t.Fatal("history lost", err)
	}
	advanceTrust(&revoked, &w, "VERIFYING", a.clock)
	w.TrustRevision = revoked.ApprovedRevision
	w.SnapshotID = revoked.SnapshotID
	a.digest = TrustSnapshotDigest(revoked)
	if _, err = l.Propose(ctx, "77777777-7777-4777-8777-777777777777", revoked, w); err == nil {
		t.Fatal("terminal revocation resurrected")
	}
}
func TestTrustRejectsStaleRevisionAndTargetDrift(t *testing.T) {
	for _, mode := range []string{"target-drift", "competing-revision", "scope", "initial-active"} {
		t.Run(mode, func(t *testing.T) {
			l, a, s, w, _ := trustSetup(t)
			defer l.Close()
			ctx := context.Background()
			if mode == "scope" {
				w.Scope.EstateID = "other_estate"
			}
			if mode == "initial-active" {
				s.Trust.Status = "ACTIVE"
				s.Trust.ActivatedAt = &a.clock
				s.Trust.ActivationEvidenceReference = w.ID
			}
			a.digest = TrustSnapshotDigest(s)
			p, err := l.Propose(ctx, proposalID, s, w)
			if mode == "scope" || mode == "initial-active" {
				if err == nil {
					t.Fatal("invalid proposal accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "competing-revision" {
				trustCommit(t, l, a, s, w, 9)
			} else {
				a.digest = "sha256:" + fmt.Sprintf("%064d", 1)
			}
			a.actor = "44444444-4444-4444-8444-444444444444"
			if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err == nil {
				t.Fatal("stale approval accepted")
			}
		})
	}
}
func TestTrustActivationRequiresCurrentReceipts(t *testing.T) {
	l, a, s, w, _ := trustSetup(t)
	defer l.Close()
	ctx := context.Background()
	for i, status := range []string{"REQUESTED", "CONFIGURING", "VERIFYING"} {
		if i > 0 {
			advanceTrust(&s, &w, status, a.clock)
		}
		trustCommit(t, l, a, s, w, i+1)
	}
	advanceTrust(&s, &w, "ACTIVE", a.clock)
	a.digest = TrustSnapshotDigest(s)
	a.actor = "33333333-3333-4333-8333-333333333333"
	p, err := l.Propose(ctx, proposalID, s, w)
	if err != nil {
		t.Fatal(err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	a.references.mutateReceipt = func(r *ApprovedReference) { r.NonSecret = false }
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err == nil {
		t.Fatal("unapproved activation")
	}
	a.references.mutateReceipt = nil
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	a.references.err = ErrUnavailable
	if _, err = l.Trust(ctx, s.Trust.ID); err == nil {
		t.Fatal("authority outage accepted")
	}
	// Emergency containment does not depend on the receipt service.
	if err = l.Contain(ctx, s.Trust.ID, s.ApprovedRevision, "REVOKED"); err != nil {
		t.Fatal(err)
	}
}
func TestTrustClockRollbackAfterRestart(t *testing.T) {
	l, a, s, w, path := trustSetup(t)
	trustCommit(t, l, a, s, w, 1)
	ctx := context.Background()
	a.clock = s.ValidUntil
	if _, err := l.Trust(ctx, s.Trust.ID); err == nil {
		t.Fatal("expired trust")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	a.clock = s.ValidUntil.Add(-time.Minute)
	l, err := OpenTrustLedger(path, a, a, a, func() time.Time { return a.clock })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err = l.Trust(ctx, s.Trust.ID); err == nil {
		t.Fatal("expiry reopened on rollback")
	}
}
func TestTrustActiveChangesRequireReverification(t *testing.T) {
	_, f := setup(t, "oidc")
	previous := f.snapshot.Trust
	current := previous
	current.Revision++
	current.AttributeMappingReference = "ref_changedmapping"
	if trustTransition(previous, current) {
		t.Fatal("active configuration bypassed reverification")
	}
	current.Status = "ROTATING"
	if !trustTransition(previous, current) {
		t.Fatal("rotation rejected")
	}
}

func TestTrustCommandsUsePrivateTransport(t *testing.T) {
	l, a, s, w, _ := trustSetup(t)
	defer l.Close()
	access := &isolatedAccess{}
	h, err := NewAuthorityHandler(AuthoritySources{Access: access, Governance: l, TrustLedger: l})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) })
	client.tokens = &testAuthorityToken{value: "isolated-service-token"}
	ctx := context.Background()
	a.digest = TrustSnapshotDigest(s)
	p, err := client.ProposeTrust(ctx, proposalID, s, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.DecideTrust(ctx, p.ID, p.TargetDigest, true); !errors.Is(err, ErrDenied) {
		t.Fatal("self approval", err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	if _, err = client.DecideTrust(ctx, p.ID, p.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	got, err := client.Trust(ctx, s.Trust.ID)
	if err != nil || !sameSnapshot(got, s) {
		t.Fatal(err)
	}
	access.err = ErrDenied
	if err = client.ContainTrust(ctx, s.Trust.ID, 1, "REVOKED"); !errors.Is(err, ErrDenied) {
		t.Fatal("access bypass", err)
	}
	access.err = nil
	if err = client.ContainTrust(ctx, s.Trust.ID, 1, "REVOKED"); err != nil {
		t.Fatal(err)
	}
	got, err = client.Trust(ctx, s.Trust.ID)
	if err != nil || got.Trust.Status != "REVOKED" {
		t.Fatal(err)
	}
}
