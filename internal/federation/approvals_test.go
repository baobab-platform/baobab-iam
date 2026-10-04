package federation

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type approvalFixture struct {
	actor    string
	clock    time.Time
	digest   string
	err      error
	onTarget func()
}

func (f *approvalFixture) AuthorizeApproval(context.Context, string, ReferenceExpectation) (ApprovalActor, error) {
	return ApprovalActor{f.actor, f.clock.Add(time.Minute)}, f.err
}
func (f *approvalFixture) ResolveApprovedTarget(context.Context, ReferenceExpectation) (string, error) {
	if f.onTarget != nil {
		f.onTarget()
	}
	return f.digest, f.err
}
func approvalSetup(t *testing.T) (*ApprovalLedger, *approvalFixture, ApprovedReference, string) {
	t.Helper()
	_, f := setup(t, "oidc")
	a := &approvalFixture{actor: "33333333-3333-4333-8333-333333333333", clock: f.clock, digest: "sha256:" + strings.Repeat("c", 64)}
	w := ReferenceExpectation{ID: f.bundle.Trust.ProviderBinding.ConfigurationReference, Kind: "federation_configuration", TrustID: f.bundle.Trust.ID, SnapshotID: f.snapshot.SnapshotID, TrustRevision: 1, ProviderID: f.platform.ProviderID, EngineInstanceID: f.platform.EngineInstanceID, Scope: f.platform.Scope}
	r := ApprovedReference{Expectation: w, Status: "APPROVED", NonSecret: true, ValidFrom: a.clock.Add(-time.Minute), ExpiresAt: a.clock.Add(10 * time.Minute)}
	path := filepath.Join(t.TempDir(), "approvals.db")
	l, err := OpenApprovalLedger(path, a, a, func() time.Time { return a.clock })
	if err != nil {
		t.Fatal(err)
	}
	return l, a, r, path
}

const proposalID = "55555555-5555-4555-8555-555555555555"

func TestApprovalRequiresFourEyesAndSurvivesRestart(t *testing.T) {
	l, a, r, path := approvalSetup(t)
	ctx := context.Background()
	p, err := l.Propose(ctx, proposalID, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Reference(ctx, r.Expectation); err == nil {
		t.Fatal("pending accepted")
	}
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); !errors.Is(err, ErrDenied) {
		t.Fatal("self approval", err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenApprovalLedger(path, a, a, func() time.Time { return a.clock })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err = l.Reference(ctx, r.Expectation); err != nil {
		t.Fatal(err)
	}
	if err = l.Revoke(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Reference(ctx, r.Expectation); err == nil {
		t.Fatal("revoked accepted")
	}
	newID := "66666666-6666-4666-8666-666666666666"
	a.actor = p.Maker
	if _, err = l.Propose(ctx, newID, r); err != nil {
		t.Fatal(err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	if _, err = l.Decide(ctx, newID, p.TargetDigest, true); err == nil {
		t.Fatal("revoked snapshot resurrected")
	}
}
func TestApprovalDriftExpiryAuthorityAndRevocation(t *testing.T) {
	for _, mode := range []string{"target-drift", "authority-down", "expiry", "cross-scope", "revoke-during-read"} {
		t.Run(mode, func(t *testing.T) {
			l, a, r, _ := approvalSetup(t)
			defer l.Close()
			ctx := context.Background()
			p, err := l.Propose(ctx, proposalID, r)
			if err != nil {
				t.Fatal(err)
			}
			a.actor = "44444444-4444-4444-8444-444444444444"
			if _, err = l.Decide(ctx, p.ID, p.TargetDigest, true); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "target-drift":
				a.digest = "sha256:" + strings.Repeat("d", 64)
			case "authority-down":
				a.err = ErrUnavailable
			case "expiry":
				a.clock = r.ExpiresAt
			case "cross-scope":
				r.Expectation.Scope.EstateID = "other_estate"
			case "revoke-during-read":
				a.onTarget = func() {
					a.onTarget = nil
					if err := l.Revoke(ctx, p.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err = l.Reference(ctx, r.Expectation); err == nil {
				t.Fatal("unsafe receipt accepted")
			}
		})
	}
}
func TestApprovalConcurrentDecisionSingleWinner(t *testing.T) {
	l, a, r, _ := approvalSetup(t)
	defer l.Close()
	p, err := l.Propose(context.Background(), proposalID, r)
	if err != nil {
		t.Fatal(err)
	}
	a.actor = "44444444-4444-4444-8444-444444444444"
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.Decide(context.Background(), p.ID, p.TargetDigest, true)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("winners=%d", success)
	}
}
func TestApprovalRejectsUnsafeAndUnavailableInputs(t *testing.T) {
	l, a, r, _ := approvalSetup(t)
	defer l.Close()
	for _, change := range []func(*ApprovedReference){func(r *ApprovedReference) { r.NonSecret = false }, func(r *ApprovedReference) { r.Expectation.Kind = "arbitrary" }, func(r *ApprovedReference) { r.Expectation.EventID = proposalID }, func(r *ApprovedReference) { r.Expectation.TrustRevision = 0 }} {
		bad := r
		change(&bad)
		if _, err := l.Propose(context.Background(), proposalID, bad); err == nil {
			t.Fatal("invalid proposed")
		}
	}
	a.err = errors.New("database connection secret detail")
	if _, err := l.Propose(context.Background(), proposalID, r); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := OpenApprovalLedger(filepath.Join(t.TempDir(), "x"), nil, a, time.Now); err == nil {
		t.Fatal("missing authority accepted")
	}
}
