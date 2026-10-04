package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestAuthoritySnapshotSurvivesWireTimeNormalization(t *testing.T) {
	_, facts := setup(t, "oidc")
	events, policy, _, _, _ := oidcSetup(t)
	defer events.Close()
	// Real monotonic-clock metadata cannot survive JSON. A fixed-offset source
	// and the UTC wire representation must nevertheless identify the same fact.
	facts.snapshot.ValidUntil = time.Now().Add(time.Minute)
	facts.snapshot.Trust.CreatedAt = facts.snapshot.Trust.CreatedAt.In(time.FixedZone("source", 7200))
	h, err := NewAuthorityHandler(AuthoritySources{Access: &isolatedAccess{}, Governance: facts, Configuration: policy})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a, err := NewHTTPAuthority(server.URL, &testAuthorityToken{value: "isolated-service-token"}, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	wire := facts.snapshot
	wire.Trust = canonicalTrust(wire.Trust)
	wire.ValidUntil = wire.ValidUntil.UTC()
	if _, err := a.OIDCConfiguration(context.Background(), wire); err != nil {
		t.Fatal("same wire snapshot denied", err)
	}
	wire.Trust.ProviderBinding.ConfigurationReference = "ref_otherconfiguration"
	if _, err := a.OIDCConfiguration(context.Background(), wire); !errors.Is(err, ErrUnverified) {
		t.Fatal("configuration substitution accepted", err)
	}
}

func TestMakerRevocationPreservesIndependentApprovalHistory(t *testing.T) {
	l, actor, receipt, path := approvalSetup(t)
	ctx := context.Background()
	p, err := l.Propose(ctx, proposalID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	actor.actor = "44444444-4444-4444-8444-444444444444"
	approved, err := l.Decide(ctx, p.ID, p.TargetDigest, true)
	if err != nil {
		t.Fatal(err)
	}
	actor.actor = p.Maker
	actor.clock = actor.clock.Add(time.Second)
	if err := l.Revoke(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenApprovalLedger(path, actor, actor, func() time.Time { return actor.clock })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	revoked, err := l.proposal(ctx, p.ID)
	if err != nil || revoked.Status != "REVOKED" || revoked.Checker != approved.Checker || !revoked.DecidedAt.Equal(approved.DecidedAt) || revoked.Revoker != p.Maker || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(actor.clock) {
		t.Fatal("approval or revocation history lost", revoked, err)
	}
	if _, err := l.Reference(ctx, receipt.Expectation); err == nil {
		t.Fatal("revoked approval accepted")
	}
}

func TestOIDCPruningPreservesLiveEvidenceAndRejectsClockRollback(t *testing.T) {
	e, f, snapshot, key, path := oidcSetup(t)
	ctx := context.Background()
	r, err := e.Begin(ctx, snapshot, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Complete(ctx, r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(f, snapshot, r)), snapshot); err != nil {
		t.Fatal(err)
	}
	if count, err := e.Prune(ctx, 1); err != nil || count != 0 {
		t.Fatal("live replay/evidence pruned", count, err)
	}
	if _, _, err := e.Verify(ctx, r.ID, snapshot); err != nil {
		t.Fatal(err)
	}
	if count, err := e.Prune(ctx, 1); err != nil || count != 0 {
		t.Fatal("unexpired consumed evidence pruned", count, err)
	}
	f.clock = f.clock.Add(6 * time.Minute)
	removed := 0
	for i := 0; i < 3; i++ {
		count, err := e.Prune(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		removed += count
	}
	if removed != 3 {
		t.Fatal("expired records retained", removed)
	}
	if err := e.db.View(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{requestsBucket, eventsBucket, replayBucket} {
			if key, _ := tx.Bucket(bucket).Cursor().First(); key != nil {
				t.Error("expired bucket not empty", string(bucket))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = OpenOIDCEvents(path, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	f.clock = f.clock.Add(-6 * time.Minute)
	if _, err := e.Begin(ctx, snapshot, secretDigest(browserSecret)); !errors.Is(err, ErrDenied) {
		t.Fatal("restart clock rollback resurrected acceptance", err)
	}
	if _, _, err := e.Verify(ctx, r.ID, snapshot); err == nil {
		t.Fatal("pruned event resurrected")
	}
}

func TestOIDCPruningCursorMakesProgressPastLiveRequests(t *testing.T) {
	e, f, snapshot, _, _ := oidcSetup(t)
	defer e.Close()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := e.Begin(ctx, snapshot, secretDigest(browserSecret)); err != nil {
			t.Fatal(err)
		}
	}
	f.clock = f.clock.Add(4 * time.Minute)
	live, err := e.Begin(ctx, snapshot, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(2 * time.Minute)
	removed := 0
	for i := 0; i < 12; i++ {
		count, err := e.Prune(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		removed += count
	}
	if removed != 4 {
		t.Fatal("expired requests starved", removed)
	}
	if err := e.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(requestsBucket)
		if b.Get([]byte(live.ID)) == nil || b.Stats().KeyN != 1 {
			t.Fatal("live request removed or expired request retained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
