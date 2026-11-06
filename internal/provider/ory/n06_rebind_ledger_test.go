package ory_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/securityops"
	"github.com/jackc/pgx/v5/pgxpool"
)

type n06OwnerBinding struct{ principal, domain string }

func (b n06OwnerBinding) CurrentRebindBinding(context.Context, provider.ExternalSubject) (ory.RebindBinding, error) {
	return ory.RebindBinding{Principal: b.principal, Domain: b.domain}, nil
}

type n06OwnerReview struct {
	approved     bool
	sameReviewer bool
}

func (r n06OwnerReview) CurrentRebindReview(context.Context, provider.ExternalSubject) (ory.RebindReview, error) {
	if !r.approved {
		return ory.RebindReview{}, errors.New("missing independent review")
	}
	approver := "ref_distinctreviewer"
	if r.sameReviewer {
		approver = "ref_requestingactor"
	}
	return ory.RebindReview{
		RequestedBy: "ref_requestingactor", ApprovedBy: approver,
		RecoveryReference: "ref_nativeproviderproof",
		DecisionReference: "ref_currentriskdecision",
		ExactSubject:      true, PrivilegedApproval: true,
		ObservedAt: time.Now().UTC().Add(-time.Second),
	}, nil
}

type n06OwnerRecovery struct{}

func (n06OwnerRecovery) VerifyRecovery(context.Context, securityops.RecoveryAction) (securityops.RecoveryEvidence, error) {
	return securityops.RecoveryEvidence{
		ExactProviderSession: true, RecoveryCompleted: true, ObservedAt: time.Now().UTC(),
		OriginalReference: "ref_syntheticproviderrecovery",
	}, nil
}
func TestN06RebindLedgerRequiresRealPG17CurrentHoldAndDistinctReview(t *testing.T) {
	if os.Getenv("IAM_N06_DISPOSABLE_PG") != "1" {
		t.Skip("requires real isolated PostgreSQL 17")
	}
	config, err := pgxpool.ParseConfig(os.Getenv("IAM_N06_TEST_DATABASE_URL"))
	if err != nil || config.ConnConfig.Database != "n06_ci" ||
		config.ConnConfig.Host != "127.0.0.1" {
		t.Fatal("foreign PG17 authority refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = pool.Exec(ctx, securityops.Schema()); err != nil {
		t.Fatal("N06 owner DDL", err)
	}
	var indexKey [32]byte
	if _, err = rand.Read(indexKey[:]); err != nil {
		t.Fatal(err)
	}
	store, err := securityops.NewStore(ctx, pool, indexKey[:], time.Now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	principal := "principal-n06-" + hex.EncodeToString(nonce)
	subject := provider.ExternalSubject{Issuer: "https://kratos.ci.example", Subject: "11111111-2222-4333-8444-555555555555"}
	domain := "n06-recovery"
	now := time.Now().UTC()
	action := securityops.RecoveryAction{
		Principal: principal, Issuer: subject.Issuer, SecurityDomain: domain,
		Reason: "SUSPECTED_TAKEOVER", ObservedAt: now.Add(-time.Second),
		HoldUntil: now.Add(26 * time.Hour),
	}
	binding := n06OwnerBinding{principal, domain}
	authority := &ory.LedgerRebindAuthority{
		Holds: store, Bindings: binding, Reviews: n06OwnerReview{approved: true}, Clock: time.Now,
	}
	if _, err = authority.CurrentWebAuthnRebind(ctx, subject); err == nil {
		t.Fatal("unrecorded recovery hold authorised rebinding")
	}
	if err = store.RecordRecovery(ctx, action, n06OwnerRecovery{}); err != nil {
		t.Fatal("original PG17 recovery hold not persisted", err)
	}
	evidence, err := authority.CurrentWebAuthnRebind(ctx, subject)
	if err != nil || !evidence.CurrentSecurityHold || !evidence.DistinctReviewer ||
		evidence.RequestedByReference == evidence.IndependentReviewerReference {
		t.Fatal("live PG17 recovery hold was not correctly read")
	}
	authority.Reviews = n06OwnerReview{approved: false}
	if _, err = authority.CurrentWebAuthnRebind(ctx, subject); err == nil {
		t.Fatal("missing independent reviewer bypassed persisted hold")
	}
	authority.Reviews = n06OwnerReview{approved: true, sameReviewer: true}
	if _, err = authority.CurrentWebAuthnRebind(ctx, subject); err == nil {
		t.Fatal("self-approval bypassed held account")
	}
	authority.Reviews = n06OwnerReview{approved: true}
	authority.Bindings = n06OwnerBinding{principal: "other-principal", domain: domain}
	if _, err = authority.CurrentWebAuthnRebind(ctx, subject); err == nil {
		t.Fatal("foreign Principal reused original recovery hold")
	}
	authority.Bindings = n06OwnerBinding{principal: principal, domain: "other-domain"}
	if _, err = authority.CurrentWebAuthnRebind(ctx, subject); err == nil {
		t.Fatal("foreign domain reused original recovery hold")
	}
}
