package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type journalStub struct {
	restricted bool
	failed     bool
	puts       int
	subjects   []provider.ExternalSubject
}

func (j *journalStub) PutRestricted(_ context.Context, record Restriction) error {
	j.puts++
	if j.failed {
		return errors.New("journal down")
	}
	j.restricted = true
	j.subjects = []provider.ExternalSubject{record.Subject}
	return nil
}

func (j *journalStub) IsRestricted(_ context.Context, _ provider.ExternalSubject) (bool, error) {
	if j.failed {
		return false, errors.New("journal down")
	}
	return j.restricted, nil
}

func (j *journalStub) ListRestricted(_ context.Context) ([]provider.ExternalSubject, error) {
	if j.failed {
		return nil, errors.New("journal down")
	}
	return j.subjects, nil
}

type authorityStub struct {
	decision Decision
	failed   bool
}

func (a *authorityStub) AuthorizeRestriction(_ context.Context, _ Restriction) (Decision, error) {
	if a.failed {
		return Decision{}, errors.New("denied")
	}
	return a.decision, nil
}

type nativeStub struct {
	disabled     bool
	calls        int
	active       int
	wrongSubject bool
}

func (n *nativeStub) DisableIdentity(_ context.Context, _ provider.ExternalSubject) error {
	n.calls++
	n.disabled = true
	return nil
}

func (n *nativeStub) EnableIdentity(_ context.Context, _ provider.ExternalSubject) error {
	panic("privacy replay cannot reenable a human identity")
}

func (n *nativeStub) RevokeSessions(_ context.Context, _ provider.ExternalSubject) error {
	n.calls++
	return nil
}

func (n *nativeStub) GetIdentity(_ context.Context, subject provider.ExternalSubject) (*provider.ProviderIdentity, error) {
	if n.wrongSubject {
		subject.Subject = "other"
	}
	status := provider.IdentityStatusActive
	if n.disabled {
		status = provider.IdentityStatusDisabled
	}
	return &provider.ProviderIdentity{Issuer: subject.Issuer, Subject: subject.Subject, Status: status}, nil
}

func (n *nativeStub) ActiveSessionCount(_ context.Context, _ provider.ExternalSubject) (int, error) {
	return n.active, nil
}

type cpStub struct {
	witness CPReadback
}

func (c *cpStub) VerifyRestrictedPrincipal(_ context.Context, _ provider.ExternalSubject) (CPReadback, error) {
	return c.witness, nil
}

type checkpointStub struct {
	proof CheckpointProof
	calls int
	drift bool
}

func (c *checkpointStub) VerifyComplete(_ context.Context) (CheckpointProof, error) {
	c.calls++
	p := c.proof
	if c.drift && c.calls > 1 {
		p.Revision = "different-revision-00001"
	}
	return p, nil
}

func setup(now time.Time) (*Service, *RestoreReconciler, *journalStub, *nativeStub, *cpStub, *checkpointStub, Restriction) {
	subject := provider.ExternalSubject{Issuer: "https://iam.example.test", Subject: "person-0001"}
	record := Restriction{Subject: subject, DecisionID: "decision-0000000001"}
	journal := &journalStub{}
	authority := &authorityStub{decision: Decision{
		DecisionID: record.DecisionID,
		Subject:    subject,
		ActorID:    "approver-00000000001",
		VerifiedAt: now.Add(-time.Second),
		ExpiresAt:  now.Add(time.Minute),
	}}
	service := &Service{Authority: authority, Journal: journal, Now: func() time.Time { return now }}
	native := &nativeStub{}
	cp := &cpStub{witness: CPReadback{
		Subject:       subject,
		CurrentDenied: true,
		ObservedAt:    now.Add(-time.Second),
		EvidenceRef:   "cp-original-veto-evidence",
	}}
	checkpoint := &checkpointStub{proof: CheckpointProof{
		Revision:    "checkpoint-00000001",
		EvidenceRef: "independent-custody-receipt",
		ObservedAt:  now.Add(-time.Second),
	}}
	reconciler := &RestoreReconciler{
		Journal:    journal,
		Provider:   native,
		CP:         cp,
		Checkpoint: checkpoint,
		Now:        func() time.Time { return now },
	}
	return service, reconciler, journal, native, cp, checkpoint, record
}

func TestRestrictiveTombstonePrecedesAnyReactivation(t *testing.T) {
	service, _, journal, _, _, _, record := setup(time.Now().UTC())
	if err := service.RecordRestriction(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if journal.puts != 1 {
		t.Fatal("missing durable restriction")
	}
	if !errors.Is(service.CheckReactivation(context.Background(), record.Subject), ErrPrivacyHold) {
		t.Fatal("restricted identity reactivation allowed")
	}
}

func TestRestrictionRequiresCurrentIndependentPrivacyDecision(t *testing.T) {
	service, _, journal, _, _, _, record := setup(time.Now().UTC())
	service.Authority = &authorityStub{failed: true}
	if service.RecordRestriction(context.Background(), record) == nil || journal.puts != 0 {
		t.Fatal("unauthorized privacy write")
	}
	service, _, journal, _, _, _, record = setup(time.Now().UTC())
	service.Authority = &authorityStub{decision: Decision{
		DecisionID: record.DecisionID,
		Subject:    provider.ExternalSubject{Issuer: record.Subject.Issuer, Subject: "other"},
		ActorID:    "approver-00000000001",
		VerifiedAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
	}}
	if service.RecordRestriction(context.Background(), record) == nil || journal.puts != 0 {
		t.Fatal("subject substitution accepted")
	}
}

func TestJournalOutageDeniesReactivationAndRestriction(t *testing.T) {
	service, _, journal, _, _, _, record := setup(time.Now().UTC())
	journal.failed = true
	if service.RecordRestriction(context.Background(), record) == nil {
		t.Fatal("failed write accepted")
	}
	if !errors.Is(service.CheckReactivation(context.Background(), record.Subject), ErrPrivacyHold) {
		t.Fatal("failed read permitted reactivation")
	}
}

func TestRestoreReappliesOnlyRestrictiveAuthority(t *testing.T) {
	_, reconciler, journal, native, _, _, record := setup(time.Now().UTC())
	journal.restricted = true
	journal.subjects = []provider.ExternalSubject{record.Subject}
	if err := reconciler.ReassertRestriction(context.Background(), record.Subject); err != nil {
		t.Fatal(err)
	}
	if !native.disabled || native.calls != 2 {
		t.Fatalf("native disable/revoke missing: %d", native.calls)
	}
	if count, err := reconciler.ReassertAll(context.Background()); err != nil || count != 1 {
		t.Fatalf("replay count=%d err=%v", count, err)
	}
}

func TestRestoreRejectsCurrentDriftAndIncompleteCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*RestoreReconciler, *journalStub, *nativeStub, *cpStub, *checkpointStub)
	}{
		{"missing-restriction", func(_ *RestoreReconciler, journal *journalStub, _ *nativeStub, _ *cpStub, _ *checkpointStub) {
			journal.restricted = false
		}},
		{"active-sessions", func(_ *RestoreReconciler, _ *journalStub, native *nativeStub, _ *cpStub, _ *checkpointStub) {
			native.active = 1
		}},
		{"identity-substitution", func(_ *RestoreReconciler, _ *journalStub, native *nativeStub, _ *cpStub, _ *checkpointStub) {
			native.wrongSubject = true
		}},
		{"cp-veto-missing", func(_ *RestoreReconciler, _ *journalStub, _ *nativeStub, cp *cpStub, _ *checkpointStub) {
			cp.witness.CurrentDenied = false
		}},
		{"checkpoint-drift", func(_ *RestoreReconciler, _ *journalStub, _ *nativeStub, _ *cpStub, checkpoint *checkpointStub) {
			checkpoint.drift = true
		}},
		{"checkpoint-absent", func(reconciler *RestoreReconciler, _ *journalStub, _ *nativeStub, _ *cpStub, _ *checkpointStub) {
			reconciler.Checkpoint = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, reconciler, journal, native, cp, checkpoint, record := setup(time.Now().UTC())
			journal.restricted = true
			journal.subjects = []provider.ExternalSubject{record.Subject}
			tc.mutate(reconciler, journal, native, cp, checkpoint)
			if _, err := reconciler.ReassertAll(context.Background()); !errors.Is(err, ErrPrivacyHold) {
				t.Fatal("unsafe restore replay reported success")
			}
		})
	}
}
