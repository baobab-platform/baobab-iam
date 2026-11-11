package securityops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type journalStub struct {
	phase    Phase
	err      error
	events   []Phase
	reserves int
}

func (j *journalStub) Reserve(_ context.Context, _ Intent) (Phase, error) {
	j.reserves++
	if j.err != nil {
		return "", j.err
	}
	if j.phase == "" {
		return PhaseFenced, nil
	}
	return j.phase, nil
}

func (j *journalStub) Mark(_ context.Context, _ string, phase Phase) error {
	j.events = append(j.events, phase)
	return nil
}

type authorityStub struct {
	approval      Authorization
	calls         int
	recheckDenied bool
	denyOnCall    int
}

func (a *authorityStub) AuthorizeContainment(_ context.Context, _ Intent) (Authorization, error) {
	a.calls++
	if (a.recheckDenied && a.calls > 1) || a.calls == a.denyOnCall {
		return Authorization{}, errors.New("revoked")
	}
	return a.approval, nil
}

type providerStub struct {
	disabled     bool
	calls        []string
	disableErr   error
	revokeErr    error
	readErr      error
	active       int
	wrongSubject bool
}

func (p *providerStub) DisableIdentity(_ context.Context, _ provider.ExternalSubject) error {
	p.calls = append(p.calls, "disable")
	if p.disableErr == nil {
		p.disabled = true
	}
	return p.disableErr
}

func (p *providerStub) EnableIdentity(_ context.Context, _ provider.ExternalSubject) error {
	panic("incident containment may never reenable")
}

func (p *providerStub) RevokeSessions(_ context.Context, _ provider.ExternalSubject) error {
	p.calls = append(p.calls, "revoke")
	return p.revokeErr
}

func (p *providerStub) GetIdentity(_ context.Context, subject provider.ExternalSubject) (*provider.ProviderIdentity, error) {
	p.calls = append(p.calls, "read")
	if p.readErr != nil {
		return nil, p.readErr
	}
	status := provider.IdentityStatusActive
	if p.disabled {
		status = provider.IdentityStatusDisabled
	}
	if p.wrongSubject {
		subject.Subject = "different"
	}
	return &provider.ProviderIdentity{Issuer: subject.Issuer, Subject: subject.Subject, Status: status}, nil
}

func (p *providerStub) ActiveSessionCount(_ context.Context, _ provider.ExternalSubject) (int, error) {
	p.calls = append(p.calls, "count")
	return p.active, nil
}

type resourceStub struct {
	denial CurrentResourceDenial
	err    error
	calls  int
}

func (r *resourceStub) VerifyCurrentDenial(_ context.Context, _ provider.ExternalSubject, _ string) (CurrentResourceDenial, error) {
	r.calls++
	return r.denial, r.err
}

func setup(now time.Time) (*Containment, *journalStub, *providerStub, *resourceStub, *authorityStub, Intent) {
	journal := &journalStub{}
	native := &providerStub{}
	resource := &resourceStub{denial: CurrentResourceDenial{
		ExactSubjectDenied: true,
		CanonicalDenied:    true,
		ObservedAt:         now.Add(-time.Second),
		EvidenceReference:  "source-evidence-receipt",
	}}
	authority := &authorityStub{approval: Authorization{
		ActorID:    "6d5417fd-c3d0-4795-8f15-52f0cc3180b1",
		DecisionID: "f540b5da-33c6-4771-a17b-6aa1119ac9b9",
		VerifiedAt: now.Add(-time.Second),
		ValidUntil: now.Add(time.Minute),
	}}
	intent := Intent{
		OperationID: "incident-operation-0001",
		IncidentID:  "incident-000000000001",
		Subject:     provider.ExternalSubject{Issuer: "https://iam.example.test", Subject: "human-001"},
	}
	containment := &Containment{
		Authority: authority,
		Journal:   journal,
		Provider:  native,
		Resource:  resource,
		Now:       func() time.Time { return now },
	}
	return containment, journal, native, resource, authority, intent
}

func TestIncidentContainmentRequiresCurrentNativeAndCPReadback(t *testing.T) {
	containment, journal, native, resource, authority, intent := setup(time.Now().UTC())
	if err := containment.Execute(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if journal.reserves != 1 || authority.calls != 3 || resource.calls != 1 || !native.disabled {
		t.Fatal("missing original containment witnesses")
	}
	expected := []Phase{PhaseDisabled, PhaseRevoked, PhaseVerified}
	if len(journal.events) != len(expected) {
		t.Fatalf("phases: %v", journal.events)
	}
	for n, value := range expected {
		if journal.events[n] != value {
			t.Fatalf("phase %d: %v", n, journal.events[n])
		}
	}
	if len(native.calls) < 2 || native.calls[0] != "disable" || native.calls[1] != "read" {
		t.Fatalf("wrong mutation ordering: %v", native.calls)
	}
}

func TestFailClosedBeforeNativeMutation(t *testing.T) {
	now := time.Now().UTC()
	containment, journal, native, _, _, intent := setup(now)
	journal.err = errors.New("database down")
	if containment.Execute(context.Background(), intent) == nil || len(native.calls) != 0 {
		t.Fatal("provider mutation without durable journal")
	}
	containment, journal, native, _, authority, intent := setup(now)
	authority.recheckDenied = true
	if containment.Execute(context.Background(), intent) == nil {
		t.Fatal("recheck denial must stop mutation")
	}
	if len(native.calls) != 0 || len(journal.events) != 1 || journal.events[0] != PhaseUnknown {
		t.Fatalf("missing UNKNOWN on recheck refusal: %v %v", native.calls, journal.events)
	}
	containment, journal, native, _, authority, intent = setup(now)
	authority.approval.ValidUntil = now
	if containment.Execute(context.Background(), intent) == nil || journal.reserves != 0 || len(native.calls) != 0 {
		t.Fatal("expired authorization must not reserve or mutate")
	}
}

func TestWithdrawalAfterDisableStopsSessionRevocation(t *testing.T) {
	containment, journal, native, _, authority, intent := setup(time.Now().UTC())
	authority.denyOnCall = 3
	if containment.Execute(context.Background(), intent) == nil || !native.disabled {
		t.Fatal("partial containment was not reported as held")
	}
	for _, call := range native.calls {
		if call == "revoke" {
			t.Fatal("session revocation ran after authority was withdrawn")
		}
	}
	if len(journal.events) != 2 || journal.events[0] != PhaseDisabled || journal.events[1] != PhaseUnknown {
		t.Fatalf("partial effect was not journaled: %v", journal.events)
	}
}

func TestProviderAndResourceFailuresNeverBecomeVerified(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*providerStub, *resourceStub)
	}{
		{"disable", func(native *providerStub, _ *resourceStub) {
			native.disableErr = errors.New("failed")
		}},
		{"native-subject", func(native *providerStub, _ *resourceStub) {
			native.wrongSubject = true
		}},
		{"native-session", func(native *providerStub, _ *resourceStub) {
			native.active = 1
		}},
		{"resource-denial", func(_ *providerStub, resource *resourceStub) {
			resource.denial.CanonicalDenied = false
		}},
		{"resource-observation", func(_ *providerStub, resource *resourceStub) {
			resource.denial.EvidenceReference = ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			containment, journal, native, resource, _, intent := setup(time.Now().UTC())
			tc.mutate(native, resource)
			if containment.Execute(context.Background(), intent) == nil {
				t.Fatal("expected refusal")
			}
			if len(journal.events) == 0 || journal.events[len(journal.events)-1] != PhaseUnknown {
				t.Fatalf("journal must end UNKNOWN: %v", journal.events)
			}
			for _, phase := range journal.events {
				if phase == PhaseVerified {
					t.Fatal("false containment success")
				}
			}
		})
	}
}

func TestVerifiedHistoryIsNotCurrentTrust(t *testing.T) {
	containment, journal, native, resource, _, intent := setup(time.Now().UTC())
	journal.phase = PhaseVerified
	native.disabled = true
	if err := containment.Execute(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	for _, call := range native.calls {
		if call == "disable" || call == "revoke" {
			t.Fatal("verified replay mutated native provider")
		}
	}
	resource.denial.ExactSubjectDenied = false
	if containment.Execute(context.Background(), intent) == nil {
		t.Fatal("stale successful receipt bypassed current denial")
	}
	if journal.events[len(journal.events)-1] != PhaseUnknown {
		t.Fatal("drift must be marked unknown")
	}
}

func TestInvalidScopeRefused(t *testing.T) {
	containment, journal, native, _, _, intent := setup(time.Now().UTC())
	intent.Subject.Issuer = ""
	if containment.Execute(context.Background(), intent) == nil {
		t.Fatal("missing issuer accepted")
	}
	if journal.reserves != 0 || len(native.calls) != 0 {
		t.Fatal("invalid intent triggered effects")
	}
}
