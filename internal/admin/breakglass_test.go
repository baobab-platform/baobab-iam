package admin

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testJournal struct {
	lease    Lease
	reserved int
	activate int
}

func (j *testJournal) Reserve(_ context.Context, lease Lease) error {
	j.reserved++
	if j.reserved > 1 {
		return ErrBreakGlassDenied
	}
	j.lease = lease
	return nil
}

func (j *testJournal) Activate(_ context.Context, id string) error {
	if j.lease.Request.LeaseID != id || j.lease.Status != StatePending {
		return ErrBreakGlassDenied
	}
	j.activate++
	j.lease.Status = StateActive
	return nil
}

func (j *testJournal) Read(_ context.Context, id string) (Lease, error) {
	if id != j.lease.Request.LeaseID {
		return Lease{}, ErrBreakGlassDenied
	}
	return j.lease, nil
}

func (j *testJournal) Terminate(_ context.Context, id string) error {
	if j.lease.Request.LeaseID != id || j.lease.Status != StateActive {
		return ErrBreakGlassDenied
	}
	j.lease.Status = StateTerminated
	return nil
}

type testVerifier struct {
	proof        Witness
	calls        int
	change       bool
	unauthorized bool
}

func (v *testVerifier) VerifyEmergency(_ context.Context, _ Request) (Witness, error) {
	v.calls++
	if v.unauthorized {
		return Witness{}, errors.New("authority absent")
	}
	proof := v.proof
	if v.change && v.calls > 1 {
		proof.ApproverID = "6d5417fd-c3d0-4795-8f15-52f0cc3180b1"
	}
	return proof, nil
}

type testNotice struct {
	now   time.Time
	calls int
	fail  bool
}

func (n *testNotice) RaiseCritical(_ context.Context, request Request, _ Witness) (Receipt, error) {
	n.calls++
	if n.fail {
		return Receipt{}, errors.New("alert outage")
	}
	return Receipt{LeaseID: request.LeaseID, Reference: "critical-security-event", ObservedAt: n.now}, nil
}

func (n *testNotice) RecordActivation(_ context.Context, request Request, _ Witness) (Receipt, error) {
	n.calls++
	if n.fail {
		return Receipt{}, errors.New("audit outage")
	}
	return Receipt{LeaseID: request.LeaseID, Reference: "append-only-audit-receipt", ObservedAt: n.now}, nil
}

func setup(now time.Time) (*BreakGlass, *testJournal, *testVerifier, *testNotice, *testNotice, Request) {
	request := Request{
		LeaseID:    "ca3b4c09-6769-468f-984e-b1091625a949",
		IncidentID: "df4667a7-f4d7-48c4-9305-7eab4ed5c991",
		Action:     "SUSPEND_FEDERATION",
		ScopeType:  "FEDERATION",
		ScopeID:    "1ed9f1a9-b97e-4214-b272-46a6c81eb6d5",
		Reason:     "INCIDENT_CONTAINMENT",
	}
	verifier := &testVerifier{proof: Witness{
		ActorID:              "6f4d8236-9b72-4b8b-935b-a19cb18c6050",
		ApproverID:           "ce709d30-3849-4ef0-a043-ad5c1972d73a",
		ApprovedAt:           now.Add(-time.Second),
		ExpiresAt:            now.Add(10 * time.Minute),
		IndependentAuthRef:   "hardware-auth-security-witness",
		IndependentReviewRef: "independent-security-checker",
	}}
	journal := &testJournal{}
	alerts := &testNotice{now: now.Add(-time.Second)}
	audit := &testNotice{now: now.Add(-time.Second)}
	service := &BreakGlass{
		Verifier: verifier,
		Alerts:   alerts,
		Audit:    audit,
		Journal:  journal,
		Now:      func() time.Time { return now },
	}
	return service, journal, verifier, alerts, audit, request
}

func TestScopedBreakGlassActivationAndTermination(t *testing.T) {
	service, journal, verifier, alerts, audit, request := setup(time.Now().UTC())
	if err := service.Activate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if journal.reserved != 1 || journal.activate != 1 || alerts.calls != 1 ||
		audit.calls != 1 || verifier.calls != 2 || journal.lease.Status != StateActive {
		t.Fatal("unwitnessed emergency activation")
	}
	if err := service.Check(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Terminate(context.Background(), request.LeaseID); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(service.Check(context.Background(), request), ErrBreakGlassDenied) {
		t.Fatal("terminated emergency lease remained usable")
	}
}

func TestUnknownScopeCannotActivate(t *testing.T) {
	service, journal, _, _, _, request := setup(time.Now().UTC())
	request.Action = "GRANT_TENANT_ADMIN"
	if !errors.Is(service.Activate(context.Background(), request), ErrBreakGlassDenied) {
		t.Fatal("business-authority escalation accepted")
	}
	request.ScopeType = ""
	if !errors.Is(service.Activate(context.Background(), request), ErrBreakGlassDenied) {
		t.Fatal("unregistered action with an empty scope was accepted")
	}
	request.Action = "SUSPEND_FEDERATION"
	request.ScopeType = "ISSUER"
	if !errors.Is(service.Activate(context.Background(), request), ErrBreakGlassDenied) {
		t.Fatal("action/scope substitution accepted")
	}
	if journal.reserved != 0 {
		t.Fatal("invalid request persisted")
	}
}

func TestNoActivationOnApprovalOrAuditFailure(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testVerifier, *testNotice, *testNotice)
	}{
		{"approval-changed", func(verifier *testVerifier, _ *testNotice, _ *testNotice) {
			verifier.change = true
		}},
		{"unavailable-verifier", func(verifier *testVerifier, _ *testNotice, _ *testNotice) {
			verifier.unauthorized = true
		}},
		{"critical-alert-failed", func(_ *testVerifier, alerts *testNotice, _ *testNotice) {
			alerts.fail = true
		}},
		{"audit-failed", func(_ *testVerifier, _ *testNotice, audit *testNotice) {
			audit.fail = true
		}},
		{"self-approval", func(verifier *testVerifier, _ *testNotice, _ *testNotice) {
			verifier.proof.ApproverID = verifier.proof.ActorID
		}},
		{"expired-lease", func(verifier *testVerifier, _ *testNotice, _ *testNotice) {
			verifier.proof.ExpiresAt = verifier.proof.ApprovedAt.Add(16 * time.Minute)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, journal, verifier, alerts, audit, request := setup(time.Now().UTC())
			tc.mutate(verifier, alerts, audit)
			if !errors.Is(service.Activate(context.Background(), request), ErrBreakGlassDenied) {
				t.Fatal("unqualified emergency path accepted")
			}
			if journal.activate != 0 {
				t.Fatal("activated without all witnesses")
			}
		})
	}
}

func TestLeaseCannotBeReusedForDifferentTarget(t *testing.T) {
	service, _, _, _, _, request := setup(time.Now().UTC())
	if err := service.Activate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.ScopeID = "f8ee65b7-0b2f-4f1e-86f7-14346cf70910"
	if !errors.Is(service.Check(context.Background(), request), ErrBreakGlassDenied) {
		t.Fatal("scope-changing emergency use allowed")
	}
}
