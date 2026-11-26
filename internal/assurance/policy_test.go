package assurance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fixedReader struct {
	proof NativeEvidence
	err   error
}

func (f fixedReader) CurrentAuthentication(context.Context, CurrentSessionKey) (NativeEvidence, error) {
	return f.proof, f.err
}

type fixedRisk struct {
	proof Risk
	err   error
}

func (f fixedRisk) CurrentRisk(context.Context, CurrentSessionKey, Operation) (Risk, error) {
	return f.proof, f.err
}
func fixture(now time.Time) (*NativeEvaluator, CurrentSessionKey) {
	key := CurrentSessionKey{Issuer: "https://issuer.test", Subject: "subject-1", SessionID: "session-1"}
	return &NativeEvaluator{
		Policy: DefaultDevelopmentPolicy(),
		Now:    func() time.Time { return now },
		Authentication: fixedReader{proof: NativeEvidence{
			Issuer: key.Issuer, Subject: key.Subject, SessionID: key.SessionID,
			ObservedAt: now.Add(-time.Second), AuthenticatedAt: now.Add(-time.Minute),
			ExpiresAt: now.Add(time.Hour), AAL: A2, Methods: []string{"password", "totp"},
		}},
		Risk: fixedRisk{proof: Risk{ObservedAt: now.Add(-time.Second), Level: "low", RecoveryStateChecked: true, PrivilegedContextVerified: true}},
	}, key
}
func withProof(e *NativeEvaluator, fn func(*NativeEvidence)) {
	r := e.Authentication.(fixedReader)
	fn(&r.proof)
	e.Authentication = r
}
func withRisk(e *NativeEvaluator, fn func(*Risk)) {
	r := e.Risk.(fixedRisk)
	fn(&r.proof)
	e.Risk = r
}
func TestN06StrongMFAIsNotPasskeyOrPrivilegedAuthority(t *testing.T) {
	now := time.Date(2026, 10, 31, 14, 0, 0, 0, time.UTC)
	e, k := fixture(now)
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != Allow {
		t.Fatalf("current AAL2 failed A2: %+v", d)
	}
	for _, op := range []Operation{HighValueApproval, ChangeCredential, ChangeRecovery, GrantPrivileged, BreakGlass} {
		if d := e.Check(context.Background(), k, op); d.Outcome != StepUp {
			t.Fatalf("TOTP incorrectly promoted to A3/A4 for %s: %+v", op, d)
		}
	}
	withProof(e, func(p *NativeEvidence) {
		p.PasskeyUsed = true
		p.UserVerified = true
		p.OriginBound = true
		p.Methods = []string{"webauthn"}
	})
	if d := e.Check(context.Background(), k, HighValueApproval); d.Outcome != Allow || d.Observed != A3 {
		t.Fatalf("fresh UV bound passkey not recognized: %+v", d)
	}
	if d := e.Check(context.Background(), k, GrantPrivileged); d.Outcome != StepUp {
		t.Fatalf("A3 incorrectly upgraded to A4: %+v", d)
	}
	withProof(e, func(p *NativeEvidence) { p.HardwareBound = true })
	if d := e.Check(context.Background(), k, GrantPrivileged); d.Outcome != Allow || d.Observed != A4 {
		t.Fatalf("verified A4 evidence denied: %+v", d)
	}
}
func TestN06A3NeedsEveryCurrentFactorProperty(t *testing.T) {
	now := time.Now().UTC()
	for _, mutate := range []func(*NativeEvidence){
		func(p *NativeEvidence) { p.PasskeyUsed = false },
		func(p *NativeEvidence) { p.UserVerified = false },
		func(p *NativeEvidence) { p.OriginBound = false },
		func(p *NativeEvidence) { p.Methods = []string{"totp"} },
		func(p *NativeEvidence) { p.AAL = A1 },
		func(p *NativeEvidence) { p.SessionID = "other" },
		func(p *NativeEvidence) { p.Subject = "different" },
		func(p *NativeEvidence) { p.Issuer = "https://other.test" },
		func(p *NativeEvidence) { p.ObservedAt = now.Add(-31 * time.Second) },
		func(p *NativeEvidence) { p.AuthenticatedAt = now.Add(-6 * time.Minute) },
		func(p *NativeEvidence) { p.AuthenticatedAt = now.Add(time.Second) },
		func(p *NativeEvidence) { p.ObservedAt = now.Add(time.Second) },
	} {
		e, k := fixture(now)
		withProof(e, func(p *NativeEvidence) {
			p.PasskeyUsed = true
			p.UserVerified = true
			p.OriginBound = true
			p.Methods = []string{"webauthn"}
		})
		mutateProof := e.Authentication.(fixedReader)
		mutate(&mutateProof.proof)
		e.Authentication = mutateProof
		if d := e.Check(context.Background(), k, HighValueApproval); d.Outcome == Allow {
			t.Fatalf("forged/stale passkey or session obtained A3: %+v", mutateProof.proof)
		}
	}
}
func TestN06RecoveryHoldAndRiskNeverDowngradeMin(t *testing.T) {
	now := time.Now().UTC()
	e, k := fixture(now)
	withProof(e, func(p *NativeEvidence) {
		p.PasskeyUsed = true
		p.UserVerified = true
		p.OriginBound = true
		p.Methods = []string{"webauthn"}
		p.RecoveryCompletedAt = now.Add(-time.Hour)
	})
	if d := e.Check(context.Background(), k, HighValueApproval); d.Outcome != Deny || d.Reason != "POST_RECOVERY_HOLD" {
		t.Fatalf("sensitive recovery lock bypass: %+v", d)
	}
	withProof(e, func(p *NativeEvidence) { p.RecoveryCompletedAt = time.Time{} })
	withRisk(e, func(r *Risk) { r.Level = "high" })
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != Allow || d.Required != A3 {
		t.Fatalf("risk failed to raise minimum: %+v", d)
	}
	withProof(e, func(p *NativeEvidence) { p.PasskeyUsed = false })
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != StepUp || d.Required != A3 {
		t.Fatalf("high-risk TOTP allowed: %+v", d)
	}
	withRisk(e, func(r *Risk) { r.Level = "critical" })
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != Deny {
		t.Fatalf("critical risk allowed: %+v", d)
	}
	withRisk(e, func(r *Risk) { r.Level = "unknown" })
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != Deny {
		t.Fatalf("unknown risk allowed: %+v", d)
	}
}
func TestN06UnreviewedOrUnavailableProofFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	e, k := fixture(now)
	for _, op := range []Operation{"", "admin:activate", "trade:buy:approve"} {
		if d := e.Check(context.Background(), k, op); d.Outcome != Deny {
			t.Fatalf("unreviewed operation allowed: %+v", d)
		}
	}
	e.Authentication = fixedReader{err: errors.New("provider expired")}
	if d := e.Check(context.Background(), k, OrdinaryBuyer); d.Outcome != Deny {
		t.Fatalf("missing proof allowed: %+v", d)
	}
	e, k = fixture(now)
	e.Risk = nil
	if d := e.Check(context.Background(), k, CommitBuyer); d.Outcome != Deny {
		t.Fatalf("missing risk allowed: %+v", d)
	}
	e, k = fixture(now)
	k.SessionID = "browser-supplied-cookie"
	if d := e.Check(context.Background(), k, OrdinaryBuyer); d.Outcome != Deny {
		t.Fatalf("session substitution allowed: %+v", d)
	}
}
func TestN06ConsequentialPolicyFloorsCannotBeDowngraded(t *testing.T) {
	for _, tc := range []struct {
		op  Operation
		req Policy
	}{
		{CommitBuyer, Policy{Level: A1, MaxAge: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{CommitBuyer, Policy{Level: A2, MaxAge: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{HighValueApproval, Policy{Level: A2, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: time.Hour}},
		{HighValueApproval, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: time.Hour}},
		{HighValueApproval, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: 24 * time.Hour}},
		{ChangeCredential, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: time.Hour}},
		{ChangeCredential, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: 24 * time.Hour}},
		{ChangeRecovery, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: time.Hour}},
		{ChangeRecovery, Policy{Level: A3, MaxAge: time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: 24 * time.Hour}},
		{CommitBuyer, Policy{Level: A2, MaxAge: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{HighValueApproval, Policy{Level: A3, MaxAge: time.Hour, RecoveryHold: 24 * time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{HighValueApproval, Policy{Level: A3, MaxAge: time.Minute, RecoveryHold: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{ChangeRecovery, Policy{Level: A3, MaxAge: time.Hour, RecoveryHold: 24 * time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{ChangeCredential, Policy{Level: A3, MaxAge: time.Minute, RecoveryHold: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}},
		{GrantPrivileged, Policy{Level: A4, MaxAge: time.Hour, RecoveryHold: 24 * time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true, RequirePrivilegedWitness: true}},
		{BreakGlass, Policy{Level: A4, MaxAge: time.Minute, RecoveryHold: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true, RequirePrivilegedWitness: true}},
	} {
		policy := DefaultDevelopmentPolicy()
		policy[tc.op] = tc.req
		if err := policy.Validate(); err == nil {
			t.Fatalf("operation %s accepted a weakened reviewed floor: %+v", tc.op, tc.req)
		}
	}
	policy := DefaultDevelopmentPolicy()
	policy[CommitBuyer] = Policy{Level: A3, MaxAge: 5 * time.Minute, RequireCurrentRisk: true, RequireRecoveryState: true, RecoveryHold: 24 * time.Hour}
	if err := policy.Validate(); err != nil {
		t.Fatalf("stronger risk-bound buyer commitment must remain valid: %v", err)
	}
}

func TestN06PolicyNeverWeakenedByUnreviewedAdmin(t *testing.T) {
	p := DefaultDevelopmentPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p[GrantPrivileged] = Policy{Level: A2, MaxAge: time.Hour, RequireCurrentRisk: true, RequireRecoveryState: true}
	if err := p.Validate(); err == nil {
		t.Fatal("privileged A2 downgrade accepted")
	}
	p = DefaultDevelopmentPolicy()
	p[ChangeRecovery] = Policy{Level: A1, MaxAge: time.Hour}
	if err := p.Validate(); err == nil {
		t.Fatal("recovery weak-auth bypass accepted")
	}
	if reason := PublicReason(NativeDecision{Outcome: Deny, Reason: "some sensitive token 123"}); strings.Contains(reason, "token 123") {
		t.Fatal("sensitive assurance error copied to public response")
	}
}
