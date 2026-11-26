package assurance

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fixedNativeReader struct {
	proofs []NativeEvidence
	calls  int
	err    error
}

func (r *fixedNativeReader) CurrentAuthentication(_ context.Context, _ CurrentSessionKey) (NativeEvidence, error) {
	r.calls++
	if r.err != nil {
		return NativeEvidence{}, r.err
	}
	i := r.calls - 1
	if i >= len(r.proofs) {
		i = len(r.proofs) - 1
	}
	return r.proofs[i], nil
}

type fixedNativeRisk struct {
	risks []Risk
	calls int
	err   error
}

func (r *fixedNativeRisk) CurrentRisk(_ context.Context, _ CurrentSessionKey, _ Operation) (Risk, error) {
	r.calls++
	if r.err != nil {
		return Risk{}, r.err
	}
	i := r.calls - 1
	if i >= len(r.risks) {
		i = len(r.risks) - 1
	}
	return r.risks[i], nil
}

func nativeFixture(now time.Time) (*NativeEvaluator, CurrentSessionKey, NativeEvidence, Risk) {
	key := CurrentSessionKey{Issuer: "https://identity.example", Subject: "identity-123", SessionID: "session-123"}
	proof := NativeEvidence{
		Issuer: key.Issuer, Subject: key.Subject, SessionID: key.SessionID,
		ObservedAt: now.Add(-time.Second), AuthenticatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), AAL: A2, Methods: []string{"password", "totp"},
	}
	risk := Risk{ObservedAt: now.Add(-time.Second), Level: "low", RecoveryStateChecked: true}
	reader := &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	riskReader := &fixedNativeRisk{risks: []Risk{risk, risk}}
	e := &NativeEvaluator{
		Policy: DefaultDevelopmentPolicy(), Authentication: reader, Risk: riskReader,
		Now: func() time.Time { return now },
	}
	return e, key, proof, risk
}

func TestNativePolicyUsesSharedReviewedVocabulary(t *testing.T) {
	p := DefaultDevelopmentPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if OrdinaryBuyer != Login || CommitBuyer != BuyerCommit ||
		ChangeCredential != CredentialChange || ChangeRecovery != RecoveryRebind ||
		GrantPrivileged != PrivilegedGrant {
		t.Fatal("native route aliases diverged from the common operation vocabulary")
	}
	if p[HighValueApproval].Level != A3 || p[HighValueApproval].RecoveryHold < 24*time.Hour ||
		p[PrivilegedGrant].Level != A4 || !p[PrivilegedGrant].RequirePrivilegedWitness {
		t.Fatal("shared high-assurance policy floors were weakened")
	}
}

func TestNativeEvaluatorReReadsProviderAndRiskBeforeAllow(t *testing.T) {
	now := time.Now().UTC()
	e, key, _, _ := nativeFixture(now)
	decision := e.Check(context.Background(), key, CommitBuyer)
	if decision.Outcome != Allow || decision.Observed != A2 {
		t.Fatalf("expected A2 allow, got %#v", decision)
	}
	reader := e.Authentication.(*fixedNativeReader)
	risk := e.Risk.(*fixedNativeRisk)
	if reader.calls != 2 || risk.calls != 2 {
		t.Fatalf("favorable result did not re-read provider and risk: provider=%d risk=%d", reader.calls, risk.calls)
	}
}

func TestNativeEvaluatorAcceptsAuthenticationCompletedDuringProviderRead(t *testing.T) {
	started := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	e, key, proof, _ := nativeFixture(started)
	proof.AuthenticatedAt = started.Add(500 * time.Millisecond)
	proof.ObservedAt = started.Add(800 * time.Millisecond)
	second := proof
	second.ObservedAt = started.Add(1500 * time.Millisecond)
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, second}}
	var calls int
	e.Now = func() time.Time {
		calls++
		switch calls {
		case 1:
			return started
		case 2:
			return started.Add(time.Second)
		case 3:
			return started.Add(2 * time.Second)
		default:
			return started.Add(3 * time.Second)
		}
	}
	decision := e.Check(context.Background(), key, OrdinaryBuyer)
	if decision.Outcome != Allow {
		t.Fatalf("a session authenticated during the provider read was rejected: %#v", decision)
	}
}

func TestNativeEvaluatorAcceptsFreshReadTimesAndRejectsChangedEvidence(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		edit func(*NativeEvidence, *Risk)
		want Outcome
	}{
		{"independent observations", func(*NativeEvidence, *Risk) {}, Allow},
		{"changed session", func(p *NativeEvidence, _ *Risk) { p.SessionID = "another-session" }, Deny},
		{"provider level cannot establish A4", func(p *NativeEvidence, _ *Risk) { p.AAL = A4 }, Deny},
		{"older readback", func(p *NativeEvidence, _ *Risk) { p.ObservedAt = now.Add(-2 * time.Second) }, Deny},
		{"future provider observation", func(p *NativeEvidence, _ *Risk) { p.ObservedAt = now.Add(time.Second) }, Deny},
		{"changed risk", func(_ *NativeEvidence, r *Risk) { r.Level = "critical" }, Deny},
		{"future risk observation", func(_ *NativeEvidence, r *Risk) { r.ObservedAt = now.Add(time.Second) }, Deny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, key, first, risk := nativeFixture(now)
			second, nextRisk := first, risk
			first.ObservedAt, second.ObservedAt = now.Add(time.Millisecond), now.Add(3*time.Millisecond)
			risk.ObservedAt, nextRisk.ObservedAt = now.Add(2*time.Millisecond), now.Add(4*time.Millisecond)
			tc.edit(&second, &nextRisk)
			e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{first, second}}
			e.Risk = &fixedNativeRisk{risks: []Risk{risk, nextRisk}}
			var tick time.Duration
			e.Now = func() time.Time { instant := now.Add(tick); tick += time.Millisecond; return instant }
			if got := e.Check(context.Background(), key, BuyerCommit); got.Outcome != tc.want {
				t.Fatalf("outcome: %+v, want %s", got, tc.want)
			}
		})
	}
}

func TestNativeEvaluatorRequiresRPBoundUserVerifiedPasskeyForA3(t *testing.T) {
	now := time.Now().UTC()
	e, key, proof, _ := nativeFixture(now)
	decision := e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != StepUp || decision.Required != A3 {
		t.Fatalf("A2/TOTP must not satisfy A3: %#v", decision)
	}

	proof.Operation = HighValueApproval
	proof.PasskeyUsed = true
	proof.UserVerified = true
	proof.OriginBound = true
	proof.Methods = []string{"webauthn"}
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	decision = e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != Allow || decision.Observed != A3 {
		t.Fatalf("RP-bound user-verified passkey should satisfy A3 without mandatory attestation: %#v", decision)
	}

	proof.UserVerified = false
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	decision = e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != StepUp {
		t.Fatalf("passkey without user verification must not satisfy A3: %#v", decision)
	}
}

func TestNativeEvaluatorRejectsOperationBoundPasskeyEvidenceForAnotherOperation(t *testing.T) {
	now := time.Now().UTC()
	e, key, proof, _ := nativeFixture(now)
	proof.Operation = HighValueApproval
	proof.PasskeyUsed, proof.UserVerified, proof.OriginBound = true, true, true
	proof.Methods = []string{"webauthn"}
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	decision := e.Check(context.Background(), key, CommitBuyer)
	if decision.Outcome != Deny || decision.Reason != "ASSURANCE_OPERATION_MISMATCH" {
		t.Fatalf("operation-bound A3 proof was reused for another operation: %#v", decision)
	}
}

func TestNativeEvaluatorHighRiskRaisesFloorAndCriticalRiskDenies(t *testing.T) {
	now := time.Now().UTC()
	e, key, proof, risk := nativeFixture(now)
	risk.Level = "high"
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision := e.Check(context.Background(), key, CommitBuyer)
	if decision.Outcome != StepUp || decision.Required != A3 {
		t.Fatalf("high risk should raise A2 to A3: %#v", decision)
	}
	proof.Operation = CommitBuyer
	proof.PasskeyUsed, proof.UserVerified, proof.OriginBound = true, true, true
	proof.Methods = []string{"webauthn"}
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision = e.Check(context.Background(), key, CommitBuyer)
	if decision.Outcome != Allow || decision.Observed != A3 {
		t.Fatalf("fresh A3 evidence should satisfy high-risk step-up: %#v", decision)
	}
	risk.Level = "critical"
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision = e.Check(context.Background(), key, CommitBuyer)
	if decision.Outcome != Deny {
		t.Fatalf("critical risk must deny: %#v", decision)
	}
}

func TestNativeEvaluatorA4RequiresHardwareAndIndependentWitness(t *testing.T) {
	now := time.Now().UTC()
	e, key, proof, risk := nativeFixture(now)
	proof.PasskeyUsed, proof.UserVerified, proof.OriginBound = true, true, true
	proof.HardwareBound = true
	proof.Methods = []string{"webauthn", "hardware-key"}
	risk.PrivilegedContextVerified = true
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision := e.Check(context.Background(), key, GrantPrivileged)
	if decision.Outcome != Allow || decision.Observed != A4 {
		t.Fatalf("hardware-bound A3 plus independent witness should satisfy A4: %#v", decision)
	}
	proof.HardwareBound = false
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	decision = e.Check(context.Background(), key, GrantPrivileged)
	if decision.Outcome != StepUp {
		t.Fatalf("A4 without hardware binding must step up: %#v", decision)
	}
	proof.HardwareBound = true
	risk.PrivilegedContextVerified = false
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision = e.Check(context.Background(), key, GrantPrivileged)
	if decision.Outcome != Deny {
		t.Fatalf("A4 without independent witness must deny: %#v", decision)
	}
}

func TestNativeEvaluatorRecoveryHoldAndMissingCurrentStateFailClosed(t *testing.T) {
	now := time.Now().UTC()
	e, key, proof, risk := nativeFixture(now)
	proof.RecoveryCompletedAt = now.Add(-time.Hour)
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	decision := e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != Deny || decision.Reason != "POST_RECOVERY_HOLD" {
		t.Fatalf("recent recovery must hold A3: %#v", decision)
	}
	proof.RecoveryCompletedAt = time.Time{}
	risk.RecoveryStateChecked = false
	e.Authentication = &fixedNativeReader{proofs: []NativeEvidence{proof, proof}}
	e.Risk = &fixedNativeRisk{risks: []Risk{risk, risk}}
	decision = e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != Deny || decision.Reason != "CURRENT_RISK_UNKNOWN" {
		t.Fatalf("missing recovery state must fail closed: %#v", decision)
	}
	e.Risk = &fixedNativeRisk{err: errors.New("unavailable")}
	decision = e.Check(context.Background(), key, HighValueApproval)
	if decision.Outcome != Deny {
		t.Fatalf("risk reader failure must deny: %#v", decision)
	}
}

func TestNativePolicyCannotWeakenSharedFloors(t *testing.T) {
	cases := []struct {
		name string
		edit func(NativePolicy)
	}{
		{"buyer floor", func(p NativePolicy) { x := p[BuyerCommit]; x.Level = A1; p[BuyerCommit] = x }},
		{"current risk", func(p NativePolicy) { x := p[BuyerCommit]; x.RequireCurrentRisk = false; p[BuyerCommit] = x }},
		{"recovery state", func(p NativePolicy) { x := p[BuyerCommit]; x.RequireRecoveryState = false; p[BuyerCommit] = x }},
		{"recovery hold", func(p NativePolicy) { x := p[HighValueApproval]; x.RecoveryHold = time.Hour; p[HighValueApproval] = x }},
		{"privileged witness", func(p NativePolicy) {
			x := p[PrivilegedGrant]
			x.RequirePrivilegedWitness = false
			p[PrivilegedGrant] = x
		}},
		{"missing operation", func(p NativePolicy) { delete(p, BreakGlass) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultDevelopmentPolicy()
			tc.edit(p)
			if err := p.Validate(); err == nil {
				t.Fatal("weakened or incomplete policy accepted")
			}
		})
	}
}

func TestPublicReasonDoesNotExposeProviderDetails(t *testing.T) {
	d := NativeDecision{Outcome: Deny, Reason: "opaque provider identity/session detail"}
	if got := PublicReason(d); got != "AUTHENTICATION_DENIED" {
		t.Fatalf("unexpected public reason %q", got)
	}
	if got := PublicReason(NativeDecision{Outcome: StepUp, Reason: "fresh authenticator required"}); got != "STEP_UP_REQUIRED" {
		t.Fatalf("unexpected step-up reason %q", got)
	}
	if got := PublicReason(NativeDecision{Outcome: Allow, Reason: "ASSURANCE_MET_NOT_AUTHORIZATION"}); got != "ASSURANCE_MET_NOT_AUTHORIZATION" {
		t.Fatalf("unexpected allow reason %q", got)
	}
}
