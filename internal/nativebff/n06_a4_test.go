package nativebff

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

type n06A4Hardware struct {
	valid    bool
	observed time.Time
}

func (h n06A4Hardware) CurrentDeviceAttestation(_ context.Context, _ assurance.CurrentSessionKey, _ []byte) (CurrentHardwareAttestation, error) {
	return CurrentHardwareAttestation{
		ExactDeviceKey: h.valid, HardwareAttestationVerified: h.valid,
		PinnedTrustRootVerified: h.valid, NonExportablePrivateKeyVerified: h.valid,
		OriginalReference: "ref_origindeviceevidence", ObservedAt: h.observed,
	}, nil
}

type n06A4Approval struct {
	valid    bool
	observed time.Time
}

func (h n06A4Approval) CurrentPrivilegedApproval(_ context.Context, _ assurance.CurrentSessionKey,
	_ assurance.Operation, _, _ string) (A4PrivilegedApproval, error) {
	return A4PrivilegedApproval{
		ExactSession: h.valid, CurrentPrivilege: h.valid, IndependentReviewer: h.valid,
		SameOperation: h.valid, OriginalReference: "ref_origincpreviewer",
		ObservedAt: h.observed,
	}, nil
}

type n06A4Risk struct{ value assurance.Risk }

func (r n06A4Risk) CurrentRisk(context.Context, assurance.CurrentSessionKey, assurance.Operation) (assurance.Risk, error) {
	return r.value, nil
}

type n06A4AdvancingRisk struct {
	clock *time.Time
	delay time.Duration
}

func (r n06A4AdvancingRisk) CurrentRisk(context.Context, assurance.CurrentSessionKey, assurance.Operation) (assurance.Risk, error) {
	*r.clock = r.clock.Add(r.delay)
	return assurance.Risk{ObservedAt: *r.clock, Level: "low", RecoveryStateChecked: true, PrivilegedContextVerified: true}, nil
}

func n06A4Fixture(t *testing.T) (*A4Verifier, A4Request) {
	t.Helper()
	f := makeA3Fixture(t)
	when := f.v.Now()
	f.challenges.item.Operation = assurance.GrantPrivileged
	original := f.v.Kratos.(a3Current).evidence
	original.Operation = assurance.GrantPrivileged
	original.PasskeyUsed = true
	original.UserVerified = true
	original.OriginBound = true
	original.Methods = []string{"webauthn"}
	original.ObservedAt = when
	original.AuthenticatedAt = when.Add(-10 * time.Second)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic signer unavailable")
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal("ephemeral public signing key")
	}
	request := A4Request{
		Session: f.challenges.item.Session, Operation: assurance.GrantPrivileged,
		A3: original, ChallengeID: f.challenges.item.ID,
		DevicePublicKeyDER: public, RequesterReference: "ref_independentrequester",
		IndependentReviewerReference: "ref_differentreviewer",
	}
	digest := sha256.Sum256(a4Transcript(request.Session, request.Operation, f.challenges.item.Nonce,
		request.RequesterReference, request.IndependentReviewerReference))
	request.HardwareSignatureDER, err = ecdsa.SignASN1(rand.Reader, private, digest[:])
	if err != nil {
		t.Fatal("synthetic device assertion unavailable")
	}
	v := &A4Verifier{
		Challenges: f.challenges, Hardware: n06A4Hardware{valid: true, observed: when},
		Approvals: n06A4Approval{valid: true, observed: when},
		Risk:      n06A4Risk{assurance.Risk{ObservedAt: when, Level: "low", RecoveryStateChecked: true, PrivilegedContextVerified: true}},
		Policy:    assurance.DefaultDevelopmentPolicy(),
		Now:       func() time.Time { return when },
	}
	return v, request
}
func TestN06A4SignedHardwareAndDistinctReviewIsAuthenticationOnly(t *testing.T) {
	v, request := n06A4Fixture(t)
	evidence, err := v.Verify(context.Background(), request)
	if err != nil || !evidence.HardwareBound || !evidence.PasskeyUsed ||
		!evidence.UserVerified || !evidence.OriginBound || !evidence.AuthenticatedAt.Equal(request.A3.AuthenticatedAt) {
		t.Fatal("strict synthetic A4 signature/attestation/reviewer conformance rejected")
	}
	if _, err := v.Verify(context.Background(), request); err == nil {
		t.Fatal("signed hardware privilege transaction was replayed")
	}
}
func TestN06A4DeniesWithoutIndependentHardwareAndPrivilege(t *testing.T) {
	cases := map[string]func(*A4Verifier, *A4Request){
		"privileged-self-approval": func(_ *A4Verifier, r *A4Request) {
			r.IndependentReviewerReference = r.RequesterReference
		},
		"browser-fabricated-A3": func(_ *A4Verifier, r *A4Request) { r.A3.PasskeyUsed = false },
		"not-user-verified":     func(_ *A4Verifier, r *A4Request) { r.A3.UserVerified = false },
		"recent-known-recovery": func(v *A4Verifier, r *A4Request) { r.A3.RecoveryCompletedAt = v.Now().Add(-time.Hour) },
		"wrong-session":         func(_ *A4Verifier, r *A4Request) { r.Session.Subject = "other-subject" },
		"challenge-other-operation": func(v *A4Verifier, _ *A4Request) {
			v.Challenges.(*a3Challenges).item.Operation = assurance.BreakGlass
		},
		"wrong-operation":               func(_ *A4Verifier, r *A4Request) { r.Operation = assurance.OrdinaryBuyer },
		"other-privileged-operation":    func(_ *A4Verifier, r *A4Request) { r.Operation = assurance.BreakGlass },
		"substituted-distinct-reviewer": func(_ *A4Verifier, r *A4Request) { r.IndependentReviewerReference = "ref_anotherreviewer" },
		"substituted-requester":         func(_ *A4Verifier, r *A4Request) { r.RequesterReference = "ref_anotherrequester" },
		"tampered-signature":            func(_ *A4Verifier, r *A4Request) { r.HardwareSignatureDER[6] ^= 0x80 },
		"wrong-hardware": func(v *A4Verifier, _ *A4Request) {
			verified := v.Hardware.(n06A4Hardware)
			verified.valid = false
			v.Hardware = verified
		},
		"missing-independent-review": func(v *A4Verifier, _ *A4Request) {
			approved := v.Approvals.(n06A4Approval)
			approved.valid = false
			v.Approvals = approved
		},
		"critical-risk": func(v *A4Verifier, _ *A4Request) {
			risk := v.Risk.(n06A4Risk)
			risk.value.Level = "critical"
			v.Risk = risk
		},
		"post-recovery-risk": func(v *A4Verifier, _ *A4Request) {
			risk := v.Risk.(n06A4Risk)
			risk.value.RecoverySuspicious = true
			v.Risk = risk
		},
		"unwitnessed-context": func(v *A4Verifier, _ *A4Request) {
			risk := v.Risk.(n06A4Risk)
			risk.value.PrivilegedContextVerified = false
			v.Risk = risk
		},
		"stale-device-attestation": func(v *A4Verifier, _ *A4Request) {
			h := v.Hardware.(n06A4Hardware)
			h.observed = h.observed.Add(-10 * time.Minute)
			v.Hardware = h
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v, request := n06A4Fixture(t)
			mutate(v, &request)
			if _, err := v.Verify(context.Background(), request); err == nil {
				t.Fatal("A4 admitted missing or untrusted independent hardware/privileged proof")
			}
		})
	}
}

func TestN06A4ChecksExpiryAfterAuthorityReadback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		delay      time.Duration
		wantPermit bool
	}{
		{name: "fresh observation obtained during readback", delay: time.Second, wantPermit: true},
		{name: "challenge expired during readback", delay: 30 * time.Second},
		{name: "stale sources after readback", delay: time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, request := n06A4Fixture(t)
			clock := v.Now()
			v.Now = func() time.Time { return clock }
			v.Risk = n06A4AdvancingRisk{clock: &clock, delay: tc.delay}
			evidence, err := v.Verify(context.Background(), request)
			if (err == nil) != tc.wantPermit || tc.wantPermit && !evidence.ObservedAt.Equal(clock) {
				t.Fatalf("unexpected A4 evidence at authority completion: %v", err)
			}
		})
	}
}

func TestN06A4RechecksAuthenticationAgeAfterRiskRead(t *testing.T) {
	v, request := n06A4Fixture(t)
	clock := v.Now()
	request.A3.AuthenticatedAt = clock.Add(-v.Policy[request.Operation].MaxAge + time.Second)
	v.Now = func() time.Time { return clock }
	v.Risk = n06A4AdvancingRisk{clock: &clock, delay: 2 * time.Second}
	if _, err := v.Verify(context.Background(), request); err == nil {
		t.Fatal("A3 aged out during the independent risk check")
	}
}
