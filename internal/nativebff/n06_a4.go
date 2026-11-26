package nativebff

// IAM A4 is an independent hardware+privileged SECURITY event, not a Kratos
// AAL value, a browser ACR or a CP/domain business grant.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

var errA4Denied = errors.New("N06 independently verified hardware privileged step-up required")
var a4Ref = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

// A4Request must be constructed by a trusted IAM BFF after an actual A3
// check, never deserialized directly from a browser body.
type A4Request struct {
	Session                      assurance.CurrentSessionKey
	Operation                    assurance.Operation
	A3                           assurance.NativeEvidence
	ChallengeID                  string
	HardwareSignatureDER         []byte
	DevicePublicKeyDER           []byte
	RequesterReference           string
	IndependentReviewerReference string
}
type CurrentHardwareAttestation struct {
	ExactDeviceKey                  bool
	HardwareAttestationVerified     bool
	PinnedTrustRootVerified         bool
	NonExportablePrivateKeyVerified bool
	OriginalReference               string
	ObservedAt                      time.Time
}
type A4AttestationAuthority interface {
	// This must inspect real device attestation and current trust: boolean
	// values MUST NOT come from a browser or user-selected provider.
	CurrentDeviceAttestation(context.Context, assurance.CurrentSessionKey, []byte) (CurrentHardwareAttestation, error)
}
type A4PrivilegedApproval struct {
	ExactSession        bool
	CurrentPrivilege    bool
	IndependentReviewer bool
	SameOperation       bool
	OriginalReference   string
	ObservedAt          time.Time
}
type A4PrivilegedAuthority interface {
	CurrentPrivilegedApproval(context.Context, assurance.CurrentSessionKey, assurance.Operation, string, string) (A4PrivilegedApproval, error)
}
type A4Verifier struct {
	Challenges WebAuthnChallengeStore
	Hardware   A4AttestationAuthority
	Approvals  A4PrivilegedAuthority
	Risk       assurance.RiskReader
	Policy     assurance.NativePolicy
	Now        func() time.Time
}

func a4Transcript(session assurance.CurrentSessionKey, op assurance.Operation, nonce []byte,
	requester, reviewer string) []byte {
	// Explicit length prefixes avoid delimiter and identity ambiguity.
	result := []byte("baobab-iam-hardware-a4-v1")
	for _, part := range [][]byte{[]byte(session.Issuer), []byte(session.Subject),
		[]byte(session.SessionID), []byte(op), nonce,
		[]byte(requester), []byte(reviewer)} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		result = append(result, length[:]...)
		result = append(result, part...)
	}
	return result
}

// Verify produces an IAM authentication-assurance statement only after a
// genuine fresh, user-verified A3 session, one-use server challenge, signed
// hardware transaction, current pinned hardware attestation and a distinct
// independent privileged approval. CP still owns business permission.
func (v *A4Verifier) Verify(ctx context.Context, r A4Request) (assurance.NativeEvidence, error) {
	none := assurance.NativeEvidence{}
	if v == nil || ctx == nil || ctx.Err() != nil || v.Challenges == nil ||
		v.Hardware == nil || v.Approvals == nil || v.Risk == nil || v.Now == nil ||
		v.Policy.Validate() != nil ||
		(r.Operation != assurance.GrantPrivileged && r.Operation != assurance.BreakGlass) ||
		r.Session.Issuer == "" || r.Session.Subject == "" || r.Session.SessionID == "" ||
		!a4Ref.MatchString(r.RequesterReference) ||
		!a4Ref.MatchString(r.IndependentReviewerReference) ||
		r.RequesterReference == r.IndependentReviewerReference ||
		len(r.ChallengeID) < 12 || len(r.ChallengeID) > 160 ||
		len(r.DevicePublicKeyDER) > 2048 || len(r.DevicePublicKeyDER) < 80 ||
		len(r.HardwareSignatureDER) < 60 || len(r.HardwareSignatureDER) > 144 {
		return none, errA4Denied
	}
	requirement, ok := v.Policy[r.Operation]
	if !ok || requirement.Level != assurance.A4 ||
		!requirement.RequireCurrentRisk || !requirement.RequirePrivilegedWitness {
		return none, errA4Denied
	}
	now := v.Now().UTC()
	proof := r.A3
	if proof.Issuer != r.Session.Issuer || proof.Subject != r.Session.Subject ||
		proof.SessionID != r.Session.SessionID || proof.Operation != r.Operation || proof.AAL != assurance.A2 ||
		!proof.PasskeyUsed || !proof.UserVerified || !proof.OriginBound ||
		proof.HardwareBound || proof.ObservedAt.IsZero() ||
		proof.AuthenticatedAt.IsZero() || !proof.ExpiresAt.After(now) || proof.ObservedAt.After(now) ||
		now.Sub(proof.ObservedAt) > 30*time.Second ||
		proof.AuthenticatedAt.After(now) ||
		now.Sub(proof.AuthenticatedAt) > 5*time.Minute ||
		!hasWebAuthn(proof.Methods) {
		return none, errA4Denied
	}
	if !proof.RecoveryCompletedAt.IsZero() &&
		(proof.RecoveryCompletedAt.After(now) || now.Sub(proof.RecoveryCompletedAt) < requirement.RecoveryHold) {
		return none, errA4Denied
	}
	challenge, err := v.Challenges.Consume(ctx, r.ChallengeID)
	if err != nil || challenge.ID != r.ChallengeID ||
		challenge.Session != r.Session || challenge.Operation != r.Operation || len(challenge.Nonce) != 32 ||
		challenge.CreatedAt.IsZero() || challenge.ExpiresAt.IsZero() ||
		challenge.CreatedAt.After(now) || !challenge.ExpiresAt.After(now) ||
		now.Sub(challenge.CreatedAt) > time.Minute ||
		!validRelyingParty(challenge) {
		return none, errA4Denied
	}
	key, err := x509.ParsePKIXPublicKey(r.DevicePublicKeyDER)
	public, valid := key.(*ecdsa.PublicKey)
	if err != nil || !valid || public.Curve != elliptic.P256() {
		return none, errA4Denied
	}
	digest := sha256.Sum256(a4Transcript(r.Session, r.Operation, challenge.Nonce,
		r.RequesterReference, r.IndependentReviewerReference))
	if !ecdsa.VerifyASN1(public, digest[:], r.HardwareSignatureDER) {
		return none, errA4Denied
	}
	hardware, err := v.Hardware.CurrentDeviceAttestation(ctx, r.Session, r.DevicePublicKeyDER)
	hardwareAt := v.Now().UTC()
	if err != nil || !hardware.ExactDeviceKey || !hardware.HardwareAttestationVerified ||
		!hardware.PinnedTrustRootVerified || !hardware.NonExportablePrivateKeyVerified ||
		!a4Ref.MatchString(hardware.OriginalReference) ||
		hardwareAt.Before(now) || !a4Fresh(hardware.ObservedAt, hardwareAt, time.Minute) {
		return none, errA4Denied
	}
	approval, err := v.Approvals.CurrentPrivilegedApproval(ctx, r.Session, r.Operation,
		r.RequesterReference, r.IndependentReviewerReference)
	approvalAt := v.Now().UTC()
	if err != nil || !approval.ExactSession || !approval.CurrentPrivilege ||
		!approval.IndependentReviewer || !approval.SameOperation ||
		!a4Ref.MatchString(approval.OriginalReference) ||
		approvalAt.Before(hardwareAt) || !a4Fresh(approval.ObservedAt, approvalAt, time.Minute) {
		return none, errA4Denied
	}
	risk, err := v.Risk.CurrentRisk(ctx, r.Session, r.Operation)
	completed := v.Now().UTC()
	if err != nil || ctx.Err() != nil || completed.Before(approvalAt) ||
		!a4Fresh(risk.ObservedAt, completed, 30*time.Second) || !risk.RecoveryStateChecked ||
		!risk.PrivilegedContextVerified || risk.RecoverySuspicious ||
		(risk.Level != "low" && risk.Level != "medium") ||
		!a4Fresh(hardware.ObservedAt, completed, time.Minute) ||
		!a4Fresh(approval.ObservedAt, completed, time.Minute) ||
		!a4Fresh(proof.ObservedAt, completed, 30*time.Second) ||
		!proof.ExpiresAt.After(completed) || !challenge.ExpiresAt.After(completed) ||
		completed.Sub(challenge.CreatedAt) > time.Minute {
		return none, errA4Denied
	}
	proof.HardwareBound = true
	proof.Operation = r.Operation
	proof.AuthenticatedAt = completed
	proof.ObservedAt = completed
	return proof, nil
}

func a4Fresh(observed, checked time.Time, maximumAge time.Duration) bool {
	return !observed.IsZero() && !observed.After(checked) && checked.Sub(observed) <= maximumAge
}
