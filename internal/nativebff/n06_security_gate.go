package nativebff

import (
	"context"
	"errors"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// N06ProviderProof is an IAM-owned, independently verified Kratos session
// readback. The browser supplies ONLY the opaque Kratos cookie; it cannot
// submit assurance, a policy, ACR/AMR, risk score or an approval.
type N06ProviderProof interface {
	CurrentNativeAuthentication(context.Context, ory.NativeSessionCredential) (
		assurance.CurrentSessionKey, assurance.NativeEvidence, error)
}

type N06Gate interface {
	EvaluateNative(context.Context, ory.NativeSessionCredential, assurance.Operation) (assurance.NativeDecision, error)
}

// N06SecurityGate evaluates one verified current provider session and
// independently supplied risk at the instant of the operation. Each call
// creates a one-use proof reader; no provider proof is cached or shared
// across users, challenges or business operations.
type N06SecurityGate struct {
	Provider N06ProviderProof
	Policy   assurance.NativePolicy
	Risk     assurance.RiskReader
	Now      func() time.Time
}

type nativeProof struct {
	provider N06ProviderProof
	credential ory.NativeSessionCredential
	key assurance.CurrentSessionKey
}

func (n nativeProof) CurrentAuthentication(ctx context.Context, k assurance.CurrentSessionKey) (assurance.NativeEvidence, error) {
	if n.provider == nil || k != n.key {
		return assurance.NativeEvidence{}, errors.New("N06 session binding mismatch")
	}
	currentKey, proof, err := n.provider.CurrentNativeAuthentication(ctx, n.credential)
	if err != nil || currentKey != n.key {
		return assurance.NativeEvidence{}, errors.New("N06 current provider session changed")
	}
	return proof, nil
}

func (g *N06SecurityGate) EvaluateNative(ctx context.Context, cred ory.NativeSessionCredential, op assurance.Operation) (assurance.NativeDecision, error) {
	if g == nil || ctx == nil || ctx.Err() != nil || g.Provider == nil || g.Now == nil || g.Policy.Validate() != nil || g.Risk == nil {
		return assurance.NativeDecision{Outcome: assurance.Deny, Reason: "SECURITY_GATE_UNAVAILABLE"}, errors.New("N06 trusted assurance gate not configured")
	}
	if cred.Cookie == "" && cred.SessionToken == "" {
		return assurance.NativeDecision{Outcome: assurance.Deny, Reason: "KRATOS_SESSION_REQUIRED"}, errors.New("N06 current provider session missing")
	}
	key, _, err := g.Provider.CurrentNativeAuthentication(ctx, cred)
	if err != nil {
		return assurance.NativeDecision{Outcome: assurance.Deny, Reason: "PROVIDER_PROOF_UNAVAILABLE"}, errors.New("N06 current provider proof unavailable")
	}
	reader := nativeProof{provider: g.Provider, credential: cred, key: key}
	eval := assurance.NativeEvaluator{Policy: g.Policy, Authentication: reader, Risk: g.Risk, Now: g.Now}
	decision := eval.Check(ctx, key, op)
	return decision, nil
}
