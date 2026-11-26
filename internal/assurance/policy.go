// Package assurance evaluates current authentication evidence, not CP
// business permissions. Native provider readers and the provider-neutral
// evaluator share one operation, level and reviewed policy vocabulary.
package assurance

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"
)

// NativePolicy is the provider-native adapter view of the same server-owned
// policies used by the provider-neutral Evaluator. It is not browser supplied.
type NativePolicy map[Operation]Policy

func (p NativePolicy) Validate() error {
	return ValidatePolicies(map[Operation]Policy(p))
}

// Operation aliases preserve the N06 route vocabulary without defining a
// second set of operation classes or assurance floors.
func (l Level) Valid() bool { return rank(l) > 0 }

// CurrentSessionKey is passed from the trusted server's authenticated native
// session. No claim from a request body, query, cookie contents or frontend
// properties is accepted as an assurance statement.
type CurrentSessionKey struct {
	Issuer    string
	Subject   string
	SessionID string
}

// NativeEvidence is populated ONLY by a concrete trusted current-provider
// readback in a verified issuer session, with evidence of the actual method
// used. Enrollment or an IdP method label alone is not proof of A3.
type NativeEvidence struct {
	Issuer              string
	Subject             string
	SessionID           string
	ObservedAt          time.Time
	AuthenticatedAt     time.Time
	ExpiresAt           time.Time
	AAL                 Level
	Methods             []string
	PasskeyUsed         bool
	UserVerified        bool
	OriginBound         bool
	HardwareBound       bool
	RecoveryCompletedAt time.Time
}

type NativeReader interface {
	CurrentAuthentication(context.Context, CurrentSessionKey) (NativeEvidence, error)
}

type Risk struct {
	ObservedAt                time.Time
	Level                     string // low, medium, high, critical; unknown fails closed
	RecoveryStateChecked      bool
	RecoverySuspicious        bool
	PrivilegedContextVerified bool
}

type RiskReader interface {
	CurrentRisk(context.Context, CurrentSessionKey, Operation) (Risk, error)
}

// N06 outcomes are aliases of the shared assurance outcome vocabulary.
const (
	Allow  Outcome = MetNotAuthorization
	StepUp Outcome = StepUpRequired
	Deny   Outcome = Denied
)

type NativeDecision struct {
	Outcome  Outcome
	Required Level
	Observed Level
	Reason   string // low-cardinality reason only; never identity or secret material
}

// NativeEvaluator is a provider-native session adapter over the common
// operation/level/policy model. It re-reads the provider and risk source before
// returning a favorable result; it never makes a business authorization.
type NativeEvaluator struct {
	Policy         NativePolicy
	Authentication NativeReader
	Risk           RiskReader
	Now            func() time.Time
}

func (e *NativeEvaluator) Check(ctx context.Context, session CurrentSessionKey, op Operation) NativeDecision {
	no := NativeDecision{Outcome: Deny, Reason: "ASSURANCE_UNAVAILABLE"}
	if e == nil || ctx == nil || ctx.Err() != nil || e.Now == nil ||
		e.Authentication == nil || e.Policy.Validate() != nil ||
		session.Issuer == "" || session.Subject == "" || session.SessionID == "" {
		return no
	}
	req, ok := e.Policy[op]
	if !ok {
		no.Reason = "UNREVIEWED_OPERATION"
		return no
	}
	no.Required = req.Level
	now := e.Now().UTC()
	proof, err := e.Authentication.CurrentAuthentication(ctx, session)
	if err != nil || proof.Issuer != session.Issuer || proof.Subject != session.Subject ||
		proof.SessionID != session.SessionID || proof.ObservedAt.IsZero() ||
		proof.ObservedAt.After(now) || now.Sub(proof.ObservedAt) > 30*time.Second ||
		proof.AuthenticatedAt.IsZero() || proof.AuthenticatedAt.After(now) ||
		!proof.ExpiresAt.After(now) || now.Sub(proof.AuthenticatedAt) > req.MaxAge ||
		!proof.AAL.Valid() || len(proof.Methods) == 0 || len(proof.Methods) > 12 {
		no.Reason = "MISSING_FRESH_ISSUER_SESSION"
		return no
	}
	level := proof.AAL
	if proof.PasskeyUsed && proof.UserVerified && proof.OriginBound && hasWebAuthn(proof.Methods) && level >= A2 {
		level = A3
	}
	no.Observed = level
	if !proof.RecoveryCompletedAt.IsZero() {
		if proof.RecoveryCompletedAt.After(now) {
			no.Reason = "RECOVERY_EVIDENCE_INVALID"
			return no
		}
		if req.RecoveryHold > 0 && now.Sub(proof.RecoveryCompletedAt) < req.RecoveryHold {
			no.Reason = "POST_RECOVERY_HOLD"
			return no
		}
	}
	var firstRisk Risk
	if req.RequireCurrentRisk || req.RequireRecoveryState || req.Level == A4 {
		if e.Risk == nil {
			no.Reason = "RISK_PROOF_REQUIRED"
			return no
		}
		firstRisk, err = e.Risk.CurrentRisk(ctx, session, op)
		if err != nil || firstRisk.ObservedAt.IsZero() || firstRisk.ObservedAt.After(now) ||
			now.Sub(firstRisk.ObservedAt) > 30*time.Second ||
			!slices.Contains([]string{"low", "medium", "high", "critical"}, firstRisk.Level) ||
			(req.RequireRecoveryState && !firstRisk.RecoveryStateChecked) {
			no.Reason = "CURRENT_RISK_UNKNOWN"
			return no
		}
		if firstRisk.RecoverySuspicious || firstRisk.Level == "critical" {
			no.Reason = "SECURITY_CONTAINMENT_REQUIRED"
			return no
		}
		if firstRisk.Level == "high" && req.Level < A3 {
			no.Required = A3
		}
		if req.Level == A4 && !firstRisk.PrivilegedContextVerified {
			no.Reason = "PRIVILEGED_A4_WITNESS_REQUIRED"
			return no
		}
		if req.Level == A4 && !proof.HardwareBound {
			no.Outcome = StepUp
			no.Reason = "FRESH_HARDWARE_STEP_UP_REQUIRED"
			return no
		}
		if req.Level == A4 && level >= A3 && firstRisk.PrivilegedContextVerified && proof.HardwareBound {
			level = A4
			no.Observed = level
		}
	}
	if level < no.Required {
		no.Outcome = StepUp
		no.Reason = "FRESH_AUTHENTICATOR_REQUIRED"
		return no
	}

	// A favorable result is based on two identical, fresh provider and risk
	// observations. The reader must perform real reads, not replay a cached
	// proof from this invocation.
	second, err := e.Authentication.CurrentAuthentication(ctx, session)
	if err != nil || !reflect.DeepEqual(proof, second) {
		no.Reason = "CURRENT_SESSION_CHANGED"
		return no
	}
	if req.RequireCurrentRisk || req.RequireRecoveryState || req.Level == A4 {
		secondRisk, riskErr := e.Risk.CurrentRisk(ctx, session, op)
		if riskErr != nil || !reflect.DeepEqual(firstRisk, secondRisk) {
			no.Reason = "CURRENT_RISK_CHANGED"
			return no
		}
	}
	completed := e.Now().UTC()
	if ctx.Err() != nil || completed.Before(now) || !proof.ExpiresAt.After(completed) ||
		completed.Sub(proof.AuthenticatedAt) > req.MaxAge {
		no.Reason = "FRESH_AUTHENTICATOR_REQUIRED"
		return no
	}
	methods := slices.Clone(proof.Methods)
	seen := map[string]bool{}
	for _, method := range methods {
		if method == "" || len(method) > 64 || seen[method] {
			no.Reason = "INVALID_AUTHENTICATOR_METHODS"
			return no
		}
		seen[method] = true
	}
	no.Outcome = Allow
	no.Reason = "ASSURANCE_MET_NOT_AUTHORIZATION"
	no.Observed = level
	return no
}

func hasWebAuthn(methods []string) bool {
	for _, method := range methods {
		if method == "webauthn" || method == "passkey" {
			return true
		}
	}
	return false
}

// DefaultDevelopmentPolicy is the same conservative, reviewed policy map
// used by the provider-neutral evaluator. It is not production certification.
func DefaultDevelopmentPolicy() NativePolicy {
	return NativePolicy(ConservativePolicies())
}

// PublicReason never reflects provider response bodies, subject or risk data.
func PublicReason(d NativeDecision) string {
	if strings.HasPrefix(d.Reason, "ASSURANCE_") || d.Outcome == StepUp {
		return "STEP_UP_REQUIRED"
	}
	if d.Outcome == Allow {
		return "ASSURANCE_MET_NOT_AUTHORIZATION"
	}
	return "AUTHENTICATION_DENIED"
}
