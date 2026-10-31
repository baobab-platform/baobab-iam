// Package assurance evaluates current authentication *evidence*, not CP
// business permissions. IAM-N06 follows ADR-IAM-0024/0025/0029/0033.
//
// No browser assertions, configured passkey enrollment, or historical ACR
// alone can satisfy an operation's fresh A3/A4 requirement.
package assurance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Level uint8

const (
	A0 Level = iota
	A1
	A2
	A3
	A4
)
func (l Level) Valid() bool { return l >= A1 && l <= A4 }

type Operation string

const (
	OrdinaryBuyer Operation = "buyer.read"
	CommitBuyer Operation = "buyer.commit"
	HighValueApproval Operation = "buyer.approve"
	ChangeCredential Operation = "identity.credential.change"
	ChangeRecovery Operation = "identity.recovery.rebind"
	GrantPrivileged Operation = "iam.privileged.grant"
	BreakGlass Operation = "iam.breakglass.activate"
)

// Requirement is a reviewed server-side policy, never supplied by a browser.
// MaxAge is the maximum age of the actual provider authentication event,
// not the age of the application session or a cookie.
type Requirement struct {
	Min Level
	MaxAge time.Duration
	RecoveryHold time.Duration
	RequireCurrentRisk bool
	RequirePrivilegedWitness bool
}

type Policy map[Operation]Requirement

func (p Policy) Validate() error {
	if len(p) == 0 { return errors.New("assurance: reviewed operation policy required") }
	for operation, req := range p {
		if operation == "" || !req.Min.Valid() || req.MaxAge <= 0 ||
			req.MaxAge > 24*time.Hour || req.RecoveryHold < 0 ||
			req.RecoveryHold > 30*24*time.Hour {
			return errors.New("assurance: invalid reviewed requirement")
		}
		if (operation == GrantPrivileged || operation == BreakGlass) &&
			(req.Min != A4 || !req.RequirePrivilegedWitness || !req.RequireCurrentRisk) {
			return errors.New("assurance: privileged operation requires A4 and independent risk/context")
		}
		if (operation == ChangeCredential || operation == ChangeRecovery) &&
			req.Min < A3 {
			return errors.New("assurance: credential/rebinding operation requires phishing-resistant step-up")
		}
	}
	return nil
}

// CurrentSessionKey is passed from the trusted server's authenticated native
// session. No claim from a request body, query, cookie contents or frontend
// properties is accepted as an assurance statement.
type CurrentSessionKey struct {
	Issuer string
	Subject string
	SessionID string
}

// Evidence is populated ONLY by a concrete trusted current-provider readback
// in a verified issuer session, with evidence of the actual method USED.
// A strong authenticator merely being enrolled is never proof of use.
type Evidence struct {
	Issuer string
	Subject string
	SessionID string
	ObservedAt time.Time
	AuthenticatedAt time.Time
	AAL string // "aal1", "aal2"; provider-neutral normalization is below.
	Methods []string
	PasskeyUsed bool
	UserVerified bool
	OriginBound bool
	HardwareBound bool
	RecoveryCompletedAt time.Time
}

type Reader interface {
	CurrentAuthentication(context.Context, CurrentSessionKey) (Evidence, error)
}

type Risk struct {
	ObservedAt time.Time
	Level string // "low", "medium", "high", "critical"; unknown fails closed
	RecoverySuspicious bool
	PrivilegedContextVerified bool
}

type RiskReader interface {
	CurrentRisk(context.Context, CurrentSessionKey, Operation) (Risk, error)
}

type Outcome string

const (
	Allow Outcome = "ALLOW_AUTHENTICATION_ASSURANCE_ONLY"
	StepUp Outcome = "STEP_UP_REQUIRED"
	Deny Outcome = "DENIED"
)

type Decision struct {
	Outcome Outcome
	Required Level
	Observed Level
	Reason string // low-cardinality reason only, never identity/secret material
}

// Evaluator NEVER makes a business authorization decision. The caller must
// still query CP and the domain PEP and revalidate before commit.
type Evaluator struct {
	Policy Policy
	Authentication Reader
	Risk RiskReader
	Now func() time.Time
}

func (e *Evaluator) Check(ctx context.Context, session CurrentSessionKey, op Operation) Decision {
	no := Decision{Outcome:Deny,Reason:"ASSURANCE_UNAVAILABLE"}
	if e == nil || ctx == nil || ctx.Err() != nil || e.Now == nil ||
		e.Authentication == nil || e.Policy.Validate() != nil ||
		session.Issuer == "" || session.Subject == "" || session.SessionID == "" {
		return no
	}
	req, ok := e.Policy[op]
	if !ok { no.Reason="UNREVIEWED_OPERATION"; return no }
	no.Required=req.Min
	now:=e.Now().UTC()
	proof, err:=e.Authentication.CurrentAuthentication(ctx,session)
	if err != nil || proof.Issuer!=session.Issuer || proof.Subject!=session.Subject ||
		proof.SessionID!=session.SessionID || proof.ObservedAt.IsZero() ||
		proof.ObservedAt.After(now) || now.Sub(proof.ObservedAt)>30*time.Second ||
		proof.AuthenticatedAt.IsZero() || proof.AuthenticatedAt.After(now) ||
		now.Sub(proof.AuthenticatedAt)>req.MaxAge {
		no.Reason="MISSING_FRESH_ISSUER_SESSION"
		return no
	}
	level:=A0
	switch proof.AAL {
	case "aal1": level=A1
	case "aal2": level=A2
	default: no.Reason="UNKNOWN_PROVIDER_ASSURANCE";return no
	}
	// A3 cannot come from TOTP or an enrollment record. The Kratos/Keycloak
	// reader must independently prove THIS authentication used WebAuthn,
	// that the RP origin was bound, and user verification was performed.
	if proof.PasskeyUsed && proof.UserVerified && proof.OriginBound &&
		(slices.Contains(proof.Methods,"webauthn") || slices.Contains(proof.Methods,"passkey")) {
		if level>=A2 { level=A3 }
	}
	no.Observed=level
	if !proof.RecoveryCompletedAt.IsZero() {
		if proof.RecoveryCompletedAt.After(now) || proof.RecoveryCompletedAt.Before(proof.AuthenticatedAt.Add(-req.MaxAge)) {
			no.Reason="RECOVERY_EVIDENCE_INVALID";return no
		}
		if req.RecoveryHold>0 && now.Sub(proof.RecoveryCompletedAt)<req.RecoveryHold {
			no.Reason="POST_RECOVERY_HOLD";return no
		}
	}
	if req.RequireCurrentRisk || req.Min==A4 {
		if e.Risk==nil { no.Reason="RISK_PROOF_REQUIRED";return no }
		risk, err:=e.Risk.CurrentRisk(ctx,session,op)
		if err!=nil || risk.ObservedAt.IsZero() || risk.ObservedAt.After(now) ||
			now.Sub(risk.ObservedAt)>30*time.Second || !slices.Contains([]string{"low","medium","high","critical"},risk.Level) {
			no.Reason="CURRENT_RISK_UNKNOWN";return no
		}
		if risk.RecoverySuspicious || risk.Level=="critical" {
			no.Reason="SECURITY_CONTAINMENT_REQUIRED";return no
		}
		if risk.Level=="high" && req.Min<A3 { no.Required=A3 }
		if req.Min==A4 && (!risk.PrivilegedContextVerified || !proof.HardwareBound) {
			no.Reason="PRIVILEGED_A4_WITNESS_REQUIRED";return no
		}
		if req.Min==A4 && level>=A3 && risk.PrivilegedContextVerified && proof.HardwareBound {
			level=A4
			no.Observed=level
		}
	}
	if level<no.Required {
		no.Outcome=StepUp
		no.Reason="FRESH_AUTHENTICATOR_REQUIRED"
		return no
	}
	no.Outcome=Allow
	no.Reason="ASSURANCE_MET_NOT_AUTHORIZATION"
	return no
}

// DefaultDevelopmentPolicy is a conservative template, not certification.
// A4 remains impossible without a real risk/privilege witness and native
// phishing-resistant+hardware-bound authentication evidence.
func DefaultDevelopmentPolicy() Policy {
	return Policy{
		OrdinaryBuyer: {Min:A1, MaxAge:12*time.Hour},
		CommitBuyer: {Min:A2, MaxAge:30*time.Minute, RequireCurrentRisk:true},
		HighValueApproval: {Min:A3, MaxAge:5*time.Minute, RecoveryHold:24*time.Hour, RequireCurrentRisk:true},
		ChangeCredential: {Min:A3,MaxAge:5*time.Minute,RecoveryHold:24*time.Hour,RequireCurrentRisk:true},
		ChangeRecovery: {Min:A3,MaxAge:5*time.Minute,RecoveryHold:24*time.Hour,RequireCurrentRisk:true},
		GrantPrivileged: {Min:A4,MaxAge:5*time.Minute,RecoveryHold:24*time.Hour,RequireCurrentRisk:true,RequirePrivilegedWitness:true},
		BreakGlass: {Min:A4,MaxAge:5*time.Minute,RecoveryHold:24*time.Hour,RequireCurrentRisk:true,RequirePrivilegedWitness:true},
	}
}

// PublicReason never reflects provider response bodies, subject or risk data.
func PublicReason(d Decision) string {
	if strings.HasPrefix(d.Reason,"ASSURANCE_") || d.Outcome==StepUp { return "STEP_UP_REQUIRED" }
	if d.Outcome==Allow { return "ASSURANCE_MET_NOT_AUTHORIZATION" }
	return fmt.Sprintf("%s", "AUTHENTICATION_DENIED")
}
