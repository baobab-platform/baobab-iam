// Package assurance evaluates current, provider-authenticated human evidence against
// a server-owned operation policy. An assurance result is never a CP grant,
// tenant membership, domain authorization, or privileged role.
package assurance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"time"
)

type Operation string
const (
	Login Operation = "LOGIN"
	BuyerCommit Operation = "BUYER_COMMIT"
	HighValueApproval Operation = "HIGH_VALUE_APPROVAL"
	CredentialChange Operation = "CREDENTIAL_CHANGE"
	RecoveryRebind Operation = "RECOVERY_REBIND"
	PrivilegedGrant Operation = "PRIVILEGED_GRANT"
	BreakGlass Operation = "BREAK_GLASS"
)
type Level string
const (A1 Level = "A1"; A2 Level = "A2"; A3 Level = "A3"; A4 Level = "A4")
type Outcome string
const (Denied Outcome = "DENIED"; StepUpRequired Outcome = "STEP_UP_REQUIRED"; MetNotAuthorization Outcome = "ASSURANCE_MET_NOT_AUTHORIZATION")
type Reason string
const (
	CurrentSessionMissing Reason = "CURRENT_SESSION_MISSING"
	AssuranceUnavailable Reason = "ASSURANCE_UNAVAILABLE"
	CurrentRiskUnknown Reason = "CURRENT_RISK_UNKNOWN"
	RecoveryHold Reason = "RECOVERY_HOLD"
	FreshStepUpRequired Reason = "FRESH_STEP_UP_REQUIRED"
	PrivilegedWitnessMissing Reason = "PRIVILEGED_WITNESS_MISSING"
	AssuranceMet Reason = "ASSURANCE_MET_NOT_AUTHORIZATION"
)
const (RequestSchema = "baobab.identity.assurance-evaluation-request.v1"; ResultSchema = "baobab.identity.assurance-evaluation-result.v1")

type Request struct {
	Schema string `json:"schema"`
	AuthenticationEventReference string `json:"authentication_event_reference"`
	SessionReference string `json:"session_reference"`
	OperationClass Operation `json:"operation_class"`
}
type Result struct {
	Schema string `json:"schema"`
	Outcome Outcome `json:"outcome"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	RequiredLevel Level `json:"required_level"`
	ObservedLevel Level `json:"observed_level,omitempty"`
	AuthenticationMethods []string `json:"authentication_methods,omitempty"`
	AuthenticatedAt *time.Time `json:"authenticated_at,omitempty"`
	FreshUntil *time.Time `json:"fresh_until,omitempty"`
	EvidenceReference string `json:"evidence_reference,omitempty"`
	Reason Reason `json:"reason"`
}

// Evidence is returned only by a live, server-owned native provider reader.
// Its attestation and witness fields MUST be independently verified by that
// reader; never project unauthenticated browser, session-method or IdP labels
// into these fields. No native Kratos method alone qualifies as attested A3.
type Evidence struct {
	EventReference string
	SessionReference string
	EvidenceReference string
	Active bool
	IdentityActive bool
	ACR string
	Methods []string
	AuthenticatedAt time.Time
	ExpiresAt time.Time
	RiskChecked bool
	RecoveryStateChecked bool
	RecoveryHeld bool
	PasskeyProofEventReference string
	PasskeyRPBound bool
	PasskeyUserVerified bool
	PasskeyAttested bool
	HardwareBound bool
	PrivilegedWitnessVerified bool
	PrivilegedWitnessEventReference string
}
type Reader interface {
	// Read MUST fetch CURRENT session state, not reuse an unverified token or
	// cached assurance. It must bind both opaque references to one event.
	Read(context.Context, string, string) (Evidence, error)
}
type Policy struct {
	Level Level
	MaxAge time.Duration
	RequireCurrentRisk bool
	RequireRecoveryState bool
}
// Minimum floors are security policy, not a discretionary request attribute.
// Changing these requires an explicit reviewed ADR/policy decision.
var floors = map[Operation]Level{
	Login:A1, BuyerCommit:A2, HighValueApproval:A3, CredentialChange:A3,
	RecoveryRebind:A3, PrivilegedGrant:A4, BreakGlass:A4,
}
// Conservative development policy: higher-risk operations will be denied
// until the missing independent risk/recovery and attestation sources exist.
// It is not production or protected-environment approval.
func ConservativePolicies() map[Operation]Policy {
	return map[Operation]Policy{
		Login:{A1,30*time.Minute,false,false},
		BuyerCommit:{A2,5*time.Minute,true,true},
		HighValueApproval:{A3,5*time.Minute,true,true},
		CredentialChange:{A3,5*time.Minute,true,true},
		RecoveryRebind:{A3,5*time.Minute,true,true},
		PrivilegedGrant:{A4,2*time.Minute,true,true},
		BreakGlass:{A4,2*time.Minute,true,true},
	}
}
type Evaluator struct {
	reader Reader
	now func()time.Time
	policies map[Operation]Policy
}
func rank(level Level) int {
	switch level {case A1:return 1;case A2:return 2;case A3:return 3;case A4:return 4}
	return 0
}
func New(reader Reader, now func()time.Time, policies map[Operation]Policy) (*Evaluator,error) {
	if reader==nil || now==nil || len(policies)!=len(floors) {return nil,errors.New("complete server-owned assurance policy and reader required")}
	copied:=make(map[Operation]Policy,len(policies))
	for op,floor:=range floors {
		p,ok:=policies[op]
		if !ok || rank(p.Level)<rank(floor) || p.MaxAge<=0 || p.MaxAge>time.Hour {
			return nil,fmt.Errorf("invalid reviewed assurance policy for %s",op)
		}
		if op!=Login && (!p.RequireCurrentRisk || !p.RequireRecoveryState) {
			return nil,fmt.Errorf("risk-sensitive operation %s cannot bypass current risk/recovery",op)
		}
		copied[op]=p
	}
	return &Evaluator{reader,now,copied},nil
}
var referenceRE=regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)
// OpaqueReference hashes secret-free provider event/session identifiers.
// It is a correlation label, not a proof of authentication or bearer secret.
func OpaqueReference(parts ...string) string {
	h:=sha256.New()
	for _,p:=range parts {fmt.Fprintf(h,"%d:%s;",len(p),p)}
	return "ref_"+hex.EncodeToString(h.Sum(nil))
}
func (e *Evaluator) Evaluate(ctx context.Context, req Request) Result {
	now:=time.Now().UTC()
	if e!=nil && e.now!=nil {now=e.now().UTC()}
	level:=floors[req.OperationClass]
	if level=="" {level=A4} // unknown operation can never pass
	result:=Result{Schema:ResultSchema,Outcome:Denied,RequiredLevel:level,EvaluatedAt:now,Reason:AssuranceUnavailable}
	if e==nil || e.reader==nil || ctx==nil || ctx.Err()!=nil {return result}
	p,found:=e.policies[req.OperationClass]
	if !found || req.Schema!=RequestSchema || !referenceRE.MatchString(req.AuthenticationEventReference) || !referenceRE.MatchString(req.SessionReference) {return result}
	result.RequiredLevel=p.Level
	first,err:=e.reader.Read(ctx,req.AuthenticationEventReference,req.SessionReference)
	if err!=nil {return result}
	if first.SessionReference!=req.SessionReference || first.EventReference!=req.AuthenticationEventReference || !referenceRE.MatchString(first.EvidenceReference) ||
		!first.Active || !first.IdentityActive {
		result.Reason=CurrentSessionMissing;return result
	}
	if first.ACR!="aal1" && first.ACR!="aal2" {return result}
	observed:=A1
	if first.ACR=="aal2" {observed=A2}
	// A3 requires separately verified RP-bound user verification AND passkey
	// proof. A4 adds a separately authenticated hardware and privileged witness
	// record. Neither follows from a Kratos method string or IdP ACR.
	if observed==A2 && first.PasskeyRPBound && first.PasskeyUserVerified && first.PasskeyAttested && first.PasskeyProofEventReference==first.EventReference {observed=A3}
	if observed==A3 && first.HardwareBound && first.PrivilegedWitnessVerified && first.PrivilegedWitnessEventReference==first.EventReference {observed=A4}
	result.ObservedLevel=observed
	if p.RequireCurrentRisk && !first.RiskChecked {result.Reason=CurrentRiskUnknown;return result}
	if p.RequireRecoveryState && !first.RecoveryStateChecked {result.Reason=CurrentRiskUnknown;return result}
	if first.RecoveryHeld {result.Reason=RecoveryHold;return result}
	if rank(p.Level)==4 && (!first.PrivilegedWitnessVerified || first.PrivilegedWitnessEventReference!=first.EventReference) {result.Reason=PrivilegedWitnessMissing;return result}
	if first.AuthenticatedAt.IsZero() || first.AuthenticatedAt.After(now) || !first.ExpiresAt.After(now) {
		result.Reason=FreshStepUpRequired;result.Outcome=StepUpRequired;return result
	}
	until:=first.AuthenticatedAt.Add(p.MaxAge)
	if first.ExpiresAt.Before(until) {until=first.ExpiresAt}
	if !until.After(now) || rank(observed)<rank(p.Level) {
		result.Reason=FreshStepUpRequired;result.Outcome=StepUpRequired;return result
	}
	// A favorable answer is never based on a single read that could have
	// changed or been revoked during policy evaluation. The source MUST reread
	// the provider and the current CP dispatch. This is a source fence, not
	// an atomic revocation claim for other engines.
	second,err:=e.reader.Read(ctx,req.AuthenticationEventReference,req.SessionReference)
	if err!=nil {result.Reason=AssuranceUnavailable;return result}
	if !reflect.DeepEqual(first,second) {result.Reason=CurrentSessionMissing;return result}
	if len(first.Methods)>12 {return result}
	seen:=map[string]bool{}
	methodRE:=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	for _,method:=range first.Methods {
		if !methodRE.MatchString(method) || seen[method] {return result}
		seen[method]=true
	}
	slices.Sort(first.Methods)
	authTime:=first.AuthenticatedAt.UTC()
	freshUntil:=until.UTC()
	result.Outcome=MetNotAuthorization
	result.Reason=AssuranceMet
	result.AuthenticatedAt=&authTime
	result.FreshUntil=&freshUntil
	result.EvidenceReference=first.EvidenceReference
	result.AuthenticationMethods=first.Methods
	return result
}
