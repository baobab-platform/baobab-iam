package ory

import (
	"context"
	"fmt"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// nativeAssuranceReader is deliberately NOT an HTTP endpoint. Its credential
// is supplied only by the trusted BFF; references from the canonical request
// are checked against a freshly read Kratos session and current CP routing.
// The exact assurance capability is required: human-login permission cannot
// be reused as a separate high-risk authentication-assurance grant.
// A session method label never creates trusted A3/A4 passkey/witness evidence.
type nativeAssuranceReader struct {
	h *GovernedNativeHumanHandoff
	credential NativeSessionCredential
}
func (h *GovernedNativeHumanHandoff) currentAssuranceSession(ctx context.Context, credential NativeSessionCredential) (nativeSession,error) {
	if h==nil || h.mechanics==nil || h.authority==nil || ctx==nil || ctx.Err()!=nil {
		return nativeSession{},fmt.Errorf("native assurance unavailable")
	}
	if h.authority.CheckCapability(ctx, provider.CapabilityAuthenticationAssurance)!=nil {
		return nativeSession{},fmt.Errorf("current CP native dispatch denied")
	}
	s,err:=h.mechanics.session(ctx,credential)
	if err!=nil {return nativeSession{},fmt.Errorf("native assurance unavailable")}
	if h.authority.CheckCapability(ctx, provider.CapabilityAuthenticationAssurance)!=nil {
		return nativeSession{},fmt.Errorf("current CP native dispatch denied")
	}
	return s,nil
}
func nativeAssuranceReferences(issuer string,s nativeSession)(string,string,string){
	// Domain-separated, secret-free opaque correlation identifiers: not bearer
	// credentials. A different session or authentication event cannot inherit
	// an earlier qualification.
	sessionRef:=assurance.OpaqueReference("kratos-session",issuer,s.ID)
	eventRef:=assurance.OpaqueReference("kratos-event",issuer,s.ID,s.AuthenticatedAt.UTC().Format(time.RFC3339Nano))
	evidenceRef:=assurance.OpaqueReference("kratos-evidence",issuer,s.ID,s.Identity.ID,s.AuthenticatedAt.UTC().Format(time.RFC3339Nano))
	return eventRef,sessionRef,evidenceRef
}
// CurrentAssuranceReferences returns references only after a real current
// Kratos read bracketed by CP routing checks. Both remain bound to the
// confidential native session credential and cannot themselves authorize.
func (h *GovernedNativeHumanHandoff) CurrentAssuranceReferences(ctx context.Context,credential NativeSessionCredential)(string,string,error){
	s,err:=h.currentAssuranceSession(ctx,credential)
	if err!=nil{return "","",err}
	event,session,_:=nativeAssuranceReferences(h.mechanics.issuer.String(),s)
	return event,session,nil
}
func (r *nativeAssuranceReader) Read(ctx context.Context,eventRef,sessionRef string)(assurance.Evidence,error){
	s,err:=r.h.currentAssuranceSession(ctx,r.credential)
	if err!=nil{return assurance.Evidence{},err}
	event,session,evidence:=nativeAssuranceReferences(r.h.mechanics.issuer.String(),s)
	if event!=eventRef || session!=sessionRef {
		return assurance.Evidence{},fmt.Errorf("native session or event replaced")
	}
	return assurance.Evidence{
		EventReference:event,SessionReference:session,EvidenceReference:evidence,
		Active:s.Active,IdentityActive:s.Identity.State=="active",
		ACR:s.AAL,Methods:nativeAMR(s),
		AuthenticatedAt:s.AuthenticatedAt,ExpiresAt:s.ExpiresAt,
		// Kratos whoami does NOT independently qualify risk or recovery hold;
		// no approved attestation, RP-bound UV, hardware verification or
		// privileged witness reader is connected. Therefore BUYER_COMMIT
		// and higher-risk operation policies fail closed until their owners
		// provide original current evidence (ADR-IAM-0024/0031).
	},nil
}
// EvaluateAssurance implements the Shared identity/v1 v1 request/response
// shape in a server-only, live governed composition. It cannot grant CP or
// domain authorization and does not publish capability support as IMPLEMENTED.
// Operation policies are conservative security floors; high-risk approvals
// require separately integrated risk, recovery and authenticator witnesses.
func (h *GovernedNativeHumanHandoff) EvaluateAssurance(ctx context.Context,credential NativeSessionCredential,request assurance.Request)(assurance.Result,error){
	if h==nil || h.mechanics==nil {
		return assurance.Result{},fmt.Errorf("governed native assurance required")
	}
	e,err:=assurance.New(&nativeAssuranceReader{h:h,credential:credential},h.mechanics.now,assurance.ConservativePolicies())
	if err!=nil{return assurance.Result{},err}
	return e.Evaluate(ctx,request),nil
}
