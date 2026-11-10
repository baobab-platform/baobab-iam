package assurance

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)
var fixedNow=time.Date(2026,11,10,15,0,0,0,time.UTC)
type fakeReader struct {
	value Evidence
	second *Evidence
	err error
	reads int
}
func (r *fakeReader) Read(_ context.Context,_,_ string)(Evidence,error){
	r.reads++
	if r.err!=nil {return Evidence{},r.err}
	if r.reads>=2 && r.second!=nil {return *r.second,nil}
	return r.value,nil
}
func sample() Evidence {
	return Evidence{
		EventReference:OpaqueReference("event","provider-session-1","login-1"),
		SessionReference:OpaqueReference("session","provider-session-1"),
		EvidenceReference:OpaqueReference("evidence","provider-session-1"),
		Active:true,IdentityActive:true,ACR:"aal2",Methods:[]string{"pwd","otp"},
		AuthenticatedAt:fixedNow.Add(-time.Minute),ExpiresAt:fixedNow.Add(time.Hour),
	}
}
func newTestEvaluator(t *testing.T,r Reader) *Evaluator {
	t.Helper()
	e,err:=New(r,func()time.Time{return fixedNow},ConservativePolicies())
	if err!=nil {t.Fatal(err)}
	return e
}
func request(e Evidence,operation Operation) Request {
	return Request{Schema:RequestSchema,AuthenticationEventReference:e.EventReference,SessionReference:e.SessionReference,OperationClass:operation}
}
func TestLoginUsesCurrentNativeSessionOnly(t *testing.T) {
	s:=sample();r:=&fakeReader{value:s}
	e:=newTestEvaluator(t,r)
	res:=e.Evaluate(context.Background(),request(s,Login))
	if res.Outcome!=MetNotAuthorization || res.Reason!=AssuranceMet || res.RequiredLevel!=A1 || res.ObservedLevel!=A2 || r.reads!=2 ||
		res.EvidenceReference!=s.EvidenceReference || res.AuthenticatedAt==nil || res.FreshUntil==nil {
		t.Fatalf("login outcome=%+v, reads=%d",res,r.reads)
	}
	if res.FreshUntil.Sub(*res.AuthenticatedAt)!=30*time.Minute {t.Fatalf("freshness: %+v",res)}
	b,err:=json.Marshal(res)
	if err!=nil {t.Fatal(err)}
	var decoded map[string]any
	if err=json.Unmarshal(b,&decoded);err!=nil {t.Fatal(err)}
	for _, forbidden:=range []string{"tenant","principal","organisation","roles","permissions","capabilities","scope"} {
		if _,ok:=decoded[forbidden];ok {t.Fatalf("business authority leaked: %s",forbidden)}
	}
	if !slices.Equal(res.AuthenticationMethods,[]string{"otp","pwd"}) {t.Fatal(res.AuthenticationMethods)}
}
func TestSensitiveOperationsNeverTrustUncheckedRiskOrRecovery(t *testing.T) {
	for op:=range floors {
		if op==Login {continue}
		s:=sample()
		r:=&fakeReader{value:s}
		res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,op))
		if res.Outcome!=Denied || res.Reason!=CurrentRiskUnknown || res.EvidenceReference!="" {
			t.Fatalf("%s: %+v",op,res)
		}
		s.RiskChecked=true
		r=&fakeReader{value:s}
		res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,op))
		if res.Outcome!=Denied || res.Reason!=CurrentRiskUnknown {t.Fatalf("%s: %+v",op,res)}
		s.RecoveryStateChecked=true;s.RecoveryHeld=true
		r=&fakeReader{value:s}
		res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,op))
		if res.Outcome!=Denied || res.Reason!=RecoveryHold {t.Fatalf("%s: %+v",op,res)}
	}
}
func TestBuyerCommitA2VerifiedButNotBusinessApproval(t *testing.T) {
	s:=sample();s.RiskChecked=true;s.RecoveryStateChecked=true
	r:=&fakeReader{value:s}
	res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,BuyerCommit))
	if res.Outcome!=MetNotAuthorization || res.RequiredLevel!=A2 {t.Fatalf("qualifying source: %+v",res)}
	s.ACR="aal1"
	r=&fakeReader{value:s}
	res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,BuyerCommit))
	if res.Outcome!=StepUpRequired || res.Reason!=FreshStepUpRequired || res.EvidenceReference!="" {t.Fatalf("weak AAL: %+v",res)}
}
func TestA3RequiresSeparateAttestationAndA4RequiresHardwareAndWitness(t *testing.T) {
	s:=sample();s.RiskChecked=true;s.RecoveryStateChecked=true
	for _, incomplete:=range []Evidence{
		s,
		func() Evidence {n:=s;n.PasskeyRPBound=true;return n}(),
		func() Evidence {n:=s;n.PasskeyRPBound=true;n.PasskeyUserVerified=true;return n}(),
	} {
		r:=&fakeReader{value:incomplete}
		res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,HighValueApproval))
		if res.Outcome!=StepUpRequired || res.Reason!=FreshStepUpRequired {t.Fatalf("unattested A3: %+v",res)}
	}
	s.PasskeyRPBound=true;s.PasskeyUserVerified=true;s.PasskeyAttested=true
	r:=&fakeReader{value:s}
	res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,HighValueApproval))
	if res.Outcome!=MetNotAuthorization || res.ObservedLevel!=A3 {t.Fatalf("A3: %+v",res)}
	r=&fakeReader{value:s}
	res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,PrivilegedGrant))
	if res.Outcome!=Denied || res.Reason!=PrivilegedWitnessMissing {t.Fatalf("no witness: %+v",res)}
	s.PrivilegedWitnessVerified=true
	r=&fakeReader{value:s}
	res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,PrivilegedGrant))
	if res.Outcome!=StepUpRequired {t.Fatalf("no hardware: %+v",res)}
	s.HardwareBound=true
	r=&fakeReader{value:s}
	res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,PrivilegedGrant))
	if res.Outcome!=MetNotAuthorization || res.ObservedLevel!=A4 {t.Fatalf("A4 with independently provided witness: %+v",res)}
}
func TestMissingStaleRevokedAndChangedSessionsAreDenied(t *testing.T) {
	for name,mutate:=range map[string]func(*Evidence){
		"disabled":func(s *Evidence){s.Active=false},
		"inactive identity":func(s *Evidence){s.IdentityActive=false},
		"bad ACR":func(s *Evidence){s.ACR="special-superadmin"},
		"future event":func(s *Evidence){s.AuthenticatedAt=fixedNow.Add(time.Second)},
		"expired":func(s *Evidence){s.ExpiresAt=fixedNow},
		"stale event":func(s *Evidence){s.AuthenticatedAt=fixedNow.Add(-40*time.Minute)},
		"wrong session":func(s *Evidence){s.SessionReference=OpaqueReference("session","other")},
		"wrong event":func(s *Evidence){s.EventReference=OpaqueReference("event","other")},
		"untrusted evidence":func(s *Evidence){s.EvidenceReference="http://provider/raw-token"},
		"duplicate amr":func(s *Evidence){s.Methods=[]string{"pwd","pwd"}},
	} {
		t.Run(name,func(t *testing.T){
			s:=sample();mutate(&s)
			r:=&fakeReader{value:s}
			// Requested refs must remain the canonical, unchanged provider event.
			res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(sample(),Login))
			if res.Outcome==MetNotAuthorization || res.EvidenceReference!="" {t.Fatalf("failed to deny: %+v",res)}
		})
	}
	s:=sample();changed:=s;changed.Active=false
	r:=&fakeReader{value:s,second:&changed}
	res:=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,Login))
	if res.Outcome!=Denied || res.Reason!=CurrentSessionMissing || r.reads!=2 {t.Fatalf("revoked between reads: %+v, reads=%d",res,r.reads)}
	r=&fakeReader{err:errors.New("provider down")}
	res=newTestEvaluator(t,r).Evaluate(context.Background(),request(s,Login))
	if res.Outcome!=Denied || res.Reason!=AssuranceUnavailable {t.Fatalf("provider down: %+v",res)}
}
func TestRequestAndPolicyAreNotUserChosen(t *testing.T) {
	s:=sample();e:=newTestEvaluator(t,&fakeReader{value:s})
	for _,bad:=range []Request{
		{Schema:"other",AuthenticationEventReference:s.EventReference,SessionReference:s.SessionReference,OperationClass:Login},
		{Schema:RequestSchema,AuthenticationEventReference:"ref_x",SessionReference:s.SessionReference,OperationClass:Login},
		{Schema:RequestSchema,AuthenticationEventReference:s.EventReference,SessionReference:s.SessionReference,OperationClass:"UNREVIEWED_ADMIN"},
	} {
		res:=e.Evaluate(context.Background(),bad)
		if res.Outcome!=Denied {t.Fatalf("invalid request: %+v",res)}
	}
	for name,change:=range map[string]func(map[Operation]Policy){
		"unknown operation":func(p map[Operation]Policy){delete(p,Login);p["NEW"]=Policy{A1,time.Minute,false,false}},
		"lower privileged floor":func(p map[Operation]Policy){p[PrivilegedGrant]=Policy{A2,time.Minute,true,true}},
		"no current risk":func(p map[Operation]Policy){p[BuyerCommit]=Policy{A2,time.Minute,false,true}},
		"no recovery check":func(p map[Operation]Policy){p[BuyerCommit]=Policy{A2,time.Minute,true,false}},
		"unbounded age":func(p map[Operation]Policy){p[Login]=Policy{A1,48*time.Hour,false,false}},
	}{
		t.Run(name,func(t *testing.T){
			p:=ConservativePolicies();change(p)
			if _,err:=New(&fakeReader{value:s},func()time.Time{return fixedNow},p);err==nil {t.Fatal("accepted unsafe policy")}
		})
	}
	p:=ConservativePolicies()
	e,err:=New(&fakeReader{value:s},func()time.Time{return fixedNow},p)
	if err!=nil {t.Fatal(err)}
	p[Login]=Policy{A4,2*time.Minute,true,true}
	res:=e.Evaluate(context.Background(),request(s,Login))
	if res.Outcome!=MetNotAuthorization || res.RequiredLevel!=A1 {t.Fatal("caller mutated reviewed policy after construction")}
}
