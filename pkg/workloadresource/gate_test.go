package workloadresource

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type signedStub struct{ claim Claims; err error; calls int }
func (s *signedStub) VerifySigned(_ context.Context, _ string) (Claims,error) {
	s.calls++
	return s.claim,s.err
}
type currentStub struct{ mu sync.Mutex; active LiveStatus; calls int; revokeOn int; err error }
func (s *currentStub) ReadCurrent(_ context.Context,_ string)(LiveStatus,error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	a:=s.active
	if s.revokeOn>0 && s.calls>=s.revokeOn {a.Active=false}
	return a,s.err
}
type authorityStub struct{ calls int; err error; withdraw func() }
func (s *authorityStub) AuthorizeCurrent(_ context.Context,raw string,c Claims,o Operation)error {
	s.calls++
	if raw==""||c.ClientID==""||o.ContextID==""||o.TenantID==""||o.ResourceOperation=="" {
		return ErrDenied
	}
	if s.withdraw!=nil {s.withdraw()}
	return s.err
}

func fixture(t *testing.T)(*Gate,*signedStub,*currentStub,*authorityStub) {
	t.Helper()
	now:=time.Now().UTC().Truncate(time.Second)
	signed:=&signedStub{claim:Claims{
		Issuer:"https://issuer.invalid",Subject:"federated-subject-external",ClientID:"pulse-ci",
		Audience:[]string{"baobab-pulse"},Scopes:[]string{"intelligence:read"},
		ActorType:"workload",IssuedAt:now.Add(-time.Minute),
		ExpiresAt:now.Add(4*time.Minute),
	}}
	status:=&currentStub{active:LiveStatus{Active:true,
		Issuer:signed.claim.Issuer,Subject:signed.claim.Subject,
		ClientID:signed.claim.ClientID,Audience:[]string{"baobab-pulse"},
		Scopes:[]string{"intelligence:read"},ExpiresAt:signed.claim.ExpiresAt,
	}}
	cp:=&authorityStub{}
	p:=Profile{Issuer:"https://issuer.invalid",Audience:"baobab-pulse",
		RequiredScopes:[]string{"intelligence:read"},AllowedClients:[]string{"pulse-ci"},
		MaxTokenAge:15*time.Minute}
	g,err:=New(p,signed,status,cp)
	if err!=nil{t.Fatal(err)}
	return g,signed,status,cp
}
func op()Operation{return Operation{ContextID:"ctx-real-cp",TenantID:"tn-owned",ResourceOperation:"intelligence.search"}}
func bearer()string{return "original-signed-provider-token-not-a-mock-proof"}

func TestWorkloadResourceGateFencesLiveStateAndCP(t *testing.T){
	g,signed,status,cp:=fixture(t)
	if err:=g.Authorize(context.Background(),bearer(),op());err!=nil{
		t.Fatal("consistent signed/current/CP source rejected",err)
	}
	if signed.calls!=1||status.calls!=2||cp.calls!=1 {
		t.Fatal("issuer must be read twice for each CP operation")
	}
	cp.err=errors.New("CP grant withdrawn")
	if err:=g.Authorize(context.Background(),bearer(),op());err==nil {
		t.Fatal("unexpired JWT alone bypassed withdrawn CP")
	}
	cp.err=nil
	status.revokeOn=status.calls+2
	if err:=g.Authorize(context.Background(),bearer(),op());err==nil {
		t.Fatal("withdrawal between CP and final issuer check admitted")
	}
}
func TestWorkloadResourceNeverCachesStatusOrAuthority(t *testing.T){
	g,_,status,cp:=fixture(t)
	for i:=0;i<10;i++{
		if err:=g.Authorize(context.Background(),bearer(),op());err!=nil{t.Fatal(err)}
	}
	if status.calls!=20||cp.calls!=10{
		t.Fatal("issuer or CP lookup cached")
	}
	status.active.Active=false
	if err:=g.Authorize(context.Background(),bearer(),op());err==nil{
		t.Fatal("provider revoked but prior resource grant cached")
	}
}
func TestWorkloadResourceClaimsAndIntrospectionNegatives(t *testing.T){
	tests:=[]struct{name string;edit func(*signedStub,*currentStub,*authorityStub)}{
		{"wrong-issuer",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.Issuer="https://other.invalid"}},
		{"wrong-audience",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.Audience=[]string{"baobab-payments"}}},
		{"extra-audience",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.Audience=append(s.claim.Audience,"baobab-erp")}},
		{"unknown-client",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.ClientID="unknown"}},
		{"human-not-workload",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.ActorType="human"}},
		{"missing-scope",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.Scopes=nil}},
		{"duplicate-scope",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.Scopes=append(s.claim.Scopes,"intelligence:read")}},
		{"expired",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.ExpiresAt=time.Now().Add(-time.Second)}},
		{"future-issued",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.IssuedAt=time.Now().Add(time.Minute)}},
		{"not-before",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.NotBefore=time.Now().Add(time.Minute)}},
		{"token-overlong",func(s *signedStub,_ *currentStub,_ *authorityStub){s.claim.IssuedAt=time.Now().Add(-16*time.Minute)}},
		{"bad-signature",func(s *signedStub,_ *currentStub,_ *authorityStub){s.err=errors.New("bad signature")}},
		{"issuer-inactive",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.Active=false}},
		{"issuer-unavailable",func(_ *signedStub,p *currentStub,_ *authorityStub){p.err=errors.New("issuer transport")}},
		{"status-subject-drift",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.Subject="different"}},
		{"status-client-drift",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.ClientID="other"}},
		{"status-audience-drift",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.Audience=[]string{"baobab-trade"}}},
		{"status-scope-drift",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.Scopes=[]string{"billing:manage"}}},
		{"status-expiry-drift",func(_ *signedStub,p *currentStub,_ *authorityStub){p.active.ExpiresAt=p.active.ExpiresAt.Add(time.Second)}},
		{"CP-denied",func(_ *signedStub,_ *currentStub,c *authorityStub){c.err=errors.New("not current")}},
	}
	for _,tc:=range tests{
		t.Run(tc.name,func(t *testing.T){
			g,s,p,c:=fixture(t)
			tc.edit(s,p,c)
			if err:=g.Authorize(context.Background(),bearer(),op());err==nil{
				t.Fatal("invalid workload resource evidence accepted")
			}
		})
	}
}
func TestGateRequiresAllIndependentAuthoritiesAndTrustedProfile(t *testing.T){
	g,s,p,c:=fixture(t)
	base:=g.p
	tests:=[]struct{name string;profile Profile}{
		{"missing-client",Profile{Issuer:base.Issuer,Audience:base.Audience,MaxTokenAge:base.MaxTokenAge,RequiredScopes:base.RequiredScopes}},
		{"http-issuer",Profile{Issuer:"http://127.0.0.1:4444",Audience:base.Audience,AllowedClients:base.AllowedClients,MaxTokenAge:base.MaxTokenAge,RequiredScopes:base.RequiredScopes}},
		{"too-long",Profile{Issuer:base.Issuer,Audience:base.Audience,AllowedClients:base.AllowedClients,MaxTokenAge:time.Hour,RequiredScopes:base.RequiredScopes}},
		{"duplicate-client",Profile{Issuer:base.Issuer,Audience:base.Audience,AllowedClients:[]string{"pulse-ci","pulse-ci"},MaxTokenAge:base.MaxTokenAge,RequiredScopes:base.RequiredScopes}},
	}
	for _,test:=range tests{t.Run(test.name,func(t *testing.T){
		if _,err:=New(test.profile,s,p,c);err==nil{t.Fatal("unsafe profile accepted")}
	})}
	if _,err:=New(base,nil,p,c);err==nil{t.Fatal("unsigned resource admitted")}
	if _,err:=New(base,s,nil,c);err==nil{t.Fatal("no issuer status admitted")}
	if _,err:=New(base,s,p,nil);err==nil{t.Fatal("no CP authority admitted")}
	if err:=g.Authorize(context.Background(),bearer(),Operation{ContextID:"untrusted"});err==nil{t.Fatal("incomplete resource operation admitted")}
}
