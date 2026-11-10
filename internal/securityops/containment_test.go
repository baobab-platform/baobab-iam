package securityops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type journalStub struct {
	phase Phase
	err error
	events []Phase
	reserves int
}
func (j *journalStub) Reserve(_ context.Context, _ Intent) (Phase, error) {
	j.reserves++
	if j.err != nil { return "", j.err }
	if j.phase == "" { return PhaseFenced, nil }
	return j.phase, nil
}
func (j *journalStub) Mark(_ context.Context, _ string, p Phase) error {
	j.events = append(j.events,p)
	return nil
}
type authorityStub struct {
	approval Authorization
	call int
	recheckDenied bool
}
func (a *authorityStub) AuthorizeContainment(_ context.Context, _ Intent) (Authorization,error) {
	a.call++
	if a.recheckDenied && a.call > 1 { return Authorization{}, errors.New("revoked") }
	return a.approval,nil
}
type providerStub struct {
	disabled bool
	calls []string
	disableErr error
	revokeErr error
	readErr error
	active int
	wrongSubject bool
}
func (p *providerStub) DisableIdentity(_ context.Context,_ provider.ExternalSubject) error {
	p.calls=append(p.calls,"disable")
	if p.disableErr==nil {p.disabled=true}
	return p.disableErr
}
func (p *providerStub) EnableIdentity(_ context.Context,_ provider.ExternalSubject) error {
	panic("incident containment may never reenable")
}
func (p *providerStub) RevokeSessions(_ context.Context,_ provider.ExternalSubject) error {
	p.calls=append(p.calls,"revoke")
	return p.revokeErr
}
func (p *providerStub) GetIdentity(_ context.Context,s provider.ExternalSubject) (*provider.ProviderIdentity,error) {
	p.calls=append(p.calls,"read")
	if p.readErr!=nil {return nil,p.readErr}
	status:=provider.IdentityStatusActive
	if p.disabled {status=provider.IdentityStatusDisabled}
	if p.wrongSubject {s.Subject="different"}
	return &provider.ProviderIdentity{Issuer:s.Issuer,Subject:s.Subject,Status:status},nil
}
func (p *providerStub) ActiveSessionCount(_ context.Context,_ provider.ExternalSubject) (int,error) {
	p.calls=append(p.calls,"count")
	return p.active,nil
}
type resourceStub struct {
	denial CurrentResourceDenial
	err error
	calls int
}
func (r *resourceStub) VerifyCurrentDenial(_ context.Context,_ provider.ExternalSubject,_ string) (CurrentResourceDenial,error) {
	r.calls++
	return r.denial,r.err
}
func setup(now time.Time) (*Containment,*journalStub,*providerStub,*resourceStub,*authorityStub,Intent) {
	j:=&journalStub{}
	p:=&providerStub{}
	r:=&resourceStub{denial:CurrentResourceDenial{
		ExactSubjectDenied:true,CanonicalDenied:true,
		ObservedAt:now.Add(-time.Second),EvidenceReference:"source-evidence-receipt",
	}}
	a:=&authorityStub{approval:Authorization{
		ActorID:"6d5417fd-c3d0-4795-8f15-52f0cc3180b1",
		DecisionID:"f540b5da-33c6-4771-a17b-6aa1119ac9b9",
		VerifiedAt:now.Add(-time.Second),ValidUntil:now.Add(time.Minute),
	}}
	intent:=Intent{OperationID:"incident-operation-0001",
		IncidentID:"incident-000000000001",
		Subject:provider.ExternalSubject{Issuer:"https://iam.example.test",Subject:"human-001"}}
	c:=&Containment{Authority:a,Journal:j,Provider:p,Resource:r,Now:func()time.Time{return now}}
	return c,j,p,r,a,intent
}
func TestIncidentContainmentRequiresCurrentNativeAndCPReadback(t *testing.T) {
	now:=time.Now().UTC()
	c,j,p,r,a,intent:=setup(now)
	if err:=c.Execute(context.Background(),intent);err!=nil {t.Fatal(err)}
	if j.reserves!=1||a.call!=2||r.calls!=1||!p.disabled {t.Fatal("missing original containment witnesses")}
	expected:=[]Phase{PhaseDisabled,PhaseRevoked,PhaseVerified}
	if len(j.events)!=len(expected){t.Fatalf("phases: %v",j.events)}
	for n,v:=range expected {if j.events[n]!=v {t.Fatalf("phase %d %v",n,j.events[n])}}
	if len(p.calls)<2||p.calls[0]!="disable"||p.calls[1]!="read" {t.Fatalf("wrong mutation ordering: %v",p.calls)}
}
func TestFailClosedBeforeNativeMutation(t *testing.T) {
	now:=time.Now().UTC()
	c,j,p,_,a,intent:=setup(now)
	j.err=errors.New("database down")
	if c.Execute(context.Background(),intent)==nil {t.Fatal("journal failure must deny")}
	if len(p.calls)!=0 {t.Fatal("provider mutation without durable journal")}
	c,j,p,_,a,intent=setup(now)
	a.recheckDenied=true
	if c.Execute(context.Background(),intent)==nil {t.Fatal("recheck denial must stop mutation")}
	if len(p.calls)!=0||len(j.events)!=1||j.events[0]!=PhaseUnknown {
		t.Fatalf("missing UNKNOWN on recheck refusal: %v %v",p.calls,j.events)
	}
	c,j,p,_,a,intent=setup(now)
	a.approval.ValidUntil=now
	if c.Execute(context.Background(),intent)==nil||j.reserves!=0||len(p.calls)!=0 {
		t.Fatal("expired authorization must not reserve or mutate")
	}
}
func TestProviderAndResourceFailuresNeverBecomeVerified(t *testing.T) {
	for _,tc:=range []struct{name string;mutate func(*providerStub,*resourceStub)}{
		{"disable",func(p *providerStub,_ *resourceStub){p.disableErr=errors.New("failed")}},
		{"native-subject",func(p *providerStub,_ *resourceStub){p.wrongSubject=true}},
		{"native-session",func(p *providerStub,_ *resourceStub){p.active=1}},
		{"resource-denial",func(_ *providerStub,r *resourceStub){r.denial.CanonicalDenied=false}},
		{"resource-observation",func(_ *providerStub,r *resourceStub){r.denial.EvidenceReference=""}},
	} {
		t.Run(tc.name,func(t *testing.T){
			c,j,p,r,_,intent:=setup(time.Now().UTC())
			tc.mutate(p,r)
			if c.Execute(context.Background(),intent)==nil {t.Fatal("expected refusal")}
			if len(j.events)==0||j.events[len(j.events)-1]!=PhaseUnknown {t.Fatalf("phase journal must end UNKNOWN: %v",j.events)}
			for _,phase:=range j.events {if phase==PhaseVerified {t.Fatal("false success")}}
		})
	}
}
func TestVerifiedHistoryIsNotCurrentTrust(t *testing.T) {
	now:=time.Now().UTC()
	c,j,p,r,_,intent:=setup(now)
	j.phase=PhaseVerified
	p.disabled=true
	if err:=c.Execute(context.Background(),intent);err!=nil {t.Fatal(err)}
	for _,call:=range p.calls {if call=="disable"||call=="revoke" {t.Fatal("verified replay mutated native provider")}}
	r.denial.ExactSubjectDenied=false
	if c.Execute(context.Background(),intent)==nil {t.Fatal("stale successful receipt bypassed current denial")}
	if j.events[len(j.events)-1]!=PhaseUnknown {t.Fatal("drift must be marked unknown")}
}
func TestCrossSubjectAndInvalidScopeRefused(t *testing.T) {
	c,j,p,_,_,intent:=setup(time.Now().UTC())
	intent.Subject.Issuer=""
	if c.Execute(context.Background(),intent)==nil {t.Fatal("missing issuer accepted")}
	if j.reserves!=0||len(p.calls)!=0 {t.Fatal("invalid intent triggered effects")}
}
