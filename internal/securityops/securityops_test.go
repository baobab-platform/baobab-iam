package securityops

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)
func testDB(t *testing.T)(*Store,*pgxpool.Pool){
	t.Helper()
	if os.Getenv("IAM_N06_DISPOSABLE_PG")!="1"{t.Skip("requires a real disposable PostgreSQL 17 database")}
	dsn:=os.Getenv("IAM_N06_TEST_DATABASE_URL")
	cfg,err:=pgxpool.ParseConfig(dsn)
	if err!=nil||cfg.ConnConfig.Database!="n06_ci"||
		(cfg.ConnConfig.Host!="127.0.0.1"&&cfg.ConnConfig.Host!="localhost"){
		t.Fatal("N06 refuses non-disposable/non-local PostgreSQL")
	}
	pool,err:=pgxpool.NewWithConfig(context.Background(),cfg)
	if err!=nil{t.Fatal(err)}
	t.Cleanup(pool.Close)
	ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
	defer cancel()
	if _,err:=pool.Exec(ctx,Schema());err!=nil{t.Fatalf("N06 install reviewed migration: %v",err)}
	key:=make([]byte,32)
	if _,err:=rand.Read(key);err!=nil{t.Fatal(err)}
	s,err:=NewStore(ctx,pool,key,func()time.Time{return time.Now().UTC()})
	if err!=nil{t.Fatal(err)}
	return s,pool
}
type recoveryEvidenceTest struct{}
func (recoveryEvidenceTest) VerifyRecovery(_ context.Context,_ RecoveryAction)(RecoveryEvidence,error){
	return RecoveryEvidence{
		ExactProviderSession:true,RecoveryCompleted:true,
		ObservedAt:time.Now().UTC(),OriginalReference:"test-only-provider-recovery-original",
	},nil
}
func TestN06RecoveryHoldCannotShortenOrCrossIssuer(t *testing.T){
	s,pool:=testDB(t);ctx:=context.Background()
	id,_:=uuid()
	now:=s.now()
	profile:=RecoveryAction{
		Principal:id,Issuer:"https://kratos.example.test",SecurityDomain:"n06:test",
		Reason:"RECOVERY_COMPLETE",ObservedAt:now.Add(-time.Second),
		HoldUntil:now.Add(24*time.Hour),
	}
	if err:=s.RecordRecovery(ctx,profile,recoveryEvidenceTest{});err!=nil{t.Fatal(err)}
	until,found,err:=s.RecoveryHoldUntil(ctx,id,profile.Issuer,profile.SecurityDomain)
	if err!=nil||!found||until.Before(now.Add(23*time.Hour)){t.Fatal("new recovery hold missing")}
	shorter:=profile;shorter.HoldUntil=now.Add(time.Hour)
	if err:=s.RecordRecovery(ctx,shorter,recoveryEvidenceTest{});err!=nil{t.Fatal(err)}
	until,found,err=s.RecoveryHoldUntil(ctx,id,profile.Issuer,profile.SecurityDomain)
	if err!=nil||!found||until.Before(now.Add(23*time.Hour)){t.Fatal("replay shortened recovery risk hold")}
	second:=profile;second.Issuer="https://other-issuer.test"
	if err:=s.RecordRecovery(ctx,second,recoveryEvidenceTest{});err==nil{t.Fatal("foreign issuer owned prior recovery row")}
	principalKey,_:=s.tag("principal",id)
	if _,err:=pool.Exec(ctx,`DELETE FROM iam_security.recovery_hold WHERE principal_key=$1`,principalKey);err==nil{
		t.Fatal("direct SQL deleted recent recovery hold")
	}
	if _,err:=pool.Exec(ctx,`UPDATE iam_security.recovery_hold SET hold_until=now(),
revision=revision+1 WHERE principal_key=$1`,principalKey);err==nil{
		t.Fatal("direct SQL shortened risk hold")
	}
}
func TestN06SecurityAuditNeverStoresRawSubjectOrSecrets(t *testing.T){
	s,pool:=testDB(t);ctx:=context.Background()
	id,_:=uuid()
	secret:="my-secret@example.test"
	ev:=SafeEvent{
		Type:"recovery.completed",Actor:"operator@private.test",
		Subject:secret,CorrelationID:id,Outcome:"RECORDED",Severity:"HIGH",
		ResultCode:"PROVIDER_CONFIRMED",OccurredAt:s.now().Add(-time.Second),
	}
	eventID,err:=s.AppendEvent(ctx,ev)
	if err!=nil{t.Fatal(err)}
	var metadata string
	var subject []byte
	err=pool.QueryRow(ctx,`SELECT metadata::text,subject_key FROM iam_security.event
WHERE event_id=$1`,eventID).Scan(&metadata,&subject)
	if err!=nil||strings.Contains(metadata,secret)||len(subject)!=32||string(subject)==secret {
		t.Fatal("raw identity leaked into security evidence")
	}
	if _,err:=pool.Exec(ctx,"UPDATE iam_security.event SET outcome='ALLOWED' WHERE event_id=$1",eventID);err==nil{
		t.Fatal("tamper-resistant event rewritten")
	}
	if _,err:=pool.Exec(ctx,"DELETE FROM iam_security.event WHERE event_id=$1",eventID);err==nil{
		t.Fatal("tamper-resistant event deleted")
	}
	for _,bad:=range []SafeEvent{
		{Type:"authorization.granted",Subject:secret,CorrelationID:id,Outcome:"ALLOWED",Severity:"HIGH",ResultCode:"PROVIDER_CONFIRMED",OccurredAt:ev.OccurredAt},
		{Type:"recovery.completed",Subject:secret,CorrelationID:id,Outcome:"RECORDED",Severity:"HIGH",ResultCode:"password=secret",OccurredAt:ev.OccurredAt},
		{Type:"recovery.completed",Subject:secret,CorrelationID:"bad",Outcome:"RECORDED",Severity:"HIGH",ResultCode:"PROVIDER_CONFIRMED",OccurredAt:ev.OccurredAt},
	}{
		if _,err:=s.AppendEvent(ctx,bad);err==nil{t.Fatal("unreviewed audit payload accepted")}
	}
}
type trustedRotation struct{consumers bool;expire bool;approval bool}
func (w trustedRotation) ReadbackRotation(_ context.Context,_ Rotation,_ RotationPhase)(RotationEvidence,error){
	return RotationEvidence{
		ActualProviderReadback:true,ActualConsumersReadback:w.consumers,
		OldTokensExpired:w.expire,IndependentApproval:w.approval,
		ObservedAt:time.Now().UTC(),OriginalReference:"actual-provider-readback-placeholder-test-only",
	},nil
}
func TestN06RotationCannotRetireOldJWKSBeforeActualConsumerProof(t *testing.T){
	s,pool:=testDB(t);ctx:=context.Background()
	id,err:=s.ProposeRotation(ctx,Rotation{SecurityDomain:"iam-native",
		Environment:"development",Purpose:HydraSigning,
		PreviousRef:"vault-key-v1",NextRef:"vault-key-v2",
		OverlapUntil:s.now().Add(time.Hour)})
	if err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceRotation(ctx,id,RotationDual,trustedRotation{});err==nil {
		t.Fatal("unapproved provider rotation accepted")
	}
	phase,err:=s.AdvanceRotation(ctx,id,RotationDual,trustedRotation{approval:true})
	if err!=nil||phase.Phase!=RotationDual{t.Fatalf("dual rotation refused %v",err)}
	if _,err:=s.AdvanceRotation(ctx,id,RotationVerified,trustedRotation{approval:true});err==nil{
		t.Fatal("consumer trust readback missing")
	}
	if _,err:=s.AdvanceRotation(ctx,id,RotationVerified,trustedRotation{approval:true,consumers:true});err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceRotation(ctx,id,RotationRetired,trustedRotation{approval:true,consumers:true,expire:true});err==nil{
		t.Fatal("old JWT still live before reviewed overlap window")
	}
	if _,err:=pool.Exec(ctx,"DELETE FROM iam_security.rotation_history WHERE rotation_id=$1",id);err==nil{
		t.Fatal("rotation evidence erasable")
	}
}
type trustedIncident struct{cp bool; provider bool; approved bool}
func (w trustedIncident) VerifyContainment(_ context.Context,_ Incident,_ IncidentPhase)(IncidentEvidence,error){
	return IncidentEvidence{RealIssuerOrKratosReadback:w.provider,
		ActualCPResourceDenied:w.cp,IndependentApproval:w.approved,
		ObservedAt:time.Now().UTC(),OriginalReference:"real-issuer-CP-original-test-only"},nil
}
type incidentApprovalTest struct{approved bool}
func (w incidentApprovalTest) VerifyIncidentApproval(_ context.Context,_ Incident)(IncidentApprovalEvidence,error){
	return IncidentApprovalEvidence{
		ExactActor:true,ExactApprover:w.approved,
		ScopeAuthorized:true,RecentHighAssurance:w.approved,
		ObservedAt:time.Now().UTC(),OriginalReference:"test-only-CP-approval-readback",
	},nil
}
func TestN06IncidentRequiresIndependentActorAndCurrentResourceDenial(t *testing.T){
	s,pool:=testDB(t);ctx:=context.Background()
	id,_:=uuid()
	cmd:=Incident{IncidentID:id,Target:"human-test",TargetType:"NATIVE_IDENTITY",
		Action:DisableNative,Reason:"CONFIRMED_TAKEOVER",Requester:"one"}
	if _,err:=s.ProposeIncident(ctx,cmd,incidentApprovalTest{approved:true});err==nil{t.Fatal("self-approved security-wide disable")}
	cmd.Approver="one"
	if _,err:=s.ProposeIncident(ctx,cmd,incidentApprovalTest{approved:true});err==nil{t.Fatal("self-approved disable")}
	cmd.Approver="independent-reviewer"
	created,err:=s.ProposeIncident(ctx,cmd,incidentApprovalTest{approved:true})
	if err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentProviderApplied,trustedIncident{approved:true});err==nil{
		t.Fatal("provider not observed")
	}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentProviderApplied,trustedIncident{provider:true,approved:true});err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentCPDenied,trustedIncident{provider:true,approved:true});err==nil {
		t.Fatal("resource allowed current compromised token")
	}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentCPDenied,trustedIncident{cp:true,provider:true,approved:true});err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentVerified,trustedIncident{cp:true,provider:true,approved:true});err!=nil{t.Fatal(err)}
	if _,err:=s.AdvanceIncident(ctx,created,IncidentProviderApplied,trustedIncident{cp:true,provider:true,approved:true});err==nil{
		t.Fatal("verified security incident rolled back to provider only")
	}
	if _,err:=pool.Exec(ctx,"DELETE FROM iam_security.incident_history WHERE command_id=$1",created);err==nil{
		t.Fatal("incident history deleted")
	}
	cmd.Action="DISABLE_GLOBAL_ISSUER"
	if _,err:=s.ProposeIncident(ctx,cmd,incidentApprovalTest{approved:true});err==nil{
		t.Fatal("global issuer shutdown representable")
	}
}
