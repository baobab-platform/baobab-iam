package securityops

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

type RotationPurpose string
const (
	HydraSigning RotationPurpose = "HYDRA_SIGNING"
	HydraClient RotationPurpose = "HYDRA_CLIENT"
	KratosCookie RotationPurpose = "KRATOS_COOKIE"
	KratosCipher RotationPurpose = "KRATOS_CIPHER"
	TLSCertificate RotationPurpose = "TLS_CERT"
	FederationTrust RotationPurpose = "FEDERATION_TRUST"
)
type RotationPhase string
const (
	RotationPrepared RotationPhase = "PREPARED"
	RotationDual RotationPhase = "DUAL_VALID"
	RotationVerified RotationPhase = "CONSUMERS_VERIFIED"
	RotationRetired RotationPhase = "OLD_RETIRED"
	RotationAborted RotationPhase = "ABORTED"
	RotationUnknown RotationPhase = "UNKNOWN"
)
type Rotation struct {
	ID string
	SecurityDomain string
	Environment string
	Purpose RotationPurpose
	PreviousRef string
	NextRef string
	OverlapUntil time.Time
	Phase RotationPhase
	Revision int64
}
type RotationEvidence struct {
	ActualProviderReadback bool
	ActualConsumersReadback bool
	OldTokensExpired bool
	IndependentApproval bool
	ObservedAt time.Time
	OriginalReference string
}
type RotationWitness interface {
	ReadbackRotation(context.Context,Rotation,RotationPhase)(RotationEvidence,error)
}
func (s *Store) ProposeRotation(ctx context.Context,p Rotation)(string,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||!slices.Contains([]string{"development","staging","production"},p.Environment)||
		p.SecurityDomain==""||len(p.SecurityDomain)>80||
		!slices.Contains([]RotationPurpose{HydraSigning,HydraClient,KratosCookie,KratosCipher,TLSCertificate,FederationTrust},p.Purpose)||
		p.PreviousRef==""||p.NextRef==""||p.PreviousRef==p.NextRef||
		len(p.PreviousRef)>160||len(p.NextRef)>160||
		p.OverlapUntil.Before(s.now())||p.OverlapUntil.After(s.now().Add(90*24*time.Hour)) {
		return "",errors.New("securityops: reviewed cryptographic rotation references and overlap required")
	}
	id,err:=uuid();if err!=nil{return "",err}
	_,err=s.pool.Exec(ctx,`INSERT INTO iam_security.rotation_plan
(rotation_id,security_domain,environment,purpose,previous_key_ref,next_key_ref,overlap_until)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
	id,p.SecurityDomain,p.Environment,p.Purpose,p.PreviousRef,p.NextRef,p.OverlapUntil)
	if err!=nil{return "",errConflict(err)}
	return id,nil
}
func (s *Store) AdvanceRotation(ctx context.Context,id string,to RotationPhase,w RotationWitness)(*Rotation,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||!uuidPattern.MatchString(id)||w==nil{
		return nil,errors.New("securityops: reviewed rotation action required")
	}
	tx,err:=s.pool.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.Serializable})
	if err!=nil{return nil,errConflict(err)}
	defer tx.Rollback(ctx)
	p:=Rotation{ID:id}
	err=tx.QueryRow(ctx,`SELECT security_domain,environment,purpose,previous_key_ref,next_key_ref,
overlap_until,phase,revision FROM iam_security.rotation_plan WHERE rotation_id=$1 FOR UPDATE`,id).Scan(
		&p.SecurityDomain,&p.Environment,&p.Purpose,&p.PreviousRef,&p.NextRef,
		&p.OverlapUntil,&p.Phase,&p.Revision)
	if err!=nil{return nil,errConflict(err)}
	allowed:=map[RotationPhase]RotationPhase{
		RotationPrepared:RotationDual,
		RotationDual:RotationVerified,
		RotationVerified:RotationRetired,
	}
	if allowed[p.Phase]!=to && !(to==RotationAborted &&
		(p.Phase==RotationPrepared||p.Phase==RotationDual)) {
		return nil,errors.New("securityops: illegal key rotation state transition")
	}
	proof,err:=w.ReadbackRotation(ctx,p,to)
	now:=s.now().UTC()
	if err!=nil||!proof.IndependentApproval||!proof.ActualProviderReadback||
		proof.OriginalReference==""||proof.ObservedAt.IsZero()||
		proof.ObservedAt.After(now)||now.Sub(proof.ObservedAt)>time.Minute {
		return nil,errors.New("securityops: original approved provider rotation readback required")
	}
	if to==RotationVerified && !proof.ActualConsumersReadback {
		return nil,errors.New("securityops: consumer trust not proven")
	}
	if to==RotationRetired {
		if !proof.ActualConsumersReadback||!proof.OldTokensExpired||
			now.Before(p.OverlapUntil) {
			return nil,errors.New("securityops: old signing/trust key still needed")
		}
	}
	var version int64
	err=tx.QueryRow(ctx,`UPDATE iam_security.rotation_plan
SET phase=$2,revision=revision+1 WHERE rotation_id=$1 AND revision=$3
RETURNING revision`,id,to,p.Revision).Scan(&version)
	if err!=nil{return nil,errConflict(err)}
	if err:=tx.Commit(ctx);err!=nil{return nil,errConflict(err)}
	p.Revision=version;p.Phase=to
	return &p,nil
}

type IncidentAction string
const(
	RevokeSession IncidentAction="REVOKE_SESSION"
	DisableNative IncidentAction="DISABLE_NATIVE"
	DisableWorkload IncidentAction="DISABLE_WORKLOAD"
)
type IncidentPhase string
const(
	IncidentPending IncidentPhase="PENDING"
	IncidentProviderApplied IncidentPhase="PROVIDER_APPLIED"
	IncidentCPDenied IncidentPhase="CP_DENIED"
	IncidentVerified IncidentPhase="VERIFIED"
	IncidentUnknown IncidentPhase="UNKNOWN"
)
type Incident struct {
	CommandID string
	IncidentID string
	Target string
	TargetType string
	Action IncidentAction
	Reason string
	Requester string
	Approver string
	Phase IncidentPhase
	Revision int64
}
// ProposeIncident is an IAM-only, least-blast-radius action request.
// Global issuer/tenant/key revocation is deliberately not a representable
// command. Higher-impact actions always require separate approval identity.
func(s *Store) ProposeIncident(ctx context.Context,i Incident)(string,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||!uuidPattern.MatchString(i.IncidentID)||
		!slices.Contains([]IncidentAction{RevokeSession,DisableNative,DisableWorkload},i.Action)||
		!slices.Contains([]string{"SESSION","NATIVE_IDENTITY","WORKLOAD_CLIENT"},i.TargetType)||
		!slices.Contains([]string{"CREDENTIAL_COMPROMISE","SESSION_THEFT","CONFIRMED_TAKEOVER"},i.Reason)||
		(i.Action==RevokeSession&&i.TargetType!="SESSION")||
		(i.Action==DisableNative&&i.TargetType!="NATIVE_IDENTITY")||
		(i.Action==DisableWorkload&&i.TargetType!="WORKLOAD_CLIENT") ||
		(i.Action!=RevokeSession && (i.Approver==""||i.Approver==i.Requester)) {
		return "",errors.New("securityops: narrow incident action and distinct approver required")
	}
	target,err:=s.tag("incident-target",i.Target);if err!=nil{return "",err}
	req,err:=s.tag("incident-actor",i.Requester);if err!=nil{return "",err}
	var approver []byte
	if i.Approver!=""{approver,err=s.tag("incident-actor",i.Approver);if err!=nil{return "",err}}
	id,err:=uuid();if err!=nil{return "",err}
	_,err=s.pool.Exec(ctx,`INSERT INTO iam_security.incident_command
(command_id,incident_id,target_key,target_type,action,reason,
requester_key,approved_by_key,status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING')`,id,i.IncidentID,
		target,i.TargetType,i.Action,i.Reason,req,approver)
	if err!=nil{return "",errConflict(err)}
	return id,nil
}
type IncidentEvidence struct {
	RealIssuerOrKratosReadback bool
	ActualCPResourceDenied bool
	IndependentApproval bool
	ObservedAt time.Time
	OriginalReference string
}
type IncidentWitness interface {
	VerifyContainment(context.Context,Incident,IncidentPhase)(IncidentEvidence,error)
}
func(s *Store) AdvanceIncident(ctx context.Context,id string,to IncidentPhase,w IncidentWitness)(*Incident,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||!uuidPattern.MatchString(id)||w==nil{
		return nil,errors.New("securityops: incident witness required")
	}
	tx,err:=s.pool.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.Serializable})
	if err!=nil{return nil,errConflict(err)}
	defer tx.Rollback(ctx)
	i:=Incident{CommandID:id}
	var approver []byte
	err=tx.QueryRow(ctx,`SELECT incident_id,target_type,action,reason,status,revision,
approved_by_key FROM iam_security.incident_command WHERE command_id=$1 FOR UPDATE`,id).Scan(
		&i.IncidentID,&i.TargetType,&i.Action,&i.Reason,&i.Phase,&i.Revision,&approver)
	if err!=nil{return nil,errConflict(err)}
	expected:=map[IncidentPhase]IncidentPhase{
		IncidentPending:IncidentProviderApplied,
		IncidentProviderApplied:IncidentCPDenied,
		IncidentCPDenied:IncidentVerified,
		IncidentUnknown:IncidentProviderApplied,
	}
	if expected[i.Phase]!=to && to!=IncidentUnknown{
		return nil,errors.New("securityops: invalid incident transition")
	}
	if to==IncidentUnknown&&i.Phase==IncidentVerified{
		return nil,errors.New("securityops: separate incident required after verified containment")
	}
	if i.Action!=RevokeSession&&len(approver)!=32{
		return nil,errors.New("securityops: missing second human approval")
	}
	proof,err:=w.VerifyContainment(ctx,i,to)
	now:=s.now().UTC()
	if err!=nil||proof.OriginalReference==""||proof.ObservedAt.IsZero()||
		proof.ObservedAt.After(now)||now.Sub(proof.ObservedAt)>time.Minute||
		!proof.IndependentApproval {
		return nil,errors.New("securityops: independent incident witness missing")
	}
	if to==IncidentProviderApplied&&!proof.RealIssuerOrKratosReadback{
		return nil,errors.New("securityops: provider containment not confirmed")
	}
	if (to==IncidentCPDenied||to==IncidentVerified)&&
		(!proof.RealIssuerOrKratosReadback||!proof.ActualCPResourceDenied){
		return nil,errors.New("securityops: current CP resource denial not confirmed")
	}
	var revision int64
	err=tx.QueryRow(ctx,`UPDATE iam_security.incident_command
SET status=$2,revision=revision+1 WHERE command_id=$1 AND revision=$3
RETURNING revision`,id,to,i.Revision).Scan(&revision)
	if err!=nil{return nil,errConflict(err)}
	if err:=tx.Commit(ctx);err!=nil{return nil,errConflict(err)}
	i.Phase=to;i.Revision=revision
	return &i,nil
}
