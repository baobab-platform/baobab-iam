package securityops

import (
	"context"
	"crypto/hmac"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rebind is an IAM-native authenticator lifecycle request. It does not
// create/rename CP Principals, rewrite ExternalIdentity or grant a buyer,
// staff, supplier or legal mandate (ADR-IAM-0025).
type Rebind struct {
	RequestID string
	Principal string
	Issuer string
	Kind string
	Reason string
	Requester string
	Approver string
	Phase string
	Revision int64
}

type RebindProof struct {
	CurrentPrincipalBound bool
	RecentA3Verified bool
	IndependentApproverVerified bool
	AuthorizedScopeVerified bool
	RealKratosChangeReadback bool
	AllOldSessionsRevoked bool
	CPPrincipalUnchanged bool
	ObservedAt time.Time
	OriginalReference string
}

type RebindWitness interface {
	VerifyRebind(context.Context,Rebind,string)(RebindProof,error)
}

func (s *Store) RequestRebind(ctx context.Context,r Rebind,witness RebindWitness)(string,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||witness==nil||
		!slices.Contains([]string{"PASSKEY","TOTP","RECOVERY_FACTOR"},r.Kind)||
		!slices.Contains([]string{"LOST_DEVICE","COMPROMISE","PLANNED_REPLACEMENT"},r.Reason)||
		r.Requester==""||r.Approver==""||r.Requester==r.Approver {
		return "",errors.New("securityops: separate verified approver and credential lifecycle class required")
	}
	proof,err:=witness.VerifyRebind(ctx,r,"PENDING")
	now:=s.now().UTC()
	if err!=nil||!proof.CurrentPrincipalBound||!proof.RecentA3Verified||
		!proof.IndependentApproverVerified||!proof.AuthorizedScopeVerified||
		proof.OriginalReference==""||proof.ObservedAt.IsZero()||
		proof.ObservedAt.After(now)||now.Sub(proof.ObservedAt)>time.Minute {
		return "",errors.New("securityops: fresh A3, CP and independent reviewer not proven")
	}
	principal,err:=s.tag("principal",r.Principal);if err!=nil{return "",err}
	issuer,err:=s.tag("issuer",r.Issuer);if err!=nil{return "",err}
	requester,err:=s.tag("review-actor",r.Requester);if err!=nil{return "",err}
	approver,err:=s.tag("review-actor",r.Approver);if err!=nil{return "",err}
	id,err:=uuid();if err!=nil{return "",err}
	_,err=s.pool.Exec(ctx,`INSERT INTO iam_security.credential_rebind
(request_id,principal_key,issuer_key,credential_kind,requester_key,approver_key,reason)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,id,principal,issuer,r.Kind,requester,approver,r.Reason)
	if err!=nil{return "",errConflict(err)}
	return id,nil
}

// MarkRebind never drives native secret recovery itself: the Kratos
// self-service/administrative ceremony must occur under its own verified
// original and the old sessions must be revoked. Repeating the same phase
// cannot make a provider-side failure look like a new success.
func (s *Store) MarkRebind(ctx context.Context,request Rebind,to string,w RebindWitness)(*Rebind,error){
	if s==nil||ctx==nil||ctx.Err()!=nil||w==nil||!uuidPattern.MatchString(request.RequestID) {
		return nil,errors.New("securityops: original rebind request and witness required")
	}
	tx,err:=s.pool.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.Serializable})
	if err!=nil{return nil,errConflict(err)}
	defer tx.Rollback(ctx)
	out:=&Rebind{RequestID:request.RequestID,Principal:request.Principal,Issuer:request.Issuer,Requester:request.Requester,Approver:request.Approver}
	var principalKey,issuerKey,requesterKey,approverKey []byte
	err=tx.QueryRow(ctx,`SELECT principal_key,issuer_key,credential_kind,
requester_key,approver_key,reason,phase,revision
FROM iam_security.credential_rebind WHERE request_id=$1 FOR UPDATE`,request.RequestID).Scan(
		&principalKey,&issuerKey,&out.Kind,&requesterKey,&approverKey,
		&out.Reason,&out.Phase,&out.Revision)
	if err!=nil{return nil,errConflict(err)}
	// Compare every user-supplied reference with its persisted, keyed
	// immutable value BEFORE invoking the independent proof port.
	pk,e1:=s.tag("principal",request.Principal)
	ik,e2:=s.tag("issuer",request.Issuer)
	rk,e3:=s.tag("review-actor",request.Requester)
	ak,e4:=s.tag("review-actor",request.Approver)
	if e1!=nil||e2!=nil||e3!=nil||e4!=nil||
		!hmac.Equal(pk,principalKey)||!hmac.Equal(ik,issuerKey)||
		!hmac.Equal(rk,requesterKey)||!hmac.Equal(ak,approverKey)||
		(request.Kind!=""&&request.Kind!=out.Kind) {
		return nil,errors.New("securityops: original rebind Principal/issuer/approval mismatch")
	}
	allowed:=map[string]string{
		"PENDING":"PROVIDER_VERIFIED",
		"PROVIDER_VERIFIED":"COMMITTED",
		"UNKNOWN":"PROVIDER_VERIFIED",
	}
	if allowed[out.Phase]!=to && !(to=="UNKNOWN"&&out.Phase!="COMMITTED") {
		return nil,errors.New("securityops: invalid rebinding phase")
	}
	// The owner stores only pseudonymous references; witnesses must be bound
	// to the exactly selected stored request/credential kind, not a forged
	// second issuer or replacement business identity.
	proof,err:=w.VerifyRebind(ctx,*out,to)
	now:=s.now().UTC()
	if err!=nil||!proof.CurrentPrincipalBound||!proof.RecentA3Verified||
		!proof.IndependentApproverVerified||!proof.AuthorizedScopeVerified||
		proof.OriginalReference==""||proof.ObservedAt.IsZero()||
		proof.ObservedAt.After(now)||now.Sub(proof.ObservedAt)>time.Minute {
		return nil,errors.New("securityops: current strong credential reviewer witness unavailable")
	}
	if to=="PROVIDER_VERIFIED" && !proof.RealKratosChangeReadback {
		return nil,errors.New("securityops: native authenticator mutation not verified")
	}
	if to=="COMMITTED" && (!proof.RealKratosChangeReadback||
		!proof.AllOldSessionsRevoked||!proof.CPPrincipalUnchanged) {
		return nil,errors.New("securityops: old sessions or canonical Principal not proven unchanged")
	}
	var revision int64
	err=tx.QueryRow(ctx,`UPDATE iam_security.credential_rebind
SET phase=$2,revision=revision+1 WHERE request_id=$1 AND revision=$3
RETURNING revision`,id,to,out.Revision).Scan(&revision)
	if err!=nil{return nil,errConflict(err)}
	if err:=tx.Commit(ctx);err!=nil{return nil,errConflict(err)}
	out.Phase=to;out.Revision=revision
	return out,nil
}
