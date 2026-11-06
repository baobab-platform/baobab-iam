package ory

import (
 "context"
 "errors"
 "time"

 "github.com/baobab-platform/baobab-iam/internal/provider"
 "github.com/baobab-platform/baobab-iam/internal/securityops"
)

var errRebindLedger = errors.New("ory: original review or durable recovery hold not established")

// RebindBinding must be resolved from a trusted IAM-owned canonical mapping,
// not derived from user-controlled email, an IdP group or a browser claim.
type RebindBinding struct {
 Principal string
 Domain string
}
type RebindBindingReader interface {
 CurrentRebindBinding(context.Context,provider.ExternalSubject)(RebindBinding,error)
}
type RebindReview struct {
 RequestedBy string
 ApprovedBy string
 RecoveryReference string
 DecisionReference string
 ExactSubject bool
 PrivilegedApproval bool
 ObservedAt time.Time
}
type RebindReviewReader interface {
 CurrentRebindReview(context.Context,provider.ExternalSubject)(RebindReview,error)
}

type LedgerRebindAuthority struct {
 Holds *securityops.Store
 Bindings RebindBindingReader
 Reviews RebindReviewReader
 Clock func()time.Time
}

func (a *LedgerRebindAuthority) CurrentWebAuthnRebind(ctx context.Context, subject provider.ExternalSubject)(NativeCredentialRebindEvidence,error) {
 var none NativeCredentialRebindEvidence
 if a==nil || a.Holds==nil || a.Bindings==nil || a.Reviews==nil ||
  a.Clock==nil || ctx==nil || ctx.Err()!=nil || subject.Issuer=="" || subject.Subject=="" {
  return none,errRebindLedger
 }
 binding,err:=a.Bindings.CurrentRebindBinding(ctx,subject)
 if err!=nil || binding.Principal=="" || binding.Domain=="" {
  return none,errRebindLedger
 }
 review,err:=a.Reviews.CurrentRebindReview(ctx,subject)
 now:=a.Clock().UTC()
 if err!=nil || !review.ExactSubject || !review.PrivilegedApproval ||
  !rebindRef.MatchString(review.RequestedBy) ||
  !rebindRef.MatchString(review.ApprovedBy) ||
  !rebindRef.MatchString(review.RecoveryReference) ||
  !rebindRef.MatchString(review.DecisionReference) ||
  review.RequestedBy==review.ApprovedBy || review.ObservedAt.IsZero() ||
  review.ObservedAt.After(now) || now.Sub(review.ObservedAt)>time.Minute {
  return none,errRebindLedger
 }
 hold,exists,err:=a.Holds.RecoveryHoldUntil(ctx,binding.Principal,subject.Issuer,binding.Domain)
 if err!=nil || !exists || hold.Before(now.Add(25*time.Hour)) {
  return none,errRebindLedger
 }
 return NativeCredentialRebindEvidence{
  OriginalRecoveryReference:review.RecoveryReference,
  RequestedByReference:review.RequestedBy,
  IndependentReviewerReference:review.ApprovedBy,
  CurrentSecurityDecisionReference:review.DecisionReference,
  Issuer:subject.Issuer,Subject:subject.Subject,
  ObservedAt:review.ObservedAt,HoldUntil:hold,
  Approved:true,DistinctReviewer:true,CurrentSecurityHold:true,
 },nil
}
