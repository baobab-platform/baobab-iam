// Package admin defines bounded break-glass *evidence* controls. It never
// issues an OAuth token or a provider credential and cannot grant CP/Trade/ERP
// authority. A protected emergency executor must enforce this lease at use.
package admin

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var ErrBreakGlassDenied = errors.New("admin: emergency authority denied or unverified")

const MaxEmergencyDuration = 15 * time.Minute

var allowed = map[string]string{
	"RESTORE_IAM_ADMIN_PLANE": "IAM_ADMIN_PLANE",
	"SUSPEND_FEDERATION":      "FEDERATION",
	"SUSPEND_ISSUER":          "ISSUER",
	"REVOKE_OAUTH_CLIENT":     "OAUTH_CLIENT",
}

type Request struct {
	LeaseID    string
	IncidentID string
	Action     string
	ScopeType  string
	ScopeID    string
	Reason     string
}

func (r Request) Valid() bool {
	scopeType, known := allowed[r.Action]
	if !uuid.MatchString(r.LeaseID) || !uuid.MatchString(r.IncidentID) ||
		!uuid.MatchString(r.ScopeID) || !known || scopeType != r.ScopeType {
		return false
	}
	switch r.Reason {
	case "AUTHN_OUTAGE", "FEDERATION_OUTAGE", "INCIDENT_CONTAINMENT", "REGIONAL_DR":
		return true
	default:
		return false
	}
}

type Witness struct {
	ActorID              string
	ApproverID           string
	ApprovedAt           time.Time
	ExpiresAt            time.Time
	IndependentAuthRef   string
	IndependentReviewRef string
}

// IndependentVerifier must read current actor, checker and emergency authority
// on each call, using controls independent of the unavailable native IAM plane.
// The returned witness identifies the original approval for this exact request.
type IndependentVerifier interface {
	VerifyEmergency(context.Context, Request) (Witness, error)
}

type Receipt struct {
	Reference  string
	ObservedAt time.Time
	LeaseID    string
}

type SecurityAlert interface {
	RaiseCritical(context.Context, Request, Witness) (Receipt, error)
}
type AuditLog interface {
	RecordActivation(context.Context, Request, Witness) (Receipt, error)
}

type State string

const (
	StatePending    State = "PENDING"
	StateActive     State = "ACTIVE"
	StateTerminated State = "TERMINATED"
)

type Lease struct {
	Request Request
	Witness Witness
	Status  State
}

type LeaseJournal interface {
	Reserve(context.Context, Lease) error
	Activate(context.Context, string) error
	Read(context.Context, string) (Lease, error)
	Terminate(context.Context, string) error
}

type BreakGlass struct {
	Verifier IndependentVerifier
	Alerts   SecurityAlert
	Audit    AuditLog
	Journal  LeaseJournal
	Now      func() time.Time
}

func validApproval(w Witness, now time.Time) bool {
	return uuid.MatchString(w.ActorID) && uuid.MatchString(w.ApproverID) &&
		w.ActorID != w.ApproverID &&
		w.IndependentAuthRef != "" && w.IndependentReviewRef != "" &&
		!w.ApprovedAt.IsZero() && !w.ApprovedAt.After(now) &&
		now.Before(w.ExpiresAt) &&
		!w.ExpiresAt.After(w.ApprovedAt.Add(MaxEmergencyDuration))
}

func sameApproval(a, b Witness) bool {
	// Match the timestamps at the PostgreSQL journal's precision.
	return a.ActorID == b.ActorID && a.ApproverID == b.ApproverID &&
		a.IndependentAuthRef == b.IndependentAuthRef && a.IndependentReviewRef == b.IndependentReviewRef &&
		a.ApprovedAt.Truncate(time.Microsecond).Equal(b.ApprovedAt.Truncate(time.Microsecond)) &&
		a.ExpiresAt.Truncate(time.Microsecond).Equal(b.ExpiresAt.Truncate(time.Microsecond))
}

// Activate creates only a bounded, purpose-specific security ledger record;
// it does not retrieve or activate a standing emergency credential.
func (b *BreakGlass) Activate(ctx context.Context, request Request) error {
	if b == nil || ctx == nil || ctx.Err() != nil ||
		b.Verifier == nil || b.Alerts == nil || b.Audit == nil ||
		b.Journal == nil || b.Now == nil || !request.Valid() {
		return ErrBreakGlassDenied
	}
	w, err := b.Verifier.VerifyEmergency(ctx, request)
	now := b.Now().UTC()
	if err != nil || !validApproval(w, now) || now.Sub(w.ApprovedAt) > time.Minute {
		return ErrBreakGlassDenied
	}
	lease := Lease{Request: request, Witness: w, Status: StatePending}
	if err := b.Journal.Reserve(ctx, lease); err != nil {
		return ErrBreakGlassDenied
	}
	// Confirm the independently sourced actor is still authorized after
	// reserving. Any failure leaves PENDING, never a usable lease.
	fresh, err := b.Verifier.VerifyEmergency(ctx, request)
	at := b.Now().UTC()
	if err != nil || !validApproval(fresh, at) || !sameApproval(fresh, w) || at.Sub(w.ApprovedAt) > time.Minute {
		return ErrBreakGlassDenied
	}
	alert, err := b.Alerts.RaiseCritical(ctx, request, w)
	if err != nil || !validReceipt(alert, request.LeaseID, b.Now().UTC()) {
		return ErrBreakGlassDenied
	}
	audit, err := b.Audit.RecordActivation(ctx, request, w)
	if err != nil || !validReceipt(audit, request.LeaseID, b.Now().UTC()) {
		return ErrBreakGlassDenied
	}
	current, err := b.Verifier.VerifyEmergency(ctx, request)
	at = b.Now().UTC()
	if err != nil || !validApproval(current, at) || !sameApproval(current, w) || at.Sub(w.ApprovedAt) > time.Minute ||
		!validReceipt(alert, request.LeaseID, at) || !validReceipt(audit, request.LeaseID, at) {
		return ErrBreakGlassDenied
	}
	if err := b.Journal.Activate(ctx, request.LeaseID); err != nil {
		return ErrBreakGlassDenied
	}
	return nil
}

func validReceipt(r Receipt, id string, now time.Time) bool {
	return r.LeaseID == id && r.Reference != "" &&
		!r.ObservedAt.IsZero() && !r.ObservedAt.After(now) &&
		now.Sub(r.ObservedAt) <= time.Minute
}

// Check cannot confer privileges. The actual emergency executor must verify
// the action/target, use a separate independent credential, and audit EVERY
// operation. Revoked/expired or changed emergency authority always denies.
func (b *BreakGlass) Check(ctx context.Context, request Request) error {
	if b == nil || ctx == nil || ctx.Err() != nil || b.Journal == nil ||
		b.Verifier == nil || b.Now == nil || !request.Valid() {
		return ErrBreakGlassDenied
	}
	lease, err := b.Journal.Read(ctx, request.LeaseID)
	now := b.Now().UTC()
	if err != nil || lease.Request != request || lease.Status != StateActive ||
		!validApproval(lease.Witness, now) {
		return ErrBreakGlassDenied
	}
	current, err := b.Verifier.VerifyEmergency(ctx, request)
	now = b.Now().UTC()
	if err != nil || !validApproval(lease.Witness, now) || !validApproval(current, now) || !sameApproval(current, lease.Witness) {
		return ErrBreakGlassDenied
	}
	return nil
}

func (b *BreakGlass) Terminate(ctx context.Context, leaseID string) error {
	if b == nil || ctx == nil || ctx.Err() != nil ||
		b.Journal == nil || !uuid.MatchString(leaseID) {
		return ErrBreakGlassDenied
	}
	if err := b.Journal.Terminate(ctx, leaseID); err != nil {
		return ErrBreakGlassDenied
	}
	return nil
}
