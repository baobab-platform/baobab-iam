// Package securityops coordinates narrow, deny-only IAM incident containment.
// ADR-IAM-0029: detection is not authorization; provider disablement is not
// downstream resource denial. No method here enables or grants authority.
package securityops

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

var operationID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{15,159}$`)

type Intent struct {
	OperationID string
	IncidentID  string
	Subject     provider.ExternalSubject
}

// Authorization must be supplied by a trusted, current Security/CP authority
// at the point of execution. A caller's asserted role is never sufficient.
type Authorization struct {
	ActorID    string
	VerifiedAt time.Time
	ValidUntil time.Time
	DecisionID string
}

type Authorizer interface {
	AuthorizeContainment(context.Context, Intent) (Authorization, error)
}

type Phase string

const (
	PhaseFenced   Phase = "FENCED"
	PhaseDisabled Phase = "IDENTITY_DISABLED"
	PhaseRevoked  Phase = "SESSIONS_REVOKED"
	PhaseVerified Phase = "VERIFIED"
	PhaseUnknown  Phase = "UNKNOWN"
)

// The durable journal seals exactly one incident/operation/issuer/subject
// intent BEFORE side effects. UNKNOWN must not remove the security fence.
type Journal interface {
	Reserve(context.Context, Intent) (Phase, error)
	Mark(context.Context, string, Phase) error
}

// NativeProvider uses genuine provider admin methods with independent reads.
// It does not prove CP or domain authority.
type NativeProvider interface {
	provider.IdentityLifecycleManager
	provider.SessionRevoker
	provider.IdentityReader
	ActiveSessionCount(context.Context, provider.ExternalSubject) (int, error)
}

// CurrentResourceDenial is a fresh independent CP/resource readback, not a
// caller-supplied JWT or an assertion by the provider that it returned HTTP 2xx.
type CurrentResourceDenial struct {
	ExactSubjectDenied bool
	CanonicalDenied    bool
	ObservedAt         time.Time
	EvidenceReference  string
}

type ResourceWitness interface {
	VerifyCurrentDenial(context.Context, provider.ExternalSubject, string) (CurrentResourceDenial, error)
}

type Containment struct {
	Authority Authorizer
	Journal   Journal
	Provider  NativeProvider
	Resource  ResourceWitness
	Now       func() time.Time
}

// Execute permits only issuer+subject-scoped identity containment. A session,
// workload, federation, tenant or issuer incident needs its own purpose-bound
// command and authority check; this path must never widen its blast radius.
// Retried VERIFIED operations are reobserved rather than blindly accepted.
func (c *Containment) Execute(ctx context.Context, intent Intent) (err error) {
	if c == nil || ctx == nil || ctx.Err() != nil ||
		c.Authority == nil || c.Journal == nil || c.Provider == nil ||
		c.Resource == nil || c.Now == nil ||
		!operationID.MatchString(intent.OperationID) ||
		!operationID.MatchString(intent.IncidentID) ||
		intent.Subject.Validate() != nil {
		return errors.New("securityops: invalid or incomplete incident containment configuration")
	}
	now := c.Now().UTC()
	auth, authErr := c.Authority.AuthorizeContainment(ctx, intent)
	if authErr != nil || !operationID.MatchString(auth.ActorID) ||
		!operationID.MatchString(auth.DecisionID) ||
		auth.VerifiedAt.IsZero() || auth.VerifiedAt.After(now) ||
		now.Sub(auth.VerifiedAt) > time.Minute || !now.Before(auth.ValidUntil) {
		return errors.New("securityops: current independent containment authority unavailable")
	}
	phase, err := c.Journal.Reserve(ctx, intent)
	if err != nil {
		return errors.New("securityops: durable incident fence unavailable")
	}
	// No call to the provider may occur before the durable fence commits.
	defer func() {
		if err != nil {
			recovery, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = c.Journal.Mark(recovery, intent.OperationID, PhaseUnknown)
		}
	}()
	currentAuthorization := func() bool {
		fresh, e := c.Authority.AuthorizeContainment(ctx, intent)
		at := c.Now().UTC()
		return e == nil && fresh.ActorID == auth.ActorID && fresh.DecisionID == auth.DecisionID &&
			!fresh.VerifiedAt.IsZero() && !fresh.VerifiedAt.After(at) &&
			at.Sub(fresh.VerifiedAt) <= time.Minute && at.Before(fresh.ValidUntil)
	}
	if phase != PhaseVerified {
		if !currentAuthorization() {
			return errors.New("securityops: containment authorization changed before mutation")
		}
		if e := c.Provider.DisableIdentity(ctx, intent.Subject); e != nil {
			return errors.New("securityops: native identity disablement unconfirmed")
		}
		if e := c.confirmIdentity(ctx, intent.Subject); e != nil {
			return e
		}
		if e := c.Journal.Mark(ctx, intent.OperationID, PhaseDisabled); e != nil {
			return errors.New("securityops: disable receipt not durable")
		}
		if !currentAuthorization() {
			return errors.New("securityops: containment authorization changed before session revocation")
		}
		if e := c.Provider.RevokeSessions(ctx, intent.Subject); e != nil {
			return errors.New("securityops: native session revocation unconfirmed")
		}
		if e := c.Journal.Mark(ctx, intent.OperationID, PhaseRevoked); e != nil {
			return errors.New("securityops: revocation receipt not durable")
		}
	}
	if e := c.confirmIdentity(ctx, intent.Subject); e != nil {
		return e
	}
	count, e := c.Provider.ActiveSessionCount(ctx, intent.Subject)
	if e != nil || count != 0 {
		return errors.New("securityops: native sessions remain or readback failed")
	}
	denial, e := c.Resource.VerifyCurrentDenial(ctx, intent.Subject, intent.IncidentID)
	at := c.Now().UTC()
	if e != nil || !denial.ExactSubjectDenied || !denial.CanonicalDenied ||
		denial.ObservedAt.IsZero() || denial.ObservedAt.After(at) ||
		at.Sub(denial.ObservedAt) > time.Minute || denial.EvidenceReference == "" {
		return errors.New("securityops: current resource/CP denial unproven")
	}
	// Independent resource readback may block while CP or Security withdraws
	// the actor's incident authorization. Re-evaluate immediately before the
	// irreversible VERIFIED journal transition, including already-VERIFIED
	// replay paths; a withdrawal leaves UNKNOWN and never releases the fence.
	if ctx.Err() != nil || !currentAuthorization() {
		return errors.New("securityops: containment authority withdrawn before verified commit")
	}
	if e = c.Journal.Mark(ctx, intent.OperationID, PhaseVerified); e != nil {
		return errors.New("securityops: verification receipt not durable")
	}
	return nil
}

func (c *Containment) confirmIdentity(ctx context.Context, subject provider.ExternalSubject) error {
	observed, err := c.Provider.GetIdentity(ctx, subject)
	if err != nil || observed == nil ||
		observed.Issuer != subject.Issuer || observed.Subject != subject.Subject ||
		observed.Status != provider.IdentityStatusDisabled {
		return errors.New("securityops: native identity disable readback missing or mismatched")
	}
	return nil
}
