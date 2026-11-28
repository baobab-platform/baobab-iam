package admin

import (
	"context"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

const revokeOAuthClient = "REVOKE_OAUTH_CLIENT"

var denialReference = regexp.MustCompile(`^ref_[a-z0-9_-]{8,128}$`)

// WorkloadTarget is a current, independently resolved scope-to-client binding.
// ResolveWorkloadTarget must restrict the target to the executor's reviewed issuer.
type WorkloadTarget struct {
	ScopeID    string
	Client     provider.ProviderWorkloadReference
	Revision   int64
	ValidUntil time.Time
}

type WorkloadTargetAuthority interface {
	ResolveWorkloadTarget(context.Context, Request) (WorkloadTarget, error)
}

// WorkloadIssuanceDisabler must verify the native grant change by reading the
// exact provider client back independently of the mutation response.
type WorkloadIssuanceDisabler interface {
	DisableWorkload(context.Context, provider.ProviderWorkloadReference) error
}

type WorkloadDenial struct {
	Target     WorkloadTarget
	Reference  string
	ObservedAt time.Time
}

// WorkloadDenialWitness returns original CP and resource evidence that
// previously issued authority is refused for the exact workload binding.
type WorkloadDenialWitness interface {
	VerifyWorkloadDenial(context.Context, Request, WorkloadTarget) (WorkloadDenial, error)
}

type WorkloadExecutionJournal interface {
	ReserveWorkloadExecution(context.Context, Request, WorkloadTarget) error
	VerifyWorkloadExecution(context.Context, Request, WorkloadDenial) error
}

type WorkloadRevoker struct {
	Lease   *BreakGlass
	Targets WorkloadTargetAuthority
	Hydra   WorkloadIssuanceDisabler
	Denial  WorkloadDenialWitness
	Journal WorkloadExecutionJournal
}

// Execute consumes one lease for one attempt. An interrupted or ambiguous
// attempt remains reserved for investigation and cannot silently run again.
func (e *WorkloadRevoker) Execute(ctx context.Context, request Request) error {
	if e == nil || ctx == nil || ctx.Err() != nil || e.Lease == nil ||
		e.Targets == nil || e.Hydra == nil || e.Denial == nil || e.Journal == nil ||
		request.Action != revokeOAuthClient || e.Lease.Check(ctx, request) != nil {
		return ErrBreakGlassDenied
	}
	target, err := e.Targets.ResolveWorkloadTarget(ctx, request)
	started := e.Lease.Now().UTC()
	if err != nil || target.ScopeID != request.ScopeID || target.Revision < 1 ||
		target.Client.ProviderClientID == "" || target.Client.LogicalClientID == "" ||
		!started.Before(target.ValidUntil) || e.Journal.ReserveWorkloadExecution(ctx, request, target) != nil {
		return ErrBreakGlassDenied
	}
	current, err := e.Targets.ResolveWorkloadTarget(ctx, request)
	if err != nil || !sameWorkloadTarget(current, target) || e.Lease.Check(ctx, request) != nil ||
		ctx.Err() != nil || !withinExecution(e.Lease.Now().UTC(), started, target.ValidUntil) {
		return ErrBreakGlassDenied
	}
	if e.Hydra.DisableWorkload(ctx, target.Client) != nil {
		return ErrBreakGlassDenied
	}
	changedAt := e.Lease.Now().UTC()
	proof, err := e.Denial.VerifyWorkloadDenial(ctx, request, target)
	if err != nil || !sameWorkloadTarget(proof.Target, target) || !denialReference.MatchString(proof.Reference) ||
		proof.ObservedAt.Before(changedAt) || e.Lease.Check(ctx, request) != nil {
		return ErrBreakGlassDenied
	}
	finished := e.Lease.Now().UTC()
	if ctx.Err() != nil || changedAt.Before(started) || !withinExecution(finished, changedAt, target.ValidUntil) ||
		proof.ObservedAt.After(finished) || finished.Sub(proof.ObservedAt) > time.Minute {
		return ErrBreakGlassDenied
	}
	return e.Journal.VerifyWorkloadExecution(ctx, request, proof)
}

func withinExecution(now, started, expires time.Time) bool {
	return !now.Before(started) && now.Before(expires)
}

func sameWorkloadTarget(left, right WorkloadTarget) bool {
	return left.ScopeID == right.ScopeID && left.Client == right.Client &&
		left.Revision == right.Revision && left.ValidUntil.Equal(right.ValidUntil)
}
