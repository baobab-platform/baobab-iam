package workloadresource

import (
	"context"
	"errors"
)

// Canonical provider capability name from the pinned Shared identity contract.
// It is a capability to resolve through CP, never a local support declaration.
const WorkloadIssueCapability = "identity.workload-token.issue"

// ResourceAuthorizer is the provider-neutral resource admission boundary.
// Gate and RegisteredGate both implement this contract.
type ResourceAuthorizer interface {
	Authorize(context.Context, string, Operation) error
}

// RegisteredProviderAuthority MUST perform fresh CP capability resolution
// and verify its current owner-controlled provider/instance/support/binding,
// scoped security-domain references, deployed artifact and revision. An IAM
// provider-health check or local config/registry is not an implementation.
type RegisteredProviderAuthority interface {
	CheckCapability(context.Context, string) error
}

// RegisteredGate requires current CP registration BOTH before and after
// resource-side issuer-status, CP-context, and native owner-policy enforcement.
// It grants nothing by itself; native operations must still recheck at commit.
// The two CP reads are deliberately NOT treated as an atomic cross-service
// transaction. Missing/currently revoked authority is DENY, never fallback.
type RegisteredGate struct {
	resource ResourceAuthorizer
	provider RegisteredProviderAuthority
}

// NewRegisteredGate is the ONLY public registered-gate constructor and
// requires the actual N03 signed issuer/current-CP/native Gate, not an
// arbitrary caller-controlled ResourceAuthorizer implementation.
func NewRegisteredGate(resource *Gate, provider RegisteredProviderAuthority) (*RegisteredGate, error) {
	return newRegisteredGate(resource, provider)
}

// Internal test hook permits negative unit fixtures without giving deployed
// consumers a supported path to skip cryptographic issuer validation.
func newRegisteredGate(resource ResourceAuthorizer, provider RegisteredProviderAuthority) (*RegisteredGate, error) {
	if absent(resource) || absent(provider) {
		return nil, ErrDenied
	}
	return &RegisteredGate{resource: resource, provider: provider}, nil
}

func (g *RegisteredGate) Authorize(ctx context.Context, bearer string, op Operation) error {
	if g == nil || absent(g.resource) || absent(g.provider) ||
		ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	if err := g.provider.CheckCapability(ctx, WorkloadIssueCapability); err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	if err := g.resource.Authorize(ctx, bearer, op); err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	if err := g.provider.CheckCapability(ctx, WorkloadIssueCapability); err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	return nil
}

// CheckRegisteredAuthority is useful to distinguish a real CP-denied
// issuer/binding from ordinary resource denial in INTERNAL diagnostics only.
// It is not an HTTP status code, an approval or a source of domain rights.
func (g *RegisteredGate) CheckRegisteredAuthority(ctx context.Context) error {
	if g == nil || absent(g.provider) || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	if err := g.provider.CheckCapability(ctx, WorkloadIssueCapability); err != nil || ctx.Err() != nil {
		return errors.Join(ErrDenied, err)
	}
	return nil
}

var _ ResourceAuthorizer = (*RegisteredGate)(nil)
var _ ResourceAuthorizer = (*Gate)(nil)
