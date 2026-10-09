package federation

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
)

// RuntimeBindingAuthority is a CP-owned current projection. Implementations must
// prove scope, current support/binding, profile and deployed artifact evidence.
// No implementation may infer these from provider configuration or local flags.
// The existing federation-only HTTP projection does not implement this port.
type RuntimeBindingAuthority interface {
	RuntimeBinding(context.Context, string, string, Scope, string) (PlatformSnapshot, error)
}

type RuntimeDispatchConfig struct {
	Resolver                                                      CapabilityResolver
	Contexts                                                      ResolutionContexts
	Platform                                                      RuntimeBindingAuthority
	Scope                                                         Scope
	CapabilityKey, ProviderID, EngineInstanceID, ServiceReference string
	Now                                                           func() time.Time
}

// RuntimeDispatch gates one composition-bound executable target. CP selects;
// the composition inventory cannot silently substitute another provider.
// Check must be called inside each operation, never cached as readiness.
type RuntimeDispatch struct{ config RuntimeDispatchConfig }

func NewRuntimeDispatch(c RuntimeDispatchConfig) (*RuntimeDispatch, error) {
	if absent(c.Resolver) || absent(c.Contexts) || absent(c.Platform) || c.Now == nil || !validScope(c.Scope) ||
		!providerPattern.MatchString(c.ProviderID) || len(c.ProviderID) < 10 || len(c.ProviderID) > 63 ||
		!instancePattern.MatchString(c.EngineInstanceID) || len(c.EngineInstanceID) < 6 || len(c.EngineInstanceID) > 63 ||
		!iamServiceReference.MatchString(c.ServiceReference) || len(c.ServiceReference) > 512 || runtimeFacet(c.CapabilityKey) == "" {
		return nil, ErrInvalid
	}
	return &RuntimeDispatch{c}, nil
}

func runtimeFacet(key string) string {
	switch key {
	case "identity.authentication.perform":
		return "HUMAN_AUTHENTICATION"
	case "identity.workload-token.issue":
		return "WORKLOAD_TOKEN_ISSUANCE"
	}
	return ""
}

func (d *RuntimeDispatch) resolve(ctx context.Context, h ResolutionContext) (CapabilityResolution, error) {
	c := d.config
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return CapabilityResolution{}, ErrUnavailable
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	correlation := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	r, err := c.Resolver.ResolveCapability(ctx, CapabilityRequest{c.CapabilityKey, 1, h.ContextID, correlation})
	if err != nil {
		return r, authorityError(err)
	}
	now := c.Now().UTC()
	if !validCapabilityID(r.ResolutionID, "res") || r.ContextID != h.ContextID || r.CorrelationID != correlation ||
		r.CapabilityKey != c.CapabilityKey || r.ContractVersion != 1 || r.Decision != "RESOLVED" || r.ReasonCode != "" ||
		!validCapabilityID(r.GrantID, "grant") || !validCapabilityID(r.BindingID, "bind") || r.Invocation == nil ||
		r.ResolvedAt.IsZero() || r.ResolvedAt.After(now) || r.ExpiresAt == nil || !now.Before(*r.ExpiresAt) ||
		!r.ResolvedAt.Before(*r.ExpiresAt) || r.ExpiresAt.After(h.ExpiresAt) {
		return r, ErrDenied
	}
	i := r.Invocation
	if i.ProviderID != c.ProviderID || i.EngineInstanceID != c.EngineInstanceID || i.ServiceReference != c.ServiceReference || i.Protocol != "http" || i.ContractVersion != 1 {
		return r, ErrDenied
	}
	return r, nil
}

func (d *RuntimeDispatch) profile(ctx context.Context) (PlatformSnapshot, error) {
	c := d.config
	p, err := c.Platform.RuntimeBinding(ctx, c.ProviderID, c.EngineInstanceID, c.Scope, runtimeFacet(c.CapabilityKey))
	if err != nil {
		return p, authorityError(err)
	}
	if p.ProviderID != c.ProviderID || p.EngineInstanceID != c.EngineInstanceID || p.Scope != c.Scope ||
		p.ProviderStatus != "ACTIVE" || p.InstanceStatus != "ACTIVE" || p.BindingStatus != "ACTIVE" ||
		p.RuntimeCapability != runtimeFacet(c.CapabilityKey) || p.SupportStatus != "VERIFIED" || p.ProfileRevision < 1 ||
		!digestPattern.MatchString(p.ArtifactDigest) || p.ArtifactDigest != p.DeployedArtifactDigest || !c.Now().UTC().Before(p.EvidenceExpiresAt) {
		return p, ErrDenied
	}
	return p, nil
}

func (d *RuntimeDispatch) Check(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	c := d.config
	started := c.Now().UTC()
	if started.IsZero() {
		return ErrInvalid
	}
	h, err := c.Contexts.Context(ctx)
	if err != nil {
		return authorityError(err)
	}
	if !validResolutionContextID(h.ContextID) || !started.Before(h.ExpiresAt) {
		return ErrDenied
	}
	r, err := d.resolve(ctx, h)
	if err != nil {
		return err
	}
	p, err := d.profile(ctx)
	if err != nil {
		return err
	}
	// Recheck resolution and profile after authority reads. Withdrawal or revision
	// drift denies this operation rather than silently switching its target.
	current, err := d.resolve(ctx, h)
	if err != nil {
		return err
	}
	latest, err := d.profile(ctx)
	if err != nil {
		return err
	}
	handle, err := c.Contexts.Context(ctx)
	if err != nil {
		return authorityError(err)
	}
	finished := c.Now().UTC()
	if finished.Before(started) || ctx.Err() != nil || handle != h || current.BindingID != r.BindingID || current.GrantID != r.GrantID ||
		latest != p || !finished.Before(h.ExpiresAt) || !finished.Before(*r.ExpiresAt) || !finished.Before(*current.ExpiresAt) || !finished.Before(p.EvidenceExpiresAt) {
		return ErrDenied
	}
	return nil
}

// CheckCapability prevents a workload gate being reused for human login, or vice versa.
func (d *RuntimeDispatch) CheckCapability(ctx context.Context, key string) error {
	if d == nil || key != d.config.CapabilityKey {
		return ErrDenied
	}
	return d.Check(ctx)
}
