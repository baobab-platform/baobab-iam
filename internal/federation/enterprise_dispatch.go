package federation

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// ResolutionContext is an IAM-workload-owned CP context handle and its upper
// lifetime bound. The protected source is renewed by the deployment's context
// acquisition process, not copied from estate login requests.
type ResolutionContext struct {
	ContextID string    `json:"context_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ResolutionContexts interface {
	Context(context.Context) (ResolutionContext, error)
}

type FileResolutionContexts struct{ Path string }

func (f FileResolutionContexts) Context(ctx context.Context) (ResolutionContext, error) {
	var out ResolutionContext
	if ctx == nil || ctx.Err() != nil || f.Path == "" || LoadServiceDocument(f.Path, &out) != nil {
		return ResolutionContext{}, ErrUnavailable
	}
	return out, nil
}

// EnterpriseAdapterBinding is a composition inventory of executable mechanics,
// not an authority registry. Entries convey no support, lifecycle, health,
// entitlement or approval; CP must select and independently verify every use.
type EnterpriseAdapterBinding struct {
	ProviderID, EngineInstanceID, ServiceReference string
	Adapter                                        provider.EnterpriseFederationProvider
}

// DispatchObservation contains safe decision metadata only. No token, callback,
// session, subject, assertion or configuration bytes reach the observer.
type DispatchObservation struct {
	ResolutionID, CorrelationID, ProviderID, EngineInstanceID, Outcome string
}

type EnterpriseDispatchConfig struct {
	Resolver   CapabilityResolver
	Contexts   ResolutionContexts
	Governance GovernanceAuthority
	Platform   PlatformAuthority
	Scope      Scope
	Adapters   []EnterpriseAdapterBinding
	Now        func() time.Time
	Observe    func(DispatchObservation)
}

type EnterpriseDispatch struct{ config EnterpriseDispatchConfig }

var iamServiceReference = regexp.MustCompile(`^service://baobab-iam(?:/[a-z0-9-]+)+$`)

func NewEnterpriseDispatch(c EnterpriseDispatchConfig) (*EnterpriseDispatch, error) {
	if absent(c.Resolver) || absent(c.Contexts) || absent(c.Governance) || absent(c.Platform) ||
		!validScope(c.Scope) || c.Now == nil || len(c.Adapters) == 0 || len(c.Adapters) > 16 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, binding := range c.Adapters {
		u, err := url.Parse(binding.ServiceReference)
		if !validBinding(Binding{binding.ProviderID, binding.EngineInstanceID, "ref_config", "ref_material"}) ||
			absent(binding.Adapter) || err != nil || u.Scheme != "service" || u.Host != "baobab-iam" ||
			u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path == "" ||
			!iamServiceReference.MatchString(binding.ServiceReference) || seen[binding.ProviderID+"/"+binding.EngineInstanceID] {
			return nil, ErrInvalid
		}
		seen[binding.ProviderID+"/"+binding.EngineInstanceID] = true
	}
	c.Adapters = slices.Clone(c.Adapters)
	return &EnterpriseDispatch{config: c}, nil
}

func (d *EnterpriseDispatch) selectAdapter(ctx context.Context, trustID string) (adapter provider.EnterpriseFederationProvider, err error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(trustID) {
		return nil, ErrInvalid
	}
	c := d.config
	observation := DispatchObservation{Outcome: "DENIED"}
	defer func() {
		if c.Observe != nil {
			if err == nil {
				observation.Outcome = "SELECTED"
			}
			c.Observe(observation)
		}
	}()
	now := c.Now().UTC()
	started := now
	if now.IsZero() {
		return nil, ErrInvalid
	}
	s, err := c.Governance.Trust(ctx, trustID)
	if err != nil {
		return nil, authorityError(err)
	}
	if ValidateTrust(s.Trust) != nil || s.Trust.UpdatedAt.After(now) || s.Trust.ID != trustID || s.Trust.Status != "ACTIVE" || s.Trust.Revision == 0 || s.ApprovedRevision != s.Trust.Revision ||
		!exact(s.SnapshotID) || !now.Before(s.ValidUntil) || !validBinding(s.Trust.ProviderBinding) ||
		!slices.Contains(s.Trust.OrganisationIDs, c.Scope.OrganisationID) || !slices.Contains(s.Trust.EstateIDs, c.Scope.EstateID) {
		return nil, ErrDenied
	}
	facet := RuntimeOIDCFederation
	if s.Trust.Protocol == "SAML2" {
		facet = RuntimeSAMLFederation
	} else if s.Trust.Protocol != "OIDC" {
		return nil, ErrUnsupported
	}
	contextHandle, err := c.Contexts.Context(ctx)
	if err != nil {
		return nil, authorityError(err)
	}
	if !validResolutionContextID(contextHandle.ContextID) || !now.Before(contextHandle.ExpiresAt) {
		return nil, ErrDenied
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, ErrUnavailable
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	correlation := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	observation.CorrelationID = correlation
	request := CapabilityRequest{"identity.authentication.perform", 1, contextHandle.ContextID, correlation}
	r, err := c.Resolver.ResolveCapability(ctx, request)
	if err != nil {
		return nil, authorityError(err)
	}
	now = c.Now().UTC()
	if !validCapabilityID(r.ResolutionID, "res") || r.ContextID != request.ContextID || r.CorrelationID != correlation ||
		r.CapabilityKey != request.CapabilityKey || r.Decision != "RESOLVED" || r.ReasonCode != "" ||
		r.ContractVersion != 1 || !validCapabilityID(r.GrantID, "grant") || !validCapabilityID(r.BindingID, "bind") ||
		r.ResolvedAt.IsZero() || r.ResolvedAt.After(now) || r.ExpiresAt == nil || !now.Before(*r.ExpiresAt) ||
		!r.ResolvedAt.Before(*r.ExpiresAt) || r.ExpiresAt.After(contextHandle.ExpiresAt) || r.Invocation == nil {
		return nil, ErrDenied
	}
	observation.ResolutionID = r.ResolutionID
	i := r.Invocation
	if i.ProviderID != s.Trust.ProviderBinding.ProviderID || i.EngineInstanceID != s.Trust.ProviderBinding.EngineInstanceID ||
		i.ContractVersion != 1 || i.Protocol != "http" {
		return nil, ErrDenied
	}
	observation.ProviderID, observation.EngineInstanceID = i.ProviderID, i.EngineInstanceID
	// Current CP profile/deployment evidence is a read-only projection. It cannot
	// replace the resolved grant/binding or activate provider support locally.
	p, err := c.Platform.FederationBinding(ctx, s.Trust.ProviderBinding, c.Scope, facet)
	if err != nil {
		return nil, authorityError(err)
	}
	if err = ValidateServicePlatformSnapshot(p, s.Trust.ProviderBinding, c.Scope, facet, c.Now().UTC()); err != nil {
		return nil, err
	}
	current, err := c.Governance.Trust(ctx, trustID)
	if err != nil {
		return nil, authorityError(err)
	}
	finished := c.Now().UTC()
	if finished.Before(started) || !sameSnapshot(s, current) || !finished.Before(s.ValidUntil) || !finished.Before(*r.ExpiresAt) ||
		!finished.Before(contextHandle.ExpiresAt) || !finished.Before(p.EvidenceExpiresAt) || ctx.Err() != nil {
		return nil, ErrDenied
	}
	for _, binding := range c.Adapters {
		if binding.ProviderID == i.ProviderID && binding.EngineInstanceID == i.EngineInstanceID && binding.ServiceReference == i.ServiceReference {
			return binding.Adapter, nil
		}
	}
	return nil, ErrUnsupported
}

func (d *EnterpriseDispatch) Check(ctx context.Context, trustID string) error {
	_, err := d.selectAdapter(ctx, trustID)
	return err
}

func (d *EnterpriseDispatch) BeginFederation(ctx context.Context, input provider.EnterpriseLogin) (provider.EnterpriseChallenge, error) {
	adapter, err := d.selectAdapter(ctx, input.TrustID)
	if err != nil {
		return provider.EnterpriseChallenge{}, err
	}
	return adapter.BeginFederation(ctx, input)
}

func (d *EnterpriseDispatch) CompleteFederation(ctx context.Context, input provider.EnterpriseCallback) (provider.EnterpriseEvent, error) {
	adapter, err := d.selectAdapter(ctx, input.TrustID)
	if err != nil {
		return provider.EnterpriseEvent{}, err
	}
	return adapter.CompleteFederation(ctx, input)
}

var _ provider.EnterpriseFederationProvider = (*EnterpriseDispatch)(nil)
