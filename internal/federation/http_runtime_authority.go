package federation

import (
	"context"
	"crypto/tls"
	"time"
)

// RuntimeAuthorityTarget is reviewed composition configuration, not login input
// or a local registry. A separate adapter is bound to each exact CP target.
// Reference existence is not approval: deployment must supply approved immutable
// configuration and security-domain references. CP independently checks current
// reference ownership, lifecycle and the exact profile/release/deployment.
type RuntimeAuthorityTarget struct {
	ProviderID, EngineInstanceID                    string
	Scope                                           Scope
	RuntimeCapability                               string
	ConfigurationReference, SecurityDomainReference string
}

type HTTPRuntimeAuthority struct {
	transport *HTTPAuthority
	target    RuntimeAuthorityTarget
	now       func() time.Time
}

// NewHTTPRuntimeAuthority retains the hardened fixed-origin transport: verified
// TLS, current service credential per call, bounded strict JSON, no redirects,
// proxy environment, retries, provider-selected URLs or authority caching.
func NewHTTPRuntimeAuthority(origin string, tokens AuthorityTokens, tlsConfig *tls.Config,
	target RuntimeAuthorityTarget, now func() time.Time,
) (*HTTPRuntimeAuthority, error) {
	if !providerPattern.MatchString(target.ProviderID) || len(target.ProviderID) < 10 || len(target.ProviderID) > 63 ||
		!instancePattern.MatchString(target.EngineInstanceID) || len(target.EngineInstanceID) < 6 || len(target.EngineInstanceID) > 63 ||
		!validScope(target.Scope) || len(target.Scope.OrganisationID) < 3 ||
		(target.RuntimeCapability != "HUMAN_AUTHENTICATION" && target.RuntimeCapability != "WORKLOAD_TOKEN_ISSUANCE") ||
		!validRef(target.ConfigurationReference) || !validRef(target.SecurityDomainReference) || now == nil {
		return nil, ErrInvalid
	}
	transport, err := NewHTTPAuthority(origin, tokens, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &HTTPRuntimeAuthority{transport: transport, target: target, now: now}, nil
}

type runtimeBindingWire struct {
	ProviderID              string `json:"provider_id"`
	EngineInstanceID        string `json:"engine_instance_id"`
	OrganisationID          string `json:"organisation_id"`
	EstateID                string `json:"estate_id"`
	RuntimeCapability       string `json:"runtime_capability"`
	ConfigurationReference  string `json:"configuration_reference"`
	SecurityDomainReference string `json:"security_domain_reference"`
}

func (a *HTTPRuntimeAuthority) RuntimeBinding(ctx context.Context, providerID, instanceID string, scope Scope, facet string) (PlatformSnapshot, error) {
	if a == nil || a.now == nil || a.transport == nil || ctx == nil {
		return PlatformSnapshot{}, ErrInvalid
	}
	t := a.target
	if providerID != t.ProviderID || instanceID != t.EngineInstanceID || scope != t.Scope || facet != t.RuntimeCapability {
		return PlatformSnapshot{}, ErrDenied
	}
	started := a.now().UTC()
	if started.IsZero() {
		return PlatformSnapshot{}, ErrInvalid
	}
	var out PlatformSnapshot
	err := a.transport.call(ctx, "/internal/identity-runtime/v1/binding", runtimeBindingWire{
		t.ProviderID, t.EngineInstanceID, t.Scope.OrganisationID, t.Scope.EstateID,
		t.RuntimeCapability, t.ConfigurationReference, t.SecurityDomainReference,
	}, &out)
	if err != nil {
		return PlatformSnapshot{}, err
	}
	finished := a.now().UTC()
	if ctx.Err() != nil || finished.Before(started) || out.ProviderID != t.ProviderID || out.EngineInstanceID != t.EngineInstanceID ||
		out.Scope != t.Scope || out.RuntimeCapability != t.RuntimeCapability ||
		out.ProviderStatus != "ACTIVE" || out.InstanceStatus != "ACTIVE" || out.BindingStatus != "ACTIVE" ||
		out.SupportStatus != "VERIFIED" || out.ProfileRevision == 0 || !digestPattern.MatchString(out.ArtifactDigest) ||
		out.ArtifactDigest != out.DeployedArtifactDigest || !finished.Before(out.EvidenceExpiresAt) {
		return PlatformSnapshot{}, ErrUnverified
	}
	return out, nil
}

var _ RuntimeBindingAuthority = (*HTTPRuntimeAuthority)(nil)
