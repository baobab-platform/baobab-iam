package federation

import (
	"context"
	"crypto/tls"
	"time"
)

// RuntimeComposition is reviewed deployment configuration. None of it may be
// deserialized from a token request. Credential files are independently rotated
// by deployment; configuration-reference existence does not imply approval.
type RuntimeComposition struct {
	CPOrigin                string               `json:"cp_origin"`
	ResolutionTokenFile     string               `json:"resolution_token_file"`
	RuntimeTokenFile        string               `json:"runtime_token_file"`
	ContextTarget           RuntimeContextTarget `json:"context_target"`
	ProviderID              string               `json:"provider_id"`
	EngineInstanceID        string               `json:"engine_instance_id"`
	EstateID                string               `json:"estate_id"`
	ServiceReference        string               `json:"service_reference"`
	ConfigurationReference  string               `json:"configuration_reference"`
	SecurityDomainReference string               `json:"security_domain_reference"`
}

// StartRuntimeComposition builds the production C4-01 adapters and supervises
// caller-owned context acquisition. Separate credentials retain least privilege
// for context/capability reads and runtime-profile reads. It allocates no grants.
func StartRuntimeComposition(ctx context.Context, c RuntimeComposition, capability string, tlsConfig *tls.Config) (*RuntimeDispatch, *SupervisedContexts, error) {
	if c.ResolutionTokenFile == "" || c.RuntimeTokenFile == "" {
		return nil, nil, ErrInvalid
	}
	resolver, err := NewHTTPAuthority(c.CPOrigin, FileAuthorityTokens{c.ResolutionTokenFile}, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	scope := Scope{OrganisationID: c.ContextTarget.OrganisationID, EstateID: c.EstateID}
	platform, err := NewHTTPRuntimeAuthority(c.CPOrigin, FileAuthorityTokens{c.RuntimeTokenFile}, tlsConfig, RuntimeAuthorityTarget{ProviderID: c.ProviderID, EngineInstanceID: c.EngineInstanceID, Scope: scope, RuntimeCapability: runtimeFacet(capability), ConfigurationReference: c.ConfigurationReference, SecurityDomainReference: c.SecurityDomainReference}, time.Now)
	if err != nil {
		return nil, nil, err
	}
	// Validate static target before starting a worker or contacting CP.
	dispatch, err := NewRuntimeDispatch(RuntimeDispatchConfig{Resolver: resolver, Contexts: FileResolutionContexts{}, Platform: platform, Scope: scope, CapabilityKey: capability, ProviderID: c.ProviderID, EngineInstanceID: c.EngineInstanceID, ServiceReference: c.ServiceReference, Now: time.Now})
	if err != nil {
		return nil, nil, err
	}
	contexts, err := StartSupervisedContexts(ctx, func(call context.Context) (ResolutionContext, error) {
		return resolver.AcquireRuntimeContext(call, c.ContextTarget, time.Now)
	}, time.Now, 5*time.Second, 15*time.Second)
	if err != nil {
		return nil, nil, err
	}
	dispatch.config.Contexts = contexts
	return dispatch, contexts, nil
}
