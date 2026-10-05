package keycloak

import (
	"context"
	"net/url"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// EnterpriseAdapter is the permanent bounded Keycloak capability. It does not
// implement native identity, workload issuance or provider selection.
type EnterpriseAdapter struct {
	Events                               *federation.BrokerEvents
	Governance                           federation.GovernanceAuthority
	Configuration                        federation.BrokerConfigurationAuthority
	ProviderID, EngineInstanceID, Issuer string
}

func (a *EnterpriseAdapter) snapshot(ctx context.Context, id string) (federation.TrustSnapshot, federation.BrokerConfiguration, error) {
	if a == nil || a.Events == nil || a.Governance == nil || a.Configuration == nil || a.ProviderID == "" || a.EngineInstanceID == "" || a.Issuer == "" {
		return federation.TrustSnapshot{}, federation.BrokerConfiguration{}, &provider.ProviderError{Kind: provider.ErrInvalidArgument, Message: "unbound enterprise adapter"}
	}
	s, err := a.Governance.Trust(ctx, id)
	if err != nil {
		return s, federation.BrokerConfiguration{}, err
	}
	if s.Trust.ProviderBinding.ProviderID != a.ProviderID || s.Trust.ProviderBinding.EngineInstanceID != a.EngineInstanceID {
		return s, federation.BrokerConfiguration{}, federation.ErrDenied
	}
	c, err := a.Configuration.BrokerConfiguration(ctx, s)
	if err != nil {
		return s, c, err
	}
	if c.Settings.Issuer != a.Issuer {
		return s, c, federation.ErrDenied
	}
	return s, c, nil
}
func (a *EnterpriseAdapter) BeginFederation(ctx context.Context, input provider.EnterpriseLogin) (provider.EnterpriseChallenge, error) {
	s, c, err := a.snapshot(ctx, input.TrustID)
	if err != nil {
		return provider.EnterpriseChallenge{}, err
	}
	result, err := a.Events.Begin(ctx, s, input.SessionDigest)
	if err != nil {
		return provider.EnterpriseChallenge{}, err
	}
	auth, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		return provider.EnterpriseChallenge{}, federation.ErrInvalid
	}
	q := auth.Query()
	q.Set("kc_idp_hint", c.Settings.ProviderRoute)
	auth.RawQuery = q.Encode()
	return provider.EnterpriseChallenge{EventID: result.EventID, State: result.State, Nonce: result.Nonce, PKCEVerifier: result.PKCEVerifier, AuthorizationURL: auth.String(), ExpiresAt: result.ExpiresAt}, nil
}
func (a *EnterpriseAdapter) CompleteFederation(ctx context.Context, input provider.EnterpriseCallback) (provider.EnterpriseEvent, error) {
	s, _, err := a.snapshot(ctx, input.TrustID)
	if err != nil {
		return provider.EnterpriseEvent{}, err
	}
	err = a.Events.Complete(ctx, s, federation.BrokerCallback{EventID: input.EventID, State: input.State, BrowserSecret: input.BrowserSecret, PKCEVerifier: input.PKCEVerifier, Code: input.Code, Issuer: input.Issuer})
	if err != nil {
		return provider.EnterpriseEvent{}, err
	}
	return provider.EnterpriseEvent{EventID: input.EventID}, nil
}

var _ provider.EnterpriseFederationProvider = (*EnterpriseAdapter)(nil)
