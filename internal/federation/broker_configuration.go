package federation

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// BrokerSettings is reviewed native provider configuration, not token-derived
// routing. ProviderRoute is an opaque provider-specific IdP binding.
type BrokerSettings struct {
	Issuer, ClientID, AuthorizationEndpoint, TokenEndpoint, RedirectURI, ProviderRoute string
	SigningAlgorithm                                                                   string
	Confidential                                                                       bool
}
type SAMLSettings struct{ EntityID, ACSURL string }
type BrokerConfiguration struct {
	TrustID, SnapshotID string
	Revision            uint64
	Binding             Binding
	Settings            BrokerSettings
	BrokerJWKS          json.RawMessage
	Upstream            OIDCConfiguration
	SAML                SAMLSettings
	SigningCertificates []string
	ValidUntil          time.Time
}
type BrokerConfigurationAuthority interface {
	BrokerConfiguration(context.Context, TrustSnapshot) (BrokerConfiguration, error)
}

func (p *NativeProtocol) BrokerConfiguration(ctx context.Context, s TrustSnapshot) (BrokerConfiguration, error) {
	w, err := p.base(ctx, s)
	if err != nil {
		return BrokerConfiguration{}, err
	}
	w.ID = s.Trust.ProviderBinding.ConfigurationReference
	w.Kind = "federation_configuration"
	var settings NativeOIDCSettings
	configExpiry, err := p.read(ctx, w, &settings)
	if err != nil {
		return BrokerConfiguration{}, err
	}
	if settings.Broker == nil {
		return BrokerConfiguration{}, ErrUnsupported
	}
	w.ID = s.Trust.ProviderBinding.TrustMaterialReference
	w.Kind = "federation_trust_material"
	var material NativeOIDCTrustMaterial
	materialExpiry, err := p.read(ctx, w, &material)
	if err != nil {
		return BrokerConfiguration{}, err
	}
	c := BrokerConfiguration{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, Revision: s.ApprovedRevision, Binding: s.Trust.ProviderBinding, Settings: *settings.Broker, BrokerJWKS: material.BrokerJWKS, SigningCertificates: material.SigningCertificates, ValidUntil: minimum(s.ValidUntil, configExpiry, materialExpiry)}
	if settings.SAML != nil {
		c.SAML = *settings.SAML
	}
	c.Upstream = OIDCConfiguration{TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, Revision: s.ApprovedRevision, Binding: s.Trust.ProviderBinding, ClientID: settings.ClientID, SigningAlgorithm: settings.SigningAlgorithm, JWKS: material.JWKS, ValidUntil: c.ValidUntil}
	w.ID = s.Trust.ProviderBinding.ConfigurationReference
	w.Kind = "federation_configuration"
	if e, err := p.read(ctx, w, &settings); err != nil || e != configExpiry {
		return BrokerConfiguration{}, ErrUnverified
	}
	w.ID = s.Trust.ProviderBinding.TrustMaterialReference
	w.Kind = "federation_trust_material"
	if e, err := p.read(ctx, w, &material); err != nil || e != materialExpiry {
		return BrokerConfiguration{}, ErrUnverified
	}
	if _, err = p.base(ctx, s); err != nil {
		return BrokerConfiguration{}, err
	}
	return c, nil
}

func brokerURL(value string, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery {
		return nil, ErrInvalid
	}
	if u.Scheme != "https" && !(allowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return nil, ErrDenied
	}
	return u, nil
}
