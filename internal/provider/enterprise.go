package provider

import (
	"context"
	"time"
)

// EnterpriseFederationProvider runs an approved, bound enterprise login. The
// result is opaque verified evidence for IAM consumption, never a canonical
// identity, business permission or provider-local account identifier.
type EnterpriseFederationProvider interface {
	BeginFederation(context.Context, EnterpriseLogin) (EnterpriseChallenge, error)
	CompleteFederation(context.Context, EnterpriseCallback) (EnterpriseEvent, error)
}
type EnterpriseLogin struct{ TrustID, SessionDigest string }
type EnterpriseChallenge struct {
	EventID, State, Nonce, PKCEVerifier, AuthorizationURL string
	ExpiresAt                                             time.Time
}
type EnterpriseCallback struct {
	TrustID, EventID, State, BrowserSecret, PKCEVerifier, Code, Issuer string
}
type EnterpriseEvent struct{ EventID string }
