package ory

import (
	"context"
	"fmt"
	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// GovernedNativeHumanHandoff consumes current CP routing before EACH login and
// consent acceptance. It retains all native session and replay fences. The
// authority must cover the composed Kratos/Hydra runtime; this wrapper grants
// neither tenant membership nor canonical identity mapping. Only this
// composition accepts NativeHumanConfig.TokenProfiles, so governed buyer
// consent always runs under current CP dispatch authority.
type GovernedNativeHumanHandoff struct {
	mechanics *NativeHumanHandoff
	authority DispatchAuthority
}

func NewGovernedNativeHumanHandoff(c NativeHumanConfig, authority DispatchAuthority) (*GovernedNativeHumanHandoff, error) {
	if absentDispatchAuthority(authority) {
		return nil, fmt.Errorf("current CP dispatch authority required")
	}
	h, err := newNativeHumanHandoff(c)
	if err != nil {
		return nil, err
	}
	h.authority = authority
	return &GovernedNativeHumanHandoff{h, authority}, nil
}
func (h *GovernedNativeHumanHandoff) AcceptLogin(ctx context.Context, challenge string, credential NativeSessionCredential, intent humanauth.Request) (string, error) {
	if h == nil || ctx == nil {
		return "", fmt.Errorf("invalid governed handoff")
	}
	if err := h.authority.CheckCapability(ctx, provider.CapabilityHumanAuthentication); err != nil {
		return "", fmt.Errorf("current CP native dispatch denied")
	}
	return h.mechanics.AcceptLogin(ctx, challenge, credential, intent)
}
func (h *GovernedNativeHumanHandoff) AcceptConsent(ctx context.Context, challenge string, credential NativeSessionCredential, intent humanauth.Request, consented bool) (string, error) {
	if h == nil || ctx == nil {
		return "", fmt.Errorf("invalid governed handoff")
	}
	if err := h.authority.CheckCapability(ctx, provider.CapabilityHumanAuthentication); err != nil {
		return "", fmt.Errorf("current CP native dispatch denied")
	}
	return h.mechanics.AcceptConsent(ctx, challenge, credential, intent, consented)
}


// AuthenticatorAAL returns only the Kratos-verified current assurance level,
// after fresh CP dispatch and native whoami. No browser AAL or user claim is
// accepted as step-up evidence. This does not assign BAOBAB-A2/A3: the
// separately governed assurance policy controls that mapping.
func (h *GovernedNativeHumanHandoff) AuthenticatorAAL(ctx context.Context, credential NativeSessionCredential) (string, error) {
	if h == nil || h.mechanics == nil || h.authority == nil || ctx == nil || ctx.Err() != nil {
		return "", fmt.Errorf("native assurance unavailable")
	}
	if h.authority.CheckCapability(ctx, provider.CapabilityHumanAuthentication) != nil {
		return "", fmt.Errorf("current CP native dispatch denied")
	}
	session, err := h.mechanics.session(ctx, credential)
	if err != nil {
		return "", fmt.Errorf("native assurance unavailable")
	}
	if h.authority.CheckCapability(ctx, provider.CapabilityHumanAuthentication) != nil {
		return "", fmt.Errorf("current CP native dispatch denied")
	}
	return session.AAL, nil
}
