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
// neither tenant membership nor canonical identity mapping.
type GovernedNativeHumanHandoff struct {
	mechanics *NativeHumanHandoff
	authority DispatchAuthority
}

func NewGovernedNativeHumanHandoff(c NativeHumanConfig, authority DispatchAuthority) (*GovernedNativeHumanHandoff, error) {
	if absentDispatchAuthority(authority) {
		return nil, fmt.Errorf("current CP dispatch authority required")
	}
	h, err := NewNativeHumanHandoff(c)
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
