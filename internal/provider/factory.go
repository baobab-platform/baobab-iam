package provider

import (
	"fmt"
	"strings"
)

// ProviderName identifies a concrete adapter implementation.
type ProviderName string

const (
	ProviderOry      ProviderName = "ory"
	ProviderKeycloak ProviderName = "keycloak"
)

// ParseProviderName normalizes a configuration string to a known ProviderName.
func ParseProviderName(s string) (ProviderName, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ory", "kratos", "hydra":
		return ProviderOry, nil
	case "keycloak", "kc":
		return ProviderKeycloak, nil
	default:
		return "", fmt.Errorf("provider: unknown name %q (want ory or keycloak)", s)
	}
}

// Note: concrete constructors live in subpackages (ory.NewAdapter,
// keycloak.NewAdapter). Callers that need a live IdentityProvider should
// construct the chosen adapter in the composition root (main/wire) using the
// matching Config type, after ParseProviderName selects the implementation.
//
// This package deliberately does not import ory/ or keycloak/ to avoid an
// import cycle and to keep the contract layer free of HTTP client details.
