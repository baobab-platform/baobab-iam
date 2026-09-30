package provider

import "fmt"

// Validate checks that ExternalSubject has both issuer and subject.
func (s ExternalSubject) Validate() error {
	if s.Issuer == "" || s.Subject == "" {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "issuer and subject are required",
		}
	}
	return nil
}

// Validate checks required fields on a workload provisioning request.
// It does not contact the provider.
func (s WorkloadProvisioningSpec) Validate() error {
	if s.LogicalClientID == "" {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "LogicalClientID is required",
		}
	}
	switch s.AuthMethod {
	case WorkloadAuthClientSecret, WorkloadAuthPrivateKeyJWT:
		// ok
	case "":
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "AuthMethod is required",
		}
	default:
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: fmt.Sprintf("unknown AuthMethod %q", s.AuthMethod),
		}
	}
	return nil
}

// Validate checks that IdentityProvisioningSpec has traits and does not
// embed forbidden business keys in Traits (lightweight guard).
func (s IdentityProvisioningSpec) Validate() error {
	if len(s.Traits) == 0 {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "Traits are required",
		}
	}
	for _, forbidden := range []string{
		"tenant", "legal_entity", "legalEntity", "capability", "market",
		"buyer_purchase_limit", "erp_role", "supplier_approval",
	} {
		if _, ok := s.Traits[forbidden]; ok {
			return &ProviderError{
				Kind:    ErrInvalidArgument,
				Message: fmt.Sprintf("Traits must not contain business field %q (ADR-0020/0021)", forbidden),
			}
		}
	}
	return nil
}

// NormalizeAllowedScopes applies Gate IAM-M4 TRANSLATE rules for scope names
// frozen in Keycloak client JSON but normalized for Ory / shared contracts.
//
// ADR-IAM-0019 + gate-iam-m4-client-inventory:
//   - "context:resolve" (Keycloak defaultClientScopes spelling) → "context-resolve"
//
// Unknown scopes pass through unchanged (PRESERVE). Empty strings are dropped.
// The returned slice is a copy; the input is never mutated.
func NormalizeAllowedScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	out := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if s == "" {
			continue
		}
		// TRANSLATE: Keycloak historical scope name → Baobab freeze spelling.
		if s == "context:resolve" {
			s = "context-resolve"
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
