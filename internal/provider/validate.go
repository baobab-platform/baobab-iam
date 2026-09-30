package provider

import (
	"fmt"
	"time"
)

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

// Validate checks a no-static-secret federated workload trust request.
func (s FederatedWorkloadTrustSpec) Validate() error {
	if s.LogicalClientID == "" {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "LogicalClientID is required"}
	}
	if s.AssertionIssuer == "" || s.AssertionSubject == "" {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "AssertionIssuer and AssertionSubject are required"}
	}
	if len(s.AssertionJWK) == 0 {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "AssertionJWK public key is required"}
	}
	if kid, _ := s.AssertionJWK["kid"].(string); kid == "" {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "AssertionJWK must contain kid"}
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := s.AssertionJWK[privateField]; ok {
			return &ProviderError{Kind: ErrInvalidArgument, Message: fmt.Sprintf("AssertionJWK must contain public key material only; private field %q is forbidden", privateField)}
		}
	}
	if s.TrustExpiresAt.IsZero() || !s.TrustExpiresAt.After(time.Now().UTC()) {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "TrustExpiresAt must be in the future"}
	}
	if len(NormalizeAllowedScopes(s.AllowedScopes)) == 0 {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "AllowedScopes are required"}
	}
	if len(s.IntendedAudiences) == 0 {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "IntendedAudiences are required for consumer activation evidence"}
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

// NormalizeAllowedScopes preserves Shared's canonical authorization vocabulary
// while accepting the short-lived migration spelling used by early M4 work.
//
// Shared contracts/authorization/v1/scope-registry.yaml is authoritative:
//   - "context:resolve" is canonical.
//   - "context-resolve" was a migration-branch artefact and translates back to
//     the canonical scope; it MUST NOT create a second authorization meaning.
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
		// TRANSLATE only the migration-branch alias back to Shared authority.
		if s == "context-resolve" {
			s = "context:resolve"
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
