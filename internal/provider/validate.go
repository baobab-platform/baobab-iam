package provider

import (
	"fmt"
	"strings"
	"time"
)

func requireNonEmptyTrimmed(label, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: fmt.Sprintf("%s is required", label),
		}
	}
	return nil
}

// requireCanonicalEnum rejects values that are not already in canonical form.
// Security-sensitive enums must not accept padded input that later fails a
// raw equality comparison (audit finding: private_key_jwt → client_secret).
func requireCanonicalEnum(label, value string) error {
	if value != strings.TrimSpace(value) {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: fmt.Sprintf("%s must be canonical (no leading/trailing whitespace): %q", label, value),
		}
	}
	return nil
}

// Validate checks that ExternalSubject has both issuer and subject.
func (s ExternalSubject) Validate() error {
	if err := requireNonEmptyTrimmed("issuer", s.Issuer); err != nil {
		return err
	}
	if err := requireNonEmptyTrimmed("subject", s.Subject); err != nil {
		return err
	}
	return nil
}

// Validate checks required fields on a workload provisioning request.
// It does not contact the provider.
//
// AuthMethod and LifecycleStatus are fail-closed: non-canonical (padded)
// representations are rejected so downstream adapters never branch on a
// different string than Validate accepted.
func (s WorkloadProvisioningSpec) Validate() error {
	if err := requireNonEmptyTrimmed("LogicalClientID", s.LogicalClientID); err != nil {
		return err
	}
	if err := requireCanonicalEnum("AuthMethod", string(s.AuthMethod)); err != nil {
		return err
	}
	switch s.AuthMethod {
	case WorkloadAuthClientSecret, WorkloadAuthPrivateKeyJWT:
		// ok
	case WorkloadAuthFederatedJWTBearer:
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "federated JWT bearer workloads must use FederatedWorkloadTrustSpec instead of WorkloadProvisioningSpec",
		}
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
	if err := s.LifecycleStatus.ValidateForProvision(); err != nil {
		return err
	}
	if len(NormalizeAllowedScopes(s.AllowedScopes)) == 0 {
		return &ProviderError{
			Kind:    ErrInvalidArgument,
			Message: "AllowedScopes are required for workload provisioning",
		}
	}
	return nil
}

// Validate checks a no-static-secret federated workload trust request.
func (s FederatedWorkloadTrustSpec) Validate() error {
	if err := requireNonEmptyTrimmed("LogicalClientID", s.LogicalClientID); err != nil {
		return err
	}
	if err := requireNonEmptyTrimmed("AssertionIssuer", s.AssertionIssuer); err != nil {
		return err
	}
	if err := requireNonEmptyTrimmed("AssertionSubject", s.AssertionSubject); err != nil {
		return err
	}
	if len(s.AssertionJWK) == 0 {
		return &ProviderError{Kind: ErrInvalidArgument, Message: "AssertionJWK public key is required"}
	}
	if kid, _ := s.AssertionJWK["kid"].(string); strings.TrimSpace(kid) == "" {
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
	if err := s.LifecycleStatus.ValidateForProvision(); err != nil {
		return err
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
		s = strings.TrimSpace(s)
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
	if len(out) == 0 {
		return nil
	}
	return out
}
