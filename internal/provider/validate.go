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
