package keycloak

import "github.com/baobab-platform/baobab-iam/internal/provider"

// CanonicalSupportDeclarations declares the permanent enterprise federation capability.
func (*EnterpriseAdapter) CanonicalSupportDeclarations() []provider.CanonicalProviderDeclaration {
	return []provider.CanonicalProviderDeclaration{{
		ProviderKey:       "baobab-iam.keycloak",
		ImplementationKey: "keycloak",
		Support: []provider.CanonicalSupport{{
			CapabilityKey:        provider.CapabilityEnterpriseFederation,
			ContractVersions:     []int{1},
			ImplementationStatus: "PARTIAL",
		}},
	}}
}

var _ provider.CanonicalSupportSource = (*EnterpriseAdapter)(nil)
