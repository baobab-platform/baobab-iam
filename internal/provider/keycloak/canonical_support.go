package keycloak

import "github.com/baobab-platform/baobab-iam/internal/provider"

// CanonicalSupportDeclarations declares the permanent enterprise implementation.
// Broker mechanics do not constitute the full human authentication contract.
func (*EnterpriseAdapter) CanonicalSupportDeclarations() []provider.CanonicalProviderDeclaration {
	return []provider.CanonicalProviderDeclaration{{ProviderKey: "baobab-iam.keycloak", ImplementationKey: "keycloak", Support: []provider.CanonicalSupport{{CapabilityKey: "identity.authentication.perform", ContractVersions: []int{1}, ImplementationStatus: "PARTIAL"}}}}
}

var _ provider.CanonicalSupportSource = (*EnterpriseAdapter)(nil)
