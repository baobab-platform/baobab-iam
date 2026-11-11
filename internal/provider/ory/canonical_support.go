package ory

import "github.com/baobab-platform/baobab-iam/internal/provider"

// CanonicalSupportDeclarations is secret-free construction metadata, independent
// of endpoints and credentials. Full Shared entry-path conformance is unfinished;
// admin operations and candidate token acceptance do not justify IMPLEMENTED.
func (*Adapter) CanonicalSupportDeclarations() []provider.CanonicalProviderDeclaration {
	return []provider.CanonicalProviderDeclaration{
		{ProviderKey: "baobab-iam.kratos", ImplementationKey: "kratos", Support: []provider.CanonicalSupport{{CapabilityKey: provider.CapabilityHumanAuthentication, ContractVersions: []int{1}, ImplementationStatus: "PARTIAL"}, {CapabilityKey: provider.CapabilityAuthenticationAssurance, ContractVersions: []int{1}, ImplementationStatus: "PARTIAL"}}},
		{ProviderKey: "baobab-iam.hydra", ImplementationKey: "hydra", Support: []provider.CanonicalSupport{{CapabilityKey: provider.CapabilityWorkloadTokenIssue, ContractVersions: []int{1}, ImplementationStatus: "PARTIAL"}}},
	}
}

var _ provider.CanonicalSupportSource = (*Adapter)(nil)
