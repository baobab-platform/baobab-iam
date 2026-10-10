package provider

// Canonical Shared capability keys consumed by governed runtime operation gates.
// They name pinned Shared vocabulary; they are not CP grants or runtime authority.
const (
	CapabilityHumanAuthentication = "identity.authentication.perform"
	CapabilityWorkloadTokenIssue  = "identity.workload-token.issue"
)

// CanonicalSupport describes construction conformance to a pinned Shared
// capability. It is not CP ProviderCapabilitySupport or runtime authority.
// Mechanical ProviderInfo flags cannot promote these declarations.
type CanonicalSupport struct {
	CapabilityKey        string `json:"capability_key"`
	ContractVersions     []int  `json:"contract_versions"`
	ImplementationStatus string `json:"implementation_status"`
}

// CanonicalProviderDeclaration keeps combined adapters' implementations
// distinct. CP allocates actual provider and engine-instance identifiers.
type CanonicalProviderDeclaration struct {
	ProviderKey       string             `json:"provider_key"`
	ImplementationKey string             `json:"implementation_key"`
	Support           []CanonicalSupport `json:"support"`
}

type CanonicalSupportSource interface {
	CanonicalSupportDeclarations() []CanonicalProviderDeclaration
}
