package provider_test

import (
	"slices"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// These are source declarations, not CP ProviderCapabilitySupport grants.
// Every key here is canonical at the Shared pin; every support remains
// PARTIAL until the complete corresponding v1 contract is qualified.
func TestIAMCanonicalProviderSupportReconcilesSharedV1(t *testing.T) {
	oryDeclarations := (*ory.Adapter)(nil).CanonicalSupportDeclarations()
	keycloakDeclarations := (*keycloak.EnterpriseAdapter)(nil).CanonicalSupportDeclarations()
	decls := append(oryDeclarations, keycloakDeclarations...)

	want := map[string][]string{
		"baobab-iam.kratos": {
			provider.CapabilityHumanAuthentication,
			provider.CapabilityAuthenticationAssurance,
		},
		"baobab-iam.hydra": {
			provider.CapabilityWorkloadTokenIssue,
		},
		"baobab-iam.keycloak": {
			provider.CapabilityHumanAuthentication,
			provider.CapabilityEnterpriseFederation,
		},
	}
	seen := map[string]bool{}
	for _, declaration := range decls {
		keys, known := want[declaration.ProviderKey]
		if !known || seen[declaration.ProviderKey] {
			t.Fatalf("unexpected or duplicate provider %s", declaration.ProviderKey)
		}
		seen[declaration.ProviderKey] = true
		actual := make([]string, 0, len(declaration.Support))
		for _, support := range declaration.Support {
			if support.ImplementationStatus != "PARTIAL" {
				t.Fatalf("unsupported implementation promotion: %s %s", declaration.ProviderKey, support.CapabilityKey)
			}
			if !slices.Equal(support.ContractVersions, []int{1}) || slices.Contains(actual, support.CapabilityKey) {
				t.Fatalf("bad or duplicate v1 support: %s %s", declaration.ProviderKey, support.CapabilityKey)
			}
			actual = append(actual, support.CapabilityKey)
		}
		slices.Sort(actual)
		slices.Sort(keys)
		if !slices.Equal(actual, keys) {
			t.Fatalf("%s: actual support %v, expected %v", declaration.ProviderKey, actual, keys)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("incomplete canonical provider inventory: %v", seen)
	}
}
