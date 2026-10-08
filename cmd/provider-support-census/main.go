// provider-support-census exports the actual adapters' construction declarations.
// It performs no network access and never emits runtime identifiers or authority.
package main

import (
	"encoding/json"
	"os"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func main() {
	var declarations []provider.CanonicalProviderDeclaration
	for _, source := range []provider.CanonicalSupportSource{(*ory.Adapter)(nil), (*keycloak.EnterpriseAdapter)(nil)} {
		declarations = append(declarations, source.CanonicalSupportDeclarations()...)
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Classification string                                  `json:"classification"`
		Providers      []provider.CanonicalProviderDeclaration `json:"providers"`
	}{"EXECUTABLE_CONSTRUCTION_CENSUS", declarations}); err != nil {
		os.Exit(1)
	}
}
