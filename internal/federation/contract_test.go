package federation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// CI validates JSON produced by these Go types against the exact pinned Shared
// schemas and semantic validator; no local substitute schema is authoritative.
func TestExportContractRecords(t *testing.T) {
	dir := os.Getenv("FEDERATION_CONTRACT_OUTPUT_DIR")
	if dir == "" {
		t.Skip("pinned Shared compatibility export is run by check-federation-contracts.py")
	}
	for _, protocol := range []string{"oidc", "saml2"} {
		_, f := setup(t, protocol)
		data, err := json.Marshal(f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, protocol+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, f := setup(t, "oidc")
	request := CapabilityRequest{"identity.authentication.perform", 1, "ctx_iamowned", "11111111-1111-4111-8111-111111111111"}
	response, err := (&dispatchResolver{f: f}).ResolveCapability(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"resolution-request": request, "resolution-response": response} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
