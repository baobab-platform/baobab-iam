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
}
