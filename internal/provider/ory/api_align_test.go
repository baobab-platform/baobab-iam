package ory

import (
	"encoding/json"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// Ensures lifecycle disable/enable encodes RFC 6902 patch for /state.
func TestJSONPatchStateShape(t *testing.T) {
	patch := []jsonPatchOp{{
		Op:    "replace",
		Path:  "/state",
		Value: "inactive",
	}}
	b, err := json.Marshal(patch)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0]["op"] != "replace" || decoded[0]["path"] != "/state" {
		t.Fatalf("unexpected patch: %s", b)
	}
}

func TestMapImportedCredentialsHashedPassword(t *testing.T) {
	out := mapImportedCredentials(&provider.ImportedCredentials{
		PasswordHash: &provider.PasswordHashImport{
			Algorithm: "bcrypt",
			Hash:      "$2a$10$example",
		},
	})
	pw, ok := out["password"].(map[string]any)
	if !ok {
		t.Fatalf("password missing: %#v", out)
	}
	cfg := pw["config"].(map[string]any)
	if cfg["hashed_password"] != "$2a$10$example" {
		t.Fatalf("hashed_password: %#v", cfg)
	}
}
