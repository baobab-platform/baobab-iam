package ory

import (
	"encoding/json"
	"testing"
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
	out := mapImportedCredentials(&providerImportedCredsFixture())
	pw, ok := out["password"].(map[string]any)
	if !ok {
		t.Fatalf("password missing: %#v", out)
	}
	cfg := pw["config"].(map[string]any)
	if cfg["hashed_password"] != "$2a$10$example" {
		t.Fatalf("hashed_password: %#v", cfg)
	}
}

// local fixture to avoid importing provider types into a circular test helper style
func providerImportedCredsFixture() *struct {
	PasswordHash *struct {
		Algorithm string
		Hash      string
	}
} {
	return nil
}
