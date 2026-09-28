package provider_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Forbidden canonical field names must not appear under internal/provider
// as required Baobab identity keys (Gate IAM-M1 evidence).
var forbiddenSnippets = []string{
	"keycloak_user_id",
	"ory_identity_id",
	"KeycloakUserID",
	"OryIdentityID",
}

func TestNoForbiddenCanonicalFieldNamesInProviderPackage(t *testing.T) {
	root := "."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			// Allow mention in this test file only.
			if strings.Contains(path, "forbidden_fields_test.go") {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(b)
		for _, snip := range forbiddenSnippets {
			if strings.Contains(content, snip) {
				t.Errorf("%s contains forbidden snippet %q", path, snip)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
