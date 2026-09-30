package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestPersistGeneratedSecretRequiresPrivateOutput(t *testing.T) {
	w := &provider.ProviderWorkload{
		LogicalClientID: "baobab-cp-workload",
		ClientSecret:    "super-secret",
	}
	if _, err := persistGeneratedSecret("", w); err == nil {
		t.Fatal("expected generated secret to require ORY_SECRET_OUTPUT_DIR")
	}

	dir := filepath.Join(t.TempDir(), "secrets")
	path, err := persistGeneratedSecret(dir, w)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "baobab-cp-workload.client-secret") {
		t.Fatalf("path=%q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "super-secret\n" {
		t.Fatal("secret handoff did not preserve cleartext value")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o want 0600", info.Mode().Perm())
	}
}

func TestPersistGeneratedSecretNoopWhenUnchanged(t *testing.T) {
	path, err := persistGeneratedSecret("", &provider.ProviderWorkload{LogicalClientID: "existing"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "(unchanged)" {
		t.Fatalf("path=%q", path)
	}
}
