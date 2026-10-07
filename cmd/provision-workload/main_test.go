package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestFederatedWorkloadCannotFallBackToClientSecret(t *testing.T) {
	// Every federated_workload_token identity that has a client-secret path to refuse, including the ERP provisioner (shared#235).
	for id, scopes := range map[string][]string{
		"baobab-cp-workload":              {"billing:manage"},
		"baobab-cp-provisioning-workload": {"erp:provision"},
		"baobab-subscriptions-workload":   {"payment:execute"},
	} {
		err := provisionOne(context.Background(), nil, id, scopes, "")
		if err == nil || !strings.Contains(err.Error(), "federated_workload_token") {
			t.Fatalf("%s: expected fail-closed federated workload guard, got %v", id, err)
		}
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
