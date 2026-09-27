package ory_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func TestNewAdapter_RequiresConfig(t *testing.T) {
	_, err := ory.NewAdapter(ory.Config{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestNewAdapter_OK(t *testing.T) {
	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin:4434",
		HydraAdminURL:  "http://hydra-admin:4445",
		PublicIssuer:   "https://identity.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.ProviderInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "ory" || info.Issuer != "https://identity.example" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if !info.Capabilities.HumanIdentity || !info.Capabilities.WorkloadIdentity {
		t.Fatalf("capabilities: %+v", info.Capabilities)
	}
}

func TestRequireIssuerMismatch(t *testing.T) {
	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin:4434",
		HydraAdminURL:  "http://hydra-admin:4445",
		PublicIssuer:   "https://identity.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.GetIdentity(context.Background(), provider.ExternalSubject{
		Issuer:  "https://other.example",
		Subject: "x",
	})
	if !provider.IsInvalidArgument(err) {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

// Compile-time / runtime assertion that Adapter satisfies IdentityProvider.
var _ provider.IdentityProvider = (*ory.Adapter)(nil)
