package keycloak_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
)

func TestNewAdapterRequiresConfig(t *testing.T) {
	_, err := keycloak.NewAdapter(keycloak.Config{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestUnsupportedProvisionIdentity(t *testing.T) {
	a, err := keycloak.NewAdapter(keycloak.Config{
		AdminURL:     "http://localhost:8080/admin",
		Realm:        "baobab",
		PublicIssuer: "https://iam.example/realms/baobab",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ProvisionIdentity(context.Background(), provider.IdentityProvisioningSpec{
		Traits: map[string]any{"email": "x@y.z"},
	})
	if !provider.IsUnsupported(err) {
		t.Fatalf("expected unsupported, got %v", err)
	}
}

func TestIssuerMismatchGetIdentity(t *testing.T) {
	a, err := keycloak.NewAdapter(keycloak.Config{
		AdminURL:     "http://localhost:8080/admin",
		Realm:        "baobab",
		PublicIssuer: "https://iam.example/realms/baobab",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.GetIdentity(context.Background(), provider.ExternalSubject{
		Issuer:  "https://other.example",
		Subject: "u1",
	})
	if !provider.IsInvalidArgument(err) {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestUnsupportedWorkload(t *testing.T) {
	a, err := keycloak.NewAdapter(keycloak.Config{
		AdminURL:     "http://localhost:8080/admin",
		Realm:        "baobab",
		PublicIssuer: "https://iam.example/realms/baobab",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		AuthMethod:      provider.WorkloadAuthClientSecret,
	})
	if !provider.IsUnsupported(err) {
		t.Fatalf("expected unsupported, got %v", err)
	}
}

var _ provider.IdentityProvider = (*keycloak.Adapter)(nil)
