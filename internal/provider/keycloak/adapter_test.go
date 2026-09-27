package keycloak_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
)

func TestNewAdapter_RequiresConfig(t *testing.T) {
	_, err := keycloak.NewAdapter(keycloak.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnsupportedMethods(t *testing.T) {
	a, err := keycloak.NewAdapter(keycloak.Config{
		AdminURL:     "http://keycloak:8080",
		Realm:        "baobab",
		PublicIssuer: "https://iam.example/realms/baobab",
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.ProviderInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "keycloak" {
		t.Fatalf("name=%s", info.Name)
	}
	_, err = a.ProvisionIdentity(context.Background(), provider.IdentityProvisioningSpec{})
	if !provider.IsUnsupported(err) {
		t.Fatalf("expected unsupported, got %v", err)
	}
}

var _ provider.IdentityProvider = (*keycloak.Adapter)(nil)
