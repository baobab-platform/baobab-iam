package ory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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


func TestGetIdentityPopulatesConfiguredIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/identities/id-1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"id-1",
			"schema_id":"default",
			"state":"active",
			"traits":{"email":"alice@example.com"},
			"metadata_public":{},
			"created_at":"2026-09-30T00:00:00Z",
			"updated_at":"2026-09-30T00:00:00Z"
		}`))
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL,
		HydraAdminURL:  "http://hydra-admin:4445",
		PublicIssuer:   "https://identity.example",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := a.GetIdentity(context.Background(), provider.ExternalSubject{
		Issuer:  "https://identity.example",
		Subject: "id-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "https://identity.example" {
		t.Fatalf("issuer=%q want configured issuer", got.Issuer)
	}
	if got.ExternalSubject().Issuer == "" {
		t.Fatal("ExternalSubject must never lose issuer")
	}
}

// Compile-time / runtime assertion that Adapter satisfies IdentityProvider.
var _ provider.IdentityProvider = (*ory.Adapter)(nil)
