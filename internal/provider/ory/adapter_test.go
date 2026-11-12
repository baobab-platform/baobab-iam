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
		HTTPClient:     ory.ProviderFixtureClient(srv),
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

// Disabling the Kratos record alone is not a confirmed kill-switch. All
// previous native sessions must be revoked and the disabled state reread.
// These are synthetic HTTP negative tests, not original real-provider evidence.
func TestDisableIdentityRequiresCurrentProviderRevocationAndReadback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failPatch   bool
		failRevoke  bool
		failRead    bool
		stillActive bool
		want        []string
		ok          bool
	}{
		{name: "success", want: []string{"PATCH", "DELETE", "GET"}, ok: true},
		{name: "patch-unavailable", failPatch: true, want: []string{"PATCH"}},
		{name: "revoke-unavailable", failRevoke: true, want: []string{"PATCH", "DELETE"}},
		{name: "readback-unavailable", failRead: true, want: []string{"PATCH", "DELETE", "GET"}},
		{name: "readback-remains-active", stillActive: true, want: []string{"PATCH", "DELETE", "GET"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method)
				if r.URL.Path != "/admin/identities/native-1" &&
					r.URL.Path != "/admin/identities/native-1/sessions" {
					http.NotFound(w, r)
					return
				}
				switch r.Method {
				case http.MethodPatch:
					if tc.failPatch {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				case http.MethodDelete:
					if tc.failRevoke {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				case http.MethodGet:
					if tc.failRead {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					state := "inactive"
					if tc.stillActive {
						state = "active"
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"native-1","state":"` + state + `","schema_id":"default"}`))
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			adapter, err := ory.NewAdapter(ory.Config{
				KratosAdminURL: server.URL,
				HydraAdminURL:  server.URL,
				PublicIssuer:   "https://native.example.test",
				HTTPClient:     ory.ProviderFixtureClient(server),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = adapter.DisableIdentity(context.Background(), provider.ExternalSubject{
				Issuer: "https://native.example.test", Subject: "native-1",
			})
			if (err == nil) != tc.ok {
				t.Fatalf("disable succeeded despite missing provider revocation/readback: %v", err)
			}
			if len(calls) != len(tc.want) {
				t.Fatalf("unexpected native calls: %v, expected %v", calls, tc.want)
			}
			for i := range calls {
				if calls[i] != tc.want[i] {
					t.Fatalf("native call order changed: %v, expected %v", calls, tc.want)
				}
			}
		})
	}
}

// Compile-time / runtime assertion that Adapter satisfies IdentityProvider.
var _ provider.IdentityProvider = (*ory.Adapter)(nil)

func TestUnverifiedCredentialImportsFailBeforeHTTP(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: server.URL, HydraAdminURL: server.URL, PublicIssuer: "https://identity.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, credentials := range []*provider.ImportedCredentials{
		{PasswordHash: &provider.PasswordHashImport{Algorithm: "bcrypt", Hash: "test"}},
		{TOTP: &provider.TOTPImport{Secret: "test"}},
		{WebAuthn: []provider.WebAuthnImport{{CredentialJSON: []byte(`{}`)}}},
	} {
		_, err := adapter.ProvisionIdentity(context.Background(), provider.IdentityProvisioningSpec{
			Traits: map[string]any{"email": "source@example.com"}, Credentials: credentials,
		})
		if !provider.IsUnsupported(err) {
			t.Fatalf("unverified import accepted: %v", err)
		}
	}
	if requests != 0 {
		t.Fatal("unverified credential material reached provider")
	}
}
