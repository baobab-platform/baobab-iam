package ory_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// ADR-0007: invalid native client IDs must not reach Hydra Admin and a
// mismatched readback must not become a mutation. These are protocol fixtures,
// NOT connected issuer/CP owner workload acceptance.
func TestHydraClientIdentityCannotSelectForeignAdminResource(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()
	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL, HydraAdminURL: srv.URL,
		PublicIssuer: "https://identity.example", HTTPClient: ory.ProviderFixtureClient(srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"..", "../operator", "unsafe/client", "unsafe?role=admin", "unsafe#fragment", "%2F", "foo\\bar", " spaced", "foo\nbar"} {
		t.Run(id, func(t *testing.T) {
			ref := provider.ProviderWorkloadReference{ProviderClientID: id}
			if err := a.DisableWorkload(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("malformed Hydra ID accepted: %v", err)
			}
			if err := a.SuspendWorkload(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("suspend accepted malformed Hydra ID: %v", err)
			}
			if _, err := a.RotateWorkloadCredentials(context.Background(), ref); !provider.IsInvalidArgument(err) {
				t.Fatalf("rotate accepted malformed Hydra ID: %v", err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("unsafe identities reached Hydra admin endpoint %d times", requests)
	}
}

func TestHydraMismatchedClientReadbackMustNotPermitDisable(t *testing.T) {
	reads, puts := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/admin/clients/expected-client" {
			reads++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "foreign-client", "grant_types": []string{"client_credentials"},
			})
			return
		}
		if r.Method == http.MethodPut {
			puts++
		}
		http.Error(w, "unexpected access", http.StatusForbidden)
	}))
	defer srv.Close()
	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: srv.URL, HydraAdminURL: srv.URL,
		PublicIssuer: "https://identity.example", HTTPClient: ory.ProviderFixtureClient(srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.DisableWorkload(context.Background(), provider.ProviderWorkloadReference{
		ProviderClientID: "expected-client",
	})
	if !errors.Is(err, &provider.ProviderError{Kind: provider.ErrConflict}) || reads != 1 || puts != 0 {
		t.Fatalf("foreign client response was allowed to trigger disable; err=%v reads=%d puts=%d", err, reads, puts)
	}
}

func TestHydraProvisioningRequiresOriginalCreateIdentity(t *testing.T) {
	for name, response := range map[string]string{
		"missing identity":   `{}`,
		"foreign identity":   `{"client_id":"foreign-client"}`,
		"malformed response": `{"client_id":`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/admin/clients" {
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, response)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			adapter, err := ory.NewAdapter(ory.Config{
				KratosAdminURL: server.URL, HydraAdminURL: server.URL,
				PublicIssuer: "https://identity.example", HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := adapter.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{
				LogicalClientID: "baobab-trade-workload", DisplayName: "Trade Workload",
				AllowedScopes: []string{"context:resolve"}, AuthMethod: provider.WorkloadAuthClientSecret,
			})
			if result != nil || !errors.Is(err, &provider.ProviderError{Kind: provider.ErrConflict}) {
				t.Fatalf("unverified provider response did not fail closed: %v", err)
			}
		})
	}
}
