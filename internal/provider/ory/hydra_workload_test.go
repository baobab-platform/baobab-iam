package ory_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// TestProvisionWorkload_CreateAndNormalizeScopes verifies M4 bootstrap:
// LogicalClientID is used as Hydra client_id, and the temporary migration alias
// context-resolve is translated back to Shared's canonical context:resolve.
func TestProvisionWorkload_CreateAndNormalizeScopes(t *testing.T) {
	var mu sync.Mutex
	var posted map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin/clients/"):
			// Not found → create path.
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/clients":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			_ = json.Unmarshal(body, &posted)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			// Echo minimal create response (secret may be echoed by Hydra).
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin.example", // unused for workload
		HydraAdminURL:  srv.URL,
		PublicIssuer:   "http://127.0.0.1:4444",
		HTTPClient:     srv.Client(),
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	wload, err := a.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		DisplayName:     "Baobab Trade Workload",
		// Migration alias plus a canonical Baobab workload permission.
		AllowedScopes: []string{"context-resolve", "provider-migration:task"},
		AuthMethod:    provider.WorkloadAuthClientSecret,
		Metadata: map[string]string{
			"gate": "IAM-M4",
		},
	})
	if err != nil {
		t.Fatalf("ProvisionWorkload: %v", err)
	}
	if wload.LogicalClientID != "baobab-trade-workload" {
		t.Fatalf("LogicalClientID: %q", wload.LogicalClientID)
	}
	if wload.ProviderClientID != "baobab-trade-workload" {
		t.Fatalf("ProviderClientID: %q (want stable logical id)", wload.ProviderClientID)
	}
	if wload.Issuer != "http://127.0.0.1:4444" {
		t.Fatalf("Issuer: %q", wload.Issuer)
	}
	if wload.ClientSecret == "" {
		t.Fatal("expected generated client secret on create")
	}

	mu.Lock()
	defer mu.Unlock()
	if posted == nil {
		t.Fatal("no POST body captured")
	}
	if posted["client_id"] != "baobab-trade-workload" {
		t.Fatalf("client_id: %#v", posted["client_id"])
	}
	scope, _ := posted["scope"].(string)
	if !strings.Contains(scope, "context:resolve") {
		t.Fatalf("scope missing canonical context:resolve after TRANSLATE: %q", scope)
	}
	if strings.Contains(scope, "context-resolve") {
		t.Fatalf("scope still has non-canonical migration alias context-resolve: %q", scope)
	}
	if !strings.Contains(scope, "provider-migration:task") {
		t.Fatalf("scope missing provider-migration:task: %q", scope)
	}
	grants, _ := posted["grant_types"].([]any)
	if len(grants) != 1 || grants[0] != "client_credentials" {
		t.Fatalf("grant_types: %#v", grants)
	}
}

// TestDisableWorkload_ClearsGrantTypes ensures soft-disable (M4 rollback path)
// clears grant_types without requiring DELETE (Keycloak client remains until dual-run ends).
func TestDisableWorkload_ClearsGrantTypes(t *testing.T) {
	var putBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/clients/baobab-trade-workload":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"client_id":"baobab-trade-workload",
				"client_name":"Baobab Trade Workload",
				"grant_types":["client_credentials"],
				"scope":"actor-type-workload context-resolve",
				"token_endpoint_auth_method":"client_secret_post"
			}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/clients/baobab-trade-workload":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &putBody)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin.example",
		HydraAdminURL:  srv.URL,
		PublicIssuer:   "http://127.0.0.1:4444",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	if err := a.DisableWorkload(context.Background(), provider.ProviderWorkloadReference{
		LogicalClientID: "baobab-trade-workload",
	}); err != nil {
		t.Fatalf("DisableWorkload: %v", err)
	}
	grants, _ := putBody["grant_types"].([]any)
	if len(grants) != 0 {
		t.Fatalf("expected empty grant_types on disable, got %#v", grants)
	}
}
