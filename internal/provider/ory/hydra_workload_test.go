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
		HTTPClient:     ory.ProviderFixtureClient(srv),
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

// TestHydraWorkloadDisableRefusesUnverifiedProviderReadback proves that a
// 200 admin PUT alone cannot certify token-issuer grant withdrawal.
func TestHydraWorkloadDisableRefusesUnverifiedProviderReadback(t *testing.T) {
	for _, behaviour := range []string{"ignores-write", "readback-error", "different-client", "verified"} {
		t.Run(behaviour, func(t *testing.T) {
			reads := 0
			puts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/clients/baobab-trade-workload" {
					http.NotFound(w, r)
					return
				}
				switch r.Method {
				case http.MethodGet:
					reads++
					if reads == 2 && behaviour == "readback-error" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					clientID := "baobab-trade-workload"
					grants := []string{"client_credentials"}
					if reads == 2 {
						if behaviour == "verified" || behaviour == "different-client" {
							grants = []string{}
						}
						if behaviour == "different-client" {
							clientID = "baobab-other-workload"
						}
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"client_id": clientID, "grant_types": grants,
						"scope": "actor-type-workload context:resolve",
					})
				case http.MethodPut:
					puts++
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			a, err := ory.NewAdapter(ory.Config{
				KratosAdminURL: server.URL, HydraAdminURL: server.URL,
				PublicIssuer: "https://issuer.example.test", HTTPClient: ory.ProviderFixtureClient(server),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = a.DisableWorkload(context.Background(), provider.ProviderWorkloadReference{
				LogicalClientID: "baobab-trade-workload",
			})
			if (err == nil) != (behaviour == "verified") {
				t.Fatalf("client grant withdrawal was misclassified: %v", err)
			}
			if reads != 2 || puts != 1 {
				t.Fatalf("issuer readback absent: reads=%d puts=%d", reads, puts)
			}
		})
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
			if putBody != nil {
				_ = json.NewEncoder(w).Encode(putBody)
				return
			}
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
		HTTPClient:     ory.ProviderFixtureClient(srv),
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

// TestProvisionWorkload_DisablesCreatedClientWhenConfigurationReadbackFails
// proves that a client created successfully is not left enabled when the
// independent issuer readback fails. A pre-existing client is never disabled.
func TestProvisionWorkload_DisablesCreatedClientWhenConfigurationReadbackFails(t *testing.T) {
	for _, behaviour := range []string{"verified-cleanup", "unverified-cleanup", "preexisting"} {
		t.Run(behaviour, func(t *testing.T) {
			reads, posts, puts := 0, 0, 0
			grants := []string{"client_credentials"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/clients/baobab-erp-people-reader-dev" && r.URL.Path != "/admin/clients" {
					http.NotFound(w, r)
					return
				}
				switch r.Method {
				case http.MethodGet:
					reads++
					if reads == 1 && behaviour != "preexisting" {
						http.NotFound(w, r)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"client_id":   "baobab-erp-people-reader-dev",
						"client_name": "People development reader",
						"grant_types": grants, "response_types": []string{},
						"scope":                      "context:resolve people:provider:read",
						"audience":                   []string{"baobab-control-plane"},
						"token_endpoint_auth_method": "client_secret_post",
						"metadata":                   map[string]any{"plan_digest": "approved-plan"},
						"client_credentials_grant_access_token_lifespan": "60s",
					})
				case http.MethodPost:
					posts++
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"client_id":"baobab-erp-people-reader-dev","client_secret":"synthetic-secret"}`)
				case http.MethodPut:
					puts++
					if behaviour == "verified-cleanup" {
						grants = []string{}
					}
					w.WriteHeader(http.StatusOK)
				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()

			adapter, err := ory.NewAdapter(ory.Config{
				KratosAdminURL: server.URL, HydraAdminURL: server.URL,
				PublicIssuer: "https://issuer.example.test",
				HTTPClient:   ory.ProviderFixtureClient(server),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = adapter.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{
				LogicalClientID:       "baobab-erp-people-reader-dev",
				DisplayName:           "People development reader",
				AllowedScopes:         []string{"context:resolve", "people:provider:read"},
				Audiences:             []string{"baobab-control-plane"},
				AuthMethod:            provider.WorkloadAuthClientSecret,
				AccessTokenTTLSeconds: 120,
				RequireNew:            true,
				Metadata:              map[string]string{"plan_digest": "approved-plan"},
			})
			if err == nil {
				t.Fatal("configuration readback mismatch was accepted")
			}
			switch behaviour {
			case "verified-cleanup":
				if !strings.Contains(err.Error(), "provider-side disable was verified") {
					t.Fatalf("verified cleanup was not reported: %v", err)
				}
				if reads != 4 || posts != 1 || puts != 1 {
					t.Fatalf("unexpected cleanup sequence: reads=%d posts=%d puts=%d", reads, posts, puts)
				}
			case "unverified-cleanup":
				if !strings.Contains(err.Error(), "issuer state UNKNOWN") {
					t.Fatalf("unverified cleanup was not fail-closed: %v", err)
				}
				if reads != 4 || posts != 1 || puts != 1 {
					t.Fatalf("unexpected cleanup sequence: reads=%d posts=%d puts=%d", reads, posts, puts)
				}
			case "preexisting":
				if !provider.IsAlreadyExists(err) {
					t.Fatalf("pre-existing client was not refused: %v", err)
				}
				if reads != 1 || posts != 0 || puts != 0 {
					t.Fatalf("pre-existing client was mutated: reads=%d posts=%d puts=%d", reads, posts, puts)
				}
			}
		})
	}
}
