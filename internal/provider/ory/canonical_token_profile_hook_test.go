package ory

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

// The sender fixture represents Hydra after credential verification. The live
// foundation suite independently tests Hydra's cryptographic verification;
// this test proves the actual canonical hook composition, not that signature.
func TestCanonicalTokenProfileHookComposition(t *testing.T) {
	for _, credential := range []string{"client_credentials", "federated_workload_token"} {
		t.Run(credential, func(t *testing.T) {
			for _, scenario := range []string{"allowed", "provisioned", "revoked", "missing-auth", "missing-audience", "substituted-audience", "extra-audience", "missing-scope", "inflated-scope", "subject-mismatch"} {
				t.Run(scenario, func(t *testing.T) {
					config := tokenprofile.Config{Environment: "production", SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{"worker": {Environment: "production", CredentialType: credential, Status: "ACTIVE", Scopes: []string{"context:resolve", "billing:read"}, Audiences: []string{"baobab-cp", "baobab-billing"}}}}
					grant, subject := "client_credentials", "worker"
					payload := map[string][]string{}
					if credential == "federated_workload_token" {
						grant, subject = tokenprofile.FederatedGrant, "service-account-worker"
						config.Bindings = map[string]tokenprofile.Binding{"worker": {Issuer: "https://projected.example", Subject: subject}}
						claims, _ := json.Marshal(map[string]string{"iss": "https://projected.example", "sub": subject})
						payload["assertion"] = []string{"e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature-fixture"}
					}
					key := strings.Repeat("k", 32)
					auth := key
					audiences := []string{"baobab-cp"}
					scopes := []string{"context:resolve"}
					expected := http.StatusForbidden
					switch scenario {
					case "allowed":
						expected = http.StatusOK
					case "provisioned", "revoked":
						p := config.Workloads["worker"]
						p.Status = strings.ToUpper(scenario)
						config.Workloads["worker"] = p
					case "missing-auth":
						auth = ""
						expected = http.StatusUnauthorized
					case "missing-audience":
						audiences = nil
					case "substituted-audience":
						audiences = []string{"unallocated-resource"}
					case "extra-audience":
						audiences = append(audiences, "baobab-billing")
					case "missing-scope":
						scopes = nil
					case "inflated-scope":
						scopes = []string{"context:resolve", "billing:read"}
					case "subject-mismatch":
						subject = "other"
					}
					hook, err := NewCanonicalTokenProfileHook(config, key)
					if err != nil {
						t.Fatal(err)
					}
					body, _ := json.Marshal(map[string]any{"session": map[string]any{"client_id": "worker", "id_token": map[string]string{"subject": subject}}, "request": map[string]any{"client_id": "worker", "grant_types": []string{grant}, "requested_scopes": scopes, "granted_scopes": []string{"context:resolve"}, "granted_audience": audiences, "payload": payload}})
					req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(string(body)))
					req.Header.Set("X-Baobab-Token-Hook-Key", auth)
					result := httptest.NewRecorder()
					hook.ServeHTTP(result, req)
					if result.Code != expected {
						t.Fatalf("want %d got %d", expected, result.Code)
					}
					if result.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("missing private response control")
					}
					if expected == http.StatusOK && !strings.Contains(result.Body.String(), `"actor_type":"workload"`) {
						t.Fatal("canonical workload claims missing")
					}
				})
			}
		})
	}
}
