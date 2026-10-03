package ory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

func TestTokenProfileHookAuthenticatedAndGoverned(t *testing.T) {
	config := tokenprofile.Config{SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd", Workloads: map[string]tokenprofile.Workload{"trade": {CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-control-plane"}}}}
	key := strings.Repeat("k", 32)
	hook, err := NewTokenProfileHook(config, key)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"session":{"client_id":"trade","id_token":{"subject":"trade"},"extra":{"actor_type":"human","tenant_id":"forged"}},"request":{"client_id":"trade","grant_types":["client_credentials"],"requested_scopes":["context:resolve"],"granted_scopes":["context:resolve"],"granted_audience":["baobab-control-plane"],"payload":{"actor_type":["human"],"azp":["forged"],"tenant_id":["forged"]}}}`
	for _, name := range []string{"authenticated", "missing-auth", "wrong-auth", "wrong-client", "wrong-audience", "trailing-json", "oversized"} {
		t.Run(name, func(t *testing.T) {
			payload := body
			auth := key
			expected := http.StatusOK
			switch name {
			case "missing-auth":
				auth = ""
				expected = http.StatusUnauthorized
			case "wrong-auth":
				auth = strings.Repeat("x", 32)
				expected = http.StatusUnauthorized
			case "wrong-client":
				payload = strings.Replace(body, `"client_id":"trade"`, `"client_id":"other"`, 1)
				expected = http.StatusForbidden
			case "wrong-audience":
				payload = strings.ReplaceAll(body, "baobab-control-plane", "baobab-payments")
				expected = http.StatusForbidden
			case "trailing-json":
				payload += `{}`
				expected = http.StatusBadRequest
			case "oversized":
				payload = strings.Repeat(" ", 1<<20) + body
				expected = http.StatusBadRequest
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(payload))
			req.Header.Set("X-Baobab-Token-Hook-Key", auth)
			response := httptest.NewRecorder()
			hook.ServeHTTP(response, req)
			if response.Code != expected {
				t.Fatalf("expected %d, got %d", expected, response.Code)
			}
			if expected == http.StatusOK {
				var result struct {
					Session struct {
						Claims map[string]any `json:"access_token"`
					} `json:"session"`
				}
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Session.Claims["actor_type"] != "workload" || result.Session.Claims["azp"] != "trade" || len(result.Session.Claims) != 3 {
					t.Fatal("caller-controlled claims escaped policy")
				}
			}
		})
	}
	// Handler policy must not change if its caller later mutates configuration.
	p := config.Workloads["trade"]
	p.Scopes[0] = "billing:read"
	config.Workloads["trade"] = p
	req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(body))
	req.Header.Set("X-Baobab-Token-Hook-Key", key)
	response := httptest.NewRecorder()
	hook.ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatal("hook policy was mutated after construction")
	}
}
