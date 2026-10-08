package main

import (
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecutableHookProductionRejectsMechanicsOnlyRegistration(t *testing.T) {
	for _, environment := range []string{"staging", "production"} {
		config := tokenprofile.Config{Environment: environment, SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{"worker": {Environment: environment, CredentialType: "client_credentials", Status: "PROVISIONED", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-cp"}}}}
		key := strings.Repeat("k", 32)
		hook, err := configuredHook(config, key)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(`{"session":{"client_id":"worker","id_token":{"subject":"worker"}},"request":{"client_id":"worker","grant_types":["client_credentials"],"requested_scopes":["context:resolve"],"granted_scopes":["context:resolve"],"granted_audience":["baobab-cp"],"payload":{"audience":["baobab-cp"],"scope":["context:resolve"]}}}`))
		request.Header.Set("X-Baobab-Token-Hook-Key", key)
		result := httptest.NewRecorder()
		hook.ServeHTTP(result, request)
		expected := http.StatusOK
		if environment == "production" {
			expected = http.StatusForbidden
		}
		if result.Code != expected {
			t.Fatalf("%s expected %d got %d", environment, expected, result.Code)
		}
	}
}
