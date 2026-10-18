package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

type hookAuthority struct {
	denied bool
	calls  int
}

func (a *hookAuthority) CheckCapability(_ context.Context, key string) error {
	a.calls++
	if a.denied || key != provider.CapabilityWorkloadTokenIssue {
		return errors.New("denied")
	}
	return nil
}

// Test the actual command factory rather than just the provider constructor.
// Authentication and ACTIVE admission must precede CP, with no environment bypass.
func TestExecutableRequiresGovernedDispatchInEveryEnvironment(t *testing.T) {
	for _, environment := range []string{"development", "staging", "production"} {
		t.Run(environment, func(t *testing.T) {
			config := tokenprofile.Config{Environment: environment, SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{"worker": {Environment: environment, CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-cp"}}}}
			key := strings.Repeat("k", 32)
			if _, err := configuredHook(config, key, nil); err == nil {
				t.Fatal("missing authority accepted")
			}
			var typedNil *hookAuthority
			if _, err := configuredHook(config, key, typedNil); err == nil {
				t.Fatal("typed nil accepted")
			}
			a := &hookAuthority{}
			hook, err := configuredHook(config, key, a)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"session":{"client_id":"worker","id_token":{"subject":"worker"}},"request":{"client_id":"worker","grant_types":["client_credentials"],"requested_scopes":["context:resolve"],"granted_scopes":["context:resolve"],"granted_audience":["baobab-cp"],"payload":{}}}`
			call := func(authenticated bool) int {
				req := httptest.NewRequest("POST", "/", strings.NewReader(body))
				if authenticated {
					req.Header.Set("X-Baobab-Token-Hook-Key", key)
				}
				w := httptest.NewRecorder()
				hook.ServeHTTP(w, req)
				return w.Code
			}
			if call(false) != http.StatusUnauthorized || a.calls != 0 {
				t.Fatal("unauthenticated authority access")
			}
			if call(true) != http.StatusOK || a.calls != 1 {
				t.Fatal("current authority denied")
			}
			a.denied = true
			if call(true) != http.StatusForbidden || a.calls != 2 {
				t.Fatal("withdrawn authority accepted")
			}
			config.Workloads["worker"] = tokenprofile.Workload{Environment: environment, CredentialType: "client_credentials", Status: "PROVISIONED", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-cp"}}
			hook, err = configuredHook(config, key, a)
			if err != nil {
				t.Fatal(err)
			}
			if call(true) != http.StatusForbidden || a.calls != 2 {
				t.Fatal("PROVISIONED admission reached CP")
			}
		})
	}
}
