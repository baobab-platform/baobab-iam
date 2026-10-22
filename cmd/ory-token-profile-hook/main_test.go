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
			if _, err := configuredHook(config, key, nil, nil); err == nil {
				t.Fatal("missing authority accepted")
			}
			var typedNil *hookAuthority
			if _, err := configuredHook(config, key, typedNil, nil); err == nil {
				t.Fatal("typed nil accepted")
			}
			a := &hookAuthority{}
			hook, err := configuredHook(config, key, a, nil)
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
			hook, err = configuredHook(config, key, a, nil)
			if err != nil {
				t.Fatal(err)
			}
			if call(true) != http.StatusForbidden || a.calls != 2 {
				t.Fatal("PROVISIONED admission reached CP")
			}
		})
	}
}

// Human buyer issuance is opt-in through the separate consent seal key, which
// may never be the hook authentication key (ADR-0010 section 0.6).
func TestExecutableConsentSealKeyIsSeparateAndBounded(t *testing.T) {
	config := tokenprofile.Config{Environment: "staging", SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{"worker": {Environment: "staging", CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-cp"}}}}
	key := strings.Repeat("k", 32)
	if _, err := configuredHook(config, key, &hookAuthority{}, []byte(strings.Repeat("s", tokenprofile.MinConsentSealKeyBytes))); err != nil {
		t.Fatal(err)
	}
	for name, seal := range map[string][]byte{"hook key reused": []byte(key), "short": []byte("short"), "empty": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := configuredHook(config, key, &hookAuthority{}, seal); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
