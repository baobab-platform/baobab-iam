package ory

import (
	"context"
	"errors"
	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testDispatchAuthority struct {
	calls int
	err   error
}

func (a *testDispatchAuthority) CheckCapability(context.Context, string) error {
	a.calls++
	return a.err
}

func TestGovernedTokenHookAuthenticatedCurrentAuthority(t *testing.T) {
	c := tokenprofile.Config{Environment: "production", SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{"worker": {Environment: "production", CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-cp"}}}}
	key := strings.Repeat("k", 32)
	if _, err := NewGovernedCanonicalTokenProfileHook(c, key, nil); err == nil {
		t.Fatal("nil authority accepted")
	}
	var nilAuthority *testDispatchAuthority
	if _, err := NewGovernedCanonicalTokenProfileHook(c, key, nilAuthority); err == nil {
		t.Fatal("typed nil authority accepted")
	}
	a := &testDispatchAuthority{}
	h, err := NewGovernedCanonicalTokenProfileHook(c, key, a)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"session":{"client_id":"worker","id_token":{"subject":"worker"}},"request":{"client_id":"worker","requested_scopes":["context:resolve"],"granted_scopes":["context:resolve"],"granted_audience":["baobab-cp"],"grant_types":["client_credentials"]}}`
	for _, scenario := range []string{"unauthenticated", "allowed", "withdrawn"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		expected := http.StatusOK
		if scenario != "unauthenticated" {
			req.Header.Set("X-Baobab-Token-Hook-Key", key)
		} else {
			expected = http.StatusUnauthorized
		}
		if scenario == "withdrawn" {
			a.err = errors.New("CP unavailable")
			expected = http.StatusForbidden
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != expected {
			t.Fatal(scenario, out.Code, out.Body.String())
		}
		if scenario == "unauthenticated" && a.calls != 0 {
			t.Fatal("unauthenticated sender reached authority")
		}
	}
	if a.calls != 2 {
		t.Fatal("authority cached")
	}
}
func TestGovernedNativeHandoffRejectsBeforeProviderAccess(t *testing.T) {
	a := &testDispatchAuthority{err: errors.New("withdrawn")}
	h := &GovernedNativeHumanHandoff{mechanics: &NativeHumanHandoff{}, authority: a}
	if _, err := h.AcceptLogin(context.Background(), "opaque", NativeSessionCredential{}, humanauth.Request{}); err == nil {
		t.Fatal("login accepted")
	}
	if _, err := h.AcceptConsent(context.Background(), "opaque", NativeSessionCredential{}, humanauth.Request{}, true); err == nil {
		t.Fatal("consent accepted")
	}
	if a.calls != 2 {
		t.Fatal("authority not rechecked")
	}
}
