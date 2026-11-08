package provider_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/keycloak"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// ProviderConformanceSuite checks the shared boundary against controlled HTTP
// fixtures. Unsupported adapter operations must be declared honestly. This
// harness does not certify a live provider or production cutover readiness.
func ProviderConformanceSuite(t *testing.T, adapter provider.IdentityProvider, issuer string) {
	t.Helper()
	ctx := context.Background()
	info, err := adapter.ProviderInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Issuer != issuer || info.Name != info.Capabilities.Provider {
		t.Fatal("provider metadata mismatch")
	}
	if info.Capabilities.PasswordImport || info.Capabilities.TOTPImport || info.Capabilities.PasskeyImport {
		t.Fatal("unverified imports advertised as supported")
	}
	for _, subject := range []provider.ExternalSubject{
		{Issuer: "https://foreign.example", Subject: "id"},
		{Issuer: issuer, Subject: " "},
	} {
		_, err := adapter.GetIdentity(ctx, subject)
		if !provider.IsInvalidArgument(err) {
			t.Fatalf("unsafe subject accepted: %v", err)
		}
		if err := adapter.DisableIdentity(ctx, subject); !provider.IsInvalidArgument(err) {
			t.Fatalf("unsafe disable: %v", err)
		}
		if err := adapter.RevokeSessions(ctx, subject); !provider.IsInvalidArgument(err) {
			t.Fatalf("unsafe revoke: %v", err)
		}
	}
	subject := provider.ExternalSubject{Issuer: issuer, Subject: "id"}
	identity, err := adapter.GetIdentity(ctx, subject)
	if info.Capabilities.HumanIdentity {
		if err != nil || identity == nil || identity.Issuer != issuer || identity.Subject != subject.Subject {
			t.Fatalf("normalized identity failed: identity=%+v err=%v", identity, err)
		}
		if err := adapter.DisableIdentity(ctx, subject); err != nil {
			t.Fatal(err)
		}
		if err := adapter.EnableIdentity(ctx, subject); err != nil {
			t.Fatal(err)
		}
	} else {
		if !provider.IsUnsupported(err) {
			t.Fatalf("undeclared read support: %v", err)
		}
		if err := adapter.DisableIdentity(ctx, subject); !provider.IsUnsupported(err) {
			t.Fatalf("undeclared lifecycle support: %v", err)
		}
	}
	err = adapter.RevokeSessions(ctx, subject)
	if info.Capabilities.SessionRevocation {
		if err != nil {
			t.Fatal(err)
		}
	} else if !provider.IsUnsupported(err) {
		t.Fatalf("undeclared session support: %v", err)
	}
}

func TestProviderConformanceSuite(t *testing.T) {
	// Preserve actual lifecycle state in this controlled Kratos HTTP fixture.
	// A GET that always reports ACTIVE makes a properly fail-closed adapter
	// reject the test itself rather than demonstrating a successful disable.
	var identityActive atomic.Bool
	identityActive.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/admin/identities/id" {
			w.Header().Set("Content-Type", "application/json")
			state := "inactive"
			if identityActive.Load() {
				state = "active"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "id", "state": state, "traits": map[string]any{"email": "source@example.com"}})
			return
		}
		if r.Method == http.MethodPatch && r.URL.Path == "/admin/identities/id" {
			var patch []map[string]any
			if json.NewDecoder(r.Body).Decode(&patch) != nil || len(patch) != 1 || patch[0]["path"] != "/state" || patch[0]["op"] != "replace" {
				t.Error("invalid provider lifecycle patch")
				http.Error(w, "invalid lifecycle patch", http.StatusBadRequest)
				return
			}
			state, ok := patch[0]["value"].(string)
			if !ok || (state != "active" && state != "inactive") {
				t.Error("invalid provider lifecycle target state")
				http.Error(w, "invalid target state", http.StatusBadRequest)
				return
			}
			identityActive.Store(state == "active")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/admin/identities/id/sessions" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	t.Run("OryAdapter", func(t *testing.T) {
		adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: server.URL, HydraAdminURL: server.URL, PublicIssuer: "https://identity.example"})
		if err != nil {
			t.Fatal(err)
		}
		ProviderConformanceSuite(t, adapter, "https://identity.example")
	})
	t.Run("KeycloakAdapter", func(t *testing.T) {
		adapter, err := keycloak.NewAdapter(keycloak.Config{AdminURL: server.URL, Realm: "baobab", PublicIssuer: "https://legacy.example/realms/baobab"})
		if err != nil {
			t.Fatal(err)
		}
		ProviderConformanceSuite(t, adapter, "https://legacy.example/realms/baobab")
	})
}
