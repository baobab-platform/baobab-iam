package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testAuthorityToken struct {
	value string
	err   error
}

func (t *testAuthorityToken) Token(context.Context) (string, error) { return t.value, t.err }
func tlsAuthority(t *testing.T, h http.HandlerFunc) (*HTTPAuthority, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	a, err := NewHTTPAuthority(server.URL, &testAuthorityToken{value: "service-token"}, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return a, server
}
func TestHTTPAuthorityAuthenticatedStrictTransport(t *testing.T) {
	_, f := setup(t, "oidc")
	calls := 0
	a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/internal/federation/v1/trust" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer service-token" || r.URL.RawQuery != "" {
			t.Error("credential/path binding")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.snapshot)
	})
	s, err := a.Trust(context.Background(), f.snapshot.Trust.ID)
	if err != nil || s.SnapshotID != f.snapshot.SnapshotID || calls != 1 {
		t.Fatal(s, err, calls)
	}
	if _, err = a.Trust(context.Background(), "../target"); err == nil || calls != 1 {
		t.Fatal("invalid ID reached source")
	}
}
func TestHTTPAuthorityFailuresNeverProduceProof(t *testing.T) {
	_, f := setup(t, "oidc")
	valid, _ := json.Marshal(f.snapshot)
	cases := []struct {
		name        string
		code        int
		media, body string
		want        error
	}{
		{"unauthorized", 401, "application/json", "{}", ErrDenied}, {"down", 503, "application/json", "secret-database-detail", ErrUnavailable}, {"unsupported", 501, "application/json", "{}", ErrUnsupported}, {"redirect", 302, "application/json", "{}", ErrUnavailable},
		{"unknown", 200, "application/json", `{"CallerBoolean":true}`, ErrInvalid}, {"duplicate", 200, "application/json", `{"SnapshotID":"a","SnapshotID":"b"}`, ErrInvalid}, {"null", 200, "application/json", `{"SnapshotID":null}`, ErrInvalid}, {"trailing", 200, "application/json", string(valid) + " {}", ErrInvalid}, {"oversize", 200, "application/json", strings.Repeat("a", 65537), ErrInvalid}, {"html", 200, "text/html", "{}", ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.Header().Set("Location", "https://credential-leak.example")
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			})
			out, err := a.Trust(context.Background(), f.snapshot.Trust.ID)
			if !errors.Is(err, tc.want) || out.SnapshotID != "" {
				t.Fatal(out, err)
			}
		})
	}
}
func TestHTTPAuthorityRejectsUnsafeConfigurationAndTLS(t *testing.T) {
	token := &testAuthorityToken{value: "x"}
	for _, origin := range []string{"http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?token=x", "https://example.test/#frag"} {
		if _, err := NewHTTPAuthority(origin, token, nil); err == nil {
			t.Fatal(origin)
		}
	}
	if _, err := NewHTTPAuthority("https://example.test", token, &tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Fatal("insecure accepted")
	}
	if _, err := NewHTTPAuthority("https://example.test", nil, nil); err == nil {
		t.Fatal("anonymous authority")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted server reached") }))
	defer server.Close()
	a, err := NewHTTPAuthority(server.URL, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Trust(context.Background(), proposalID)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestHTTPAuthorityFederationBindingUsesSnakeCaseWire(t *testing.T) {
	_, facts := setup(t, "oidc")
	a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/federation/v1/binding" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		if _, ok := wire["Binding"]; ok {
			t.Fatal("legacy Binding key emitted")
		}
		if _, ok := wire["Scope"]; ok {
			t.Fatal("legacy Scope key emitted")
		}
		if _, ok := wire["RuntimeCapability"]; ok {
			t.Fatal("legacy RuntimeCapability key emitted")
		}
		if _, ok := wire["binding"].(map[string]any); !ok {
			t.Fatalf("binding missing from %v", wire)
		}
		scope, ok := wire["scope"].(map[string]any)
		if !ok || scope["organisation_id"] != facts.platform.Scope.OrganisationID || scope["estate_id"] != facts.platform.Scope.EstateID {
			t.Fatalf("scope wire = %v", wire["scope"])
		}
		if wire["runtime_capability"] != facts.platform.RuntimeCapability {
			t.Fatalf("runtime capability wire = %v", wire["runtime_capability"])
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(facts.platform); err != nil {
			t.Fatal(err)
		}
	})
	out, err := a.FederationBinding(context.Background(), facts.bundle.Trust.ProviderBinding, facts.platform.Scope, facts.platform.RuntimeCapability)
	if err != nil {
		t.Fatal(err)
	}
	if out.ProviderID != facts.platform.ProviderID || out.RuntimeCapability != facts.platform.RuntimeCapability {
		t.Fatalf("snapshot = %#v", out)
	}
}

func TestHTTPAuthorityCPApprovalSourceWireUsesSnakeCase(t *testing.T) {
	_, facts := setup(t, "oidc")
	want := ReferenceExpectation{
		ID:               facts.snapshot.Trust.ProviderBinding.ConfigurationReference,
		Kind:             "federation_configuration",
		TrustID:          facts.snapshot.Trust.ID,
		SnapshotID:       facts.snapshot.SnapshotID,
		TrustRevision:    facts.snapshot.ApprovedRevision,
		ProviderID:       facts.snapshot.Trust.ProviderBinding.ProviderID,
		EngineInstanceID: facts.snapshot.Trust.ProviderBinding.EngineInstanceID,
		Scope:            facts.platform.Scope,
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	actorID := "33333333-3333-4333-8333-333333333333"
	validUntil := facts.clock.Add(time.Minute)

	t.Run("target", func(t *testing.T) {
		a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/internal/federation/v1/target" {
				t.Fatalf("path = %q", r.URL.Path)
			}
			var wire map[string]any
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
				t.Fatal(err)
			}
			if wire["trust_id"] != want.TrustID || wire["provider_id"] != want.ProviderID || wire["engine_instance_id"] != want.EngineInstanceID {
				t.Fatalf("target wire = %v", wire)
			}
			scope, ok := wire["scope"].(map[string]any)
			if !ok || scope["organisation_id"] != want.Scope.OrganisationID || scope["estate_id"] != want.Scope.EstateID {
				t.Fatalf("target scope = %v", wire["scope"])
			}
			if _, legacy := wire["TrustID"]; legacy {
				t.Fatal("legacy TrustID key emitted")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"digest": digest})
		})
		got, err := a.ResolveApprovedTarget(context.Background(), want)
		if err != nil || got != digest {
			t.Fatalf("target = %q err=%v", got, err)
		}
	})

	t.Run("approval-authority", func(t *testing.T) {
		a, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/internal/federation/v1/approval-authority" {
				t.Fatalf("path = %q", r.URL.Path)
			}
			var wire map[string]any
			if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
				t.Fatal(err)
			}
			if wire["action"] != "PROPOSE" || wire["subject_token"] != "human-governance-token.header.signature" {
				t.Fatalf("approval wire = %v", wire)
			}
			target, ok := wire["target"].(map[string]any)
			if !ok || target["trust_id"] != want.TrustID || target["snapshot_id"] != want.SnapshotID {
				t.Fatalf("approval target = %v", wire["target"])
			}
			if _, legacy := wire["Action"]; legacy {
				t.Fatal("legacy Action key emitted")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"principal_id": actorID,
				"valid_until":  validUntil,
			})
		})
		ctx, err := WithGovernanceSubjectToken(context.Background(), "human-governance-token.header.signature")
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.AuthorizeApproval(ctx, "PROPOSE", want)
		if err != nil || got.PrincipalID != actorID || !got.ValidUntil.Equal(validUntil) {
			t.Fatalf("actor = %#v err=%v", got, err)
		}
	})
}
