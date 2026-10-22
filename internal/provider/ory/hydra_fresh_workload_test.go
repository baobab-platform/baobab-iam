package ory_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// Transport observations exercise denial boundaries only. They are not actual
// issuer provenance, named CMS identities, or a connected qualification receipt.
func TestFreshWorkloadIndependentSecurityReadback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing bool
		field    string
		value    any
	}{
		{name: "fresh"}, {name: "existing-refused-before-write", existing: true},
		{name: "extra-grant", field: "grant_types", value: []string{"client_credentials", "authorization_code"}},
		{name: "response-flow", field: "response_types", value: []string{"token"}},
		{name: "extra-scope", field: "scope", value: "context:validate content:entry:resolve"},
		{name: "duplicate-scope", field: "scope", value: "context:validate context:validate"},
		{name: "wrong-audience", field: "audience", value: []string{"foreign"}},
		{name: "wrong-auth", field: "token_endpoint_auth_method", value: "client_secret_basic"},
		{name: "redirect", field: "redirect_uris", value: []string{"https://example.test/callback"}},
		{name: "logout", field: "post_logout_redirect_uris", value: []string{"https://example.test/logout"}},
		{name: "cors", field: "allowed_cors_origins", value: []string{"https://example.test"}},
		{name: "key-url", field: "jwks_uri", value: "https://example.test/keys"},
		{name: "key-material", field: "jwks", value: map[string]any{"keys": []any{}}},
		{name: "wrong-owner", field: "metadata", value: map[string]any{"owner": "foreign"}},
		{name: "extra-metadata", field: "metadata", value: map[string]any{"owner": "unit-owner", "extra": true}},
		{name: "missing-grant", field: "grant_types", value: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exists, reads, writes := tc.existing, 0, 0
			var stored map[string]any
			transport := workloadTTLTransport(func(r *http.Request) (*http.Response, error) {
				status := http.StatusOK
				value := map[string]any{}
				switch r.Method {
				case http.MethodGet:
					reads++
					if !exists {
						status = http.StatusNotFound
						break
					}
					if stored != nil {
						for k, v := range stored {
							value[k] = v
						}
					}
					if tc.field != "" {
						value[tc.field] = tc.value
					}
				case http.MethodPost:
					writes++
					if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
						t.Fatal("invalid request")
					}
					stored = value
					exists = true
					status = http.StatusCreated
				default:
					t.Fatal("fresh workload attempted replacement")
				}
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})
			a, err := ory.NewAdapter(ory.Config{KratosAdminURL: "https://kratos.example.test", HydraAdminURL: "https://hydra.example.test", PublicIssuer: "https://issuer.example.test", HTTPClient: &http.Client{Transport: transport}})
			if err != nil {
				t.Fatal(err)
			}
			w, err := a.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{LogicalClientID: "unit-fresh", AllowedScopes: []string{"context:validate"}, Audiences: []string{"baobab-control-plane"}, AuthMethod: provider.WorkloadAuthClientSecret, RequireNew: true, AccessTokenTTLSeconds: 60, Metadata: map[string]string{"owner": "unit-owner"}})
			if tc.existing {
				if err == nil || w != nil || writes != 0 || reads != 1 {
					t.Fatal("existing client not refused before mutation")
				}
				return
			}
			if writes != 1 || reads != 2 {
				t.Fatal("creation was not independently read back")
			}
			if tc.field != "" {
				if err == nil || w != nil {
					t.Fatal("changed issuer authority accepted")
				}
				return
			}
			if err != nil || w == nil || len(w.ClientSecret) < 32 {
				t.Fatal("valid fresh client denied")
			}
		})
	}
}
