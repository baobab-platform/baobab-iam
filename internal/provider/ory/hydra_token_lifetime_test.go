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

type workloadTTLTransport func(*http.Request) (*http.Response, error)

func (f workloadTTLTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Protocol-only tests: no issuer, registry row or runtime qualification exists.
func TestWorkloadTokenLifetimeIndependentReadback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		seconds  int
		existing bool
		override string
		deny     bool
	}{
		{name: "create-short", seconds: 60},
		{name: "update-short", seconds: 60, existing: true},
		{name: "equivalent-duration", seconds: 60, override: "1m0s"},
		{name: "minimum", seconds: 1},
		{name: "maximum", seconds: 300},
		{name: "create-default", seconds: 0},
		{name: "preserve-existing-default", seconds: 0, existing: true},
		{name: "ignored-despite-create-echo", seconds: 60, override: "1h", deny: true},
		{name: "ignored-update", seconds: 60, existing: true, override: "1h", deny: true},
		{name: "malformed-readback", seconds: 60, override: "invalid", deny: true},
		{name: "missing-readback", seconds: 60, override: "missing", deny: true},
		{name: "wrong-client-readback", seconds: 60, override: "foreign", deny: true},
		{name: "negative-before-io", seconds: -1, deny: true},
		{name: "over-limit-before-io", seconds: 301, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := map[string]any{"client_id": "unit-client", "grant_types": []string{"client_credentials"},
				"scope": "context:resolve", "token_endpoint_auth_method": "client_secret_post",
				"client_credentials_grant_access_token_lifespan": "30s"}
			exists, mutated, gets, calls := tc.existing, false, 0, 0
			transport := workloadTTLTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status, value := http.StatusOK, map[string]any{}
				switch r.Method {
				case http.MethodGet:
					gets++
					if !exists {
						status = http.StatusNotFound
						break
					}
					for k, v := range stored {
						value[k] = v
					}
					if mutated && tc.override != "" {
						switch tc.override {
						case "missing":
							delete(value, "client_credentials_grant_access_token_lifespan")
						case "foreign":
							value["client_id"] = "foreign-client"
						default:
							value["client_credentials_grant_access_token_lifespan"] = tc.override
						}
					}
				case http.MethodPost, http.MethodPut:
					if json.NewDecoder(r.Body).Decode(&value) != nil {
						t.Fatal("invalid admin request")
					}
					stored, exists, mutated = value, true, true
					if r.Method == http.MethodPost {
						status = http.StatusCreated
					}
				default:
					t.Fatal("unexpected admin method")
				}
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal("invalid protocol test observation")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})
			a, err := ory.NewAdapter(ory.Config{KratosAdminURL: "https://kratos.example.test", HydraAdminURL: "https://hydra.example.test",
				PublicIssuer: "https://issuer.example.test", HTTPClient: &http.Client{Transport: transport}})
			if err != nil {
				t.Fatal("adapter construction failed")
			}
			w, err := a.ProvisionWorkload(context.Background(), provider.WorkloadProvisioningSpec{LogicalClientID: "unit-client",
				AllowedScopes: []string{"context:resolve"}, AuthMethod: provider.WorkloadAuthClientSecret, AccessTokenTTLSeconds: tc.seconds})
			if tc.deny {
				if err == nil || w != nil {
					t.Fatal("invalid or unretained lifetime was accepted")
				}
				if (tc.seconds < 0 || tc.seconds > 300) && calls != 0 {
					t.Fatal("invalid ceiling reached provider I/O")
				}
				return
			}
			if err != nil || w == nil {
				t.Fatal("valid lifetime request denied")
			}
			if tc.seconds == 0 {
				if gets != 1 {
					t.Fatal("unspecified ceiling changed the provider-default path")
				}
				if tc.existing && stored["client_credentials_grant_access_token_lifespan"] != "30s" {
					t.Fatal("existing ceiling discarded")
				}
				if !tc.existing {
					if _, present := stored["client_credentials_grant_access_token_lifespan"]; present {
						t.Fatal("default ceiling invented")
					}
				}
			} else if gets != 2 {
				t.Fatal("ceiling was not independently read after mutation")
			}
			if tc.seconds == 60 && tc.override == "" {
				ref := provider.ProviderWorkloadReference{LogicalClientID: "unit-client"}
				if _, err := a.RotateWorkloadCredentials(context.Background(), ref); err != nil {
					t.Fatal("rotation failed")
				}
				if stored["client_credentials_grant_access_token_lifespan"] != "60s" {
					t.Fatal("rotation discarded token ceiling")
				}
				if err := a.DisableWorkload(context.Background(), ref); err != nil {
					t.Fatal("disable failed")
				}
				if stored["client_credentials_grant_access_token_lifespan"] != "60s" {
					t.Fatal("disable discarded token ceiling")
				}
			}
		})
	}
}
