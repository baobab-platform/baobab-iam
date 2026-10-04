package ory_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func TestProvisionFederatedWorkloadCreatesNoSecretClientAndExactTrust(t *testing.T) {
	var mu sync.Mutex
	var clientBody map[string]any
	var trustBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/clients/baobab-cp-workload":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/admin/clients":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			_ = json.Unmarshal(body, &clientBody)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(body)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/trust/grants/jwt-bearer/issuers":
			if got := r.URL.Query().Get("issuer"); got != "https://workload-issuer.example" {
				t.Fatalf("issuer query=%q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/trust/grants/jwt-bearer/issuers":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			_ = json.Unmarshal(body, &trustBody)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"id":"trust-cp-1",
				"allow_any_subject":false,
				"expires_at":"2026-10-01T12:00:00Z",
				"issuer":"https://workload-issuer.example",
				"scope":["billing:manage","billing:read"],
				"subject":"system:serviceaccount:baobab:baobab-cp-workload"
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin.example",
		HydraAdminURL:  srv.URL,
		PublicIssuer:   "https://identity.example",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	expires := time.Now().UTC().Add(24 * time.Hour)
	got, err := a.ProvisionFederatedWorkload(context.Background(), provider.FederatedWorkloadTrustSpec{
		LogicalClientID:  "baobab-cp-workload",
		DisplayName:      "Baobab Control Plane Workload",
		AllowedScopes:    []string{"billing:manage", "billing:read"},
		IntendedAudiences: []string{"baobab-subscriptions"},
		AssertionIssuer:  "https://workload-issuer.example",
		AssertionSubject: "system:serviceaccount:baobab:baobab-cp-workload",
		AssertionJWK: map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": "workload-2026-09",
			"x":   "11qYAYLef_qJaoX7nBdl5d9u0a4lV0V7MblzRc7QzYQ",
		},
		TrustExpiresAt: expires,
	})
	if err != nil {
		t.Fatalf("ProvisionFederatedWorkload: %v", err)
	}
	if got.TrustID != "trust-cp-1" || got.AuthMethod != provider.WorkloadAuthFederatedJWTBearer {
		t.Fatalf("unexpected trust result: %+v", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if clientBody["client_id"] != "baobab-cp-workload" {
		t.Fatalf("client_id=%v", clientBody["client_id"])
	}
	if clientBody["token_endpoint_auth_method"] != "none" {
		t.Fatalf("token_endpoint_auth_method=%v", clientBody["token_endpoint_auth_method"])
	}
	if _, ok := clientBody["client_secret"]; ok {
		t.Fatal("federated client must not contain client_secret")
	}
	if _, ok := clientBody["audience"]; ok {
		t.Fatal("Shared logical audience must not be copied into Hydra URL resource-indicator audience")
	}
	grants, _ := clientBody["grant_types"].([]any)
	if len(grants) != 1 || grants[0] != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatalf("grant_types=%#v", grants)
	}
	scope, _ := clientBody["scope"].(string)
	if !strings.Contains(scope, "billing:manage") || !strings.Contains(scope, "billing:read") {
		t.Fatalf("scope=%q", scope)
	}
	meta, _ := clientBody["metadata"].(map[string]any)
	if meta["baobab_credential_type"] != "federated_workload_token" {
		t.Fatalf("metadata=%#v", meta)
	}

	if trustBody["allow_any_subject"] != false {
		t.Fatalf("allow_any_subject=%v", trustBody["allow_any_subject"])
	}
	if trustBody["issuer"] != "https://workload-issuer.example" {
		t.Fatalf("trust issuer=%v", trustBody["issuer"])
	}
	if trustBody["subject"] != "system:serviceaccount:baobab:baobab-cp-workload" {
		t.Fatalf("trust subject=%v", trustBody["subject"])
	}
	jwk, _ := trustBody["jwk"].(map[string]any)
	if jwk["kid"] != "workload-2026-09" {
		t.Fatalf("jwk=%#v", jwk)
	}
}

func TestFederatedWorkloadTrustRejectsPrivateJWK(t *testing.T) {
	spec := provider.FederatedWorkloadTrustSpec{
		LogicalClientID:   "baobab-cp-workload",
		AllowedScopes:     []string{"billing:manage"},
		IntendedAudiences: []string{"baobab-subscriptions"},
		AssertionIssuer:   "https://workload-issuer.example",
		AssertionSubject:  "cp",
		AssertionJWK:      map[string]any{"kty": "RSA", "kid": "x", "n": "abc", "e": "AQAB", "d": "private"},
		TrustExpiresAt:     time.Now().UTC().Add(time.Hour),
	}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected private JWK material to be rejected")
	}
}

func TestRotateWorkloadCredentialsRejectsFederatedWorkload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/clients/baobab-cp-workload":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"client_id":"baobab-cp-workload","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"],"token_endpoint_auth_method":"none","metadata":{"baobab_credential_type":"federated_workload_token"}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/admin/clients/baobab-cp-workload":
			t.Fatal("rotateClientCredentials must not write a static secret for a federated workload")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: "http://kratos-admin.example",
		HydraAdminURL:  srv.URL,
		PublicIssuer:   "https://identity.example",
		HTTPClient:     srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = a.RotateWorkloadCredentials(context.Background(), provider.ProviderWorkloadReference{LogicalClientID: "baobab-cp-workload"})
	if err == nil {
		t.Fatal("expected federated workload secret rotation to be rejected")
	}
}
