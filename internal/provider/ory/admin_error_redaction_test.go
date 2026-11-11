package ory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// ADR-0017: arbitrary upstream error bodies are not safe operational logs.
// A Kratos/Hydra admin reverse proxy can echo passwords, bearer tokens or
// client secrets on a malformed request. Only the operation/status may escape.
func TestKratosAdminErrorRedactsProviderBody(t *testing.T) {
	secret := "fixture-only-sensitive-bearer-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"token":"`+secret+`","private_key":"do-not-log"}`, http.StatusForbidden)
	}))
	defer server.Close()
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: server.URL,
		HydraAdminURL:  server.URL,
		PublicIssuer:   "https://identity.example",
		HTTPClient:     server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.GetIdentity(context.Background(), provider.ExternalSubject{
		Issuer:  "https://identity.example",
		Subject: "subject-1",
	})
	if err == nil {
		t.Fatal("provider denial was not propagated")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "private_key") ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("provider error disclosed secret material or lost safe status: %v", err)
	}
}

// Shared error mapping is also used by Hydra admin operations; a proxy that
// reflects workload secrets must not leak them into caller-visible errors.
func TestHydraAdminErrorRedactsProviderBody(t *testing.T) {
	secret := "fixture-only-hydra-client-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"client_secret":"`+secret+`","access_token":"do-not-log"}`, http.StatusForbidden)
	}))
	defer server.Close()
	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: server.URL,
		HydraAdminURL:  server.URL,
		PublicIssuer:   "https://identity.example",
		HTTPClient:     server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = adapter.DisableWorkload(context.Background(), provider.ProviderWorkloadReference{
		ProviderClientID: "bounded-client",
	})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "access_token") ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("Hydra admin error disclosed sensitive body or lost safe status: %v", err)
	}
}
