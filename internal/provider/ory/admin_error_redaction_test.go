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
		HTTPClient:     ory.ProviderFixtureClient(server),
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
