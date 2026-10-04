// Test-only harness compiled inside an unchanged, immutable CP checkout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/baobab-platform/baobab-cp/api"
	"github.com/baobab-platform/baobab-cp/internal/auth"
	"github.com/baobab-platform/baobab-cp/internal/domain"
	"github.com/baobab-platform/baobab-cp/internal/repository"
	"github.com/baobab-platform/baobab-cp/internal/store"
)

const issuer = "http://127.0.0.1:4444"

type input struct {
	Validator string `json:"validator"`
	Subject   string `json:"subject"`
	Scenario  string `json:"scenario"`
}

// Embedding fails closed for operations this fixture never invokes.
type tenants struct {
	store.TenantStore
	suspended bool
}

func (s tenants) GetTenant(_ context.Context, id string) (domain.Tenant, error) {
	if id != "tn_m4fixture" {
		return domain.Tenant{}, domain.NotFoundError("fixture tenant absent")
	}
	state := string(domain.LifecycleActive)
	if s.suspended {
		state = string(domain.LifecycleSuspended)
	}
	return domain.Tenant{TenantID: id, ObservedState: state}, nil
}

func run(in input) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var audit bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&audit, nil)))
	verifier, err := auth.NewOIDCVerifier(ctx, issuer, "baobab-control-plane")
	if err != nil {
		return nil, err
	}
	// Use CP's real registry parser; names and authority are CI-only fixtures.
	dir, err := os.MkdirTemp("", "iam-cp-route-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	status := "ACTIVE"
	if in.Scenario == "revoked-validator" {
		status = "REVOKED"
	}
	registryFile := filepath.Join(dir, "registry.yaml")
	registryBody := "workloads:\n  m4-ci-validator:\n    status: " + status + "\n    allowed_scopes: [context:validate]\n    validates_audiences: [baobab-erp]\n  m4-ci-unregistered:\n    status: ACTIVE\n    allowed_scopes: [context:validate]\n  m4-ci-no-scope:\n    status: ACTIVE\n    allowed_scopes: [context:resolve]\n"
	if err := os.WriteFile(registryFile, []byte(registryBody), 0600); err != nil {
		return nil, err
	}
	registry, err := auth.LoadWorkloadRegistryFile(registryFile)
	if err != nil {
		return nil, err
	}
	repo := repository.NewInMemoryRepository()
	identities := map[string]string{}
	for _, name := range []string{"m4-ci-subject", "m4-ci-other-subject", "m4-ci-validator"} {
		id := domain.NewPrincipalID()
		if err := repo.CreateIdentity(ctx, domain.Principal{ID: id, ActorType: "workload", Status: "ACTIVE"}); err != nil {
			return nil, err
		}
		linkStatus := "ACTIVE"
		if in.Scenario == "revoked-external-link" && name == "m4-ci-subject" {
			linkStatus = "REVOKED"
		}
		if err := repo.LinkExternalIdentity(ctx, domain.ExternalIdentity{ID: domain.NewExternalIdentityID(), PrincipalID: id, Issuer: issuer, Subject: name, Status: linkStatus}); err != nil {
			return nil, err
		}
		identities[name] = id
	}
	now := time.Now().UTC()
	expiry := now.Add(5 * time.Minute)
	owner := identities["m4-ci-subject"]
	if in.Scenario == "other-owner" {
		owner = identities["m4-ci-other-subject"]
	}
	if in.Scenario == "validator-owner" {
		owner = identities["m4-ci-validator"]
	}
	stored := domain.Context{ID: domain.NewUUIDv7(), PrincipalID: owner, TenantID: "tn_m4fixture", LegalEntityID: "M4-FIXTURE",
		CorrelationID: domain.NewUUIDv7(), ResolvedAt: now, ExpiresAt: &expiry,
		Provenance: map[string]domain.ContextSource{"tenant_id": {Source: "isolated-cp-fixture", TrustLevel: domain.TrustSystem}}}
	if in.Scenario == "unbounded" {
		stored.ExpiresAt = nil
	}
	if in.Scenario == "expired-context" {
		past := now.Add(-time.Minute)
		stored.ResolvedAt, stored.ExpiresAt = now.Add(-2*time.Minute), &past
	}
	if err := repo.CreateContext(ctx, stored); err != nil {
		return nil, err
	}
	contextID := stored.ID
	if in.Scenario == "unknown-context" {
		contextID = domain.NewUUIDv7()
	}
	if in.Scenario == "malformed-context" {
		contextID = "not-a-context"
	}
	handler := api.New(api.Dependencies{Store: tenants{suspended: in.Scenario == "suspended-tenant"}, WorkloadVerifier: verifier,
		WorkloadRegistry: registry, Contexts: repo, Identities: repo, SubjectVerifiers: &auth.AudienceVerifiers{Issuer: issuer}})
	data, err := json.Marshal(map[string]string{"context_id": contextID, "subject_token": in.Subject})
	if err != nil {
		return nil, err
	}
	// Actual HTTP transport and CP's production router/middleware/handler.
	server := httptest.NewServer(handler)
	defer server.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/platform-context/validate", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if in.Scenario != "missing-validator" {
		request.Header.Set("Authorization", "Bearer "+in.Validator)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil, errors.New("invalid CP response")
	}
	// Credentials must not leak through production response or audit output.
	for _, token := range []string{in.Validator, in.Subject} {
		if token != "" && (bytes.Contains(raw, []byte(token)) || bytes.Contains(audit.Bytes(), []byte(token))) {
			return nil, errors.New("credential leaked")
		}
	}
	result := map[string]any{"status": response.StatusCode, "code": body["code"], "detail": body["detail"], "credentials_absent": true}
	if response.StatusCode == http.StatusOK {
		result["context_matches"] = body["context_id"] == contextID && body["tenant_id"] == stored.TenantID && body["expires_at"] != nil
		result["no_store"] = response.Header.Get("Cache-Control") == "no-store"
		_, legalEntityExposed := body["legal_entity_id"]
		result["legal_entity_absent"] = !legalEntityExposed
	}
	return result, nil
}

func main() {
	var in input
	if json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&in) != nil {
		os.Exit(2)
	}
	result, err := run(in)
	if err != nil {
		// Do not print provider errors, request bodies, tokens or audit output.
		os.Exit(2)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(2)
	}
}
