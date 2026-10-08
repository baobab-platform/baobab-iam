package ory_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

func TestLiveCPContextRoute(t *testing.T) {
	if os.Getenv("ORY_CP_ROUTE_PROBE") == "" || os.Getenv("ORY_TOKEN_PROFILE") != "1" {
		t.Skip("requires immutable CP route probe and isolated Hydra hook")
	}
	f := newWorkloadFixture(t)
	// These are disposable CI identities, never canonical Shared allocations.
	forms := map[string]url.Values{}
	for _, fixture := range []struct {
		id, scope string
		audiences []string
	}{
		{"m4-ci-validator", "context:validate", []string{"baobab-control-plane"}},
		{"m4-ci-no-scope", "context:resolve", []string{"baobab-control-plane"}},
		{"m4-ci-unregistered", "context:validate", []string{"baobab-control-plane"}},
		{"m4-ci-subject", "context:resolve", []string{"baobab-erp", "baobab-control-plane"}},
	} {
		w, err := f.adapter.ProvisionWorkload(f.ctx, provider.WorkloadProvisioningSpec{LogicalClientID: fixture.id, AllowedScopes: []string{fixture.scope}, Audiences: fixture.audiences, AuthMethod: provider.WorkloadAuthClientSecret})
		if err != nil {
			t.Fatal("provision disposable route fixture")
		}
		f.cleanup(t, "/admin/clients/"+url.PathEscape(fixture.id))
		form := secretForm(fixture.id, w.ClientSecret, fixture.scope)
		form.Set("audience", fixture.audiences[0])
		forms[fixture.id] = form
	}
	validator := f.exchange(t, forms["m4-ci-validator"], false).AccessToken
	noScope := f.exchange(t, forms["m4-ci-no-scope"], false).AccessToken
	unregistered := f.exchange(t, forms["m4-ci-unregistered"], false).AccessToken
	subject := f.exchange(t, forms["m4-ci-subject"], false).AccessToken
	// Prove success does not require an IAM tenant authority claim.
	parts := strings.Split(subject, ".")
	if len(parts) != 3 {
		t.Fatal("invalid signed fixture token")
	}
	claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(claimsData, &claims) != nil {
		t.Fatal("invalid signed fixture claims")
	}
	if _, exists := claims["tenant_id"]; exists {
		t.Fatal("fixture must not embed tenant authority")
	}
	type result struct {
		Status            int    `json:"status"`
		Code              string `json:"code"`
		Detail            string `json:"detail"`
		CredentialsAbsent bool   `json:"credentials_absent"`
		ContextMatches    bool   `json:"context_matches"`
		NoStore           bool   `json:"no_store"`
		LegalEntityAbsent bool   `json:"legal_entity_absent"`
	}
	scenarios := map[string]int{}
	probe := func(t *testing.T, name, scenario, bearer, token string, status int, code string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(map[string]string{"validator": bearer, "subject": token, "scenario": scenario})
			if err != nil {
				t.Fatal("encode private route input")
			}
			cmd := exec.CommandContext(f.ctx, os.Getenv("ORY_CP_ROUTE_PROBE"))
			cmd.Stdin = bytes.NewReader(data)
			output, err := cmd.Output()
			if err != nil {
				t.Fatal("CP route probe infrastructure failure")
			}
			var got result
			if json.Unmarshal(output, &got) != nil {
				t.Fatal("invalid safe route result")
			}
			if got.Status != status || got.Code != code || !got.CredentialsAbsent {
				t.Fatalf("unexpected CP route decision: HTTP %d code %s", got.Status, got.Code)
			}
			if status == 200 && (!got.ContextMatches || !got.NoStore || !got.LegalEntityAbsent) {
				t.Fatal("trusted response does not match bounded canonical context")
			}
			if status == 404 && got.Detail != "the referenced context_id does not exist or has expired" {
				t.Fatal("context failures must remain indistinguishable")
			}
			scenarios[name] = got.Status
		})
	}
	probe(t, "accept-context-without-tenant-claim", "owned", validator, subject, 200, "")
	refreshed := f.exchange(t, forms["m4-ci-subject"], false).AccessToken
	if refreshed == subject {
		t.Fatal("subject refresh did not produce a distinct credential")
	}
	probe(t, "accept-refreshed-subject", "owned", validator, refreshed, 200, "")
	wrongAudienceForm := secretForm("m4-ci-subject", forms["m4-ci-subject"].Get("client_secret"), "context:resolve")
	wrongAudienceForm.Set("audience", "baobab-control-plane")
	wrongAudience := f.exchange(t, wrongAudienceForm, false).AccessToken
	probe(t, "reject-wrong-subject-audience", "owned", validator, wrongAudience, 401, "SUBJECT_TOKEN_INVALID")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		t.Fatal("invalid fixture signature")
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	probe(t, "reject-tampered-subject", "owned", validator, strings.Join(parts, "."), 401, "SUBJECT_TOKEN_INVALID")
	probe(t, "reject-missing-validator", "missing-validator", "", subject, 401, "AUTH_TOKEN_REQUIRED")
	probe(t, "reject-validator-without-scope", "owned", noScope, subject, 403, "AUTHORIZATION_DENIED")
	probe(t, "reject-unregistered-validator", "owned", unregistered, subject, 403, "CONTEXT_VALIDATION_NOT_PERMITTED")
	probe(t, "reject-revoked-validator", "revoked-validator", validator, subject, 403, "AUTHORIZATION_DENIED")
	for _, scenario := range []string{"other-owner", "validator-owner", "unknown-context", "expired-context", "unbounded", "revoked-external-link"} {
		name := "reject-" + scenario
		if scenario == "unbounded" {
			name = "reject-unbounded-context"
		}
		probe(t, name, scenario, validator, subject, 404, "CONTEXT_NOT_FOUND")
	}
	probe(t, "reject-suspended-tenant", "suspended-tenant", validator, subject, 403, "TENANT_NOT_ACTIVE")
	// Real provider expiry, without forging a token or changing CP's clock.
	var client map[string]any
	foundationRequest(t, f.ctx, f.client, http.MethodGet, f.admin+"/admin/clients/m4-ci-subject", nil, "", 200, &client)
	client["client_credentials_grant_access_token_lifespan"] = "5s"
	foundationRequest(t, f.ctx, f.client, http.MethodPut, f.admin+"/admin/clients/m4-ci-subject", client, "", 200, nil)
	short := f.exchange(t, forms["m4-ci-subject"], false)
	if short.ExpiresIn > 5 {
		t.Fatal("provider expiry fixture was not enforced")
	}
	select {
	case <-time.After(6 * time.Second):
	case <-f.ctx.Done():
		t.Fatal("expiry fixture timeout")
	}
	probe(t, "reject-expired-subject", "owned", validator, short.AccessToken, 401, "SUBJECT_TOKEN_INVALID")
	if t.Failed() {
		return
	}
	evidence := map[string]any{
		"fixture_only": true, "consumer_repository": "baobab-platform/baobab-cp",
		"consumer_commit": "c84063cb07dce76e1ffac4b12fa29c5e4e5ec855",
		"route":           "POST /v1/platform-context/validate",
		"actual_protected_route_tested_in_fixture": true,
		"deployed_resource_route_tested":           false, "canonical_activation_proven": false,
		"production_scope_allocations_changed": false, "credentials_absent": true,
		"subject_without_tenant_claim": true, "scenarios": scenarios,
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(os.Getenv("ORY_M4_EVIDENCE_DIR"), "cp-context-route.json"), append(data, '\n'), 0600) != nil {
		t.Fatal("write safe route evidence")
	}
}

// TestLiveCanonicalCPContextRoute proves the complete fixture composition:
// authenticated Hydra admission of ACTIVE workloads, signed token issuance,
// CP's production verifier and the actual protected context route. The CP
// registry and identities remain isolated fixtures, so this is integration
// evidence rather than live registration or deployment acceptance.
func TestLiveCanonicalCPContextRoute(t *testing.T) {
	if os.Getenv("ORY_CP_ROUTE_PROBE") == "" || os.Getenv("ORY_TOKEN_PROFILE") != "1" {
		t.Skip("requires immutable CP route probe and isolated canonical Hydra hook")
	}
	f := newWorkloadFixture(t)
	issue := func(id, scope, audience string) string {
		w, err := f.adapter.ProvisionWorkload(f.ctx, provider.WorkloadProvisioningSpec{LogicalClientID: id, AllowedScopes: []string{scope}, Audiences: []string{audience}, AuthMethod: provider.WorkloadAuthClientSecret})
		if err != nil {
			t.Fatal("provision canonical route fixture")
		}
		f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
		form := secretForm(id, w.ClientSecret, scope)
		form.Set("audience", audience)
		token := f.exchange(t, form, false)
		if _, err := ory.ProjectWorkloadTokenResponse(token.RawResponse, tokenprofile.WorkloadTokenRequest{WorkloadID: id, Audience: audience, Scopes: []string{scope}}); err != nil {
			t.Fatal("canonical route token projection failed")
		}
		return token.AccessToken
	}
	validator := issue("m4-ci-validator", "context:validate", "baobab-control-plane")
	subject := issue("m4-ci-subject", "context:resolve", "baobab-erp")
	input, err := json.Marshal(map[string]string{"validator": validator, "subject": subject, "scenario": "owned"})
	if err != nil {
		t.Fatal("encode canonical route input")
	}
	cmd := exec.CommandContext(f.ctx, os.Getenv("ORY_CP_ROUTE_PROBE"))
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("canonical CP route probe infrastructure failure")
	}
	var result struct {
		Status            int  `json:"status"`
		CredentialsAbsent bool `json:"credentials_absent"`
		ContextMatches    bool `json:"context_matches"`
		NoStore           bool `json:"no_store"`
		LegalEntityAbsent bool `json:"legal_entity_absent"`
	}
	if json.Unmarshal(output, &result) != nil || result.Status != http.StatusOK || !result.CredentialsAbsent || !result.ContextMatches || !result.NoStore || !result.LegalEntityAbsent {
		t.Fatal("canonically admitted tokens were not accepted by the protected CP route")
	}
}
