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
)

func TestLiveCPConsumerVerifier(t *testing.T) {
	if os.Getenv("ORY_CP_CONSUMER_PROBE") == "" || os.Getenv("ORY_TOKEN_PROFILE") != "1" {
		t.Skip("requires pinned CP probe and governed isolated Hydra")
	}
	f := newWorkloadFixture(t)
	const id = "baobab-trade-workload"
	p := f.profile(t, id, "client_credentials")
	w, err := f.adapter.ProvisionWorkload(f.ctx, provider.WorkloadProvisioningSpec{LogicalClientID: id, AllowedScopes: p.Scopes, Audiences: p.Audiences, AuthMethod: provider.WorkloadAuthClientSecret})
	if err != nil {
		t.Fatal("provision consumer fixture")
	}
	f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
	form := secretForm(id, w.ClientSecret, p.Scopes[0])
	form.Set("audience", strings.Join(p.Audiences, " "))
	token := f.exchange(t, form, false)
	probe := func(t *testing.T, raw, audience, scope string, wrongIssuer bool, verified, required bool) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"token": raw, "audience": audience, "scope": scope, "wrong_issuer": wrongIssuer})
		if err != nil {
			t.Fatal("encode private probe input")
		}
		cmd := exec.CommandContext(f.ctx, os.Getenv("ORY_CP_CONSUMER_PROBE"))
		cmd.Stdin = bytes.NewReader(data)
		// Never print stdin, stdout on error, or a credential-bearing command line.
		output, err := cmd.Output()
		if err != nil {
			t.Fatal("CP consumer probe infrastructure failure")
		}
		var result struct {
			Verified bool `json:"verified"`
			Required bool `json:"required_scope_present"`
			Identity bool `json:"workload_identity_matches"`
		}
		if json.Unmarshal(output, &result) != nil {
			t.Fatal("invalid safe probe result")
		}
		if result.Verified != verified || result.Required != required || (verified && !result.Identity) {
			t.Fatal("CP consumer verification result differs from expectation")
		}
	}
	t.Run("accept-governed-workload", func(t *testing.T) { probe(t, token.AccessToken, p.Audiences[0], p.Scopes[0], false, true, true) })
	t.Run("reject-wrong-audience", func(t *testing.T) { probe(t, token.AccessToken, "baobab-payments", p.Scopes[0], false, false, false) })
	t.Run("reject-wrong-issuer", func(t *testing.T) { probe(t, token.AccessToken, p.Audiences[0], p.Scopes[0], true, false, false) })
	t.Run("missing-required-scope", func(t *testing.T) { probe(t, token.AccessToken, p.Audiences[0], "billing:manage", false, true, false) })
	t.Run("reject-tampered-token", func(t *testing.T) {
		parts := strings.Split(token.AccessToken, ".")
		if len(parts) != 3 {
			t.Fatal("invalid fixture token")
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(signature) == 0 {
			t.Fatal("invalid fixture signature")
		}
		signature[0] ^= 1
		parts[2] = base64.RawURLEncoding.EncodeToString(signature)
		probe(t, strings.Join(parts, "."), p.Audiences[0], p.Scopes[0], false, false, false)
	})
	t.Run("reject-expired-provider-token", func(t *testing.T) {
		// Configure a five-second lifetime through the real isolated Hydra client,
		// rather than forging/re-signing a token or modifying the CP verifier clock.
		var client map[string]any
		foundationRequest(t, f.ctx, f.client, http.MethodGet, f.admin+"/admin/clients/"+id, nil, "", 200, &client)
		client["client_credentials_grant_access_token_lifespan"] = "5s"
		foundationRequest(t, f.ctx, f.client, http.MethodPut, f.admin+"/admin/clients/"+id, client, "", 200, nil)
		short := f.exchange(t, form, false)
		if short.ExpiresIn > 5 {
			t.Fatal("short token lifetime not enforced")
		}
		select {
		case <-time.After(6 * time.Second):
		case <-f.ctx.Done():
			t.Fatal("expiry fixture timeout")
		}
		probe(t, short.AccessToken, p.Audiences[0], p.Scopes[0], false, false, false)
	})
	if t.Failed() {
		return
	}
	evidence := map[string]any{"fixture_only": true, "consumer_repository": "baobab-platform/baobab-cp", "consumer_commit": "20235ac2c4e1c0285e747a5a4b41c1eefb3a4dd7", "actual_consumer_verifier_tested": true, "deployed_resource_route_tested": false, "canonical_activation_proven": false}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(os.Getenv("ORY_M4_EVIDENCE_DIR"), "cp-consumer-verifier.json"), append(data, '\n'), 0600) != nil {
		t.Fatal("write safe consumer evidence")
	}
}
