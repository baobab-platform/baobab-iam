package ory_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// Compare released and isolated backport audience behavior without relabeling claims.
func TestLiveTokenProfileFederatedAudienceBoundary(t *testing.T) {
	if os.Getenv("ORY_TOKEN_PROFILE") != "1" {
		t.Skip("requires private token-profile hook fixture")
	}
	f := newWorkloadFixture(t)
	for _, id := range []string{"baobab-cp-workload", "baobab-subscriptions-workload"} {
		t.Run(id, func(t *testing.T) {
			p := f.profile(t, id, "federated_workload_token")
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal("generate disposable assertion signer")
			}
			kid := "profile-ci-" + randomFixtureID(t)
			issuer := "https://projected.m4-ci.invalid/" + id
			subject := "system:serviceaccount:m4-ci:" + id
			jwk := map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
			trust, err := f.adapter.ProvisionFederatedWorkload(f.ctx, provider.FederatedWorkloadTrustSpec{LogicalClientID: id, AllowedScopes: p.Scopes, IntendedAudiences: p.Audiences, AssertionIssuer: issuer, AssertionSubject: subject, AssertionJWK: jwk, TrustExpiresAt: time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)})
			if err != nil {
				t.Fatal("provision federated profile fixture")
			}
			f.cleanup(t, "/admin/clients/"+url.PathEscape(id))
			f.cleanup(t, "/admin/trust/grants/jwt-bearer/issuers/"+url.PathEscape(trust.TrustID))
			now := time.Now().Unix()
			assertion := signAssertion(t, key, kid, map[string]any{"iss": issuer, "sub": subject, "aud": []string{f.issuer + "/oauth2/token"}, "iat": now - 5, "nbf": now - 5, "exp": now + 120, "jti": randomFixtureID(t)})
			form := url.Values{"grant_type": {bearerGrant}, "client_id": {id}, "assertion": {assertion}, "scope": {p.Scopes[0]}}
			if os.Getenv("ORY_HYDRA_AUDIENCE_CANDIDATE") != "1" {
				response := f.exchange(t, form, true)
				if response.Error != "access_denied" {
					t.Fatal("released provider mismatch must fail closed")
				}
				return
			}
			form.Set("audience", p.Audiences[0])
			token := f.exchange(t, form, false)
			claims := f.verify(t, token, []string{p.Scopes[0]}, id)
			if claims["sub"] != subject || claims["azp"] != id || claims["actor_type"] != "workload" ||
				!sameScopes(claimStrings(claims["aud"]), []string{p.Audiences[0]}) || claims["scope"] != p.Scopes[0] {
				t.Fatal("candidate signed token violates the governed workload profile")
			}
			probe := func(raw, audience, scope string, wrongIssuer, wantVerified, wantScope bool) {
				input, _ := json.Marshal(map[string]any{"token": raw, "audience": audience, "scope": scope,
					"wrong_issuer": wrongIssuer, "expected_client_id": id, "expected_subject": subject})
				cmd := exec.CommandContext(f.ctx, os.Getenv("ORY_CP_CONSUMER_PROBE"))
				cmd.Stdin = bytes.NewReader(input)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				output, err := cmd.Output()
				var result struct {
					Verified bool `json:"verified"`
					Scope    bool `json:"required_scope_present"`
					Identity bool `json:"workload_identity_matches"`
				}
				if err != nil || json.Unmarshal(output, &result) != nil || result.Verified != wantVerified ||
					result.Scope != wantScope || (wantVerified && !result.Identity) {
					// The probe's output is booleans only and it never prints the token, so this is safe to log.
					t.Fatalf("candidate CP consumer verification failed: want verified=%t scope=%t, got %s; exec error: %v; stderr: %.300s",
						wantVerified, wantScope, strings.TrimSpace(string(output)), err, stderr.String())
				}
			}
			probe(token.AccessToken, p.Audiences[0], p.Scopes[0], false, true, true)
			probe(token.AccessToken, "unregistered-resource", p.Scopes[0], false, false, false)
			probe(token.AccessToken, p.Audiences[0], p.Scopes[0], true, false, false)
			probe(token.AccessToken, p.Audiences[0], "unregistered:scope", false, true, false)
			parts := strings.Split(token.AccessToken, ".")
			signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
			signature[0] ^= 1
			parts[2] = base64.RawURLEncoding.EncodeToString(signature)
			probe(strings.Join(parts, "."), p.Audiences[0], p.Scopes[0], false, false, false)
			receipt, _ := json.Marshal(map[string]any{"fixture_only": true, "workload_id": id, "signature_verified": true,
				"logical_audience_matches": true, "cp_consumer_verified": true, "canonical_activation_proven": false, "production_accepted": false})
			if os.WriteFile(filepath.Join(os.Getenv("ORY_M4_EVIDENCE_DIR"), "candidate-"+id+".json"), receipt, 0600) != nil {
				t.Fatal("write sanitized candidate receipt")
			}
			// Hydra's original replay and exact assertion verification remain mandatory.
			f.exchange(t, form, true)
			for _, audience := range []string{"", "unregistered-resource"} {
				fresh := signAssertion(t, key, kid, map[string]any{"iss": issuer, "sub": subject,
					"aud": []string{f.issuer + "/oauth2/token"}, "iat": now - 5, "nbf": now - 5, "exp": now + 120, "jti": randomFixtureID(t)})
				form.Set("assertion", fresh)
				if audience == "" {
					form.Del("audience")
				} else {
					form.Set("audience", audience)
				}
				f.exchange(t, form, true)
			}
		})
	}
}
