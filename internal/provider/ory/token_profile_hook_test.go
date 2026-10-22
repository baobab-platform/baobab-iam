package ory

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

func TestTokenProfileHookAuthenticatedAndGoverned(t *testing.T) {
	config := tokenprofile.Config{Environment: "production", SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd", Workloads: map[string]tokenprofile.Workload{"trade": {Environment: "production", CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-control-plane"}}}}
	key := strings.Repeat("k", 32)
	hook, err := NewTokenProfileHook(config, key)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"session":{"client_id":"trade","id_token":{"subject":"trade","id_token_claims":{"auth_time":"0001-01-01T00:00:00Z","acr":"","amr":null}},"extra":{"actor_type":"human","tenant_id":"forged"}},"request":{"client_id":"trade","grant_types":["client_credentials"],"requested_scopes":["context:resolve"],"granted_scopes":["context:resolve"],"granted_audience":["baobab-control-plane"],"payload":{"actor_type":["human"],"azp":["forged"],"tenant_id":["forged"]}}}`
	for _, name := range []string{"authenticated", "missing-auth", "wrong-auth", "wrong-client", "wrong-audience", "trailing-json", "oversized"} {
		t.Run(name, func(t *testing.T) {
			payload := body
			auth := key
			expected := http.StatusOK
			switch name {
			case "missing-auth":
				auth = ""
				expected = http.StatusUnauthorized
			case "wrong-auth":
				auth = strings.Repeat("x", 32)
				expected = http.StatusUnauthorized
			case "wrong-client":
				payload = strings.Replace(body, `"client_id":"trade"`, `"client_id":"other"`, 1)
				expected = http.StatusForbidden
			case "wrong-audience":
				payload = strings.ReplaceAll(body, "baobab-control-plane", "baobab-payments")
				expected = http.StatusForbidden
			case "trailing-json":
				payload += `{}`
				expected = http.StatusBadRequest
			case "oversized":
				payload = strings.Repeat(" ", 1<<20) + body
				expected = http.StatusBadRequest
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(payload))
			req.Header.Set("X-Baobab-Token-Hook-Key", auth)
			response := httptest.NewRecorder()
			hook.ServeHTTP(response, req)
			if response.Code != expected {
				t.Fatalf("expected %d, got %d", expected, response.Code)
			}
			if expected == http.StatusOK {
				var result struct {
					Session struct {
						Claims map[string]any `json:"access_token"`
					} `json:"session"`
				}
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Session.Claims["actor_type"] != "workload" || result.Session.Claims["azp"] != "trade" || len(result.Session.Claims) != 3 {
					t.Fatal("caller-controlled claims escaped policy")
				}
			}
		})
	}
	// Handler policy must not change if its caller later mutates configuration.
	p := config.Workloads["trade"]
	p.Scopes[0] = "billing:read"
	config.Workloads["trade"] = p
	req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(body))
	req.Header.Set("X-Baobab-Token-Hook-Key", key)
	response := httptest.NewRecorder()
	hook.ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatal("hook policy was mutated after construction")
	}
}

// Exercise the actual pinned callback shape, including the verified assertion
// retained in Hydra's sanitized payload. Cryptographic verification is Hydra's
// responsibility and is independently exercised by the live foundation suite.
func TestTokenProfileHookFederatedBinding(t *testing.T) {
	config := tokenprofile.Config{
		Environment:  "production",
		SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd",
		Workloads: map[string]tokenprofile.Workload{
			"cp": {Environment: "production", CredentialType: "federated_workload_token", Status: "PROVISIONED", Scopes: []string{"billing:read"}, Audiences: []string{"baobab-subscriptions"}},
		},
		Bindings: map[string]tokenprofile.Binding{
			"cp": {Issuer: "https://projected.invalid", Subject: "service-account-cp"},
		},
	}
	key := strings.Repeat("k", 32)
	hook, err := NewTokenProfileHook(config, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exact-binding", "wrong-issuer", "wrong-subject", "assertion-audience-leak"} {
		t.Run(name, func(t *testing.T) {
			issuer, subject := "https://projected.invalid", "service-account-cp"
			audience := "baobab-subscriptions"
			expected := http.StatusOK
			switch name {
			case "wrong-issuer":
				issuer = "https://another.invalid"
				expected = http.StatusForbidden
			case "wrong-subject":
				subject = "another-service-account"
				expected = http.StatusForbidden
			case "assertion-audience-leak":
				audience = "https://issuer.invalid/oauth2/token"
				expected = http.StatusForbidden
			}
			assertionClaims, err := json.Marshal(map[string]string{"iss": issuer, "sub": subject})
			if err != nil {
				t.Fatal(err)
			}
			// Synthetic provider callback evidence, never a real bearer credential.
			assertion := "fixture." + base64.RawURLEncoding.EncodeToString(assertionClaims) + ".fixture"
			body, err := json.Marshal(map[string]any{
				"session": map[string]any{"client_id": "cp", "id_token": map[string]string{"subject": "service-account-cp"}},
				"request": map[string]any{"client_id": "cp", "grant_types": []string{tokenprofile.FederatedGrant}, "requested_scopes": []string{"billing:read"}, "granted_scopes": []string{"billing:read"}, "granted_audience": []string{audience}, "payload": map[string][]string{"assertion": {assertion}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(string(body)))
			req.Header.Set("X-Baobab-Token-Hook-Key", key)
			response := httptest.NewRecorder()
			hook.ServeHTTP(response, req)
			if response.Code != expected {
				t.Fatalf("expected %d, got %d", expected, response.Code)
			}
		})
	}
}

// ADR-SHARED-042 section 14: a human grant is admitted only for an ACTIVE
// estate BFF's human token profile and carries only the assurance its login
// accepted. Synthetic BFF only; not connected acceptance.
func TestTokenProfileHookHumanGrant(t *testing.T) {
	config := tokenprofile.Config{Environment: "staging", SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{
		"estate-bff": {Environment: "staging", CredentialType: "client_credentials", Status: "ACTIVE",
			Scopes: []string{"trade:buyer-handoff"}, Audiences: []string{"baobab-trade"},
			HumanTokenProfile:   &tokenprofile.HumanTokenProfile{Purpose: "ESTATE_BFF_BUYER", Audiences: []string{"baobab-trade"}, Scopes: []string{"trade:buy"}},
			HumanScopeAudiences: map[string][]string{"trade:buy": {"baobab-trade"}}},
	}}
	key := strings.Repeat("k", 32)
	sealKey := []byte(strings.Repeat("s", tokenprofile.MinConsentSealKeyBytes))
	hook, err := NewTokenProfileHook(config, key, WithHumanConsentSealKey(sealKey))
	if err != nil {
		t.Fatal(err)
	}
	seal, err := tokenprofile.SealHumanConsent(sealKey, "consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"openid", "trade:buy"}, []string{"baobab-trade"})
	if err != nil {
		t.Fatal(err)
	}
	sealJSON, _ := json.Marshal(seal)
	forged, _ := json.Marshal(tokenprofile.HumanConsentSeal{Audience: []string{"baobab-trade"}, Seal: "forged"})
	body := `{"session":{"client_id":"estate-bff","consent_challenge":"consent-challenge-0001","id_token":{"subject":"kratos-identity-0001","id_token_claims":{"acr":"aal2","amr":["pwd","otp","mfa"],"auth_time":"2026-10-22T12:00:00Z"}},"extra":{"actor_type":"workload","tenant_id":"forged","baobab_human_consent":` + string(sealJSON) + `}},"request":{"client_id":"estate-bff","grant_types":["authorization_code"],"requested_scopes":["openid","trade:buy"],"granted_scopes":["openid","trade:buy"],"granted_audience":["baobab-trade"],"payload":{}}}`
	cases := map[string]struct {
		payload string
		status  int
	}{
		"authorization code": {body, http.StatusOK},
		// The shape real Hydra sends on a code exchange: the consent grant is
		// not yet on the request, so the requested scopes are the ceiling.
		"code exchange before grant copy": {strings.Replace(body, `"granted_scopes":["openid","trade:buy"],"granted_audience":["baobab-trade"]`, `"granted_scopes":[],"granted_audience":[]`, 1), http.StatusOK},
		"code exchange outside profile": {strings.Replace(strings.Replace(body, `"granted_scopes":["openid","trade:buy"],"granted_audience":["baobab-trade"]`, `"granted_scopes":[],"granted_audience":[]`, 1),
			`"requested_scopes":["openid","trade:buy"]`, `"requested_scopes":["openid","trade:buy","context:resolve"]`, 1), http.StatusForbidden},
		"code exchange audience without scopes": {strings.Replace(body, `"granted_scopes":["openid","trade:buy"]`, `"granted_scopes":[]`, 1), http.StatusForbidden},
		"refresh without grant": {strings.Replace(strings.Replace(body, `"authorization_code"`, `"refresh_token"`, 1),
			`"granted_scopes":["openid","trade:buy"],"granted_audience":["baobab-trade"]`, `"granted_scopes":[],"granted_audience":[]`, 1), http.StatusForbidden},
		"refresh without audience": {strings.Replace(strings.Replace(body, `"authorization_code"`, `"refresh_token"`, 1),
			`"granted_audience":["baobab-trade"]`, `"granted_audience":[]`, 1), http.StatusForbidden},
		"refresh":                {strings.Replace(body, `"authorization_code"`, `"refresh_token"`, 1), http.StatusOK},
		"no assurance evidence":  {strings.Replace(body, `"acr":"aal2",`, ``, 1), http.StatusForbidden},
		"workload scope":         {strings.ReplaceAll(body, `"openid","trade:buy"`, `"trade:buy","context:resolve"`), http.StatusForbidden},
		"control plane audience": {strings.Replace(body, `"granted_audience":["baobab-trade"]`, `"granted_audience":["baobab-control-plane"]`, 1), http.StatusForbidden},
		"unregistered client":    {strings.ReplaceAll(body, `"estate-bff"`, `"rogue-bff"`), http.StatusForbidden},
		// A grant governed consent did not seal is refused, however exact.
		"unsealed":      {strings.Replace(body, `,"baobab_human_consent":`+string(sealJSON), ``, 1), http.StatusForbidden},
		"forged seal":   {strings.Replace(body, string(sealJSON), string(forged), 1), http.StatusForbidden},
		"replayed seal": {strings.Replace(body, `"consent_challenge":"consent-challenge-0001"`, `"consent_challenge":"consent-challenge-0002"`, 1), http.StatusForbidden},
		"no challenge":  {strings.Replace(body, `"consent_challenge":"consent-challenge-0001",`, ``, 1), http.StatusForbidden},
		"other human":   {strings.Replace(body, `"subject":"kratos-identity-0001"`, `"subject":"kratos-identity-0002"`, 1), http.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(tc.payload))
			req.Header.Set("X-Baobab-Token-Hook-Key", key)
			response := httptest.NewRecorder()
			hook.ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, response.Code)
			}
			if tc.status != http.StatusOK {
				return
			}
			var result struct {
				Session struct {
					Claims map[string]any `json:"access_token"`
				} `json:"session"`
			}
			if json.Unmarshal(response.Body.Bytes(), &result) != nil {
				t.Fatal("invalid hook response")
			}
			claims := result.Session.Claims
			// Session extra and request payload never reach the token, and the
			// hook never states scope: Hydra's own scope claim is the grant.
			if claims["actor_type"] != "human" || claims["azp"] != "estate-bff" || claims["acr"] != "aal2" ||
				claims["tenant_id"] != nil || claims["scope"] != nil || claims[tokenprofile.ConsentSealClaim] != nil {
				t.Fatalf("claims = %#v", claims)
			}
		})
	}
}

// Without the consent seal key the hook issues no human token at all, and the
// seal key can never double as the hook authentication key.
func TestTokenProfileHookHumanIssuanceNeedsTheSealKey(t *testing.T) {
	config := tokenprofile.Config{Environment: "staging", SharedCommit: strings.Repeat("a", 40), Workloads: map[string]tokenprofile.Workload{
		"estate-bff": {Environment: "staging", CredentialType: "client_credentials", Status: "ACTIVE",
			Scopes: []string{"trade:buyer-handoff"}, Audiences: []string{"baobab-trade"},
			HumanTokenProfile:   &tokenprofile.HumanTokenProfile{Purpose: "ESTATE_BFF_BUYER", Audiences: []string{"baobab-trade"}, Scopes: []string{"trade:buy"}},
			HumanScopeAudiences: map[string][]string{"trade:buy": {"baobab-trade"}}},
	}}
	key := strings.Repeat("k", 32)
	sealKey := []byte(strings.Repeat("s", tokenprofile.MinConsentSealKeyBytes))
	seal, _ := tokenprofile.SealHumanConsent(sealKey, "consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"openid", "trade:buy"}, []string{"baobab-trade"})
	sealJSON, _ := json.Marshal(seal)
	body := `{"session":{"client_id":"estate-bff","consent_challenge":"consent-challenge-0001","id_token":{"subject":"kratos-identity-0001","id_token_claims":{"acr":"aal2","auth_time":"2026-10-22T12:00:00Z"}},"extra":{"baobab_human_consent":` + string(sealJSON) + `}},"request":{"client_id":"estate-bff","grant_types":["authorization_code"],"requested_scopes":["openid","trade:buy"],"granted_scopes":[],"granted_audience":[],"payload":{}}}`
	hook, err := NewTokenProfileHook(config, key)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/ory/token-profile", strings.NewReader(body))
	req.Header.Set("X-Baobab-Token-Hook-Key", key)
	response := httptest.NewRecorder()
	hook.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("hook without a seal key issued a human token: %d", response.Code)
	}
	for name, option := range map[string]HookOption{
		"short seal key":       WithHumanConsentSealKey([]byte("short")),
		"seal key is hook key": WithHumanConsentSealKey([]byte(key)),
		"nil option":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewTokenProfileHook(config, key, option); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
