package ory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

// ADR-SHARED-042 section 14 (CAA-03): governed buyer consent. A synthetic
// ACTIVE estate BFF only; this proves IAM's consent decision against a fake
// provider, not connected IAM acceptance or any registry allocation.
func buyerProfiles(change func(*tokenprofile.Workload)) *tokenprofile.Config {
	bff := tokenprofile.Workload{Environment: "staging", CredentialType: "client_credentials", Status: "ACTIVE",
		Scopes: []string{"trade:buyer-handoff"}, Audiences: []string{"baobab-trade"},
		HumanTokenProfile:   &tokenprofile.HumanTokenProfile{Purpose: "ESTATE_BFF_BUYER", Audiences: []string{"baobab-trade"}, Scopes: []string{"trade:buy"}},
		HumanScopeAudiences: map[string][]string{"trade:buy": {"baobab-trade"}}}
	if change != nil {
		change(&bff)
	}
	return &tokenprofile.Config{SharedCommit: strings.Repeat("b", 40), Environment: "staging", Workloads: map[string]tokenprofile.Workload{"estate-bff": bff}}
}

type buyerProvider struct {
	server   *httptest.Server
	requests int
	accepted map[string]map[string]any
}

// newBuyerProvider serves an exact Hydra challenge for intent and a current
// Kratos session, and records every acceptance body by kind.
func newBuyerProvider(t *testing.T, intent humanauth.Request, now time.Time) *buyerProvider {
	t.Helper()
	p := &buyerProvider{accepted: map[string]map[string]any{}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests++
		if r.URL.Path == "/sessions/whoami" {
			json.NewEncoder(w).Encode(map[string]any{"id": "session-id", "active": true, "expires_at": now.Add(time.Hour), "authenticated_at": now.Add(-time.Minute),
				"authenticator_assurance_level": "aal2", "authentication_methods": []map[string]string{{"method": "password"}, {"method": "totp"}},
				"identity": map[string]string{"id": "exact-kratos-subject", "state": "active"}})
			return
		}
		kind := "login"
		if strings.Contains(r.URL.Path, "/consent") {
			kind = "consent"
		}
		if r.Method == http.MethodPut {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			p.accepted[kind] = body
			json.NewEncoder(w).Encode(map[string]string{"redirect_to": p.server.URL + "/oauth2/auth?" + kind + "_verifier=private-verifier"})
			return
		}
		query := url.Values{"response_type": {"code"}, "client_id": {intent.ClientID}, "redirect_uri": {intent.RedirectURI}, "scope": {intent.Scope}, "state": {intent.State}, "nonce": {intent.Nonce}, "code_challenge": {intent.CodeChallenge}, "code_challenge_method": {"S256"}}
		json.NewEncoder(w).Encode(map[string]any{"challenge": "opaque-" + kind, "consent_request_id": "consent-request-0001", "request_url": p.server.URL + "/oauth2/auth?" + query.Encode(), "client": map[string]string{"client_id": intent.ClientID},
			"requested_scope": strings.Fields(intent.Scope), "requested_access_token_audience": []string{}, "subject": "exact-kratos-subject"})
	}))
	t.Cleanup(p.server.Close)
	return p
}

func buyerIntent(scope string) humanauth.Request {
	return humanauth.Request{GrantType: "authorization_code", ClientID: "estate-bff", RedirectURI: "https://estate.invalid/callback", Scope: scope,
		CodeChallenge: strings.Repeat("x", 43), CodeChallengeMethod: "S256", State: strings.Repeat("s", 32), Nonce: strings.Repeat("n", 32)}
}

var buyerSealKey = []byte(strings.Repeat("s", tokenprofile.MinConsentSealKeyBytes))

func (p *buyerProvider) config(t *testing.T, now time.Time, profiles *tokenprofile.Config) NativeHumanConfig {
	c := NativeHumanConfig{KratosPublicURL: p.server.URL, HydraAdminURL: p.server.URL, Issuer: p.server.URL, Client: p.server.Client(),
		Now: func() time.Time { return now }, Fence: openNativeTestFence(t), TokenProfiles: profiles}
	if profiles != nil {
		c.ConsentSealKey = buyerSealKey
	}
	return c
}

func TestGovernedBuyerConsentGrantsOnlyTheRegistryAudience(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	intent := buyerIntent("openid trade:buy")
	p := newBuyerProvider(t, intent, now)
	h, err := NewGovernedNativeHumanHandoff(p.config(t, now, buyerProfiles(nil)), &testDispatchAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	credential := NativeSessionCredential{SessionToken: "private-session-credential"}
	if _, err := h.AcceptLogin(context.Background(), "opaque-login", credential, intent); err != nil {
		t.Fatal("governed login for a registered buyer scope refused:", err)
	}
	if login := p.accepted["login"]; login["acr"] != "aal2" || login["subject"] != "exact-kratos-subject" {
		t.Fatalf("login body = %v", login)
	}
	if _, err := h.AcceptConsent(context.Background(), "opaque-consent", credential, intent, true); err != nil {
		t.Fatal("governed buyer consent refused:", err)
	}
	consent := p.accepted["consent"]
	raw, _ := json.Marshal(consent)
	var body struct {
		Scopes   []string `json:"grant_scope"`
		Audience []string `json:"grant_access_token_audience"`
		Remember bool     `json:"remember"`
		Session  struct {
			AccessToken struct {
				ActorType string                         `json:"actor_type"`
				Consent   *tokenprofile.HumanConsentSeal `json:"baobab_human_consent"`
			} `json:"access_token"`
		} `json:"session"`
	}
	json.Unmarshal(raw, &body)
	if !slices.Equal(body.Scopes, []string{"openid", "trade:buy"}) || !slices.Equal(body.Audience, []string{"baobab-trade"}) || body.Remember ||
		body.Session.AccessToken.ActorType != "human" || body.Session.AccessToken.Consent == nil {
		t.Fatalf("consent body = %s", raw)
	}
	// The sealed decision is exactly what the token hook later issues for, on
	// the evidence Hydra really supplies at a code exchange.
	evidence := tokenprofile.HumanEvidence{ClientID: "estate-bff", Subject: "exact-kratos-subject", Grant: "authorization_code",
		ConsentRequestID: "consent-request-0001", Consent: body.Session.AccessToken.Consent, RequestedScopes: body.Scopes,
		ACR: "aal2", AMR: []string{"pwd", "otp", "mfa"}, AuthTime: now.Unix()}
	claims, err := buyerProfiles(nil).HumanClaims(evidence, buyerSealKey)
	if err != nil || claims["azp"] != "estate-bff" {
		t.Fatalf("hook refused the consented grant: %v %v", claims, err)
	}
	evidence.ConsentRequestID = "consent-request-0002"
	if _, err := buyerProfiles(nil).HumanClaims(evidence, buyerSealKey); err == nil {
		t.Fatal("seal accepted for another consent challenge")
	}
}

func TestGovernedOIDCOnlyConsentStillGrantsNoAudience(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	intent := buyerIntent("openid email")
	p := newBuyerProvider(t, intent, now)
	h, err := NewGovernedNativeHumanHandoff(p.config(t, now, buyerProfiles(nil)), &testDispatchAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AcceptConsent(context.Background(), "opaque-consent", NativeSessionCredential{SessionToken: "private-session-credential"}, intent, true); err != nil {
		t.Fatal(err)
	}
	if audience, ok := p.accepted["consent"]["grant_access_token_audience"].([]any); !ok || len(audience) != 0 {
		t.Fatalf("OIDC-only consent granted audience %v", p.accepted["consent"]["grant_access_token_audience"])
	}
	if raw, _ := json.Marshal(p.accepted["consent"]); strings.Contains(string(raw), tokenprofile.ConsentSealClaim) {
		t.Fatal("OIDC-only consent was sealed as a buyer grant")
	}
}

func TestBuyerConsentRefusesBeforeAnyProviderRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, c := range map[string]struct {
		scope    string
		client   string
		profiles *tokenprofile.Config
	}{
		"no token profiles":  {"openid trade:buy", "estate-bff", nil},
		"unregistered BFF":   {"openid trade:buy", "other-bff", buyerProfiles(nil)},
		"provisioned BFF":    {"openid trade:buy", "estate-bff", buyerProfiles(func(w *tokenprofile.Workload) { w.Status = "PROVISIONED" })},
		"suspended BFF":      {"openid trade:buy", "estate-bff", buyerProfiles(func(w *tokenprofile.Workload) { w.Status = "SUSPENDED" })},
		"scope outside":      {"openid trade:buy payments:write", "estate-bff", buyerProfiles(nil)},
		"workload scope":     {"openid trade:buy trade:buyer-handoff", "estate-bff", buyerProfiles(nil)},
		"offline access":     {"openid trade:buy offline_access", "estate-bff", buyerProfiles(nil)},
		"no openid":          {"trade:buy", "estate-bff", buyerProfiles(nil)},
		"duplicate scope":    {"openid trade:buy trade:buy", "estate-bff", buyerProfiles(nil)},
		"control plane only": {"openid context:resolve", "estate-bff", buyerProfiles(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			intent := buyerIntent(c.scope)
			intent.ClientID = c.client
			p := newBuyerProvider(t, intent, now)
			h, err := NewGovernedNativeHumanHandoff(p.config(t, now, c.profiles), &testDispatchAuthority{})
			if err != nil {
				t.Fatal(err)
			}
			credential := NativeSessionCredential{SessionToken: "private-session-credential"}
			if _, err := h.AcceptLogin(context.Background(), "opaque-login", credential, intent); err == nil {
				t.Fatal("login admitted a business scope outside governed buyer consent")
			}
			if _, err := h.AcceptConsent(context.Background(), "opaque-consent", credential, intent, true); err == nil {
				t.Fatal("consent granted a business scope outside governed buyer consent")
			}
			if p.requests != 0 || len(p.accepted) != 0 {
				t.Fatalf("refused intent reached the provider (%d requests)", p.requests)
			}
		})
	}
}

func TestBuyerConsentRequiresGovernedCompositionAndAValidProjection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := newBuyerProvider(t, buyerIntent("openid"), now)
	if _, err := NewNativeHumanHandoff(p.config(t, now, buyerProfiles(nil))); err == nil {
		t.Fatal("ungoverned mechanics accepted token profiles")
	}
	invalid := buyerProfiles(func(w *tokenprofile.Workload) { w.HumanScopeAudiences = nil })
	if _, err := NewGovernedNativeHumanHandoff(p.config(t, now, invalid), &testDispatchAuthority{}); err == nil {
		t.Fatal("governed handoff accepted a projection without registry scope audiences")
	}
	for name, change := range map[string]func(*NativeHumanConfig){
		"profiles without seal key": func(c *NativeHumanConfig) { c.ConsentSealKey = nil },
		"seal key without profiles": func(c *NativeHumanConfig) { c.TokenProfiles = nil },
		"short seal key":            func(c *NativeHumanConfig) { c.ConsentSealKey = []byte("short") },
	} {
		t.Run(name, func(t *testing.T) {
			c := p.config(t, now, buyerProfiles(nil))
			change(&c)
			if _, err := NewGovernedNativeHumanHandoff(c, &testDispatchAuthority{}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	sealOnly := p.config(t, now, nil)
	sealOnly.ConsentSealKey = buyerSealKey
	if _, err := NewNativeHumanHandoff(sealOnly); err == nil {
		t.Fatal("ungoverned mechanics accepted a consent seal key")
	}
	// The handoff keeps its own snapshot: later mutation of the caller's
	// configuration cannot widen consent.
	profiles := buyerProfiles(nil)
	intent := buyerIntent("openid trade:buy")
	q := newBuyerProvider(t, intent, now)
	h, err := NewGovernedNativeHumanHandoff(q.config(t, now, profiles), &testDispatchAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	profiles.Workloads = map[string]tokenprofile.Workload{}
	if _, err := h.AcceptConsent(context.Background(), "opaque-consent", NativeSessionCredential{SessionToken: "private-session-credential"}, intent, true); err != nil {
		t.Fatal("snapshot did not survive caller mutation:", err)
	}
}
