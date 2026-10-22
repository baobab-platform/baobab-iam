package ory_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
	"github.com/coreos/go-oidc/v3/oidc"
)

// fixtureDispatchAuthority stands in for current CP dispatch in this
// disposable stack only. It proves nothing about CP routing.
type fixtureDispatchAuthority struct{}

func (fixtureDispatchAuthority) CheckCapability(context.Context, string) error { return nil }

// ADR-SHARED-042 section 14 (CAA-03): governed buyer consent through real
// Kratos, real Hydra and IAM's token hook. The estate BFF is a CI-only fixture
// in the disposable hook input (tests/ory-foundation/token_profile.sh), never
// a Shared allocation; nothing here is connected IAM acceptance, registry
// activation or approval of any acr value.
func TestLiveGovernedBuyerConsent(t *testing.T) {
	profilesFile, sealFile := os.Getenv("ORY_BUYER_PROFILES_FILE"), os.Getenv("ORY_BUYER_CONSENT_SEAL_KEY_FILE")
	if os.Getenv("ORY_TOKEN_PROFILE") != "1" || profilesFile == "" || sealFile == "" {
		t.Skip("requires the hooked Ory foundation with the buyer fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	kratos := envOr("ORY_KRATOS_PUBLIC_URL", "http://127.0.0.1:4433")
	ka := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	ha := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	const bff = "m4-ci-estate-bff"
	raw, err := os.ReadFile(profilesFile)
	if err != nil {
		t.Fatal("cannot read disposable hook profiles")
	}
	var profiles tokenprofile.Config
	if err := json.Unmarshal(raw, &profiles); err != nil || profiles.Workloads[bff].HumanTokenProfile == nil {
		t.Fatal("disposable hook profiles carry no buyer fixture")
	}
	sealKey, err := os.ReadFile(sealFile)
	if err != nil {
		t.Fatal("cannot read disposable consent seal key")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	email := "buyer-ci-" + hex.EncodeToString(seed[:12]) + "@baobab.invalid"
	var flow struct {
		ID string `json:"id"`
	}
	foundationRequest(t, ctx, client, "GET", kratos+"/self-service/registration/api", nil, "", 200, &flow)
	var registered struct {
		SessionToken string `json:"session_token"`
		Identity     struct {
			ID string `json:"id"`
		} `json:"identity"`
	}
	foundationRequest(t, ctx, client, "POST", kratos+"/self-service/registration?flow="+url.QueryEscape(flow.ID), map[string]any{"method": "password", "password": "Aa!9-" + hex.EncodeToString(seed), "traits": map[string]any{"email": email}}, "", 200, &registered)
	defer foundationRequest(t, context.Background(), client, "DELETE", ka+"/admin/identities/"+registered.Identity.ID, nil, "", 204, nil)
	session := ory.NativeSessionCredential{SessionToken: registered.SessionToken}

	callback := "http://127.0.0.1:3000/buyer-ci-callback"
	secret := hex.EncodeToString(seed)
	foundationRequest(t, ctx, client, "POST", ha+"/admin/clients", map[string]any{"client_id": bff, "client_secret": secret,
		"grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "scope": "openid trade:buy context:resolve",
		"audience": []string{"baobab-trade"}, "redirect_uris": []string{callback}, "token_endpoint_auth_method": "client_secret_basic", "subject_type": "public"}, "", 201, nil)
	defer foundationRequest(t, context.Background(), client, "DELETE", ha+"/admin/clients/"+bff, nil, "", 204, nil)

	h, err := ory.NewGovernedNativeHumanHandoff(ory.NativeHumanConfig{KratosPublicURL: kratos, HydraAdminURL: ha, Issuer: issuer, Now: time.Now,
		Fence: openNativeTestFence(t), TokenProfiles: &profiles, ConsentSealKey: []byte(strings.TrimSpace(string(sealKey))), AllowLoopbackHTTP: true}, fixtureDispatchAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := func(target string) *url.URL {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal("buyer browser transport failed")
		}
		defer response.Body.Close()
		if response.StatusCode != 302 && response.StatusCode != 303 {
			t.Fatalf("buyer browser HTTP %d", response.StatusCode)
		}
		location, err := response.Location()
		if err != nil {
			t.Fatal("buyer browser redirect missing")
		}
		return location
	}
	authorize := func(scope string) (humanauth.Request, string, url.Values) {
		t.Helper()
		verifier := make([]byte, 32)
		if _, err := rand.Read(verifier); err != nil {
			t.Fatal(err)
		}
		v := base64.RawURLEncoding.EncodeToString(verifier)
		sum := sha256.Sum256([]byte(v))
		intent := humanauth.Request{GrantType: "authorization_code", ClientID: bff, RedirectURI: callback, Scope: scope,
			CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256", State: hex.EncodeToString(verifier[:16]), Nonce: hex.EncodeToString(verifier[16:])}
		query := url.Values{"response_type": {"code"}, "client_id": {bff}, "redirect_uri": {callback}, "scope": {scope}, "state": {intent.State},
			"nonce": {intent.Nonce}, "code_challenge": {intent.CodeChallenge}, "code_challenge_method": {"S256"}}
		return intent, v, query
	}
	exchange := func(code, verifier string) (int, []byte) {
		t.Helper()
		form := url.Values{"grant_type": {"authorization_code"}, "redirect_uri": {callback}, "code": {code}, "code_verifier": {verifier}}
		request, _ := http.NewRequestWithContext(ctx, "POST", issuer+"/oauth2/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth(bff, secret)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("buyer token transport failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(body) > 65536 {
			t.Fatal("buyer token response exceeds bound")
		}
		return response.StatusCode, body
	}
	// Hydra admin calls whose outcome is the evidence, not a fixture step.
	admin := func(method, target string, body any) (int, string) {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, _ := http.NewRequestWithContext(ctx, method, target, strings.NewReader(string(raw)))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("Hydra admin transport failed")
		}
		defer response.Body.Close()
		var result struct {
			Redirect string `json:"redirect_to"`
		}
		json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result)
		return response.StatusCode, result.Redirect
	}
	audienceOf := func(accessToken string) []string {
		t.Helper()
		payload, err := oidc.NewRemoteKeySet(ctx, issuer+"/.well-known/jwks.json").VerifySignature(ctx, accessToken)
		if err != nil {
			t.Fatal("access token signature not verified", err)
		}
		var claims struct {
			Audience []string `json:"aud"`
		}
		json.Unmarshal(payload, &claims)
		return claims.Audience
	}
	receipt := map[string]any{"fixture_only": true, "registry_allocated": false, "canonical_activation_proven": false,
		"acr_values_approved": false, "connected_trade_tested": false}

	t.Run("governed-consent-issues-the-registry-audience", func(t *testing.T) {
		intent, verifier, query := authorize("openid trade:buy")
		login := next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
		redirect, err := h.AcceptLogin(ctx, login, session, intent)
		if err != nil {
			t.Fatal("governed buyer login refused", err)
		}
		consent := next(redirect).Query().Get("consent_challenge")
		redirect, err = h.AcceptConsent(ctx, consent, session, intent, true)
		if err != nil {
			t.Fatal("governed buyer consent refused", err)
		}
		result := next(redirect)
		if result.Query().Get("state") != intent.State || result.Query().Get("code") == "" {
			t.Fatal("buyer callback binding failed")
		}
		status, body := exchange(result.Query().Get("code"), verifier)
		if status != 200 {
			t.Fatalf("buyer code exchange HTTP %d", status)
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(body, &token) != nil || token.AccessToken == "" {
			t.Fatal("buyer token response has no access token")
		}
		payload, err := oidc.NewRemoteKeySet(ctx, issuer+"/.well-known/jwks.json").VerifySignature(ctx, token.AccessToken)
		if err != nil {
			t.Fatal("buyer access token signature not verified", err)
		}
		var claims struct {
			Extra     any      `json:"ext"`
			Seal      any      `json:"baobab_human_consent"`
			Issuer    string   `json:"iss"`
			Subject   string   `json:"sub"`
			Audience  []string `json:"aud"`
			Scope     string   `json:"scope"`
			ActorType string   `json:"actor_type"`
			AZP       string   `json:"azp"`
			ACR       string   `json:"acr"`
			AMR       []string `json:"amr"`
			// Hydra re-encodes hook claims through float64 (1.79e+09): still a
			// JSON NumericDate, so decode it as a number and require it integral.
			AuthTime float64 `json:"auth_time"`
			IssuedAt int64   `json:"iat"`
			Expiry   int64   `json:"exp"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal("buyer access token claims unreadable")
		}
		now := time.Now().Unix()
		if claims.Issuer != issuer && claims.Issuer != issuer+"/" || claims.Subject != registered.Identity.ID {
			t.Fatal("buyer token issuer or subject changed")
		}
		if !slices.Equal(claims.Audience, []string{"baobab-trade"}) || claims.Scope != "openid trade:buy" || claims.ActorType != "human" || claims.AZP != bff {
			t.Fatalf("buyer token boundary: aud=%v scope=%q actor=%q azp=%q", claims.Audience, claims.Scope, claims.ActorType, claims.AZP)
		}
		// Top-level assurance claims, as the Shared handoff contract and
		// Trade's verifier read them; never only under Hydra's ext.
		if claims.ACR != "aal1" || !slices.Equal(claims.AMR, []string{"pwd"}) || claims.AuthTime <= 0 || claims.AuthTime > float64(now) || claims.AuthTime != float64(int64(claims.AuthTime)) {
			t.Fatalf("buyer token assurance: acr=%q amr=%v auth_time=%v", claims.ACR, claims.AMR, claims.AuthTime)
		}
		if claims.Extra != nil || claims.Seal != nil {
			t.Fatalf("buyer token carries ext or seal claims: %v %v", claims.Extra, claims.Seal)
		}
		receipt["seal_absent_from_token"] = true
		if claims.Expiry-claims.IssuedAt > 900 {
			t.Fatal("buyer token outlives the 15-minute maximum")
		}
		receipt["logical_audience_matches"], receipt["assurance_claims_top_level"], receipt["actor_type_is_human"] = true, true, true
	})

	t.Run("business-scope-outside-the-profile-refused", func(t *testing.T) {
		intent, _, query := authorize("openid trade:buy context:resolve")
		login := next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
		if login == "" {
			t.Fatal("real Hydra login challenge absent")
		}
		if _, err := h.AcceptLogin(ctx, login, session, intent); err == nil {
			t.Fatal("governed login admitted a scope outside the buyer profile")
		}
		receipt["outside_scope_refused"] = true
	})

	// A consent accepted directly through the private admin API, not through
	// governed buyer consent. Hydra calls the token hook on a code exchange
	// before it copies the consent grant, and does not bound a consent-granted
	// audience by the client registration, so only the governed consent seal
	// (tokenprofile.HumanConsentSeal) lets the hook refuse such a grant.
	ungoverned := func(t *testing.T, audience []string) (int, []string) {
		t.Helper()
		_, verifier, query := authorize("openid trade:buy")
		login := next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
		status, redirect := admin("PUT", ha+"/admin/oauth2/auth/requests/login/accept?login_challenge="+url.QueryEscape(login),
			map[string]any{"subject": registered.Identity.ID, "remember": false, "acr": "aal1", "amr": []string{"pwd"}})
		if status != 200 {
			t.Fatalf("admin login accept HTTP %d", status)
		}
		consent := next(redirect).Query().Get("consent_challenge")
		status, redirect = admin("PUT", ha+"/admin/oauth2/auth/requests/consent/accept?consent_challenge="+url.QueryEscape(consent),
			map[string]any{"grant_scope": []string{"openid", "trade:buy"}, "grant_access_token_audience": audience, "remember": false})
		if status != 200 {
			return status, nil
		}
		code := next(redirect).Query().Get("code")
		if code == "" {
			return 0, nil
		}
		status, body := exchange(code, verifier)
		var token struct {
			AccessToken string `json:"access_token"`
		}
		if status != 200 || json.Unmarshal(body, &token) != nil || token.AccessToken == "" {
			return status, nil
		}
		return status, audienceOf(token.AccessToken)
	}

	t.Run("ungoverned-consent-refused-at-issuance", func(t *testing.T) {
		status, audience := ungoverned(t, []string{"baobab-trade"})
		if status == 200 {
			t.Fatalf("token hook issued for an unsealed consent: aud %v", audience)
		}
		receipt["ungoverned_consent_refused_at_issuance"] = true
	})

	t.Run("unregistered-audience-refused-at-issuance", func(t *testing.T) {
		status, audience := ungoverned(t, []string{"baobab-control-plane"})
		if status == 200 {
			t.Fatalf("token hook issued for an unregistered audience: aud %v", audience)
		}
		receipt["unregistered_audience_refused_at_issuance"] = true
	})

	if dir := os.Getenv("ORY_M4_EVIDENCE_DIR"); dir != "" && !t.Failed() {
		encoded, _ := json.MarshalIndent(receipt, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "buyer-consent.json"), append(encoded, '\n'), 0o644); err != nil {
			t.Fatal("cannot write buyer consent receipt")
		}
	}
}
