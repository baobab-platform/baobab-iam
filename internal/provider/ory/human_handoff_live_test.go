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
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
	"github.com/coreos/go-oidc/v3/oidc"
)

// This real provider journey uses disposable CI identities and OAuth clients.
// It does not supply CP registration, identity mappings or estate acceptance.
func TestLiveNativeHumanCanonicalHandoff(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" {
		t.Skip("requires isolated Ory foundation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	kratos := envOr("ORY_KRATOS_PUBLIC_URL", "http://127.0.0.1:4433")
	ka := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	ha := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	client := &http.Client{Timeout: 10 * time.Second}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	id := "native-ci-" + hex.EncodeToString(seed[:12])
	callback := "http://127.0.0.1:3000/native-ci-callback"
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
	foundationRequest(t, ctx, client, "POST", kratos+"/self-service/registration?flow="+url.QueryEscape(flow.ID), map[string]any{"method": "password", "password": "Aa!9-" + hex.EncodeToString(seed), "traits": map[string]any{"email": id + "@baobab.invalid"}}, "", 200, &registered)
	defer foundationRequest(t, context.Background(), client, "DELETE", ka+"/admin/identities/"+registered.Identity.ID, nil, "", 204, nil)
	foundationRequest(t, ctx, client, "POST", ha+"/admin/clients", map[string]any{"client_id": id, "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "scope": "openid", "redirect_uris": []string{callback}, "token_endpoint_auth_method": "none", "subject_type": "public"}, "", 201, nil)
	defer foundationRequest(t, context.Background(), client, "DELETE", ha+"/admin/clients/"+id, nil, "", 204, nil)
	h, err := ory.NewNativeHumanHandoff(ory.NativeHumanConfig{KratosPublicURL: kratos, HydraAdminURL: ha, Issuer: issuer, Now: time.Now, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(seed)
	sum := sha256.Sum256([]byte(verifier))
	intent := humanauth.Request{GrantType: "authorization_code", ClientID: id, RedirectURI: callback, Scope: "openid", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256", State: hex.EncodeToString(seed[:16]), Nonce: hex.EncodeToString(seed[16:])}
	query := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {callback}, "scope": {"openid"}, "state": {intent.State}, "nonce": {intent.Nonce}, "code_challenge": {intent.CodeChallenge}, "code_challenge_method": {"S256"}}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := func(target string) *url.URL {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal("native browser transport failed")
		}
		defer response.Body.Close()
		if response.StatusCode != 302 && response.StatusCode != 303 {
			t.Fatalf("native browser HTTP %d", response.StatusCode)
		}
		location, err := response.Location()
		if err != nil {
			t.Fatal("native browser redirect missing")
		}
		return location
	}
	login := next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
	if login == "" {
		t.Fatal("real Hydra login challenge absent")
	}
	redirect, err := h.AcceptLogin(ctx, login, registered.SessionToken, intent)
	if err != nil {
		t.Fatal("native login denied", err)
	}
	consent := next(redirect).Query().Get("consent_challenge")
	if consent == "" {
		t.Fatal("real Hydra consent challenge absent")
	}
	redirect, err = h.AcceptConsent(ctx, consent, registered.SessionToken, intent, true)
	if err != nil {
		t.Fatal("native consent denied", err)
	}
	result := next(redirect)
	if result.Scheme+"://"+result.Host+result.Path != callback || result.Query().Get("state") != intent.State || result.Query().Get("code") == "" {
		t.Fatal("native callback binding failed")
	}
	code := result.Query().Get("code")
	exchange := func(v string) (int, []byte) {
		t.Helper()
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "redirect_uri": {callback}, "code": {code}, "code_verifier": {v}}
		request, _ := http.NewRequestWithContext(ctx, "POST", issuer+"/oauth2/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("native token transport failed")
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(raw) > 65536 {
			t.Fatal("native token response exceeds bound")
		}
		return response.StatusCode, raw
	}
	status, raw := exchange(verifier)
	if status != 200 {
		t.Fatalf("native code exchange HTTP %d", status)
	}
	canonical, err := humanauth.ProjectOAuthResponse(raw)
	if err != nil || canonical.IDToken == "" {
		t.Fatal("native canonical response invalid", err)
	}
	wire, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip humanauth.Response
	if json.Unmarshal(wire, &roundtrip) != nil {
		t.Fatal("canonical response roundtrip failed")
	}
	keyset := oidc.NewRemoteKeySet(ctx, issuer+"/.well-known/jwks.json")
	verified, err := oidc.NewVerifier(issuer, keyset, &oidc.Config{ClientID: id, SupportedSigningAlgs: []string{"RS256"}}).Verify(ctx, canonical.IDToken)
	if err != nil {
		t.Fatal("native ID token verification failed", err)
	}
	if verified.Subject != registered.Identity.ID || verified.Nonce != intent.Nonce {
		t.Fatal("native issuer/subject/nonce binding changed")
	}
	if status, _ := exchange(verifier); status == 200 {
		t.Fatal("authorization code replay accepted")
	}
	if _, err := h.AcceptConsent(ctx, consent, registered.SessionToken, intent, true); err == nil {
		t.Fatal("consent challenge replay accepted")
	}
	// A fresh flow proves verifier mismatch, separately from used-code replay.
	intent.State = strings.Repeat("b", 32)
	intent.Nonce = strings.Repeat("c", 32)
	query.Set("state", intent.State)
	query.Set("nonce", intent.Nonce)
	login = next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
	redirect, err = h.AcceptLogin(ctx, login, registered.SessionToken, intent)
	if err != nil {
		t.Fatal("fresh native login denied", err)
	}
	consent = next(redirect).Query().Get("consent_challenge")
	redirect, err = h.AcceptConsent(ctx, consent, registered.SessionToken, intent, true)
	if err != nil {
		t.Fatal("fresh native consent denied", err)
	}
	code = next(redirect).Query().Get("code")
	if code == "" {
		t.Fatal("fresh native authorization code absent")
	}
	if status, _ := exchange(strings.Repeat("z", 43)); status == 200 {
		t.Fatal("wrong S256 verifier accepted")
	}
	a, err := ory.NewAdapter(ory.Config{KratosAdminURL: ka, HydraAdminURL: ha, PublicIssuer: issuer, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeSessions(ctx, provider.ExternalSubject{Issuer: issuer, Subject: registered.Identity.ID}); err != nil {
		t.Fatal(err)
	}
	login = next(issuer + "/oauth2/auth?" + query.Encode()).Query().Get("login_challenge")
	if login == "" {
		t.Fatal("fresh revocation-test login challenge absent")
	}
	if _, err := h.AcceptLogin(ctx, login, registered.SessionToken, intent); err == nil {
		t.Fatal("revoked session accepted on a fresh login challenge")
	}
	t.Log("real Kratos session to Hydra S256 code, canonical response, signed ID token, exact subject/nonce and replay denial passed")
}
