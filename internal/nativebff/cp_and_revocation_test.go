package nativebff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

type fixedCallerToken string

func (f fixedCallerToken) Token(context.Context) (string, error) { return string(f), nil }

func TestDelegatedCPResolutionUsesIndependentCallerAndHumanEvidence(t *testing.T) {
	valid := true
	var seen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if r.URL.Path != "/internal/identity/v1/principals/resolve" || r.Method != "POST" ||
			r.Header.Get("Authorization") != "Bearer "+strings.Repeat("w", 40) ||
			r.Header.Get("X-Correlation-ID") == "" {
			t.Error("wrong CP caller/route")
			w.WriteHeader(403)
			return
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil ||
			body["subject_token"] != strings.Repeat("h", 25)+"."+strings.Repeat("i", 25)+"."+strings.Repeat("j", 25) ||
			body["subject_token_type"] != "urn:ietf:params:oauth:token-type:access_token" ||
			body["correlation_id"] != r.Header.Get("X-Correlation-ID") {
			t.Error("CP did not receive separate signed subject evidence")
			w.WriteHeader(400)
			return
		}
		if !valid {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"outcome": "RESOLVED", "principal_id": "11111111-1111-4111-8111-111111111111",
			"actor_type": "human", "status": "ACTIVE", "external_identity_id": "22222222-2222-4222-8222-222222222222",
			"evidence_expires_at": time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano)})
	}))
	defer server.Close()
	r, err := NewHTTPPrincipalResolver(PrincipalResolutionConfig{
		CPOrigin: server.URL, Caller: fixedCallerToken(strings.Repeat("w", 40)), Now: time.Now, AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.ResolveHuman(context.Background(), "https://issuer.invalid", "synthetic-subject",
		strings.Repeat("h", 25)+"."+strings.Repeat("i", 25)+"."+strings.Repeat("j", 25))
	if err != nil || p.ID != "11111111-1111-4111-8111-111111111111" || seen != 1 {
		t.Fatalf("CP resolution: %v", err)
	}
	valid = false
	if _, err = r.ResolveHuman(context.Background(), "https://issuer.invalid", "synthetic-subject",
		strings.Repeat("h", 25)+"."+strings.Repeat("i", 25)+"."+strings.Repeat("j", 25)); err == nil {
		t.Fatal("CP outage still resolved Principal")
	}
}
func TestRemoteOAuthRevocationMustConfirmIssuer(t *testing.T) {
	ok := true
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		u, p, set := r.BasicAuth()
		if !set || u != "estate-bff" || p != strings.Repeat("s", 32) || r.Method != "POST" || r.URL.Path != "/oauth2/revoke" {
			t.Error("revocation lacked confidential-client proof")
			w.WriteHeader(401)
			return
		}
		if r.ParseForm() != nil || r.Form.Get("token") == "" {
			t.Error("revoke token missing")
			w.WriteHeader(400)
			return
		}
		if !ok {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	revoker, err := NewOAuthRevoker(OAuthRevokeConfig{Issuer: server.URL, ClientID: "estate-bff",
		ClientSecret: strings.Repeat("s", 32), AllowTestLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	credential := humanauth.Response{AccessToken: strings.Repeat("a", 40), RefreshToken: strings.Repeat("r", 40),
		TokenType: "Bearer", ExpiresIn: 300}
	if err = revoker.Revoke(context.Background(), credential); err != nil || calls != 2 {
		t.Fatalf("access/refresh revocation: %v", err)
	}
	ok = false
	if revoker.Revoke(context.Background(), credential) == nil {
		t.Fatal("remote revocation failure silently accepted")
	}
	if calls != 4 {
		t.Fatalf("attempted %d remote revocations, want access and refresh on both runs", calls)
	}
}

func TestOAuthRevokerAttemptsRefreshAfterAccessRejected(t *testing.T) {
	var access, refresh int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("invalid token revocation form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.Form.Get("token_type_hint") {
		case "access_token":
			access++
			w.WriteHeader(http.StatusServiceUnavailable)
		case "refresh_token":
			refresh++
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unreviewed token type")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	revoker, err := NewOAuthRevoker(OAuthRevokeConfig{
		Issuer: server.URL, ClientID: "estate-bff",
		ClientSecret: strings.Repeat("s", 32), AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential := humanauth.Response{
		AccessToken:  strings.Repeat("a", 40),
		RefreshToken: strings.Repeat("r", 40),
		TokenType:    "Bearer", ExpiresIn: 300,
	}
	if err := revoker.Revoke(context.Background(), credential); err == nil {
		t.Fatal("partial issuer revocation cannot be reported as complete")
	}
	if access != 1 || refresh != 1 {
		t.Fatalf("partial revocation did not attempt refresh: access=%d refresh=%d", access, refresh)
	}
}
