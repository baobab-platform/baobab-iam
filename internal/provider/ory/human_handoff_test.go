package ory

import (
	"context"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

func TestNativeHumanChallengeSessionAndConsentBindings(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	intent := humanauth.Request{GrantType: "authorization_code", ClientID: "estate-ci", RedirectURI: "https://estate.invalid/callback", Scope: "openid", CodeChallenge: strings.Repeat("x", 43), CodeChallengeMethod: "S256", State: strings.Repeat("s", 32), Nonce: strings.Repeat("n", 32)}
	for _, negative := range []string{"", "state", "nonce", "client", "scope", "audience", "subject", "duplicate-query", "expired", "inactive", "future-authentication", "duplicate-session", "revoked-before-accept", "no-consent", "redirect", "provider-redirect"} {
		t.Run(negative, func(t *testing.T) {
			accepts, sessions := 0, 0
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/admin/") && r.Header.Get("X-Session-Token") != "" {
					t.Error("Kratos credential sent to Hydra")
				}
				if r.URL.Path == "/sessions/whoami" {
					sessions++
					if r.Header.Get("X-Session-Token") != "private-session-credential" {
						w.WriteHeader(401)
						return
					}
					if negative == "provider-redirect" {
						http.Redirect(w, r, "https://outside.invalid/session", 302)
						return
					}
					expiry, authenticated := now.Add(time.Hour), now.Add(-time.Minute)
					if negative == "expired" {
						expiry = now
					}
					if negative == "future-authentication" {
						authenticated = now.Add(time.Second)
					}
					if negative == "duplicate-session" {
						w.Write([]byte(`{"active":true,"active":false}`))
						return
					}
					active := negative != "inactive" && !(negative == "revoked-before-accept" && sessions == 2)
					json.NewEncoder(w).Encode(map[string]any{"id": "session-id", "active": active, "expires_at": expiry, "authenticated_at": authenticated, "authenticator_assurance_level": "aal1", "identity": map[string]string{"id": "exact-kratos-subject", "state": "active"}})
					return
				}
				if r.Method == http.MethodPut {
					accepts++
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["remember"] != false {
						t.Error("remembered authority escaped")
					}
					if strings.Contains(r.URL.Path, "/login/") && body["subject"] != "exact-kratos-subject" {
						t.Error("wrong native subject")
					}
					redirect := server.URL + "/oauth2/auth?consent_verifier=private-verifier"
					if negative == "redirect" {
						redirect = "https://outside.invalid/oauth2/auth"
					}
					json.NewEncoder(w).Encode(map[string]string{"redirect_to": redirect})
					return
				}
				query := url.Values{"response_type": {"code"}, "client_id": {intent.ClientID}, "redirect_uri": {intent.RedirectURI}, "scope": {intent.Scope}, "state": {intent.State}, "nonce": {intent.Nonce}, "code_challenge": {intent.CodeChallenge}, "code_challenge_method": {"S256"}}
				if negative == "state" || negative == "nonce" || negative == "client" {
					key := negative
					if key == "client" {
						key = "client_id"
					}
					query.Set(key, "substituted")
				}
				if negative == "duplicate-query" {
					query.Add("state", intent.State)
				}
				c := map[string]any{"challenge": strings.Repeat("opaque", 700), "request_url": server.URL + "/oauth2/auth?" + query.Encode(), "client": map[string]string{"client_id": intent.ClientID}, "requested_scope": []string{"openid"}, "requested_access_token_audience": []string{}, "subject": "exact-kratos-subject"}
				if negative == "scope" {
					c["requested_scope"] = []string{"openid", "payments:write"}
				}
				if negative == "audience" {
					c["requested_access_token_audience"] = []string{"baobab-control-plane"}
				}
				if negative == "subject" {
					c["subject"] = "another-subject"
				}
				json.NewEncoder(w).Encode(c)
			}))
			defer server.Close()
			h, err := NewNativeHumanHandoff(NativeHumanConfig{KratosPublicURL: server.URL, HydraAdminURL: server.URL, Issuer: server.URL, Client: server.Client(), Now: func() time.Time { return now }, Fence: openNativeTestFence(t)})
			if err != nil {
				t.Fatal(err)
			}
			redirect, err := h.AcceptConsent(context.Background(), strings.Repeat("opaque", 700), "private-session-credential", intent, negative != "no-consent")
			if negative == "" {
				if err != nil || redirect == "" || accepts != 1 {
					t.Fatalf("valid native handoff failed: %v", err)
				}
				return
			}
			if err == nil || redirect != "" {
				t.Fatal("invalid native handoff accepted")
			}
			if negative != "redirect" && accepts != 0 {
				t.Fatal("invalid native intent or session reached Hydra acceptance")
			}
		})
	}
}

func TestNativeHumanRejectsUnprotectedOriginsAndUnsupportedIntent(t *testing.T) {
	if _, err := NewNativeHumanHandoff(NativeHumanConfig{KratosPublicURL: "https://kratos.invalid", HydraAdminURL: "https://hydra-admin.invalid", Issuer: "https://issuer.invalid", Now: time.Now}); err == nil {
		t.Fatal("constructor accepted absent replay fence")
	}
	if _, err := NewNativeHumanHandoff(NativeHumanConfig{KratosPublicURL: "http://127.0.0.1:4433", HydraAdminURL: "http://127.0.0.1:4445", Issuer: "http://127.0.0.1:4444", Now: time.Now}); err == nil {
		t.Fatal("production constructor accepted plaintext")
	}
	var h *NativeHumanHandoff
	if _, err := h.AcceptLogin(context.Background(), "challenge", "credential", humanauth.Request{}); err == nil {
		t.Fatal("nil bridge accepted handoff")
	}
}

func TestNativeChallengeFenceConcurrencyAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fence.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	fence := &nativeTestFence{db}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if fence.ConsumeNativeChallenge(context.Background(), "same-key") == nil {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("challenge fence admitted concurrent replay")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if (&nativeTestFence{db}).ConsumeNativeChallenge(context.Background(), "same-key") == nil {
		t.Fatal("restart lost replay fence")
	}
}

// Disposable durable test storage; production uses a shared atomic ledger.
type nativeTestFence struct{ db *bolt.DB }

func openNativeTestFence(t *testing.T) *nativeTestFence {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "native-fence.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &nativeTestFence{db}
}
func (f *nativeTestFence) ConsumeNativeChallenge(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("consumed"))
		if err != nil {
			return err
		}
		if bucket.Get([]byte(key)) != nil {
			return fmt.Errorf("replay")
		}
		return bucket.Put([]byte(key), []byte{1})
	})
}
