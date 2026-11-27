package nativebff

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

func TestLiveN06HydraTokenRevocationReadback(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" || os.Getenv("ORY_HYDRA_ADMIN_URL") == "" {
		t.Skip("requires disposable real Hydra Foundation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin := os.Getenv("ORY_HYDRA_ADMIN_URL")
	issuer := os.Getenv("ORY_PUBLIC_ISSUER")
	if issuer == "" {
		issuer = "http://127.0.0.1:4444"
	}
	var nonce [16]byte
	var secretBytes [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("secure Hydra test client id unavailable")
	}
	if _, err := rand.Read(secretBytes[:]); err != nil {
		t.Fatal("secure Hydra test client secret unavailable")
	}
	clientID := "n06-revoke-" + hex.EncodeToString(nonce[:])
	secret := hex.EncodeToString(secretBytes[:])
	client := &http.Client{Timeout: 5 * time.Second}
	registration, _ := json.Marshal(map[string]any{
		"client_id": clientID, "client_secret": secret,
		"grant_types": []string{"client_credentials"}, "response_types": []string{},
		"scope": "n06:revocation-test", "token_endpoint_auth_method": "client_secret_basic",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, admin+"/admin/clients", strings.NewReader(string(registration)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Hydra test client registration unavailable")
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Hydra test client registration status %d", resp.StatusCode)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		deleteReq, err := http.NewRequestWithContext(cleanup, http.MethodDelete, admin+"/admin/clients/"+url.PathEscape(clientID), nil)
		if err != nil {
			t.Error("Hydra test client cleanup request invalid")
			return
		}
		deleteResp, err := client.Do(deleteReq)
		if err != nil {
			t.Error("Hydra test client cleanup unavailable")
			return
		}
		_ = deleteResp.Body.Close()
		if deleteResp.StatusCode != http.StatusNoContent && deleteResp.StatusCode != http.StatusOK {
			t.Error("Hydra test client cleanup unconfirmed")
		}
	})

	subjectSessions, err := NewHydraSubjectSessionsRevoker(HydraSubjectSessionsConfig{
		AdminOrigin: admin, AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal("Hydra subject-session adapter unavailable", err)
	}
	if err := subjectSessions.RevokeSubjectSessions(ctx, "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal("real Hydra subject-session deletion/consent read-back failed", err)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"n06:revocation-test"}}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.SetBasicAuth(clientID, secret)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatal("Hydra token issuance unavailable")
	}
	defer tokenResp.Body.Close()
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if tokenResp.StatusCode != http.StatusOK || json.NewDecoder(tokenResp.Body).Decode(&issued) != nil ||
		len(issued.AccessToken) < 20 || !strings.EqualFold(issued.TokenType, "bearer") {
		t.Fatal("Hydra did not issue the disposable client-credentials token")
	}

	introspect := func() bool {
		values := url.Values{"token": {issued.AccessToken}}
		check, err := http.NewRequestWithContext(ctx, http.MethodPost, admin+"/admin/oauth2/introspect", strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal("Hydra token precondition readback invalid")
		}
		check.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		checkResp, err := client.Do(check)
		if err != nil {
			t.Fatal("Hydra token precondition readback unavailable")
		}
		defer checkResp.Body.Close()
		var state struct {
			Active bool `json:"active"`
		}
		if checkResp.StatusCode != http.StatusOK || json.NewDecoder(checkResp.Body).Decode(&state) != nil {
			t.Fatal("Hydra token precondition readback malformed")
		}
		return state.Active
	}
	if !introspect() {
		t.Fatal("newly issued Hydra token was not active before revocation")
	}
	revoker, err := NewHydraOAuthRevoker(HydraOAuthRevokeConfig{
		Issuer: issuer, AdminOrigin: admin, ClientID: clientID, ClientSecret: secret,
		AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal("Hydra revocation adapter unavailable", err)
	}
	if err := revoker.Revoke(ctx, humanauth.Response{AccessToken: issued.AccessToken}); err != nil {
		t.Fatal("Hydra token revocation/read-back failed", err)
	}
	if introspect() {
		t.Fatal("Hydra still considered the revoked token active")
	}
	t.Log("real disposable Hydra client-credentials token was active, revoked, and independently read back inactive")
}
