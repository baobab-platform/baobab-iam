package ory_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

// TestLiveN06KratosRecoveryCourier uses a *real disposable Kratos service*,
// its local courier and actual recovery API. No message content, credentials,
// challenge codes or session tokens are logged or written to CI artifacts.
// This case is NOT A3/A4, CP authority, or completed two-person rebinding.
func TestLiveN06KratosRecoveryCourier(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" {
		t.Skip("requires real disposable Ory Foundation")
	}
	key := os.Getenv("BAOBAB_TEST_MAIL_KEY")
	if len(key) != 64 {
		t.Fatal("ephemeral sealed SMTP readback unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	public := envOr("ORY_KRATOS_PUBLIC_URL", "http://127.0.0.1:4433")
	admin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal("secure fixture seed unavailable")
	}
	email := "recovery-" + hex.EncodeToString(seed) + "@baobab.invalid"
	passwordSeed := make([]byte, 32)
	if _, err := rand.Read(passwordSeed); err != nil {
		t.Fatal("independent credential fixture entropy unavailable")
	}
	password := "Aa!9-" + hex.EncodeToString(passwordSeed)
	var registration struct {
		ID string `json:"id"`
	}
	foundationRequest(t, ctx, client, http.MethodGet, public+"/self-service/registration/api",
		nil, "", http.StatusOK, &registration)
	var created struct {
		SessionToken string `json:"session_token"`
		Identity     struct {
			ID string `json:"id"`
		} `json:"identity"`
	}
	foundationRequest(t, ctx, client, http.MethodPost,
		public+"/self-service/registration?flow="+url.QueryEscape(registration.ID),
		map[string]any{"method": "password", "password": password,
			"traits": map[string]any{"email": email}}, "", http.StatusOK, &created)
	if created.Identity.ID == "" || created.SessionToken == "" {
		t.Fatal("live Kratos registration/session receipt missing")
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		foundationRequest(t, cleanup, client, http.MethodDelete,
			admin+"/admin/identities/"+url.PathEscape(created.Identity.ID),
			nil, "", http.StatusNoContent, nil)
	})
	foundationRequest(t, ctx, client, http.MethodGet,
		public+"/sessions/whoami", nil, created.SessionToken, http.StatusOK, nil)
	var start struct {
		ID string `json:"id"`
	}
	foundationRequest(t, ctx, client, http.MethodGet,
		public+"/self-service/recovery/api", nil, "", http.StatusOK, &start)
	if start.ID == "" {
		t.Fatal("Kratos recovery flow not created")
	}
	target := public + "/self-service/recovery?flow=" + url.QueryEscape(start.ID)
	status := submitN06Recovery(ctx, client, target, map[string]any{"method": "code", "email": email})
	if status != http.StatusOK {
		t.Fatal("Kratos did not accept recovery courier initiation")
	}
	// Only the test-run secret allows reading one disposable in-memory
	// synthetic message through the host-loopback API.
	code := ""
	until := time.Now().Add(35 * time.Second)
	for time.Now().Before(until) {
		s, err := n06RecoveryCode(ctx, client, email, key)
		if err != nil {
			t.Fatalf("sealed recovery-mail readback refused: %v", err)
		}
		if s != "" {
			code = s
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if code == "" {
		t.Fatal("Kratos courier did not deliver a bounded recovery code")
	}
	if status = submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": "00000000"}); status < 400 {
		t.Fatal("invalid recovery proof was accepted")
	}
	status = submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": code})
	if status != http.StatusOK {
		t.Fatal("real Kratos recovery code was not accepted")
	}
	// Same flow must never redeem the consumed one-time recovery code twice.
	status = submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": code})
	if status < 400 {
		t.Fatal("completed recovery flow was replayable")
	}
	// A successful recovery must not leave an old session trusted. This is
	// independently queried from the real running Kratos service.
	foundationRequest(t, ctx, client, http.MethodGet,
		public+"/sessions/whoami", nil, created.SessionToken, http.StatusUnauthorized, nil)
	t.Log("actual Kratos recovery courier, invalid-code denial, one-use proof and stale-session refusal passed")
}

func submitN06Recovery(ctx context.Context, client *http.Client, endpoint string, fields map[string]any) int {
	content, err := json.Marshal(fields)
	if err != nil {
		return 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(content))
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 65536))
	return res.StatusCode
}

var n06CodePattern = regexp.MustCompile(`(?i)(?:recovery code|your code|security code|code:)\D{0,100}([0-9]{6,8})`)

func n06RecoveryCode(ctx context.Context, client *http.Client, email, key string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://127.0.0.1:4457/messages?recipient="+url.QueryEscape(email), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Baobab-Test-Key", key)
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
		return "", errors.New("courier_http_or_media_denied")
	}
	var payload struct {
		Messages []string `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 128*1024)).Decode(&payload); err != nil {
		return "", errors.New("courier_json_refused")
	}
	if len(payload.Messages) > 4 {
		return "", errors.New("courier_excess_messages")
	}
	return n06OneDistinctRecoveryCode(payload.Messages)
}

// Kratos sends the same one-time code in both plain-text and HTML MIME
// alternatives. Repetition of the IDENTICAL code is not ambiguity.
// Two different codes, even across separate messages, must fail closed.
func n06OneDistinctRecoveryCode(messages []string) (string, error) {
	unique := make(map[string]struct{})
	for _, message := range messages {
		for _, match := range n06CodePattern.FindAllStringSubmatch(message, -1) {
			unique[match[1]] = struct{}{}
			if len(unique) > 1 {
				return "", errors.New("courier_conflicting_distinct_codes")
			}
		}
	}
	for code := range unique {
		return code, nil
	}
	return "", nil
}
