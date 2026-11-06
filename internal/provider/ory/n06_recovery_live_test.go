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
	started := submitN06Recovery(ctx, client, target, map[string]any{"method": "code", "email": email})
	if started.HTTP != http.StatusOK || started.State != "sent_email" {
		t.Fatalf("Kratos recovery courier was not initiated: http=%d state=%s", started.HTTP, started.State)
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
		seen, template, err := n06RecoveryMailMetadata(ctx, client, email, key)
		if err != nil {
			t.Fatal("sealed Kratos recovery mail status not verifiable")
		}
		t.Fatalf("Kratos recovery code absent: smtp_delivered=%t expected_plaintext_marker=%t", seen, template)
	}
	wrong := submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": "00000000"})
	if wrong.State == "passed_challenge" || wrong.HTTP == http.StatusSeeOther ||
		(wrong.HTTP == http.StatusOK && wrong.State == "") {
		t.Fatal("invalid recovery code yielded an ambiguous or successful provider flow")
	}
	correct := submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": code})
	if correct.HTTP != http.StatusOK || correct.State != "passed_challenge" {
		t.Fatalf("actual provider recovery challenge not passed: http=%d state=%s",
			correct.HTTP, correct.State)
	}
	// A second use of this original recovery flow cannot be evidence of
	// another successfully completed user-recovery transaction.
	replay := submitN06Recovery(ctx, client, target,
		map[string]any{"method": "code", "code": code})
	if replay.HTTP == http.StatusOK && replay.State == "passed_challenge" {
		t.Fatal("original recovery proof was replayed as another accepted challenge")
	}
	// A successful recovery must not leave an old session trusted. This is
	// independently queried from the real running Kratos service.
	foundationRequest(t, ctx, client, http.MethodGet,
		public+"/sessions/whoami", nil, created.SessionToken, http.StatusUnauthorized, nil)
	t.Log("actual Kratos recovery courier, invalid-code denial, one-use proof and stale-session refusal passed")
}

type n06RecoveryDecision struct {
	HTTP int
	State string
}

func submitN06Recovery(ctx context.Context, client *http.Client, endpoint string, fields map[string]any) n06RecoveryDecision {
	var refusal n06RecoveryDecision
	content, err := json.Marshal(fields)
	if err != nil { return refusal }
	req, err := http.NewRequestWithContext(ctx,http.MethodPost,endpoint,bytes.NewReader(content))
	if err != nil { return refusal }
	req.Header.Set("Accept","application/json")
	req.Header.Set("Content-Type","application/json")
	res, err := client.Do(req)
	if err != nil { return refusal }
	defer res.Body.Close()
	status:=n06RecoveryDecision{HTTP:res.StatusCode}
	// Kratos can return 200 for a form containing an error. Only its
	// *original server-side flow state* has authority for code redemption.
	if res.Header.Get("Content-Type")!="application/json" {
		_,_=io.Copy(io.Discard,io.LimitReader(res.Body,65536))
		return status
	}
	var flow struct{ State string `json:"state"` }
	if json.NewDecoder(io.LimitReader(res.Body,65536)).Decode(&flow)==nil {
		switch flow.State {
		case "choose_method","sent_email","passed_challenge":
			status.State=flow.State
		}
	}
	return status
}

var n06CodePattern = regexp.MustCompile(`(?m)^BAOBAB_N06_RECOVERY_CODE=([0-9]{6,8})\r?$`)

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

func n06RecoveryMailMetadata(ctx context.Context, client *http.Client, email, key string) (bool,bool,error) {
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,
		"http://127.0.0.1:4457/metadata?recipient="+url.QueryEscape(email),nil)
	if err!=nil{return false,false,errors.New("sealed recovery status unavailable")}
	req.Header.Set("X-Baobab-Test-Key",key)
	res,err:=client.Do(req)
	if err!=nil{return false,false,errors.New("sealed recovery status unavailable")}
	defer res.Body.Close()
	if res.StatusCode!=http.StatusOK{return false,false,errors.New("sealed recovery status refused")}
	var value struct{
		Delivered bool `json:"delivered"`
		Marker bool `json:"template_marker_present"`
	}
	if json.NewDecoder(io.LimitReader(res.Body,1024)).Decode(&value)!=nil {
		return false,false,errors.New("sealed recovery status malformed")
	}
	return value.Delivered,value.Marker,nil
}
