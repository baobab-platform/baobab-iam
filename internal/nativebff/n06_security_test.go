package nativebff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type fixedN06Gate struct {
	result  assurance.Decision
	failure bool
	calls   int
	last    assurance.Operation
}

func (f *fixedN06Gate) EvaluateNative(_ context.Context, _ ory.NativeSessionCredential, op assurance.Operation) (assurance.Decision, error) {
	f.calls++
	f.last = op
	if f.failure {
		return assurance.Decision{Outcome: assurance.Deny}, errors.New("risk unavailable")
	}
	return f.result, nil
}
func TestN06BFFRejectsUnreviewedScopeAndMissingGate(t *testing.T) {
	f := makeFixture(t)
	conf := f.h.c
	conf.N06Required = true
	conf.N06ScopeOperations = map[string]assurance.Operation{"trade:buy": assurance.CommitBuyer}
	if _, err := New(conf); err == nil {
		t.Fatal("native BFF enabled security without risk/provider proof gate")
	}
	conf.N06Gate = &fixedN06Gate{}
	if _, err := New(conf); err != nil {
		t.Fatalf("reviewed scope config rejected: %v", err)
	}
	conf.N06ScopeOperations = map[string]assurance.Operation{"other:scope": assurance.CommitBuyer}
	if _, err := New(conf); err == nil {
		t.Fatal("unregistered native scope accepted for N06")
	}
	conf.N06ScopeOperations = map[string]assurance.Operation{"trade:buy": "unknown-operation"}
	if _, err := New(conf); err == nil {
		t.Fatal("unreviewed security operation accepted")
	}
	conf.N06Required = false
	if _, err := New(conf); err == nil {
		t.Fatal("configured security without mandatory gate flag silently ignored")
	}
}
func TestN06BFFLoginAndConsentRequireCurrentSecurity(t *testing.T) {
	f := makeFixture(t)
	conf := f.h.c
	gate := &fixedN06Gate{result: assurance.Decision{Outcome: assurance.StepUp}}
	conf.N06Required = true
	conf.N06ScopeOperations = map[string]assurance.Operation{"trade:buy": assurance.CommitBuyer}
	// makeFixture registers exact openid + buyer scope to the native app.
	conf.N06Gate = gate
	h, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := startFlow(t, f)
	kratos := &http.Cookie{Name: "ory_kratos_session", Value: "verified-current-cookie"}
	started := request(h, "GET", "http://127.0.0.1:3000/auth/login?login_challenge=real-hydra-challenge", "", flow, kratos)
	if started.Code != 403 || f.hand.accepted != 0 || gate.calls != 1 || gate.last != assurance.CommitBuyer {
		t.Fatalf("N06 fresh step-up bypassed login: %d handoff=%d gate=%d", started.Code, f.hand.accepted, gate.calls)
	}
	gate.result = assurance.Decision{Outcome: assurance.Allow}
	allowed := request(h, "GET", "http://127.0.0.1:3000/auth/login?login_challenge=real-hydra-challenge", "", flow, kratos)
	if allowed.Code != 303 || f.hand.accepted != 1 {
		t.Fatalf("A2 current assurance refused: %d", allowed.Code)
	}
	gate.failure = true
	consent := request(h, "GET", "http://127.0.0.1:3000/auth/consent?consent_challenge=real-hydra-challenge", "", flow, kratos)
	if consent.Code != 403 || f.hand.accepted != 1 {
		t.Fatalf("risk outage ignored after login: %d", consent.Code)
	}
}
func TestN06KratosLiveReaderDeniesUnknownA3AndForgedProviderResponse(t *testing.T) {
	now := time.Now().UTC()
	payload := `{"id":"session-original","active":true,"expires_at":"` +
		now.Add(time.Hour).Format(time.RFC3339) +
		`","authenticated_at":"` + now.Add(-time.Minute).Format(time.RFC3339) +
		`","authenticator_assurance_level":"aal2","identity":{"id":"human-original","state":"active"},"authentication_methods":[{"method":"webauthn"}]}`
	status := 200
	reply := payload
	mime := "application/json"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions/whoami" || r.Method != "GET" || r.Header.Get("Cookie") != "ory_kratos_session=synthetic-cookie" {
			http.Error(w, "invalid request", 400)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()
	p, err := NewKratosN06Provider(issuer, nil, func() time.Time { return now }, true, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	key, proof, err := p.CurrentNativeAuthentication(context.Background(), ory.NativeSessionCredential{Cookie: "ory_kratos_session=synthetic-cookie"})
	if err != nil || key.Subject != "human-original" || proof.AAL != "aal2" {
		t.Fatalf("real Kratos browser current proof failed: %+v %+v %v", key, proof, err)
	}
	if proof.PasskeyUsed || proof.UserVerified || proof.OriginBound || proof.HardwareBound {
		t.Fatal("unaudited WebAuthn method name upgraded to A3")
	}
	for _, tc := range []struct {
		status      int
		reply, mime string
	}{
		{200, `{"id":"session-original","id":"second","active":true}`, "application/json"},
		{200, strings.Replace(payload, `"active":true`, `"active":false`, 1), "application/json"},
		{200, strings.Replace(payload, `"state":"active"`, `"state":"inactive"`, 1), "application/json"},
		{200, strings.Replace(payload, `"aal2"`, `"aal3"`, 1), "application/json"},
		{302, payload, "application/json"},
		{200, payload, "text/html"},
		{200, "null", "application/json"},
	} {
		status, reply, mime = tc.status, tc.reply, tc.mime
		if _, _, err := p.CurrentNativeAuthentication(context.Background(), ory.NativeSessionCredential{Cookie: "ory_kratos_session=synthetic-cookie"}); err == nil {
			t.Fatalf("invalid Kratos evidence was accepted: status=%d mime=%s", status, mime)
		}
	}
}
