package ory_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/nativebff"
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// This tests a real disposable Kratos password/browser session with the N06
// production reader and risk gate. Foundation loopback is not production TLS,
// native RP-verified A3/A4, a CP business grant or an estate acceptance.
func TestLiveN06KratosCurrentSessionAndRevocation(t *testing.T) {
	if os.Getenv("ORY_FOUNDATION") != "1" {
		t.Skip("real isolated Ory Foundation required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	public := envOr("ORY_KRATOS_PUBLIC_URL", "http://127.0.0.1:4433")
	admin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	hydra := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	client := &http.Client{Timeout: 10 * time.Second}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal("secure test seed unavailable")
	}
	email := "n06-native-" + hex.EncodeToString(seed[:12]) + "@baobab.invalid"
	password := "Aa!9-" + hex.EncodeToString(seed)
	var registration struct {
		ID string `json:"id"`
	}
	foundationRequest(t, ctx, client, "GET", public+"/self-service/registration/api", nil, "", 200, &registration)
	var created struct {
		Identity struct {
			ID string `json:"id"`
		} `json:"identity"`
	}
	foundationRequest(t, ctx, client, "POST", public+"/self-service/registration?flow="+url.QueryEscape(registration.ID), map[string]any{"method": "password", "password": password, "traits": map[string]any{"email": email}}, "", 200, &created)
	if created.Identity.ID == "" {
		t.Fatal("Kratos identity missing")
	}
	t.Cleanup(func() {
		ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		foundationRequest(t, ctx, client, "DELETE", admin+"/admin/identities/"+url.PathEscape(created.Identity.ID), nil, "", 204, nil)
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: nativeJSONTransport{http.DefaultTransport}}
	var login struct {
		ID string `json:"id"`
		UI struct {
			Nodes []struct {
				Attributes struct {
					Name  string `json:"name"`
					Value any    `json:"value"`
				} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}
	foundationRequest(t, ctx, browser, "GET", public+"/self-service/login/browser", nil, "", 200, &login)
	csrf := ""
	for _, node := range login.UI.Nodes {
		if node.Attributes.Name == "csrf_token" {
			csrf, _ = node.Attributes.Value.(string)
		}
	}
	if login.ID == "" || csrf == "" {
		t.Fatal("real Kratos login missing CSRF binding")
	}
	foundationRequest(t, ctx, browser, "POST", public+"/self-service/login?flow="+url.QueryEscape(login.ID), map[string]any{"method": "password", "identifier": email, "password": password, "csrf_token": csrf}, "", 200, nil)
	origin, err := url.Parse(public)
	if err != nil {
		t.Fatal(err)
	}
	cookie := ""
	for _, c := range jar.Cookies(origin) {
		if c.Name == "ory_kratos_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("real Kratos browser session cookie missing")
	}
	current, err := nativebff.NewKratosN06Provider(public, nil, time.Now, true, nil)
	if err != nil {
		t.Fatal("actual N06 reader construction denied", err)
	}
	credential := ory.NativeSessionCredential{Cookie: cookie}
	key, proof, err := current.CurrentNativeAuthentication(ctx, credential)
	if err != nil || key.Subject != created.Identity.ID || proof.SessionID == "" || (proof.AAL != "aal1" && proof.AAL != "aal2") {
		t.Fatal("real Kratos current session issuer/subject/AAL mismatch", err)
	}
	if proof.PasskeyUsed || proof.UserVerified || proof.OriginBound || proof.HardwareBound {
		t.Fatal("password login falsely promoted to A3/A4")
	}
	gate := &nativebff.N06SecurityGate{Provider: current, Policy: assurance.DefaultDevelopmentPolicy(), Risk: n06UnavailableRisk{}, Now: time.Now}
	decision, err := gate.EvaluateNative(ctx, credential, assurance.OrdinaryBuyer)
	if err != nil || decision.Outcome != assurance.Allow || decision.Required != assurance.A1 {
		t.Fatal("real Kratos authentication-only buyer read denied", err)
	}
	decision, _ = gate.EvaluateNative(ctx, credential, assurance.CommitBuyer)
	if decision.Outcome == assurance.Allow {
		t.Fatal("unavailable independent risk permitted buying")
	}
	if _, _, err := current.CurrentNativeAuthentication(ctx, ory.NativeSessionCredential{SessionToken: "untrusted"}); err == nil {
		t.Fatal("non-browser bearer accepted")
	}
	if _, _, err := current.CurrentNativeAuthentication(ctx, ory.NativeSessionCredential{Cookie: "ory_kratos_session=unissued-" + hex.EncodeToString(seed[:12])}); err == nil {
		t.Fatal("unissued cookie accepted")
	}
	adapter, err := ory.NewAdapter(ory.Config{KratosAdminURL: admin, HydraAdminURL: hydra, PublicIssuer: issuer, HTTPClient: client})
	if err != nil {
		t.Fatal("real provider revoker unavailable", err)
	}
	if err := adapter.RevokeSessions(ctx, provider.ExternalSubject{Issuer: issuer, Subject: created.Identity.ID}); err != nil {
		t.Fatal("real provider session revocation failed", err)
	}
	if _, _, err := current.CurrentNativeAuthentication(ctx, credential); err == nil {
		t.Fatal("revoked provider session remained trusted")
	}
	decision, _ = gate.EvaluateNative(ctx, credential, assurance.OrdinaryBuyer)
	if decision.Outcome == assurance.Allow {
		t.Fatal("revoked Kratos session retained authentication assurance")
	}
	t.Log("real disposable Kratos session, N06 A1/A2 readback, risk veto and provider revocation PASS; A3/A4, native CP/Trade and protected deployment not claimed")
}

type n06UnavailableRisk struct{}

func (n06UnavailableRisk) CurrentRisk(context.Context, assurance.CurrentSessionKey, assurance.Operation) (assurance.Risk, error) {
	return assurance.Risk{}, errors.New("no independent live risk authority in Ory Foundation")
}
