package nativebff

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ADR-0008: issuer+subject are not caller-granted authority. The delegated
// bearer must match them before ANY CP call, and only CP can verify the
// signature, current mapping and active entitlement. These are local negative
// fixtures, NOT connected issuer/CP acceptance evidence.
func TestDelegatedIssuerSubjectMustMatchBeforeCP(t *testing.T) {
	seen := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resolver, err := NewHTTPPrincipalResolver(PrincipalResolutionConfig{
		CPOrigin: srv.URL,
		Caller: fixedCallerToken(strings.Repeat("w", 40)),
		Now: time.Now,
		AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
	}
	invalid := map[string]string{
		"wrong issuer": testDelegatedHumanToken("https://foreign.invalid", "alice"),
		"wrong subject": testDelegatedHumanToken("https://issuer.invalid", "bob"),
		"missing subject": encode(`{"iss":"https://issuer.invalid"}`),
		"duplicate issuer": encode(`{"iss":"https://issuer.invalid","iss":"https://foreign.invalid","sub":"alice"}`),
		"duplicate subject": encode(`{"iss":"https://issuer.invalid","sub":"alice","sub":"bob"}`),
		"non-string subject": encode(`{"iss":"https://issuer.invalid","sub":123}`),
		"trailing document": encode(`{"iss":"https://issuer.invalid","sub":"alice"} {}`),
		"invalid base64": "e30.***.signature",
		"opaque bearer": strings.Repeat("x", 40),
	}
	for name, token := range invalid {
		t.Run(name, func(t *testing.T) {
			if p, err := resolver.ResolveHuman(context.Background(), "https://issuer.invalid", "alice", token); err == nil || p.ID != "" {
				t.Fatalf("unbound delegated bearer accepted: principal=%+v error=%v", p, err)
			}
		})
	}
	if seen != 0 {
		t.Fatalf("unbound token reached CP %d times", seen)
	}
}

func TestDelegatedSubjectStillRequiresCPDecision(t *testing.T) {
	seen := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	resolver, err := NewHTTPPrincipalResolver(PrincipalResolutionConfig{
		CPOrigin: srv.URL,
		Caller: fixedCallerToken(strings.Repeat("w", 40)),
		Now: time.Now,
		AllowTestLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveHuman(context.Background(), "https://issuer.invalid", "alice", testDelegatedHumanToken("https://issuer.invalid", "alice")); err == nil || seen != 1 {
		t.Fatal("matching unverified claims cannot bypass CP denial")
	}
}
