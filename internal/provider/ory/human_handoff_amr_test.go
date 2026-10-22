package ory

import (
	"slices"
	"testing"
	"time"
)

// ADR-SHARED-042 CAA-03: the login accepts only amr derived from the methods
// Kratos completed for the verified session; nothing is guessed.
func TestNativeAMRFromVerifiedSessionMethods(t *testing.T) {
	session := func(methods ...string) nativeSession {
		var s nativeSession
		for _, m := range methods {
			s.Methods = append(s.Methods, struct {
				Method string `json:"method"`
			}{m})
		}
		return s
	}
	for name, tc := range map[string]struct {
		methods []string
		want    []string
	}{
		"password":                {[]string{"password"}, []string{"pwd"}},
		"password then totp":      {[]string{"password", "totp"}, []string{"pwd", "otp", "mfa"}},
		"passkey":                 {[]string{"passkey"}, []string{"hwk"}},
		"password then webauthn":  {[]string{"password", "webauthn"}, []string{"pwd", "hwk", "mfa"}},
		"email code":              {[]string{"code"}, []string{"otp"}},
		"repeated factor":         {[]string{"totp", "lookup_secret"}, []string{"otp"}},
		"unknown method omitted":  {[]string{"magic"}, nil},
		"unknown never makes mfa": {[]string{"password", "magic"}, []string{"pwd"}},
		"none":                    {nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nativeAMR(session(tc.methods...)); !slices.Equal(got, tc.want) {
				t.Fatalf("amr = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSameNativeSessionDetectsChangedMethods(t *testing.T) {
	now := time.Now()
	a := nativeSession{ID: "s", Active: true, ExpiresAt: now.Add(time.Hour), AuthenticatedAt: now, AAL: "aal1"}
	a.Identity.ID, a.Identity.State = "subject", "active"
	b := a
	if !sameNativeSession(a, b) {
		t.Fatal("identical sessions differ")
	}
	b.Methods = append(b.Methods, struct {
		Method string `json:"method"`
	}{"totp"})
	if sameNativeSession(a, b) {
		t.Fatal("a step-up during the handoff went unnoticed")
	}
	c := a
	c.AAL = "aal2"
	if sameNativeSession(a, c) {
		t.Fatal("an assurance change during the handoff went unnoticed")
	}
}
