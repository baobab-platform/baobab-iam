package ory

import (
	"slices"
	"testing"
	"time"
)

// Kratos-reported methods are evidence, not a caller-selected factor list.
// Recovery and generic codes must not become OTP or MFA (ADR-IAM-0024/25).
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
	cases := map[string]struct {
		methods []string
		want    []string
	}{
		"password":                  {methods: []string{"password"}, want: []string{"pwd"}},
		"password then totp":        {methods: []string{"password", "totp"}, want: []string{"pwd", "otp", "mfa"}},
		"passkey":                   {methods: []string{"passkey"}, want: nil},
		"password then webauthn":    {methods: []string{"password", "webauthn"}, want: []string{"pwd"}},
		"email code is not totp":    {methods: []string{"code"}, want: nil},
		"recovery code no factor":   {methods: []string{"totp", "lookup_secret"}, want: []string{"otp"}},
		"password and lookup code":  {methods: []string{"password", "lookup_secret"}, want: []string{"pwd"}},
		"password and generic code": {methods: []string{"password", "code"}, want: []string{"pwd"}},
		"unknown method omitted":    {methods: []string{"magic"}, want: nil},
		"unknown never makes mfa":   {methods: []string{"password", "magic"}, want: []string{"pwd"}},
		"synced passkey not hwk":     {methods: []string{"password", "passkey"}, want: []string{"pwd"}},
		"none":                      {methods: nil, want: nil},
	}
	for name, tc := range cases {
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
