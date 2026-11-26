package nativebff

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/fxamacker/cbor/v2"
)

func TestN06KratosWebAuthnReaderUsesTrustedActiveIdentity(t *testing.T) {
	const subject = "01234567-89ab-cdef-0123-456789abcdef"
	id := []byte("credential-with-real-wire-encoding")
	credentialID := base64.RawURLEncoding.EncodeToString(id)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32))
	wireKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]any{"id": id, "public_key": wireKey,
		"authenticator": map[string]any{"sign_count": 0, "clone_warning": false}}
	session := assurance.CurrentSessionKey{Issuer: "https://kratos-public.example", Subject: subject, SessionID: "current-session"}
	for _, tc := range []struct {
		name    string
		state   string
		status  int
		records []map[string]any
		allow   bool
	}{
		{"active counterless credential", "active", 200, []map[string]any{valid}, true},
		{"inactive", "inactive", 200, []map[string]any{valid}, false},
		{"missing or revoked", "active", 200, nil, false},
		{"ambiguous credential", "active", 200, []map[string]any{valid, valid}, false},
		{"clone warned", "active", 200, []map[string]any{{"id": id, "public_key": wireKey, "authenticator": map[string]any{"sign_count": 1, "clone_warning": true}}}, false},
		{"missing counter", "active", 200, []map[string]any{{"id": id, "public_key": wireKey}}, false},
		{"malformed key", "active", 200, []map[string]any{{"id": id, "public_key": []byte("malformed"), "authenticator": map[string]any{"sign_count": 1}}}, false},
		{"redirect", "active", 302, []map[string]any{valid}, false},
		{"wrong provider subject", "active", 200, []map[string]any{valid}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.Method != http.MethodGet || req.URL.Path != "/admin/identities/"+subject ||
					req.URL.RawQuery != "include_credential=webauthn" || req.Header.Get("Cookie") != "" ||
					req.Header.Get("Authorization") != "" || req.Header.Get("Cache-Control") != "no-store" {
					t.Error("credential read left the reviewed, cookie-free admin API boundary")
				}
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "/should-not-follow")
				}
				providerSubject := subject
				if tc.name == "wrong provider subject" {
					providerSubject = "replacement"
				}
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": providerSubject, "state": tc.state,
					"credentials": map[string]any{"webauthn": map[string]any{"config": map[string]any{"credentials": tc.records}}},
				})
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			reader, err := NewKratosWebAuthnReader(session.Issuer, server.URL, roots)
			if err != nil {
				t.Fatal(err)
			}
			foreign := session
			foreign.Issuer = "https://other.example"
			if _, err := reader.CurrentKratosCredential(context.Background(), foreign, credentialID); err == nil {
				t.Fatal("foreign issuer accepted")
			}
			got, err := reader.CurrentKratosCredential(context.Background(), session, credentialID)
			if (err == nil) != tc.allow || calls.Load() != 1 {
				t.Fatalf("allow=%t, err=%v, calls=%d", tc.allow, err, calls.Load())
			}
			if tc.allow && (got.ID != credentialID || got.Issuer != session.Issuer || got.Subject != subject ||
				got.SignCount != 0 || !bytes.Equal(got.PublicKeyDER, der)) {
				t.Fatal("Kratos wire evidence did not round-trip to the verified credential")
			}
		})
	}
}

func TestN06KratosWebAuthnReaderRefusesAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{`{"id":"one","id":"two"}`, `{"id":"one","ID":"two"}`} {
		if err := n06UniqueJSON(json.NewDecoder(strings.NewReader(raw))); err == nil {
			t.Fatal("ambiguous identity readback accepted")
		}
	}
}
