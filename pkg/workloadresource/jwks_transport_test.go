package workloadresource

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func signedWorkloadJWT(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "pinned-local-key", "typ": "JWT"})
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": issuer, "sub": "baobab-trade-workload", "aud": "baobab-erp",
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"azp": "baobab-trade-workload", "actor_type": "workload", "scope": "erp:read",
	})
	data := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(data))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return data + "." + encode(sig)
}

func TestJWKSRetrievalUsesPinnedTLSRootsAndNeverFallbacks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests int
	jwks := map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "pinned-local-key",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/.well-known/jwks.json" || r.Method != http.MethodGet {
			http.Error(w, "invalid endpoint", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	token := signedWorkloadJWT(t, key, server.URL)

	// This exact custom CA works only if the remote KeySet retains the
	// resource verifier's HTTP client at construction. A default transport
	// rejects the private CA; the original implementation did exactly that.
	verified, err := NewOIDCSignedVerifier(server.URL, "baobab-erp", roots)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verified.VerifySigned(context.Background(), token)
	if err != nil || got.ClientID != "baobab-trade-workload" ||
		!slices.Equal(got.Audience, []string{"baobab-erp"}) ||
		!slices.Equal(got.Scopes, []string{"erp:read"}) {
		t.Fatalf("private CA JWT verification failed: claim=%+v err=%v", got, err)
	}
	if requests != 1 {
		t.Fatalf("expected one JWKS read using pinned roots, got %d", requests)
	}

	untrusted, err := NewOIDCSignedVerifier(server.URL, "baobab-erp", x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.VerifySigned(context.Background(), token); err == nil {
		t.Fatal("untrusted JWKS TLS certificate was accepted")
	}
}
