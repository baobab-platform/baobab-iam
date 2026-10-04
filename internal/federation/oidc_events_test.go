package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type oidcFixture struct {
	config OIDCConfiguration
	clock  time.Time
	err    error
	mutate func(*Assurance)
}

func (f *oidcFixture) OIDCConfiguration(context.Context, TrustSnapshot) (OIDCConfiguration, error) {
	return f.config, f.err
}
func (f *oidcFixture) MapAssurance(_ context.Context, _ TrustSnapshot, _ ExternalPrincipal, a Assurance) (Assurance, error) {
	a.MappingStatus = "MAPPED"
	a.Level = "BAOBAB-A1"
	a.MappingEvidenceReference = "ref_cidecision"
	if f.mutate != nil {
		f.mutate(&a)
	}
	return a, f.err
}
func oidcSetup(t *testing.T) (*OIDCEvents, *oidcFixture, TrustSnapshot, *rsa.PrivateKey, string) {
	t.Helper()
	_, base := setup(t, "oidc")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "ci-signing-key", Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcFixture{clock: base.clock, config: OIDCConfiguration{TrustID: base.snapshot.Trust.ID, SnapshotID: base.snapshot.SnapshotID, Revision: 1, Binding: base.snapshot.Trust.ProviderBinding, ClientID: "ci-bff", SigningAlgorithm: "RS256", JWKS: jwks, ValidUntil: base.clock.Add(10 * time.Minute)}}
	path := filepath.Join(t.TempDir(), "events.db")
	e, err := OpenOIDCEvents(path, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return e, f, base.snapshot, key, path
}
func signOIDC(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "ci-signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func oidcClaims(f *oidcFixture, s TrustSnapshot, r AuthenticationRequest) map[string]any {
	return map[string]any{"iss": s.Trust.UpstreamIssuer, "sub": "issuer-local-human-123", "aud": f.config.ClientID, "azp": f.config.ClientID, "iat": f.clock.Unix(), "exp": f.clock.Add(4 * time.Minute).Unix(), "auth_time": f.clock.Add(-time.Second).Unix(), "nonce": r.Nonce, "acr": "urn:upstream:password", "amr": []string{"pwd"}}
}

const browserSecret = "server-generated-ci-browser-session-secret-123456"

func TestOIDCActualSignatureEvidenceAndRestartReplay(t *testing.T) {
	e, f, s, key, path := oidcSetup(t)
	ctx := context.Background()
	r, err := e.Begin(ctx, s, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	token := signOIDC(t, key, oidcClaims(f, s, r))
	if err = e.Complete(ctx, r.ID, r.State, browserSecret, token, s); err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = OpenOIDCEvents(path, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	p, a, err := e.Verify(ctx, r.ID, s)
	if err != nil || p.Subject != "issuer-local-human-123" || p.Resolution.Status != "UNRESOLVED" || a.UpstreamEvidence.OIDC.ACR != "urn:upstream:password" || a.Level != "BAOBAB-A1" {
		t.Fatal(p, a, err)
	}
	if _, _, err = e.Verify(ctx, r.ID, s); err == nil {
		t.Fatal("event replay accepted")
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, browserSecret, r.State, r.Nonce} {
		if strings.Contains(string(data), secret) {
			t.Fatal("raw credential or correlation secret persisted")
		}
	}
	e, err = OpenOIDCEvents(path, f, f, func() time.Time { return f.clock }, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, _, err = e.Verify(ctx, r.ID, s); err == nil {
		t.Fatal("restart resurrected event")
	}
}
func TestOIDCProtocolDenialsBurnCorrelatedRequest(t *testing.T) {
	cases := []string{"issuer", "subject", "audience", "extra-audience", "azp", "nonce", "expiry", "future-iat", "long-lifetime", "old-auth", "future-nbf", "missing-auth", "missing-acr", "access-token-type", "bad-signature", "policy-down", "policy-drift", "mapper-upgrade", "mapper-substitution"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			e, f, s, key, _ := oidcSetup(t)
			defer e.Close()
			ctx := context.Background()
			r, err := e.Begin(ctx, s, secretDigest(browserSecret))
			if err != nil {
				t.Fatal(err)
			}
			claims := oidcClaims(f, s, r)
			switch mode {
			case "issuer":
				claims["iss"] = "https://other.example.test"
			case "subject":
				claims["sub"] = " padded "
			case "audience":
				claims["aud"] = "another-bff"
			case "extra-audience":
				claims["aud"] = []string{f.config.ClientID, "another-bff"}
			case "azp":
				claims["azp"] = "other"
			case "nonce":
				claims["nonce"] = "other"
			case "expiry":
				claims["exp"] = f.clock.Unix()
			case "future-iat":
				claims["iat"] = f.clock.Add(time.Minute).Unix()
			case "long-lifetime":
				claims["exp"] = f.clock.Add(time.Hour).Unix()
			case "old-auth":
				claims["auth_time"] = f.clock.Add(-time.Hour).Unix()
			case "future-nbf":
				claims["nbf"] = f.clock.Add(time.Second).Unix()
			case "missing-auth":
				delete(claims, "auth_time")
			case "missing-acr":
				delete(claims, "acr")
			case "access-token-type":
				claims["typ"] = "Bearer"
			case "policy-down":
				f.err = ErrUnavailable
			case "policy-drift":
				f.config.Revision = 2
			case "mapper-upgrade":
				f.mutate = func(a *Assurance) { a.Level = "BAOBAB-A4" }
			case "mapper-substitution":
				f.mutate = func(a *Assurance) { a.Subject = "other" }
			}
			token := signOIDC(t, key, claims)
			if mode == "bad-signature" {
				other, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				token = signOIDC(t, other, claims)
			}
			if err = e.Complete(ctx, r.ID, r.State, browserSecret, token, s); err == nil {
				t.Fatal("unsafe protocol accepted")
			}
			f.err = nil
			f.config.Revision = 1
			f.mutate = nil
			if err = e.Complete(ctx, r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(f, s, r)), s); err == nil {
				t.Fatal("failed assertion could be retried")
			}
			if _, _, err = e.Verify(ctx, r.ID, s); err == nil {
				t.Fatal("failed assertion became evidence")
			}
		})
	}
}
func TestOIDCBrowserBindingAndTrustRevision(t *testing.T) {
	e, f, s, key, _ := oidcSetup(t)
	defer e.Close()
	ctx := context.Background()
	r, err := e.Begin(ctx, s, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	token := signOIDC(t, key, oidcClaims(f, s, r))
	if err = e.Complete(ctx, r.ID, "wrong-state", browserSecret, token, s); err == nil {
		t.Fatal("state ignored")
	}
	if err = e.Complete(ctx, r.ID, r.State, "other-server-generated-browser-session-secret", token, s); err == nil {
		t.Fatal("browser binding ignored")
	}
	if err = e.Complete(ctx, r.ID, r.State, browserSecret, token, s); err != nil {
		t.Fatal(err)
	}
	changed := s
	changed.Trust.UpstreamIssuer = "https://other.example.test"
	if _, _, err = e.Verify(ctx, r.ID, changed); err == nil {
		t.Fatal("snapshot contents changed")
	}
	changed = s
	changed.Trust.Status = "SUSPENDED"
	if _, _, err = e.Verify(ctx, r.ID, changed); err == nil {
		t.Fatal("suspended trust accepted")
	}
	changed = s
	changed.ApprovedRevision = 2
	if _, _, err = e.Verify(ctx, r.ID, changed); err == nil {
		t.Fatal("revision changed")
	}
	if _, _, err = e.Verify(ctx, r.ID, s); err != nil {
		t.Fatal(err)
	}
}
func TestOIDCConcurrentEvidenceConsumptionSingleWinner(t *testing.T) {
	e, f, s, key, _ := oidcSetup(t)
	defer e.Close()
	ctx := context.Background()
	r, err := e.Begin(ctx, s, secretDigest(browserSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Complete(ctx, r.ID, r.State, browserSecret, signOIDC(t, key, oidcClaims(f, s, r)), s); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, err := e.Verify(ctx, r.ID, s); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("winners=%d", success)
	}
}
func TestOIDCSAMLAndUnsafeKeysRemainUnsupported(t *testing.T) {
	e, f, s, key, _ := oidcSetup(t)
	defer e.Close()
	s.Trust.Protocol = "SAML2"
	if _, _, err := e.Verify(context.Background(), proposalID, s); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	private, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "private", Algorithm: "RS256", Use: "sig"}}})
	bad := f.config
	bad.JWKS = private
	if _, err := publicOIDCKeys(bad); err == nil {
		t.Fatal("private keys accepted")
	}
	bad = f.config
	bad.SigningAlgorithm = "HS256"
	if _, err := publicOIDCKeys(bad); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
