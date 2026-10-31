package workloadresource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCSignedVerifier uses the standard issuer JWKS endpoint with pinned trust.
// It is a replaceable standards adapter, NOT an Ory-specific identity model.
type OIDCSignedVerifier struct {
	issuer string
	audience string
	client *http.Client
	keys oidc.KeySet
}

func newSignedVerifier(issuer, audience string, client *http.Client, fixture bool) (*OIDCSignedVerifier, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		u.RawQuery != "" || audience == "" || client == nil ||
		(u.Scheme != "https" && !(fixture && issuer == "http://127.0.0.1:4444")) {
		return nil, ErrDenied
	}
	return &OIDCSignedVerifier{
		issuer: issuer, audience: audience, client: client,
		keys: oidc.NewRemoteKeySet(context.Background(), strings.TrimRight(issuer, "/")+"/.well-known/jwks.json"),
	}, nil
}

// NewOIDCSignedVerifier never accepts a caller-provided HTTP client, so tests
// cannot accidentally inject an accepting transport into a protected consumer.
func NewOIDCSignedVerifier(issuer, audience string, roots *x509.CertPool) (*OIDCSignedVerifier, error) {
	return newSignedVerifier(issuer, audience, &http.Client{
		Timeout: 8*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots,
		}},
	}, false)
}

func (v *OIDCSignedVerifier) VerifySigned(ctx context.Context, raw string) (Claims, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || len(raw) < 20 || len(raw) > 16384 {
		return Claims{}, ErrDenied
	}
	id, err := oidc.NewVerifier(v.issuer, v.keys, &oidc.Config{
		ClientID: v.audience, SupportedSigningAlgs: []string{"RS256"},
	}).Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil || id == nil || id.Subject == "" || id.Issuer != v.issuer {
		return Claims{}, ErrDenied
	}
	var extra struct {
		ClientID string `json:"azp"`
		ActorType string `json:"actor_type"`
		Scope string `json:"scope"`
		NotBefore int64 `json:"nbf"`
	}
	if id.Claims(&extra) != nil || extra.ClientID == "" || extra.ActorType != "workload" {
		return Claims{}, errors.Join(ErrDenied, errors.New("invalid workload claims"))
	}
	claim := Claims{
		Issuer: id.Issuer, Subject: id.Subject, ClientID: extra.ClientID,
		Audience: id.Audience, Scopes: strings.Fields(extra.Scope),
		ActorType: extra.ActorType, IssuedAt: id.IssuedAt, ExpiresAt: id.Expiry,
	}
	if extra.NotBefore != 0 {
		claim.NotBefore = time.Unix(extra.NotBefore, 0)
	}
	return claim, nil
}

var _ SignedTokenVerifier = (*OIDCSignedVerifier)(nil)

// VerifyJWTShape is a non-authorising diagnostic that rejects non-JWT strings
// and never returns decoded claims. This is NOT a replacement for VerifySigned.
func VerifyJWTShape(raw string) error {
	if len(raw) < 20 || len(raw) > 16384 || strings.Count(raw, ".") != 2 {
		return ErrDenied
	}
	_ = json.Valid // Avoid leaking JWT claims through diagnostics.
	return nil
}
