package nativebff

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

// CallerTokenSource provides an independently registered, CP-audience
// workload bearer with identity:principal:resolve and the exact registered
// subject_principal_audiences relationship. Never reuse a human token here.
type CallerTokenSource interface {
	Token(context.Context) (string, error)
}

type PrincipalResolutionConfig struct {
	CPOrigin     string
	Caller       CallerTokenSource
	Now          func() time.Time
	TrustedRoots *x509.CertPool
	// Test-only: production never accepts an injected proxy/TLS transport.
	TestClient        *http.Client
	AllowTestLoopback bool
}
type HTTPPrincipalResolver struct {
	origin string
	client *http.Client
	caller CallerTokenSource
	now    func() time.Time
}

func NewHTTPPrincipalResolver(c PrincipalResolutionConfig) (*HTTPPrincipalResolver, error) {
	if _, err := originURL(c.CPOrigin, c.AllowTestLoopback); err != nil {
		return nil, err
	}
	if c.Caller == nil || c.Now == nil || (!c.AllowTestLoopback && c.TestClient != nil) {
		return nil, errors.New("current CP workload authority required")
	}
	httpClient := &http.Client{
		Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.TrustedRoots}, Proxy: nil},
	}
	if c.AllowTestLoopback && c.TestClient != nil {
		httpClient.Transport = c.TestClient.Transport
	}
	return &HTTPPrincipalResolver{origin: strings.TrimRight(c.CPOrigin, "/"), client: httpClient, caller: c.Caller, now: c.Now}, nil
}

func correlationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (c *HTTPPrincipalResolver) ResolveHuman(ctx context.Context, issuer, subject, subjectToken string) (Principal, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || issuer == "" || subject == "" || len(subjectToken) < 16 ||
		len(subjectToken) > 8192 || strings.Count(subjectToken, ".") != 2 || strings.ContainsAny(subjectToken, " \r\n") {
		return Principal{}, errors.New("invalid delegated human evidence")
	}
	caller, err := c.caller.Token(ctx)
	if err != nil || len(caller) < 16 || len(caller) > 8192 || strings.ContainsAny(caller, " \r\n") {
		return Principal{}, errors.New("CP workload credential unavailable")
	}
	id, err := correlationID()
	if err != nil {
		return Principal{}, err
	}
	body, err := json.Marshal(struct {
		SubjectToken     string `json:"subject_token"`
		SubjectTokenType string `json:"subject_token_type"`
		CorrelationID    string `json:"correlation_id"`
	}{subjectToken, "urn:ietf:params:oauth:token-type:access_token", id})
	if err != nil {
		return Principal{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/internal/identity/v1/principals/resolve", bytes.NewReader(body))
	if err != nil {
		return Principal{}, err
	}
	request.Header.Set("Authorization", "Bearer "+caller)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Correlation-ID", id)
	request.Header.Set("Cache-Control", "no-store")
	response, err := c.client.Do(request)
	if err != nil {
		return Principal{}, errors.New("CP principal resolver unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Principal{}, errors.New("CP principal resolution denied")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return Principal{}, errors.New("invalid CP principal resolution")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var resolved struct {
		Outcome            string    `json:"outcome"`
		PrincipalID        string    `json:"principal_id"`
		ActorType          string    `json:"actor_type"`
		Status             string    `json:"status"`
		ExternalIdentityID string    `json:"external_identity_id"`
		EvidenceExpiresAt  time.Time `json:"evidence_expires_at"`
	}
	if err = decoder.Decode(&resolved); err != nil || decoder.Decode(new(any)) != io.EOF ||
		resolved.Outcome != "RESOLVED" || resolved.ActorType != "human" || resolved.Status != "ACTIVE" ||
		!isUUID(resolved.PrincipalID) || !isUUID(resolved.ExternalIdentityID) || !c.now().Before(resolved.EvidenceExpiresAt) {
		return Principal{}, errors.New("invalid or stale CP principal evidence")
	}
	// CP already independently verified the human's issuer/subject signature,
	// registered client/audience, token status, and ACTIVE Principal mapping;
	// the BFF separately verified ID and access token subject equality.
	return Principal{ID: resolved.PrincipalID}, nil
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, ch := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
			return false
		}
	}
	return true
}

type OAuthRevokeConfig struct {
	Issuer, ClientID, ClientSecret string
	TestClient                     *http.Client
	AllowTestLoopback              bool
	TrustedRoots                   *x509.CertPool
}
type OAuthRevoker struct {
	issuer, clientID, secret string
	client                   *http.Client
}

func NewOAuthRevoker(c OAuthRevokeConfig) (*OAuthRevoker, error) {
	if _, err := originURL(c.Issuer, c.AllowTestLoopback); err != nil {
		return nil, err
	}
	if c.ClientID == "" || len(c.ClientSecret) < 32 || (!c.AllowTestLoopback && c.TestClient != nil) {
		return nil, errors.New("confidential OAuth revocation required")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.TrustedRoots}, Proxy: nil}}
	if c.AllowTestLoopback && c.TestClient != nil {
		client.Transport = c.TestClient.Transport
	}
	return &OAuthRevoker{strings.TrimRight(c.Issuer, "/"), c.ClientID, c.ClientSecret, client}, nil
}
func (o *OAuthRevoker) Revoke(ctx context.Context, tokens humanauth.Response) error {
	if o == nil || ctx == nil || tokens.AccessToken == "" {
		return errors.New("missing issuer revocation boundary")
	}
	for _, item := range []struct{ token, kind string }{
		{tokens.AccessToken, "access_token"}, {tokens.RefreshToken, "refresh_token"},
	} {
		if item.token == "" {
			continue
		}
		form := url.Values{"token": {item.token}, "token_type_hint": {item.kind}}
		req, err := http.NewRequestWithContext(ctx, "POST", o.issuer+"/oauth2/revoke", strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.SetBasicAuth(o.clientID, o.secret)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := o.client.Do(req)
		if err != nil {
			return errors.New("issuer revocation outcome unknown")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New("issuer revocation not confirmed")
		}
	}
	return nil
}

var _ PrincipalResolver = (*HTTPPrincipalResolver)(nil)
var _ Revoker = (*OAuthRevoker)(nil)
