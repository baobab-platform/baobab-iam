package nativebff

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

// HydraOAuthRevoker confirms token withdrawal through Hydra's private
// introspection API. A public revocation 200 alone is not a read-back.
type HydraOAuthRevoker struct {
	public *OAuthRevoker
	admin  string
	client *http.Client
}

type HydraOAuthRevokeConfig struct {
	Issuer, AdminOrigin, ClientID, ClientSecret string
	TrustedRoots                                 *x509.CertPool
	TestClient, AdminTestClient                  *http.Client
	AllowTestLoopback                            bool
}

func NewHydraOAuthRevoker(c HydraOAuthRevokeConfig) (*HydraOAuthRevoker, error) {
	public, err := NewOAuthRevoker(OAuthRevokeConfig{
		Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		TestClient: c.TestClient, AllowTestLoopback: c.AllowTestLoopback,
		TrustedRoots: c.TrustedRoots,
	})
	if err != nil {
		return nil, err
	}
	origin, err := originURL(c.AdminOrigin, c.AllowTestLoopback)
	if err != nil || origin.Scheme != "https" && !c.AllowTestLoopback {
		return nil, errors.New("private verified Hydra administration required")
	}
	if !c.AllowTestLoopback && (c.TrustedRoots == nil || len(c.TrustedRoots.Subjects()) == 0 || c.AdminTestClient != nil) {
		return nil, errors.New("explicit Hydra administration trust required")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.TrustedRoots, MinVersion: tls.VersionTLS12}},
	}
	if c.AllowTestLoopback && c.AdminTestClient != nil {
		client.Transport = c.AdminTestClient.Transport
	}
	return &HydraOAuthRevoker{public: public, admin: strings.TrimRight(c.AdminOrigin, "/"), client: client}, nil
}

func (h *HydraOAuthRevoker) Revoke(ctx context.Context, tokens humanauth.Response) error {
	if h == nil || h.public == nil || h.client == nil || ctx == nil || ctx.Err() != nil || tokens.AccessToken == "" {
		return errors.New("Hydra token revocation boundary unavailable")
	}
	revokeErr := h.public.Revoke(ctx, tokens)
	readbackFailed := false
	for _, token := range []string{tokens.AccessToken, tokens.RefreshToken} {
		if token == "" {
			continue
		}
		active, err := h.introspect(ctx, token)
		if err != nil || active {
			readbackFailed = true
		}
	}
	if revokeErr != nil || readbackFailed {
		return errors.New("Hydra token revocation not independently confirmed")
	}
	return nil
}

func (h *HydraOAuthRevoker) introspect(ctx context.Context, token string) (bool, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.admin+"/admin/oauth2/introspect", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return false, errors.New("Hydra token readback request invalid")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, errors.New("Hydra token readback unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		return false, errors.New("Hydra token readback denied")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return false, errors.New("Hydra token readback malformed")
	}
	var result struct {
		Active *bool `json:"active"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Active == nil {
		return false, errors.New("Hydra token readback malformed")
	}
	return *result.Active, nil
}

var _ Revoker = (*HydraOAuthRevoker)(nil)
