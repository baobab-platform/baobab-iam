package nativebff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// KratosAdminSessionRevoker is an IAM-private administrator adapter for an
// explicit all-Kratos-sessions logout. Public browsers never access this API.
// Subject is a Kratos UUID obtained from an independently signed OIDC ID token,
// not a caller-selected Principal or email. TLS roots are reviewed deployment
// data and proxy/redirect transport is disabled.
type KratosAdminSessionRevoker struct {
	origin string
	client *http.Client
}
type KratosAdminRevokeConfig struct {
	Origin       string
	TrustedRoots *x509.CertPool
}

func NewKratosAdminSessionRevoker(config KratosAdminRevokeConfig) (*KratosAdminSessionRevoker, error) {
	u, err := originURL(config.Origin, false)
	if err != nil || u.Scheme != "https" || config.TrustedRoots == nil {
		return nil, errors.New("private verified Kratos Admin boundary required")
	}
	return &KratosAdminSessionRevoker{
		origin: strings.TrimRight(config.Origin, "/"),
		client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.TrustedRoots}}},
	}, nil
}
func (r *KratosAdminSessionRevoker) RevokeNativeSessions(ctx context.Context, subject string) error {
	if r == nil || ctx == nil || ctx.Err() != nil || !isUUID(subject) {
		return errors.New("native identity subject invalid")
	}
	endpoint := r.origin + "/admin/identities/" + url.PathEscape(subject) + "/sessions"
	res, err := r.request(ctx, http.MethodDelete, endpoint)
	if err != nil {
		return errors.New("Kratos logout status unavailable")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 512))
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusOK {
		return errors.New("Kratos session revocation not confirmed")
	}

	res, err = r.request(ctx, http.MethodGet, endpoint+"?active=true")
	if err != nil {
		return errors.New("Kratos active session readback unavailable")
	}
	defer res.Body.Close()
	if !ory.EmptyActiveSessionInventory(res) {
		return errors.New("Kratos active session absence unconfirmed")
	}
	return nil
}

func (r *KratosAdminSessionRevoker) request(ctx context.Context, method, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	return r.client.Do(req)
}

var _ NativeSessionRevoker = (*KratosAdminSessionRevoker)(nil)
