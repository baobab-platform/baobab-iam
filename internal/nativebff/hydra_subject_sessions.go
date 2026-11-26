package nativebff

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HydraSubjectSessionsRevoker owns IAM-private issuer-admin session withdrawal.
// These Hydra endpoints remove remembered login and consent sessions for
// the exact signed Kratos subject. Hydra v26.2.0 exposes consent-session
// listing but not login-session listing, so only consent deletion has a
// direct session-list read-back. Login-session revocation alone does NOT
// invalidate OAuth tokens. Even issuer token introspection cannot certify
// stateless JWT denial at CP/Trade; the protected resource must be checked
// independently before an incident is declared contained.
type HydraSubjectSessionsRevoker struct {
	origin string
	client *http.Client
}
type HydraSubjectSessionsConfig struct {
	AdminOrigin       string
	Roots             *x509.CertPool
	AllowTestLoopback bool
}

func NewHydraSubjectSessionsRevoker(config HydraSubjectSessionsConfig) (*HydraSubjectSessionsRevoker, error) {
	origin, err := originURL(config.AdminOrigin, config.AllowTestLoopback)
	if err != nil || origin.Scheme != "https" && !config.AllowTestLoopback ||
		!config.AllowTestLoopback && (config.Roots == nil || len(config.Roots.Subjects()) == 0) ||
		config.AllowTestLoopback && origin.Scheme == "https" && (config.Roots == nil || len(config.Roots.Subjects()) == 0) {
		return nil, errors.New("private verified Hydra administration required")
	}
	return &HydraSubjectSessionsRevoker{
		origin: config.AdminOrigin,
		client: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: config.Roots, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}
func (h *HydraSubjectSessionsRevoker) RevokeSubjectSessions(ctx context.Context, subject string) error {
	if h == nil || ctx == nil || ctx.Err() != nil || !isUUID(subject) {
		return errors.New("invalid OAuth subject")
	}
	// Consent first: revocation may be completed partially. Never silently
	// interpret a timeout as consent or token withdrawal success.
	for _, endpoint := range []string{"/admin/oauth2/auth/sessions/consent", "/admin/oauth2/auth/sessions/login"} {
		values := url.Values{"subject": {subject}}
		if endpoint == "/admin/oauth2/auth/sessions/consent" {
			values.Set("all", "true")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodDelete, h.origin+endpoint+"?"+values.Encode(), nil)
		if err != nil {
			return errors.New("invalid Hydra session revocation")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Cache-Control", "no-store")
		response, err := h.client.Do(request)
		if err != nil {
			return errors.New("Hydra subject revocation outcome unknown")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 512))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
			return errors.New("Hydra subject revocation not confirmed")
		}
	}
	return h.verifyNoConsentSessions(ctx, subject)
}

func (h *HydraSubjectSessionsRevoker) verifyNoConsentSessions(ctx context.Context, subject string) error {
	values := url.Values{"subject": {subject}, "page_size": {"250"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.origin+"/admin/oauth2/auth/sessions/consent?"+values.Encode(), nil)
	if err != nil {
		return errors.New("invalid Hydra consent-session readback")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := h.client.Do(request)
	if err != nil {
		return errors.New("Hydra consent-session readback unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 512))
		return errors.New("Hydra consent-session readback not confirmed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || len(body) == 0 || body[0] != '[' {
		return errors.New("Hydra consent-session readback malformed")
	}
	var sessions []json.RawMessage
	if err := json.Unmarshal(body, &sessions); err != nil || len(sessions) != 0 {
		return errors.New("Hydra consent sessions remain")
	}
	return nil
}

var _ OAuthSubjectSessionRevoker = (*HydraSubjectSessionsRevoker)(nil)
