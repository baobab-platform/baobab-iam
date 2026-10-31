package workloadresource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ResourceOperationPolicy is the owning engine's native, current operation
// authorization. CP context validation is not an engine business permission.
type ResourceOperationPolicy interface {
	AuthorizeOperation(context.Context, Claims, Operation) error
}

// ValidatorCredential supplies a distinct, independently registered CP
// context:validate workload credential from the caller's private runtime.
type ValidatorCredential func(context.Context) (string, error)

// CPContextAuthority composes CP's ACTUAL context-validation HTTP route and
// the engine's own native authorization veto. It neither creates CP grants nor
// reads CP's database. An IAM workload token cannot acquire tenant authority
// by carrying a tenant/organisation/market claim.
type CPContextAuthority struct {
	endpoint string
	validator ValidatorCredential
	native ResourceOperationPolicy
	client *http.Client
}

func NewCPContextAuthority(origin string, roots *x509.CertPool,
	validator ValidatorCredential, native ResourceOperationPolicy) (*CPContextAuthority, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.Fragment != "" || u.RawQuery != "" ||
		(u.Path != "" && u.Path != "/") || validator == nil || absent(native) {
		return nil, ErrDenied
	}
	return &CPContextAuthority{
		endpoint: strings.TrimRight(origin, "/") + "/v1/platform-context/validate",
		validator: validator, native: native,
		client: &http.Client{Timeout: 8*time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: roots,
			}},
		},
	}, nil
}

func (a *CPContextAuthority) AuthorizeCurrent(ctx context.Context, raw string, claims Claims, operation Operation) error {
	if a == nil || ctx == nil || ctx.Err() != nil || raw == "" ||
		operation.ContextID == "" || operation.TenantID == "" || operation.ResourceOperation == "" {
		return ErrDenied
	}
	caller, err := a.validator(ctx)
	if err != nil || len(caller) < 20 || caller == raw || strings.TrimSpace(caller) != caller {
		return ErrDenied
	}
	payload, err := json.Marshal(struct {
		ContextID string `json:"context_id"`
		SubjectToken string `json:"subject_token"`
	}{operation.ContextID, raw})
	if err != nil { return ErrDenied }
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(payload))
	if err != nil { return ErrDenied }
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Authorization", "Bearer "+caller)
	response, err := a.client.Do(request)
	if err != nil { return ErrDenied }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		return ErrDenied
	}
	rawBody, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(rawBody) > 8192 { return ErrDenied }
	// Validate current CP identity/context, but never interpret the positive
	// context response as native authorization to perform the operation.
	var contextData struct {
		ContextID string `json:"context_id"`
		TenantID string `json:"tenant_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if json.Unmarshal(rawBody, &contextData) != nil ||
		contextData.ContextID != operation.ContextID ||
		contextData.TenantID != operation.TenantID ||
		!time.Now().Before(contextData.ExpiresAt) {
		return ErrDenied
	}
	if err := a.native.AuthorizeOperation(ctx, claims, operation); err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	return nil
}

var _ CurrentAuthority = (*CPContextAuthority)(nil)
