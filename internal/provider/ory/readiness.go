// Target path: baobab-iam/internal/provider/ory/readiness.go
//
// Readiness probes for the non-production Ory foundation (Gate IAM-M2/M3).
//
// ADR-IAM-0021 requires separate Kratos and Hydra runtimes with distinct
// public vs administrative planes. baobab-iam tooling talks to admin planes
// only (§8 / §10). These probes verify that both admin bases respond to
// health/ready before adapter operations are treated as environment-ready.
//
// Path note: Ory v25+/v26 admin health is commonly served under
// /admin/health/ready on the admin port. Public health is /health/ready on
// the public port and is intentionally not required for adapter readiness
// (adapter never calls public self-service APIs).
package ory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// ReadyStatus is the result of CheckReady against both admin planes.
type ReadyStatus struct {
	// KratosAdminOK is true when the Kratos admin base answered ready.
	KratosAdminOK bool
	// HydraAdminOK is true when the Hydra admin base answered ready.
	HydraAdminOK bool
	// Detail holds human-readable probe notes (safe for logs; no secrets).
	Detail string
}

// OK reports whether both admin planes are ready.
func (s ReadyStatus) OK() bool {
	return s.KratosAdminOK && s.HydraAdminOK
}

// CheckReady probes Kratos and Hydra admin health endpoints.
//
// It does not call PublicIssuer (OIDC discovery stays a standards path for
// token validators, not this admin adapter). Failures return a non-nil error
// and a ReadyStatus describing which plane failed.
//
// Preferred path: GET {adminBase}/admin/health/ready
// Fallback path:  GET {adminBase}/health/ready
// (covers deployments that strip the /admin prefix on the admin listener).
func (a *Adapter) CheckReady(ctx context.Context) (ReadyStatus, error) {
	if a == nil {
		return ReadyStatus{}, fmt.Errorf("ory: adapter is nil")
	}

	var status ReadyStatus
	var notes []string

	kratosOK, kratosNote := probeAdminReady(ctx, a.http, a.cfg.KratosAdminURL, "kratos")
	status.KratosAdminOK = kratosOK
	notes = append(notes, kratosNote)

	hydraOK, hydraNote := probeAdminReady(ctx, a.http, a.cfg.HydraAdminURL, "hydra")
	status.HydraAdminOK = hydraOK
	notes = append(notes, hydraNote)

	status.Detail = strings.Join(notes, "; ")
	if !status.OK() {
		return status, &provider.ProviderError{
			Kind:     provider.ErrUnavailable,
			Message:  "ory foundation admin plane not ready: " + status.Detail,
			Provider: "ory",
		}
	}
	return status, nil
}

// probeAdminReady tries admin health paths in order and returns (ok, note).
func probeAdminReady(ctx context.Context, client *http.Client, baseURL, label string) (bool, string) {
	base := trimTrailingSlash(baseURL)
	// Ordered candidates: admin-prefixed first (Ory default on admin port),
	// then root health for alternate reverse-proxy layouts.
	candidates := []string{
		base + "/admin/health/ready",
		base + "/health/ready",
	}

	var lastErr string
	for _, url := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		// Drain and close body so keep-alive connections can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true, fmt.Sprintf("%s ready via %s", label, url)
		}
		lastErr = fmt.Sprintf("%s returned HTTP %d", url, resp.StatusCode)
	}
	return false, fmt.Sprintf("%s not ready: %s", label, lastErr)
}
