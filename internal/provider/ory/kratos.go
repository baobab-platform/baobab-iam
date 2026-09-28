// Target path: baobab-iam/internal/provider/ory/kratos.go
//
// kratosClient wraps the Ory Kratos Admin API for human identity operations.
// Only the admin plane is used; public self-service flows are owned by
// Digital Estate UIs (ADR-IAM-0021).
//
// Wire shapes follow Ory Kratos Admin OpenAPI (v26.x line used in
// provider.lock.yaml): JSON Patch for partial identity updates; create
// identity POST /admin/identities; sessions DELETE /admin/identities/{id}/sessions.
package ory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// kratosClient is an internal HTTP client for Kratos Admin.
type kratosClient struct {
	baseURL string
	http    *http.Client
}

func newKratosClient(baseURL string, httpClient *http.Client) *kratosClient {
	return &kratosClient{
		baseURL: trimTrailingSlash(baseURL),
		http:    httpClient,
	}
}

// ---------------------------------------------------------------------------
// Identity read
// ---------------------------------------------------------------------------

func (c *kratosClient) getIdentity(ctx context.Context, identityID string) (*provider.ProviderIdentity, error) {
	url := fmt.Sprintf("%s/admin/identities/%s", c.baseURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, wrapErr("kratos get identity", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("kratos get identity", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrNotFound,
			Message:  "identity not found",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("kratos get identity", resp)
	}

	var raw kratosIdentity
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, wrapErr("kratos decode identity", err)
	}
	return raw.toProviderIdentity(), nil
}

// ---------------------------------------------------------------------------
// Provision / import
// ---------------------------------------------------------------------------

func (c *kratosClient) provisionIdentity(
	ctx context.Context,
	issuer string,
	spec provider.IdentityProvisioningSpec,
) (*provider.ProviderIdentity, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	body := kratosCreateIdentityRequest{
		SchemaID: "default", // matches config/ory/kratos identity schema $id binding
		Traits:   spec.Traits,
		State:    "active",
		Metadata: map[string]any{},
	}
	if spec.MigrationID != "" {
		body.Metadata["migration_id"] = spec.MigrationID
	}
	for k, v := range spec.Metadata {
		body.Metadata[k] = v
	}

	if spec.Credentials != nil {
		body.Credentials = mapImportedCredentials(spec.Credentials)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, wrapErr("kratos marshal create identity", err)
	}

	url := c.baseURL + "/admin/identities"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, wrapErr("kratos create identity", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("kratos create identity", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrAlreadyExists,
			Message:  "identity already exists",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("kratos create identity", resp)
	}

	var raw kratosIdentity
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, wrapErr("kratos decode created identity", err)
	}

	pi := raw.toProviderIdentity()
	pi.Issuer = issuer
	return pi, nil
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// setIdentityActive patches identity state via JSON Patch (Kratos Admin OpenAPI).
// A plain {"state":...} body is not accepted on PATCH /admin/identities/{id}.
func (c *kratosClient) setIdentityActive(ctx context.Context, identityID string, active bool) error {
	patch := []jsonPatchOp{{
		Op:    "replace",
		Path:  "/state",
		Value: mapState(active),
	}}
	payload, err := json.Marshal(patch)
	if err != nil {
		return wrapErr("kratos marshal state patch", err)
	}

	url := fmt.Sprintf("%s/admin/identities/%s", c.baseURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return wrapErr("kratos set state", err)
	}
	// RFC 6902; Kratos accepts application/json for patch arrays as well,
	// but json-patch+json is the documented content type for identity PATCH.
	req.Header.Set("Content-Type", "application/json-patch+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return wrapErr("kratos set state", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &provider.ProviderError{
			Kind:     provider.ErrNotFound,
			Message:  "identity not found",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return mapHTTPError("kratos set state", resp)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

func (c *kratosClient) revokeSessions(ctx context.Context, identityID string) error {
	url := fmt.Sprintf("%s/admin/identities/%s/sessions", c.baseURL, identityID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return wrapErr("kratos revoke sessions", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return wrapErr("kratos revoke sessions", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Identity gone ⇒ sessions already gone; treat as success for kill-switch.
		return nil
	}
	if resp.StatusCode >= 300 {
		return mapHTTPError("kratos revoke sessions", resp)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Kratos wire types (minimal; aligned to CreateIdentityBody / Identity)
// ---------------------------------------------------------------------------

type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

type kratosIdentity struct {
	ID        string         `json:"id"`
	SchemaID  string         `json:"schema_id"`
	State     string         `json:"state"` // "active" | "inactive"
	Traits    map[string]any `json:"traits"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Metadata  map[string]any `json:"metadata_public"`
}

func (k kratosIdentity) toProviderIdentity() *provider.ProviderIdentity {
	status := provider.IdentityStatusUnknown
	switch k.State {
	case "active":
		status = provider.IdentityStatusActive
	case "inactive":
		status = provider.IdentityStatusDisabled
	}

	attrs := map[string]any{}
	if k.Traits != nil {
		attrs["traits"] = k.Traits
	}
	if k.Metadata != nil {
		attrs["metadata"] = k.Metadata
	}
	attrs["schema_id"] = k.SchemaID

	return &provider.ProviderIdentity{
		Provider:   "ory",
		Issuer:     "", // filled by caller with PublicIssuer
		Subject:    k.ID,
		Status:     status,
		CreatedAt:  k.CreatedAt,
		UpdatedAt:  k.UpdatedAt,
		Attributes: attrs,
	}
}

type kratosCreateIdentityRequest struct {
	SchemaID    string         `json:"schema_id"`
	Traits      map[string]any `json:"traits"`
	Credentials map[string]any `json:"credentials,omitempty"`
	Metadata    map[string]any `json:"metadata_public,omitempty"`
	State       string         `json:"state,omitempty"`
}

func mapState(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

// mapImportedCredentials translates the provider-neutral credential import
// shape into the Kratos admin create-identity credentials payload
// (IdentityWithCredentials / password.config.hashed_password).
// Verify against the pinned Kratos release notes when changing provider.lock.yaml.
func mapImportedCredentials(in *provider.ImportedCredentials) map[string]any {
	out := map[string]any{}
	if in.PasswordHash != nil {
		// Prefer pre-hashed import so plaintext never crosses the admin plane.
		cfg := map[string]any{
			"hashed_password": in.PasswordHash.Hash,
		}
		if in.PasswordHash.Algorithm != "" {
			// Algorithm is often inferred from the hash encoding; retained for operators.
			cfg["algorithm"] = in.PasswordHash.Algorithm
		}
		out["password"] = map[string]any{"config": cfg}
	}
	if in.TOTP != nil {
		out["totp"] = map[string]any{
			"config": map[string]any{
				"secret": in.TOTP.Secret,
			},
		}
	}
	if len(in.WebAuthn) > 0 {
		creds := make([]json.RawMessage, 0, len(in.WebAuthn))
		for _, w := range in.WebAuthn {
			creds = append(creds, json.RawMessage(w.CredentialJSON))
		}
		out["webauthn"] = map[string]any{
			"config": map[string]any{
				"credentials": creds,
			},
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Shared HTTP helpers (used by kratos + hydra)
// ---------------------------------------------------------------------------

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func wrapErr(op string, err error) error {
	return &provider.ProviderError{
		Kind:     provider.ErrUnavailable,
		Message:  op,
		Provider: "ory",
		Cause:    err,
	}
}

func mapHTTPError(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	kind := provider.ErrUnavailable
	switch {
	case resp.StatusCode == http.StatusNotFound:
		kind = provider.ErrNotFound
	case resp.StatusCode == http.StatusConflict:
		kind = provider.ErrConflict
	case resp.StatusCode == http.StatusBadRequest:
		kind = provider.ErrInvalidArgument
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		kind = provider.ErrPermissionDenied
	}
	return &provider.ProviderError{
		Kind:     kind,
		Message:  fmt.Sprintf("%s: HTTP %d: %s", op, resp.StatusCode, truncate(string(body), 256)),
		Provider: "ory",
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
