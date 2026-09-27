// Target path: baobab-iam/internal/provider/ory/hydra.go
//
// hydraClient wraps the Ory Hydra Admin API for OAuth2 client (workload)
// lifecycle. Human authentication sessions remain in Kratos; Hydra only
// issues tokens after a successful login/consent integration.
package ory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// hydraClient is an internal HTTP client for Hydra Admin.
type hydraClient struct {
	baseURL string
	http    *http.Client
}

func newHydraClient(baseURL string, httpClient *http.Client) *hydraClient {
	return &hydraClient{
		baseURL: trimTrailingSlash(baseURL),
		http:    httpClient,
	}
}

// ---------------------------------------------------------------------------
// Provision / update client
// ---------------------------------------------------------------------------

func (c *hydraClient) provisionClient(
	ctx context.Context,
	issuer string,
	spec provider.WorkloadProvisioningSpec,
) (*provider.ProviderWorkload, error) {
	if spec.LogicalClientID == "" {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  "LogicalClientID is required",
			Provider: "ory",
		}
	}

	// Prefer stable client_id = LogicalClientID so existing Baobab references
	// remain valid across the Keycloak → Ory migration (ADR-IAM-0019 §50).
	clientID := spec.LogicalClientID

	secret, err := generateClientSecret()
	if err != nil {
		return nil, wrapErr("hydra generate secret", err)
	}

	grantTypes := []string{"client_credentials"}
	tokenEndpointAuthMethod := "client_secret_post"
	if spec.AuthMethod == provider.WorkloadAuthPrivateKeyJWT {
		tokenEndpointAuthMethod = "private_key_jwt"
		// For private_key_jwt the caller supplies JWKS out-of-band;
		// secret is not used.
		secret = ""
	}

	body := hydraOAuth2Client{
		ClientID:                clientID,
		ClientName:              spec.DisplayName,
		GrantTypes:              grantTypes,
		Scope:                   joinScopes(spec.AllowedScopes),
		Audience:                spec.Audiences,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		Metadata:                toAnyMap(spec.Metadata),
	}
	if secret != "" {
		body.ClientSecret = secret
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, wrapErr("hydra marshal client", err)
	}

	// PUT is idempotent for a known client_id; POST is create-only.
	// Prefer PUT so re-runs of bootstrap are safe.
	url := fmt.Sprintf("%s/admin/clients/%s", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return nil, wrapErr("hydra put client", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("hydra put client", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("hydra put client", resp)
	}

	var created hydraOAuth2Client
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		// Some Hydra versions return empty body on PUT success; fall back.
		created = body
		created.ClientID = clientID
	}

	now := time.Now().UTC()
	return &provider.ProviderWorkload{
		Provider:         "ory",
		LogicalClientID:  spec.LogicalClientID,
		ProviderClientID: created.ClientID,
		Issuer:           issuer,
		AuthMethod:       spec.AuthMethod,
		ClientSecret:     secret, // only non-empty for client_secret method
		CreatedAt:        now,
		UpdatedAt:        now,
		Metadata:         spec.Metadata,
	}, nil
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

func (c *hydraClient) disableClient(ctx context.Context, ref provider.ProviderWorkloadReference) error {
	clientID := ref.ProviderClientID
	if clientID == "" {
		clientID = ref.LogicalClientID
	}
	if clientID == "" {
		return &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  "client id required",
			Provider: "ory",
		}
	}

	// Soft-disable: clear grant types / secret rather than hard-delete so
	// audit trails and dual-run windows remain coherent. Hard delete can be
	// a separate operational action after Keycloak retirement.
	body := hydraOAuth2Client{
		ClientID:   clientID,
		GrantTypes: []string{}, // no grants ⇒ cannot obtain tokens
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return wrapErr("hydra marshal disable", err)
	}

	url := fmt.Sprintf("%s/admin/clients/%s", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return wrapErr("hydra disable client", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return wrapErr("hydra disable client", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &provider.ProviderError{
			Kind:     provider.ErrNotFound,
			Message:  "workload client not found",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return mapHTTPError("hydra disable client", resp)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rotate credentials
// ---------------------------------------------------------------------------

func (c *hydraClient) rotateClientCredentials(
	ctx context.Context,
	issuer string,
	ref provider.ProviderWorkloadReference,
) (*provider.ProviderWorkload, error) {
	clientID := ref.ProviderClientID
	if clientID == "" {
		clientID = ref.LogicalClientID
	}
	if clientID == "" {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrInvalidArgument,
			Message:  "client id required",
			Provider: "ory",
		}
	}

	// Fetch existing client so we preserve scopes/audience/metadata.
	existing, err := c.getClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	secret, err := generateClientSecret()
	if err != nil {
		return nil, wrapErr("hydra generate secret", err)
	}

	existing.ClientSecret = secret
	payload, err := json.Marshal(existing)
	if err != nil {
		return nil, wrapErr("hydra marshal rotate", err)
	}

	url := fmt.Sprintf("%s/admin/clients/%s", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return nil, wrapErr("hydra rotate client", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("hydra rotate client", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("hydra rotate client", resp)
	}

	now := time.Now().UTC()
	return &provider.ProviderWorkload{
		Provider:         "ory",
		LogicalClientID:  ref.LogicalClientID,
		ProviderClientID: clientID,
		Issuer:           issuer,
		AuthMethod:       provider.WorkloadAuthClientSecret,
		ClientSecret:     secret,
		CreatedAt:        now, // Hydra may not return original created_at
		UpdatedAt:        now,
	}, nil
}

func (c *hydraClient) getClient(ctx context.Context, clientID string) (*hydraOAuth2Client, error) {
	url := fmt.Sprintf("%s/admin/clients/%s", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, wrapErr("hydra get client", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("hydra get client", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrNotFound,
			Message:  "workload client not found",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("hydra get client", resp)
	}

	var client hydraOAuth2Client
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, wrapErr("hydra decode client", err)
	}
	return &client, nil
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

type hydraOAuth2Client struct {
	ClientID                string         `json:"client_id,omitempty"`
	ClientName              string         `json:"client_name,omitempty"`
	ClientSecret            string         `json:"client_secret,omitempty"`
	GrantTypes              []string       `json:"grant_types,omitempty"`
	Scope                   string         `json:"scope,omitempty"`
	Audience                []string       `json:"audience,omitempty"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method,omitempty"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	out := scopes[0]
	for i := 1; i < len(scopes); i++ {
		out += " " + scopes[i]
	}
	return out
}

func toAnyMap(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
