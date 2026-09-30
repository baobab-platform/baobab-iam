// Target path: baobab-iam/internal/provider/ory/hydra.go
//
// hydraClient wraps the Ory Hydra Admin API for OAuth2 client (workload)
// lifecycle. Human authentication sessions remain in Kratos; Hydra only
// issues tokens after a successful login/consent integration (not required
// for client_credentials workloads).
//
// Endpoints (Hydra Admin OpenAPI / OAuth2API):
//
//	POST   /admin/clients
//	GET    /admin/clients/{id}
//	PUT    /admin/clients/{id}   (full replace — preserve fields when updating)
//	DELETE /admin/clients/{id}   (not used for soft-disable)
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
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	// TRANSLATE scope spellings at the adapter boundary (M4 inventory).
	// Keycloak JSON may still list context:resolve; Hydra gets context-resolve.
	spec.AllowedScopes = provider.NormalizeAllowedScopes(spec.AllowedScopes)

	// Prefer stable client_id = LogicalClientID (ADR-IAM-0019 §50).
	clientID := spec.LogicalClientID

	tokenEndpointAuthMethod := "client_secret_post"
	if spec.AuthMethod == provider.WorkloadAuthPrivateKeyJWT {
		tokenEndpointAuthMethod = "private_key_jwt"
	}

	existing, getErr := c.getClient(ctx, clientID)
	if getErr != nil && !provider.IsNotFound(getErr) {
		return nil, getErr
	}

	var (
		secret string
		err    error
	)
	if existing == nil {
		// Create path: generate secret for client_secret methods only.
		if spec.AuthMethod != provider.WorkloadAuthPrivateKeyJWT {
			secret, err = generateClientSecret()
			if err != nil {
				return nil, wrapErr("hydra generate secret", err)
			}
		}
		body := hydraOAuth2Client{
			ClientID:                clientID,
			ClientName:              spec.DisplayName,
			GrantTypes:              []string{"client_credentials"},
			ResponseTypes:           []string{},
			Scope:                   joinScopes(spec.AllowedScopes),
			Audience:                spec.Audiences,
			TokenEndpointAuthMethod: tokenEndpointAuthMethod,
			Metadata:                toAnyMap(spec.Metadata),
		}
		if secret != "" {
			body.ClientSecret = secret
		}
		created, err := c.postClient(ctx, body)
		if err != nil {
			return nil, err
		}
		if created.ClientID == "" {
			created.ClientID = clientID
		}
		// Secret is only returned on create; prefer our generated value.
		if secret == "" && created.ClientSecret != "" {
			secret = created.ClientSecret
		}
		now := time.Now().UTC()
		return &provider.ProviderWorkload{
			Provider:         "ory",
			LogicalClientID:  spec.LogicalClientID,
			ProviderClientID: created.ClientID,
			Issuer:           issuer,
			AuthMethod:       spec.AuthMethod,
			ClientSecret:     secret,
			CreatedAt:        now,
			UpdatedAt:        now,
			Metadata:         spec.Metadata,
		}, nil
	}

	// Update path: full PUT replace — do not rotate secret (use RotateWorkloadCredentials).
	existing.ClientName = spec.DisplayName
	existing.GrantTypes = []string{"client_credentials"}
	existing.Scope = joinScopes(spec.AllowedScopes)
	existing.Audience = spec.Audiences
	existing.TokenEndpointAuthMethod = tokenEndpointAuthMethod
	existing.Metadata = toAnyMap(spec.Metadata)
	existing.ClientSecret = "" // omit so Hydra keeps current secret
	if err := c.putClient(ctx, clientID, *existing); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &provider.ProviderWorkload{
		Provider:         "ory",
		LogicalClientID:  spec.LogicalClientID,
		ProviderClientID: clientID,
		Issuer:           issuer,
		AuthMethod:       spec.AuthMethod,
		ClientSecret:     "", // not rotated
		CreatedAt:        now,
		UpdatedAt:        now,
		Metadata:         spec.Metadata,
	}, nil
}

func (c *hydraClient) postClient(ctx context.Context, body hydraOAuth2Client) (*hydraOAuth2Client, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, wrapErr("hydra marshal client", err)
	}
	url := c.baseURL + "/admin/clients"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, wrapErr("hydra post client", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("hydra post client", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrAlreadyExists,
			Message:  "workload client already exists",
			Provider: "ory",
		}
	}
	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("hydra post client", resp)
	}
	var created hydraOAuth2Client
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		created = body
	}
	return &created, nil
}

func (c *hydraClient) putClient(ctx context.Context, clientID string, body hydraOAuth2Client) error {
	body.ClientID = clientID
	payload, err := json.Marshal(body)
	if err != nil {
		return wrapErr("hydra marshal client", err)
	}
	url := fmt.Sprintf("%s/admin/clients/%s", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return wrapErr("hydra put client", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return wrapErr("hydra put client", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return mapHTTPError("hydra put client", resp)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Disable (soft)
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

	existing, err := c.getClient(ctx, clientID)
	if err != nil {
		return err
	}
	// Soft-disable: clear grants so client_credentials cannot succeed.
	// Full PUT would wipe fields if we sent a sparse body — preserve the rest.
	existing.GrantTypes = []string{}
	existing.ClientSecret = ""
	return c.putClient(ctx, clientID, *existing)
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

	existing, err := c.getClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	secret, err := generateClientSecret()
	if err != nil {
		return nil, wrapErr("hydra generate secret", err)
	}
	existing.ClientSecret = secret
	if err := c.putClient(ctx, clientID, *existing); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &provider.ProviderWorkload{
		Provider:         "ory",
		LogicalClientID:  ref.LogicalClientID,
		ProviderClientID: clientID,
		Issuer:           issuer,
		AuthMethod:       provider.WorkloadAuthClientSecret,
		ClientSecret:     secret,
		CreatedAt:        now,
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
// Wire types (OAuth2Client subset)
// ---------------------------------------------------------------------------

type hydraOAuth2Client struct {
	ClientID                string         `json:"client_id,omitempty"`
	ClientName              string         `json:"client_name,omitempty"`
	ClientSecret            string         `json:"client_secret,omitempty"`
	GrantTypes              []string       `json:"grant_types"`
	ResponseTypes           []string       `json:"response_types,omitempty"`
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
