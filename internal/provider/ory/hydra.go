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
	"net/url"
	"sort"
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
	if spec.AuthMethod == provider.WorkloadAuthFederatedJWTBearer {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrConflict,
			Message:  "federated JWT bearer workloads must be provisioned via ProvisionFederatedWorkload, not ProvisionWorkload",
			Provider: "ory",
		}
	}
	if spec.LifecycleStatus == "" {
		spec.LifecycleStatus = provider.WorkloadStatusProvisioned
	}

	// Preserve Shared canonical scopes at the adapter boundary. The only
	// translation accepted here is the retired migration alias back to Shared.
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
	if spec.LifecycleStatus == "" {
		spec.LifecycleStatus = provider.WorkloadStatusProvisioned
	}

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
			LifecycleStatus:  spec.LifecycleStatus,
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
		LifecycleStatus:  spec.LifecycleStatus,
		ClientSecret:     "", // not rotated
		CreatedAt:        now,
		UpdatedAt:        now,
		Metadata:         spec.Metadata,
	}, nil
}

const hydraJWTBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// provisionFederatedWorkload configures Hydra for an RFC 7523 workload
// assertion without creating or rotating a static OAuth client secret.
// The returned trust is provider-side evidence only; Shared remains the
// authority for whether the workload lifecycle may become ACTIVE.
func (c *hydraClient) provisionFederatedWorkload(
	ctx context.Context,
	issuer string,
	spec provider.FederatedWorkloadTrustSpec,
) (*provider.FederatedWorkloadTrust, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	spec.AllowedScopes = provider.NormalizeAllowedScopes(spec.AllowedScopes)
	clientID := spec.LogicalClientID

	existing, getErr := c.getClient(ctx, clientID)
	if getErr != nil && !provider.IsNotFound(getErr) {
		return nil, getErr
	}
	metadata := toAnyMap(spec.Metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["baobab_credential_type"] = "federated_workload_token"
	metadata["baobab_intended_audiences"] = append([]string(nil), spec.IntendedAudiences...)

	if existing == nil {
		body := hydraOAuth2Client{
			ClientID:                clientID,
			ClientName:              spec.DisplayName,
			GrantTypes:              []string{hydraJWTBearerGrantType},
			ResponseTypes:           []string{},
			Scope:                   joinScopes(spec.AllowedScopes),
			TokenEndpointAuthMethod: "none",
			Metadata:                metadata,
		}
		// Do not copy Shared logical audiences into Hydra Audience. Hydra models
		// that field as URL resource indicators; the Baobab logical audience is
		// an activation claim that must be proven by the live token profile.
		if _, err := c.postClient(ctx, body); err != nil {
			return nil, err
		}
	} else {
		if existing.TokenEndpointAuthMethod != "" && existing.TokenEndpointAuthMethod != "none" {
			return nil, &provider.ProviderError{
				Kind: provider.ErrConflict, Provider: "ory",
				Message: "refusing to convert a secret-backed workload client into federated JWT bearer trust",
			}
		}
		if existing.ClientSecret != "" {
			return nil, &provider.ProviderError{
				Kind: provider.ErrConflict, Provider: "ory",
				Message: "federated workload client unexpectedly carries a client secret",
			}
		}
		existing.ClientName = spec.DisplayName
		existing.GrantTypes = []string{hydraJWTBearerGrantType}
		existing.Scope = joinScopes(spec.AllowedScopes)
		existing.Audience = nil
		existing.TokenEndpointAuthMethod = "none"
		existing.Metadata = metadata
		existing.ClientSecret = ""
		if err := c.putClient(ctx, clientID, *existing); err != nil {
			return nil, err
		}
	}

	trustID, err := c.ensureTrustedJWTIssuer(ctx, spec)
	if err != nil {
		return nil, err
	}
	if spec.LifecycleStatus == "" {
		spec.LifecycleStatus = provider.WorkloadStatusProvisioned
	}
	return &provider.FederatedWorkloadTrust{
		Provider:          "ory",
		LogicalClientID:   spec.LogicalClientID,
		ProviderClientID:  clientID,
		TrustID:           trustID,
		Issuer:            issuer,
		AuthMethod:        provider.WorkloadAuthFederatedJWTBearer,
		LifecycleStatus:   spec.LifecycleStatus,
		AssertionIssuer:   spec.AssertionIssuer,
		AssertionSubject:  spec.AssertionSubject,
		AllowedScopes:     append([]string(nil), spec.AllowedScopes...),
		IntendedAudiences: append([]string(nil), spec.IntendedAudiences...),
		TrustExpiresAt:    spec.TrustExpiresAt.UTC(),
	}, nil
}

func (c *hydraClient) ensureTrustedJWTIssuer(ctx context.Context, spec provider.FederatedWorkloadTrustSpec) (string, error) {
	trusted, err := c.listTrustedJWTIssuers(ctx, spec.AssertionIssuer)
	if err != nil {
		return "", err
	}
	for _, item := range trusted {
		if item.Subject != spec.AssertionSubject {
			continue
		}
		if item.AllowAnySubject {
			return "", &provider.ProviderError{Kind: provider.ErrConflict, Provider: "ory", Message: "existing JWT bearer trust allows any subject"}
		}
		if !equalStringSet(item.Scope, spec.AllowedScopes) {
			return "", &provider.ProviderError{Kind: provider.ErrConflict, Provider: "ory", Message: "existing JWT bearer trust scope differs from Shared"}
		}
		if !item.ExpiresAt.IsZero() && !item.ExpiresAt.Equal(spec.TrustExpiresAt.UTC()) {
			return "", &provider.ProviderError{Kind: provider.ErrConflict, Provider: "ory", Message: "existing JWT bearer trust expiry differs from desired state"}
		}
		desiredKID, _ := spec.AssertionJWK["kid"].(string)
		if item.PublicKey.KID != "" && item.PublicKey.KID != desiredKID {
			return "", &provider.ProviderError{Kind: provider.ErrConflict, Provider: "ory", Message: "existing JWT bearer trust key id differs from desired public JWK"}
		}
		if item.ID == "" {
			return "", wrapErr("hydra trusted jwt issuer", fmt.Errorf("existing trust has no id"))
		}
		return item.ID, nil
	}

	reqBody := hydraTrustJWTIssuerRequest{
		AllowAnySubject: false,
		ExpiresAt:       spec.TrustExpiresAt.UTC(),
		Issuer:          spec.AssertionIssuer,
		JWK:             spec.AssertionJWK,
		Scope:           append([]string(nil), spec.AllowedScopes...),
		Subject:         spec.AssertionSubject,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", wrapErr("hydra marshal trusted jwt issuer", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/trust/grants/jwt-bearer/issuers", bytes.NewReader(payload))
	if err != nil {
		return "", wrapErr("hydra trust jwt issuer", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", wrapErr("hydra trust jwt issuer", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", mapHTTPError("hydra trust jwt issuer", resp)
	}
	var created hydraTrustedJWTIssuer
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", wrapErr("hydra decode trusted jwt issuer", err)
	}
	if created.ID == "" {
		return "", wrapErr("hydra trusted jwt issuer", fmt.Errorf("response has no id"))
	}
	return created.ID, nil
}

func (c *hydraClient) listTrustedJWTIssuers(ctx context.Context, issuer string) ([]hydraTrustedJWTIssuer, error) {
	endpoint := c.baseURL + "/admin/trust/grants/jwt-bearer/issuers?issuer=" + url.QueryEscape(issuer)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, wrapErr("hydra list trusted jwt issuers", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapErr("hydra list trusted jwt issuers", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, mapHTTPError("hydra list trusted jwt issuers", resp)
	}
	var out []hydraTrustedJWTIssuer
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, wrapErr("hydra decode trusted jwt issuers", err)
	}
	return out, nil
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
	if isFederatedJWTBearerClient(*existing) {
		return nil, &provider.ProviderError{
			Kind:     provider.ErrConflict,
			Message:  "federated JWT bearer workload cannot rotate a static client secret",
			Provider: "ory",
		}
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

func isFederatedJWTBearerClient(client hydraOAuth2Client) bool {
	if client.TokenEndpointAuthMethod == "none" {
		return true
	}
	for _, grant := range client.GrantTypes {
		if grant == hydraJWTBearerGrantType {
			return true
		}
	}
	if client.Metadata == nil {
		return false
	}
	if kind, ok := client.Metadata["baobab_credential_type"]; ok {
		if s, ok := kind.(string); ok && s == "federated_workload_token" {
			return true
		}
	}
	return false
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

type hydraTrustJWTIssuerRequest struct {
	AllowAnySubject bool           `json:"allow_any_subject"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Issuer          string         `json:"issuer"`
	JWK             map[string]any `json:"jwk"`
	Scope           []string       `json:"scope"`
	Subject         string         `json:"subject"`
}

type hydraTrustedJWTIssuer struct {
	ID              string                    `json:"id"`
	AllowAnySubject bool                      `json:"allow_any_subject"`
	ExpiresAt       time.Time                 `json:"expires_at"`
	Issuer          string                    `json:"issuer"`
	PublicKey       hydraTrustedJWTGrantKey   `json:"public_key"`
	Scope           []string                  `json:"scope"`
	Subject         string                    `json:"subject"`
}

type hydraTrustedJWTGrantKey struct {
	KID string `json:"kid"`
	Set string `json:"set"`
}

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

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
