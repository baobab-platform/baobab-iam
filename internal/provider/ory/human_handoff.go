package ory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

// NativeHumanHandoff implements provider mechanics only. An estate/BFF must
// retain the intent in its browser-bound, CSRF-protected transaction and obtain
// current CP routing authority before calling it. It never resolves a tenant,
// maps an identity, grants business scopes or publishes provider support.
type NativeHumanHandoff struct {
	kratos, hydra, issuer *url.URL
	client                *http.Client
	now                   func() time.Time
}

type NativeHumanConfig struct {
	KratosPublicURL, HydraAdminURL, Issuer string
	Client                                 *http.Client
	Now                                    func() time.Time
	// Disposable test providers only. Production constructors must leave false.
	AllowLoopbackHTTP bool
}

func NewNativeHumanHandoff(c NativeHumanConfig) (*NativeHumanHandoff, error) {
	parse := func(raw string) (*url.URL, error) {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			return nil, fmt.Errorf("invalid native provider origin")
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && !(c.AllowLoopbackHTTP && u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
			return nil, fmt.Errorf("native provider origin requires HTTPS")
		}
		return u, nil
	}
	k, err := parse(c.KratosPublicURL)
	if err != nil {
		return nil, err
	}
	h, err := parse(c.HydraAdminURL)
	if err != nil {
		return nil, err
	}
	i, err := parse(c.Issuer)
	if err != nil {
		return nil, err
	}
	if c.Now == nil {
		return nil, fmt.Errorf("native handoff clock required")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.Client != nil {
		client.Transport = c.Client.Transport
	}
	return &NativeHumanHandoff{k, h, i, client, c.Now}, nil
}

func (h *NativeHumanHandoff) call(ctx context.Context, method, endpoint, token string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("invalid native request")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("invalid native request")
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-Session-Token", token)
	}
	response, err := h.client.Do(request)
	if err != nil {
		return fmt.Errorf("native provider unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("native provider denied handoff")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if uniqueNativeJSON(decoder) != nil {
		return fmt.Errorf("ambiguous native provider response")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing native provider response")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid native provider response")
	}
	return nil
}

func uniqueNativeJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return fmt.Errorf("duplicate native property")
			}
			seen[key] = true
		}
		if err := uniqueNativeJSON(d); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return fmt.Errorf("invalid native JSON")
	}
	return nil
}

type nativeSession struct {
	ID              string    `json:"id"`
	Active          bool      `json:"active"`
	ExpiresAt       time.Time `json:"expires_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	AAL             string    `json:"authenticator_assurance_level"`
	Identity        struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"identity"`
}

func (h *NativeHumanHandoff) session(ctx context.Context, credential string) (nativeSession, error) {
	var s nativeSession
	if credential == "" || len(credential) > 4096 || strings.TrimSpace(credential) != credential || strings.ContainsAny(credential, "\r\n") {
		return s, fmt.Errorf("native session credential required")
	}
	if err := h.call(ctx, http.MethodGet, strings.TrimRight(h.kratos.String(), "/")+"/sessions/whoami", credential, nil, &s); err != nil {
		return s, err
	}
	if !s.Active || s.ID == "" || s.Identity.ID == "" || strings.TrimSpace(s.Identity.ID) != s.Identity.ID || s.Identity.State != "active" || !h.now().Before(s.ExpiresAt) || s.AuthenticatedAt.IsZero() || s.AuthenticatedAt.After(h.now()) || s.AAL != "aal1" && s.AAL != "aal2" {
		return nativeSession{}, fmt.Errorf("inactive or invalid native session")
	}
	return s, nil
}

type nativeChallenge struct {
	Challenge  string   `json:"challenge"`
	Subject    string   `json:"subject"`
	RequestURL string   `json:"request_url"`
	Scopes     []string `json:"requested_scope"`
	Audience   []string `json:"requested_access_token_audience"`
	Client     struct {
		ID string `json:"client_id"`
	} `json:"client"`
}

func (h *NativeHumanHandoff) challenge(ctx context.Context, kind, id string, intent humanauth.Request) (nativeChallenge, error) {
	var c nativeChallenge
	for _, scope := range strings.Fields(intent.Scope) {
		if !slices.Contains([]string{"openid", "profile", "email"}, scope) {
			return c, fmt.Errorf("native authentication cannot grant business scopes")
		}
	}
	if intent.Validate() != nil || intent.ClientID == "" || intent.RedirectURI == "" || intent.State == "" || intent.Nonce == "" || !slices.Contains(strings.Fields(intent.Scope), "openid") || intent.ACRValues != "" || id == "" || len(id) > 1024 || strings.TrimSpace(id) != id {
		return c, fmt.Errorf("incomplete or unsupported native intent")
	}
	endpoint := strings.TrimRight(h.hydra.String(), "/") + "/admin/oauth2/auth/requests/" + kind + "?" + kind + "_challenge=" + url.QueryEscape(id)
	if err := h.call(ctx, http.MethodGet, endpoint, "", nil, &c); err != nil {
		return c, err
	}
	u, err := url.Parse(c.RequestURL)
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme != h.issuer.Scheme || u.Host != h.issuer.Host || u.Path != "/oauth2/auth" || c.Challenge != id || c.Client.ID != intent.ClientID || len(c.Audience) != 0 {
		return nativeChallenge{}, fmt.Errorf("native challenge target mismatch")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nativeChallenge{}, fmt.Errorf("invalid native authorization query")
	}
	expected := map[string]string{"response_type": "code", "client_id": intent.ClientID, "redirect_uri": intent.RedirectURI, "scope": intent.Scope, "state": intent.State, "nonce": intent.Nonce, "code_challenge": intent.CodeChallenge, "code_challenge_method": "S256"}
	for key, value := range expected {
		if len(query[key]) != 1 || query.Get(key) != value {
			return nativeChallenge{}, fmt.Errorf("native challenge intent mismatch")
		}
	}
	for key := range query {
		if _, ok := expected[key]; !ok {
			return nativeChallenge{}, fmt.Errorf("unsupported native authorization parameter")
		}
	}
	if !slices.Equal(c.Scopes, strings.Fields(intent.Scope)) {
		return nativeChallenge{}, fmt.Errorf("native challenge scope mismatch")
	}
	return c, nil
}

// AcceptLogin never treats Hydra's skip hint as authentication: it verifies a
// current Kratos session and binds the retained canonical intent every time.
func (h *NativeHumanHandoff) AcceptLogin(ctx context.Context, challenge, credential string, intent humanauth.Request) (string, error) {
	return h.accept(ctx, "login", challenge, credential, intent)
}

// AcceptConsent requires explicit consent for the exact retained scope set.
// No remembered consent, workload/resource audience or inferred grants apply.
func (h *NativeHumanHandoff) AcceptConsent(ctx context.Context, challenge, credential string, intent humanauth.Request, consented bool) (string, error) {
	if !consented {
		return "", fmt.Errorf("native consent required")
	}
	return h.accept(ctx, "consent", challenge, credential, intent)
}

func (h *NativeHumanHandoff) accept(ctx context.Context, kind, id, credential string, intent humanauth.Request) (string, error) {
	if h == nil || ctx == nil || ctx.Err() != nil {
		return "", fmt.Errorf("native handoff unavailable")
	}
	c, err := h.challenge(ctx, kind, id, intent)
	if err != nil {
		return "", err
	}
	s, err := h.session(ctx, credential)
	if err != nil {
		return "", err
	}
	if c.Subject != "" && c.Subject != s.Identity.ID || kind == "consent" && c.Subject != s.Identity.ID {
		return "", fmt.Errorf("native challenge subject mismatch")
	}
	body := map[string]any{"subject": s.Identity.ID, "remember": false, "acr": s.AAL}
	if kind == "consent" {
		body = map[string]any{"grant_scope": c.Scopes, "grant_access_token_audience": []string{}, "remember": false, "session": map[string]any{"access_token": map[string]any{"actor_type": "human"}}}
	}
	// Revocation during challenge processing must not result in acceptance.
	current, err := h.session(ctx, credential)
	if err != nil || current != s {
		return "", fmt.Errorf("native session changed during handoff")
	}
	var result struct {
		Redirect string `json:"redirect_to"`
	}
	endpoint := strings.TrimRight(h.hydra.String(), "/") + "/admin/oauth2/auth/requests/" + kind + "/accept?" + kind + "_challenge=" + url.QueryEscape(id)
	if err := h.call(ctx, http.MethodPut, endpoint, "", body, &result); err != nil {
		return "", err
	}
	u, err := url.Parse(result.Redirect)
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme != h.issuer.Scheme || u.Host != h.issuer.Host || u.Path != "/oauth2/auth" {
		return "", fmt.Errorf("unsafe native handoff redirect")
	}
	return result.Redirect, nil
}
