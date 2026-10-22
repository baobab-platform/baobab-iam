package ory

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/tokenprofile"
)

// NativeHumanHandoff implements provider mechanics only. An estate/BFF must
// retain the intent in its browser-bound, CSRF-protected transaction and obtain
// current CP routing authority before calling it. It never resolves a tenant,
// maps an identity or publishes provider support. It grants business scopes
// only inside governed composition (GovernedNativeHumanHandoff) with pinned
// token profiles: governed buyer consent (buyerConsent).
type NativeHumanHandoff struct {
	kratos, hydra, issuer *url.URL
	client                *http.Client
	now                   func() time.Time
	fence                 NativeChallengeFence
	authority             DispatchAuthority
	buyer                 *tokenprofile.Config
	sealKey               []byte
}

// NativeChallengeFence must atomically consume each key exactly once across
// replicas and restarts. Keys are hashes, not challenges or session credentials.
// Failed/uncertain acceptance stays consumed; recovery starts a new flow.
type NativeChallengeFence interface {
	ConsumeNativeChallenge(context.Context, string) error
}

// NativeSessionCredential keeps browser cookies distinct from API session tokens.
// Supply exactly one credential captured by the trusted estate/BFF.
type NativeSessionCredential struct{ SessionToken, Cookie string }

type NativeHumanConfig struct {
	KratosPublicURL, HydraAdminURL, Issuer string
	Client                                 *http.Client
	Now                                    func() time.Time
	Fence                                  NativeChallengeFence
	// TokenProfiles is the pinned Shared token-profile projection the token
	// hook also serves. Only governed composition accepts it; with it, an
	// ACTIVE estate BFF's human_token_profile scopes become consentable
	// (ADR-SHARED-042 CAA-03). Without it, no business scope is ever granted.
	TokenProfiles *tokenprofile.Config
	// ConsentSealKey seals each buyer consent decision for the token hook
	// (tokenprofile.HumanConsentSeal). Required with TokenProfiles; the hook
	// holds the same IAM key, never its authentication key.
	ConsentSealKey []byte
	// Disposable test providers only. Production constructors must leave false.
	AllowLoopbackHTTP bool
}

func NewNativeHumanHandoff(c NativeHumanConfig) (*NativeHumanHandoff, error) {
	if c.TokenProfiles != nil || c.ConsentSealKey != nil {
		return nil, fmt.Errorf("buyer consent requires governed composition")
	}
	return newNativeHumanHandoff(c)
}

func newNativeHumanHandoff(c NativeHumanConfig) (*NativeHumanHandoff, error) {
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
	if c.Now == nil || c.Fence == nil {
		return nil, fmt.Errorf("native handoff clock and challenge fence required")
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.Client != nil {
		client.Transport = c.Client.Transport
	}
	var buyer *tokenprofile.Config
	if (c.TokenProfiles == nil) != (c.ConsentSealKey == nil) {
		return nil, fmt.Errorf("buyer consent needs both token profiles and the consent seal key")
	}
	if c.TokenProfiles != nil {
		if len(c.ConsentSealKey) < tokenprofile.MinConsentSealKeyBytes {
			return nil, fmt.Errorf("buyer consent seal key must contain at least %d bytes", tokenprofile.MinConsentSealKeyBytes)
		}
		if err := c.TokenProfiles.Validate(); err != nil {
			return nil, fmt.Errorf("invalid buyer consent token profiles: %w", err)
		}
		// A deep copy, so later mutation of the caller's maps cannot widen consent.
		encoded, err := json.Marshal(c.TokenProfiles)
		if err != nil {
			return nil, fmt.Errorf("invalid buyer consent token profiles")
		}
		buyer = &tokenprofile.Config{}
		if err := json.Unmarshal(encoded, buyer); err != nil {
			return nil, fmt.Errorf("invalid buyer consent token profiles")
		}
	}
	return &NativeHumanHandoff{k, h, i, client, c.Now, c.Fence, nil, buyer, slices.Clone(c.ConsentSealKey)}, nil
}

func (h *NativeHumanHandoff) call(ctx context.Context, method, endpoint string, credential NativeSessionCredential, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("invalid native request")
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("invalid native request")
	}
	request.Header.Set("Content-Type", "application/json")
	if credential.SessionToken != "" {
		request.Header.Set("X-Session-Token", credential.SessionToken)
	}
	if credential.Cookie != "" {
		request.Header.Set("Cookie", credential.Cookie)
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
	// The methods Kratos completed for this session. They become the amr the
	// login accepts; the BFF and browser never supply either.
	Methods []struct {
		Method string `json:"method"`
	} `json:"authentication_methods"`
	Identity struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"identity"`
}

func (h *NativeHumanHandoff) session(ctx context.Context, credential NativeSessionCredential) (nativeSession, error) {
	var s nativeSession
	value := credential.SessionToken + credential.Cookie
	if (credential.SessionToken == "") == (credential.Cookie == "") || len(value) > 4096 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
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
	// grantAudience is IAM's governed decision, never provider input.
	grantAudience []string
	Challenge     string `json:"challenge"`
	// ConsentRequestID is the short identifier Hydra records on the session
	// (consent_challenge, seen by the token hook); the challenge itself is an
	// encrypted flow token. Governed buyer consent seals this identifier.
	ConsentRequestID string   `json:"consent_request_id"`
	Subject          string   `json:"subject"`
	RequestURL       string   `json:"request_url"`
	Scopes           []string `json:"requested_scope"`
	Audience         []string `json:"requested_access_token_audience"`
	Client           struct {
		ID string `json:"client_id"`
	} `json:"client"`
}

func (h *NativeHumanHandoff) challenge(ctx context.Context, kind, id string, intent humanauth.Request) (nativeChallenge, error) {
	var c nativeChallenge
	audience, err := h.buyerConsent(intent)
	if err != nil {
		return c, err
	}
	if intent.Validate() != nil || intent.ClientID == "" || intent.RedirectURI == "" || intent.State == "" || intent.Nonce == "" || !slices.Contains(strings.Fields(intent.Scope), "openid") || intent.ACRValues != "" || id == "" || len(id) > 16384 || strings.TrimSpace(id) != id {
		return c, fmt.Errorf("incomplete or unsupported native intent")
	}
	endpoint := strings.TrimRight(h.hydra.String(), "/") + "/admin/oauth2/auth/requests/" + kind + "?" + kind + "_challenge=" + url.QueryEscape(id)
	if err := h.call(ctx, http.MethodGet, endpoint, NativeSessionCredential{}, nil, &c); err != nil {
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
	c.grantAudience = audience
	return c, nil
}

// buyerConsent decides what a retained intent may be granted. OIDC-only
// intents grant no audience, as before. A business scope is consentable only
// under governed composition with pinned token profiles, for an ACTIVE estate
// BFF whose Shared human_token_profile names it (tokenprofile.HumanConsent);
// the audience is the Shared scope registry's for the granted scopes, never
// the requester's. Anything else refuses before any provider or session read.
func (h *NativeHumanHandoff) buyerConsent(intent humanauth.Request) ([]string, error) {
	scopes := strings.Fields(intent.Scope)
	business := false
	for _, scope := range scopes {
		if !slices.Contains([]string{"openid", "profile", "email"}, scope) {
			business = true
		}
	}
	if !business {
		return []string{}, nil
	}
	if h.buyer == nil || h.authority == nil {
		return nil, fmt.Errorf("native authentication cannot grant business scopes")
	}
	audience, err := h.buyer.HumanConsent(intent.ClientID, scopes)
	if err != nil {
		return nil, fmt.Errorf("business scopes outside the registered estate BFF profile")
	}
	return audience, nil
}

// AcceptLogin never treats Hydra's skip hint as authentication: it verifies a
// current Kratos session and binds the retained canonical intent every time.
func (h *NativeHumanHandoff) AcceptLogin(ctx context.Context, challenge string, credential NativeSessionCredential, intent humanauth.Request) (string, error) {
	return h.accept(ctx, "login", challenge, credential, intent)
}

// AcceptConsent requires explicit consent for the exact retained scope set.
// No remembered consent, workload/resource audience or inferred grants apply.
func (h *NativeHumanHandoff) AcceptConsent(ctx context.Context, challenge string, credential NativeSessionCredential, intent humanauth.Request, consented bool) (string, error) {
	if !consented {
		return "", fmt.Errorf("native consent required")
	}
	return h.accept(ctx, "consent", challenge, credential, intent)
}

func (h *NativeHumanHandoff) accept(ctx context.Context, kind, id string, credential NativeSessionCredential, intent humanauth.Request) (string, error) {
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
	if amr := nativeAMR(s); len(amr) > 0 {
		body["amr"] = amr
	}
	if kind == "consent" {
		accessToken := map[string]any{"actor_type": "human"}
		if len(c.grantAudience) > 0 {
			// Governed buyer consent: seal exactly what is granted, for this
			// consent request, client and verified subject, for the token hook.
			seal, err := tokenprofile.SealHumanConsent(h.sealKey, c.ConsentRequestID, c.Client.ID, s.Identity.ID, c.Scopes, c.grantAudience)
			if err != nil {
				return "", fmt.Errorf("cannot seal buyer consent")
			}
			accessToken[tokenprofile.ConsentSealClaim] = seal
		}
		body = map[string]any{"grant_scope": c.Scopes, "grant_access_token_audience": c.grantAudience, "remember": false, "session": map[string]any{"access_token": accessToken}}
	}
	// Revocation during challenge processing must not result in acceptance.
	current, err := h.session(ctx, credential)
	if err != nil || !sameNativeSession(current, s) {
		return "", fmt.Errorf("native session changed during handoff")
	}
	// Governed composition rechecks CP after provider/session reads and before
	// irreversible acceptance. Failed authority does not consume the challenge.
	if h.authority != nil && h.authority.CheckCapability(ctx, provider.CapabilityHumanAuthentication) != nil {
		return "", fmt.Errorf("current CP native dispatch denied")
	}
	// Origins with an optional root slash must share the same replay key.
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(h.issuer.Scheme+"://"+h.issuer.Host+"\x00"+kind+"\x00"+id)))
	if err := h.fence.ConsumeNativeChallenge(ctx, key); err != nil {
		return "", fmt.Errorf("native challenge already consumed or fence unavailable")
	}
	var result struct {
		Redirect string `json:"redirect_to"`
	}
	endpoint := strings.TrimRight(h.hydra.String(), "/") + "/admin/oauth2/auth/requests/" + kind + "/accept?" + kind + "_challenge=" + url.QueryEscape(id)
	if err := h.call(ctx, http.MethodPut, endpoint, NativeSessionCredential{}, body, &result); err != nil {
		return "", err
	}
	u, err := url.Parse(result.Redirect)
	if err != nil || u.User != nil || u.Fragment != "" || u.Scheme != h.issuer.Scheme || u.Host != h.issuer.Host || u.Path != "/oauth2/auth" {
		return "", fmt.Errorf("unsafe native handoff redirect")
	}
	return result.Redirect, nil
}

// nativeAMR maps the methods Kratos completed for the verified session to RFC
// 8176 authentication method references (ADR-SHARED-042 CAA-03; ADR-IAM-0024
// section 13). An unrecognised method is omitted rather than guessed: absent
// amr is never evidence of a stronger method. mfa is added only when two or
// more distinct factor kinds completed.
func nativeAMR(s nativeSession) []string {
	var out []string
	add := func(value string) {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	for _, m := range s.Methods {
		switch m.Method {
		case "password":
			add("pwd")
		case "totp", "lookup_secret", "code":
			add("otp")
		case "webauthn", "passkey":
			add("hwk")
		}
	}
	if len(out) >= 2 {
		add("mfa")
	}
	return out
}

// sameNativeSession reports whether two reads describe the identical session,
// including the methods it completed, so a change during the handoff refuses.
func sameNativeSession(a, b nativeSession) bool {
	if a.ID != b.ID || a.Active != b.Active || !a.ExpiresAt.Equal(b.ExpiresAt) || !a.AuthenticatedAt.Equal(b.AuthenticatedAt) ||
		a.AAL != b.AAL || a.Identity != b.Identity || len(a.Methods) != len(b.Methods) {
		return false
	}
	for i := range a.Methods {
		if a.Methods[i] != b.Methods[i] {
			return false
		}
	}
	return true
}
