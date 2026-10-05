package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthorityTokens supplies a current service credential for each read. The
// credential never appears in an error, URL, evidence record or log.
type AuthorityTokens interface {
	Token(context.Context) (string, error)
}

// HTTPAuthority is an authenticated internal transport, not provider selection
// or a new canonical Shared API. Each authority has a separately configured
// origin and credential. A successful HTTP response is still checked by Consumer.
type HTTPAuthority struct {
	origin string
	client *http.Client
	tokens AuthorityTokens
}

type platformBindingWire struct {
	Binding Binding `json:"binding"`
	Scope   struct {
		OrganisationID string `json:"organisation_id"`
		EstateID       string `json:"estate_id"`
	} `json:"scope"`
	RuntimeCapability string `json:"runtime_capability"`
}

func newPlatformBindingWire(binding Binding, scope Scope, runtimeCapability string) platformBindingWire {
	var out platformBindingWire
	out.Binding = binding
	out.Scope.OrganisationID = scope.OrganisationID
	out.Scope.EstateID = scope.EstateID
	out.RuntimeCapability = runtimeCapability
	return out
}

func (w platformBindingWire) platformScope() Scope {
	return Scope{OrganisationID: w.Scope.OrganisationID, EstateID: w.Scope.EstateID}
}

type referenceExpectationWire struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	TrustID          string `json:"trust_id"`
	SnapshotID       string `json:"snapshot_id"`
	TrustRevision    uint64 `json:"trust_revision"`
	ProviderID       string `json:"provider_id"`
	EngineInstanceID string `json:"engine_instance_id"`
	Scope            struct {
		OrganisationID string `json:"organisation_id"`
		EstateID       string `json:"estate_id"`
	} `json:"scope"`
	EventID            string `json:"event_id,omitempty"`
	Issuer             string `json:"issuer,omitempty"`
	Subject            string `json:"subject,omitempty"`
	Level              string `json:"level,omitempty"`
	EvidenceDigest     string `json:"evidence_digest,omitempty"`
	PrincipalID        string `json:"principal_id,omitempty"`
	ExternalIdentityID string `json:"external_identity_id,omitempty"`
}

func newReferenceExpectationWire(value ReferenceExpectation) referenceExpectationWire {
	var out referenceExpectationWire
	out.ID = value.ID
	out.Kind = value.Kind
	out.TrustID = value.TrustID
	out.SnapshotID = value.SnapshotID
	out.TrustRevision = value.TrustRevision
	out.ProviderID = value.ProviderID
	out.EngineInstanceID = value.EngineInstanceID
	out.Scope.OrganisationID = value.Scope.OrganisationID
	out.Scope.EstateID = value.Scope.EstateID
	out.EventID = value.EventID
	out.Issuer = value.Issuer
	out.Subject = value.Subject
	out.Level = value.Level
	out.EvidenceDigest = value.EvidenceDigest
	out.PrincipalID = value.PrincipalID
	out.ExternalIdentityID = value.ExternalIdentityID
	return out
}

func (w referenceExpectationWire) expectation() ReferenceExpectation {
	return ReferenceExpectation{
		ID: w.ID, Kind: w.Kind, TrustID: w.TrustID, SnapshotID: w.SnapshotID,
		TrustRevision: w.TrustRevision, ProviderID: w.ProviderID, EngineInstanceID: w.EngineInstanceID,
		Scope:   Scope{OrganisationID: w.Scope.OrganisationID, EstateID: w.Scope.EstateID},
		EventID: w.EventID, Issuer: w.Issuer, Subject: w.Subject, Level: w.Level,
		EvidenceDigest: w.EvidenceDigest, PrincipalID: w.PrincipalID, ExternalIdentityID: w.ExternalIdentityID,
	}
}

type approvalAuthorityWire struct {
	Action       string                   `json:"action"`
	Target       referenceExpectationWire `json:"target"`
	SubjectToken string                   `json:"subject_token"`
}

type approvalActorWire struct {
	PrincipalID string    `json:"principal_id"`
	ValidUntil  time.Time `json:"valid_until"`
}

type digestWire struct {
	Digest string `json:"digest"`
}

// NewHTTPAuthority deliberately owns its transport: no redirect, proxy-env,
// insecure TLS or caller-selected URL can carry an authority credential away.
// Optional mTLS certificates and private roots come from deployment configuration.
func NewHTTPAuthority(origin string, tokens AuthorityTokens, tlsConfig *tls.Config) (*HTTPAuthority, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") || absent(tokens) {
		return nil, ErrInvalid
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		cfg = tlsConfig.Clone()
		if cfg.InsecureSkipVerify || cfg.KeyLogWriter != nil || cfg.VerifyConnection != nil || cfg.VerifyPeerCertificate != nil || cfg.ServerName != "" && cfg.ServerName != u.Hostname() {
			return nil, ErrInvalid
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.MaxVersion != 0 && cfg.MaxVersion < cfg.MinVersion {
			return nil, ErrInvalid
		}
	}
	t := &http.Transport{TLSClientConfig: cfg, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: 3 * time.Second, TLSHandshakeTimeout: 3 * time.Second}
	return &HTTPAuthority{strings.TrimSuffix(origin, "/"), &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tokens}, nil
}

// decodeAuthority is strict about duplicate, unknown, null and trailing values;
// omission of security fields is subsequently denied by semantic consumers.
func decodeAuthority(data []byte, out any) error {
	if len(data) == 0 || len(data) > 65536 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if uniqueJSON(d) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

func (a *HTTPAuthority) call(ctx context.Context, path string, input, output any) error {
	if a == nil || ctx == nil || absent(a.tokens) || a.client == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	token, err := a.tokens.Token(ctx)
	if err != nil || token == "" || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return ErrUnavailable
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > 65536 {
		return ErrInvalid
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, a.origin+path, bytes.NewReader(data))
	if err != nil {
		return ErrInvalid
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Cache-Control", "no-store")
	resp, err := a.client.Do(r)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest:
		return ErrInvalid
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return ErrDenied
	case http.StatusConflict, http.StatusGone:
		return ErrUnverified
	case http.StatusNotImplemented:
		return ErrUnsupported
	default:
		return ErrUnavailable
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return ErrUnavailable
	}
	return decodeAuthority(body, output)
}

// The fixed, versioned private paths have separate service-side authentication
// and authority backends. They must not be pointed at unreviewed provider APIs.
func (a *HTTPAuthority) Trust(ctx context.Context, id string) (TrustSnapshot, error) {
	var out TrustSnapshot
	if !uuidPattern.MatchString(id) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/trust", struct{ ID string }{id}, &out)
	if err != nil {
		return TrustSnapshot{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) Reference(ctx context.Context, want ReferenceExpectation) (ApprovedReference, error) {
	var out ApprovedReference
	if !validRef(want.ID) || !validScope(want.Scope) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/reference", want, &out)
	if err != nil {
		return ApprovedReference{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) FederationBinding(ctx context.Context, binding Binding, scope Scope, runtimeCapability string) (PlatformSnapshot, error) {
	var out PlatformSnapshot
	if !validBinding(binding) || !validScope(scope) || !validFederationRuntimeCapability(runtimeCapability) {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/binding", newPlatformBindingWire(binding, scope, runtimeCapability), &out)
	if err != nil {
		return PlatformSnapshot{}, err
	}
	return out, nil
}
func (a *HTTPAuthority) Resolve(ctx context.Context, issuer, subject string) (CanonicalIdentity, error) {
	var out CanonicalIdentity
	if !exact(subject) || issuer == "" || len(issuer) > 2048 {
		return out, ErrInvalid
	}
	err := a.call(ctx, "/internal/federation/v1/identity", struct{ Issuer, Subject string }{issuer, subject}, &out)
	if err != nil {
		return CanonicalIdentity{}, err
	}
	return out, nil
}

var _ GovernanceAuthority = (*HTTPAuthority)(nil)
var _ PlatformAuthority = (*HTTPAuthority)(nil)
var _ CanonicalAuthority = (*HTTPAuthority)(nil)
