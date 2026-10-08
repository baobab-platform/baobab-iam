package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
)

var brokerRequests = []byte("broker-requests-v1")
var brokerNonces = []byte("broker-nonces-v1")
var brokerCaptures = []byte("broker-captures-v1")
var brokerReplay = []byte("broker-replay-v1")
var brokerVerified = []byte("broker-events-v1")

type BrokerEventsConfig struct {
	Storage       *PostgresStorage
	Path          string
	Configuration BrokerConfigurationAuthority
	Mapper        AssuranceMapper
	Client        *http.Client
	ClientSecrets AuthorityTokens
	Now           func() time.Time
	MaxLifetime   time.Duration
	// Only explicit loopback HTTP test providers; the service root never enables it.
	AllowLoopbackHTTP bool
}
type BrokerEvents struct {
	db  ledgerDB
	cfg BrokerEventsConfig
}
type BrokerChallenge struct {
	EventID, State, Nonce, PKCEVerifier, AuthorizationURL string
	ExpiresAt                                             time.Time
}
type BrokerCallback struct{ EventID, State, BrowserSecret, PKCEVerifier, Code, Issuer string }
type BrokerEvidence struct{ TrustID, Nonce, ProviderRoute, UpstreamCorrelation, Assertion string }
type brokerRequest struct {
	Request                         storedRequest
	PKCEDigest, ConfigurationDigest string
}
type brokerCapture struct {
	Principal        ExternalPrincipal
	Assurance        Assurance
	Digest, ReplayID string
}

func OpenBrokerEvents(cfg BrokerEventsConfig) (*BrokerEvents, error) {
	if (cfg.Path == "" && cfg.Storage == nil) || absent(cfg.Configuration) || absent(cfg.Mapper) || cfg.Now == nil || cfg.MaxLifetime <= 0 || cfg.MaxLifetime > 15*time.Minute {
		return nil, ErrInvalid
	}
	db, err := openLedger(cfg.Path, cfg.Storage, "broker")
	if err != nil {
		return nil, ErrUnavailable
	}
	err = db.Update(func(tx ledgerTx) error {
		for _, name := range [][]byte{brokerRequests, brokerNonces, brokerCaptures, brokerReplay, brokerVerified, maintenanceBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	return &BrokerEvents{db: db, cfg: cfg}, nil
}
func (e *BrokerEvents) Close() error {
	if e == nil || e.db == nil {
		return ErrUnavailable
	}
	return e.db.Close()
}
func (e *BrokerEvents) clock(tx ledgerTx) error {
	return (&OIDCEvents{now: e.cfg.Now}).observeClock(tx)
}
func brokerDigest(c BrokerConfiguration) string {
	encoded, _ := json.Marshal(c)
	return nativeTargetDigest(encoded)
}

func (e *BrokerEvents) configuration(ctx context.Context, s TrustSnapshot) (BrokerConfiguration, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || !activeSnapshot(s, e.cfg.Now()) || ValidateTrust(s.Trust) != nil {
		return BrokerConfiguration{}, ErrDenied
	}
	c, err := e.cfg.Configuration.BrokerConfiguration(ctx, s)
	if err != nil {
		return BrokerConfiguration{}, authorityError(err)
	}
	if c.TrustID != s.Trust.ID || c.SnapshotID != s.SnapshotID || c.Revision != s.ApprovedRevision || c.Binding != s.Trust.ProviderBinding || !e.cfg.Now().Before(c.ValidUntil) || !exact(c.Settings.ClientID) || !exact(c.Settings.ProviderRoute) || strings.ContainsAny(c.Settings.ProviderRoute, "/?#&= ") {
		return BrokerConfiguration{}, ErrUnverified
	}
	issuer, err := brokerURL(c.Settings.Issuer, e.cfg.AllowLoopbackHTTP)
	if err != nil {
		return BrokerConfiguration{}, err
	}
	for _, value := range []string{c.Settings.AuthorizationEndpoint, c.Settings.TokenEndpoint} {
		u, err := brokerURL(value, e.cfg.AllowLoopbackHTTP)
		if err != nil || u.Scheme != issuer.Scheme || u.Host != issuer.Host {
			return BrokerConfiguration{}, ErrDenied
		}
	}
	if _, err := brokerURL(c.Settings.RedirectURI, e.cfg.AllowLoopbackHTTP); err != nil {
		return BrokerConfiguration{}, err
	}
	if c.Settings.Confidential && absent(e.cfg.ClientSecrets) {
		return BrokerConfiguration{}, ErrUnavailable
	}
	if _, err := publicOIDCKeys(OIDCConfiguration{SigningAlgorithm: c.Settings.SigningAlgorithm, JWKS: c.BrokerJWKS}); err != nil {
		return BrokerConfiguration{}, err
	}
	switch s.Trust.Protocol {
	case "OIDC":
		if c.Upstream.Binding != c.Binding || c.Upstream.TrustID != s.Trust.ID || c.Upstream.SnapshotID != s.SnapshotID || c.Upstream.Revision != c.Revision || !exact(c.Upstream.ClientID) {
			return BrokerConfiguration{}, ErrUnverified
		}
		if _, err := publicOIDCKeys(c.Upstream); err != nil {
			return BrokerConfiguration{}, err
		}
	case "SAML2":
		if !exact(c.SAML.EntityID) || len(c.SigningCertificates) == 0 {
			return BrokerConfiguration{}, ErrUnverified
		}
		if _, err := samlSigningCertificates(c.SigningCertificates, e.cfg.Now()); err != nil {
			return BrokerConfiguration{}, err
		}
		if _, err := brokerURL(c.SAML.ACSURL, false); err != nil {
			return BrokerConfiguration{}, err
		}
	default:
		return BrokerConfiguration{}, ErrUnsupported
	}
	return c, nil
}

func (e *BrokerEvents) Begin(ctx context.Context, s TrustSnapshot, sessionDigest string) (BrokerChallenge, error) {
	if !digestPattern.MatchString(sessionDigest) {
		return BrokerChallenge{}, ErrInvalid
	}
	c, err := e.configuration(ctx, s)
	if err != nil {
		return BrokerChallenge{}, err
	}
	if _, err := e.Prune(ctx, 128); err != nil {
		return BrokerChallenge{}, err
	}
	id, err := randomUUID()
	if err != nil {
		return BrokerChallenge{}, err
	}
	state, err := randomString()
	if err != nil {
		return BrokerChallenge{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return BrokerChallenge{}, err
	}
	verifier, err := randomString()
	if err != nil {
		return BrokerChallenge{}, err
	}
	now := e.cfg.Now()
	until := minimum(s.ValidUntil, c.ValidUntil, now.Add(5*time.Minute))
	sum := sha256.Sum256([]byte(verifier))
	canonical := humanauth.Request{GrantType: "authorization_code", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256", ClientID: c.Settings.ClientID, RedirectURI: c.Settings.RedirectURI, Scope: "openid", State: state, Nonce: nonce}
	if canonical.Validate() != nil {
		return BrokerChallenge{}, ErrInvalid
	}
	req := brokerRequest{Request: storedRequest{id, s.Trust.ID, s.SnapshotID, s.ApprovedRevision, sessionDigest, secretDigest(state), secretDigest(nonce), now, until, false}, PKCEDigest: secretDigest(verifier), ConfigurationDigest: brokerDigest(c)}
	encoded, _ := json.Marshal(req)
	err = e.db.Update(func(tx ledgerTx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil || !e.cfg.Now().Before(until) {
			return ErrDenied
		}
		if tx.Bucket(brokerRequests).Stats().KeyN >= 4096 {
			return ErrUnavailable
		}
		if tx.Bucket(brokerRequests).Get([]byte(id)) != nil {
			return ErrDenied
		}
		if err := tx.Bucket(brokerRequests).Put([]byte(id), encoded); err != nil {
			return err
		}
		return tx.Bucket(brokerNonces).Put([]byte(secretDigest(nonce)), []byte(id))
	})
	if err != nil {
		return BrokerChallenge{}, authorityError(err)
	}
	auth, _ := url.Parse(c.Settings.AuthorizationEndpoint)
	query := auth.Query()
	query.Set("client_id", canonical.ClientID)
	query.Set("redirect_uri", canonical.RedirectURI)
	query.Set("response_type", "code")
	query.Set("scope", canonical.Scope)
	query.Set("state", canonical.State)
	query.Set("nonce", canonical.Nonce)
	query.Set("code_challenge", canonical.CodeChallenge)
	query.Set("code_challenge_method", canonical.CodeChallengeMethod)
	query.Set("prompt", "login")
	auth.RawQuery = query.Encode()
	return BrokerChallenge{id, state, nonce, verifier, auth.String(), until}, nil
}

func (e *BrokerEvents) request(tx ledgerTx, id string, s TrustSnapshot, c BrokerConfiguration) (brokerRequest, error) {
	var req brokerRequest
	if decodeAuthority(tx.Bucket(brokerRequests).Get([]byte(id)), &req) != nil || req.Request.Consumed || req.Request.TrustID != s.Trust.ID || req.Request.SnapshotID != s.SnapshotID || req.Request.Revision != s.ApprovedRevision || !fresh(req.Request.CreatedAt, req.Request.ExpiresAt, e.cfg.Now()) || req.ConfigurationDigest != brokerDigest(c) {
		return req, ErrDenied
	}
	return req, nil
}

// Capture accepts only the authenticated provider bridge's original evidence.
// UpstreamCorrelation is the broker's independently generated nonce/request ID.
// Original tokens/XML stay in memory; only normalized evidence and hashes persist.
func (e *BrokerEvents) Capture(ctx context.Context, s TrustSnapshot, input BrokerEvidence) error {
	c, err := e.configuration(ctx, s)
	if err != nil {
		return err
	}
	if input.TrustID != s.Trust.ID || input.ProviderRoute != c.Settings.ProviderRoute || !exact(input.Nonce) || !exact(input.UpstreamCorrelation) {
		return ErrDenied
	}
	var req brokerRequest
	var id string
	err = e.db.View(func(tx ledgerTx) error {
		id = string(tx.Bucket(brokerNonces).Get([]byte(secretDigest(input.Nonce))))
		var err error
		req, err = e.request(tx, id, s, c)
		return err
	})
	if err != nil {
		return authorityError(err)
	}
	now := e.cfg.Now()
	var capture brokerCapture
	if s.Trust.Protocol == "OIDC" {
		token, err := verifyBrokerIDToken(ctx, s.Trust.UpstreamIssuer, c.Upstream, input.Assertion, secretDigest(input.UpstreamCorrelation), req.Request.CreatedAt, now, e.cfg.MaxLifetime)
		if err != nil {
			return err
		}
		until := minimum(token.ExpiresAt, s.ValidUntil, c.ValidUntil, req.Request.ExpiresAt)
		p := ExternalPrincipal{AuthenticationEventID: id, TrustID: s.Trust.ID, ProviderID: c.Binding.ProviderID, EngineInstanceID: c.Binding.EngineInstanceID, Protocol: "OIDC", Issuer: s.Trust.UpstreamIssuer, Subject: token.Subject, ActorType: "human", ObservedAt: now, ExpiresAt: until, Resolution: Resolution{Status: "UNRESOLVED"}}
		a := Assurance{AuthenticationEventID: id, TrustID: p.TrustID, ProviderID: p.ProviderID, EngineInstanceID: p.EngineInstanceID, Protocol: p.Protocol, Issuer: p.Issuer, Subject: p.Subject, UpstreamEvidence: UpstreamEvidence{OIDC: &OIDCAssurance{ActorType: "human", ACR: token.ACR, AMR: token.AMR, AuthenticatedAt: token.AuthenticatedAt, Issuer: p.Issuer, ClientID: c.Upstream.ClientID}}, MappingStatus: "UNKNOWN", AssurancePolicyReference: s.Trust.AssurancePolicyReference, EvaluatedAt: now, ExpiresAt: until}
		capture = brokerCapture{p, a, secretDigest(input.Assertion), s.Trust.UpstreamIssuer + "\x00" + secretDigest(input.Assertion)}
	} else {
		p, a, replay, err := verifyBrokerSAML(s, c, input.Assertion, input.UpstreamCorrelation, req.Request.CreatedAt, now, e.cfg.MaxLifetime)
		if err != nil {
			return err
		}
		p.AuthenticationEventID = id
		a.AuthenticationEventID = id
		p.ExpiresAt = minimum(p.ExpiresAt, req.Request.ExpiresAt)
		a.ExpiresAt = p.ExpiresAt
		capture = brokerCapture{p, a, secretDigest(input.Assertion), replay}
	}
	if ValidateBundle(Bundle{s.Trust, capture.Principal, capture.Assurance}) != nil {
		return ErrInvalid
	}
	// Recheck governed bytes before committing, as capture may cross a revocation.
	current, err := e.configuration(ctx, s)
	if err != nil || brokerDigest(current) != brokerDigest(c) {
		return ErrUnverified
	}
	encoded, _ := json.Marshal(capture)
	return authorityErrorUnlessNil(e.db.Update(func(tx ledgerTx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if _, err := e.request(tx, id, s, c); err != nil {
			return err
		}
		if tx.Bucket(brokerCaptures).Get([]byte(id)) != nil || tx.Bucket(brokerReplay).Get([]byte(secretDigest(capture.ReplayID))) != nil {
			return ErrDenied
		}
		if err := tx.Bucket(brokerReplay).Put([]byte(secretDigest(capture.ReplayID)), []byte(e.cfg.Now().Add(e.cfg.MaxLifetime).Format(time.RFC3339Nano))); err != nil {
			return err
		}
		return tx.Bucket(brokerCaptures).Put([]byte(id), encoded)
	}))
}

func (e *BrokerEvents) exchange(ctx context.Context, c BrokerConfiguration, code, verifier string) (string, error) {
	if !exact(code) || len(code) > 4096 || len(verifier) < 43 || len(verifier) > 128 {
		return "", ErrDenied
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.Settings.RedirectURI}, "client_id": {c.Settings.ClientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Settings.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrInvalid
	}
	if c.Settings.Confidential {
		secret, err := e.cfg.ClientSecrets.Token(ctx)
		if err != nil || !exact(secret) {
			return "", ErrUnavailable
		}
		req.SetBasicAuth(c.Settings.ClientID, secret)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	transport := http.DefaultTransport
	if e.cfg.Client != nil && e.cfg.Client.Transport != nil {
		transport = e.cfg.Client.Transport
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return "", ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 || response.StatusCode != http.StatusOK {
		return "", ErrDenied
	}
	token, err := humanauth.ProjectOAuthResponse(body)
	if err != nil || token.IDToken == "" {
		return "", ErrDenied
	}
	return token.IDToken, nil
}

func (e *BrokerEvents) Complete(ctx context.Context, s TrustSnapshot, input BrokerCallback) error {
	c, err := e.configuration(ctx, s)
	if err != nil {
		return err
	}
	if !uuidPattern.MatchString(input.EventID) || input.Issuer != c.Settings.Issuer || len(input.State) > 512 || len(input.BrowserSecret) < 32 || len(input.BrowserSecret) > 512 {
		return ErrDenied
	}
	var req brokerRequest
	var capture brokerCapture
	err = e.db.Update(func(tx ledgerTx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		var err error
		req, err = e.request(tx, input.EventID, s, c)
		if err != nil {
			return err
		}
		if !equalSecret(input.State, req.Request.StateDigest) || !equalSecret(input.BrowserSecret, req.Request.SessionDigest) || !equalSecret(input.PKCEVerifier, req.PKCEDigest) {
			return ErrDenied
		}
		if decodeAuthority(tx.Bucket(brokerCaptures).Get([]byte(input.EventID)), &capture) != nil || !e.cfg.Now().Before(capture.Assurance.ExpiresAt) {
			return ErrDenied
		}
		req.Request.Consumed = true
		encoded, _ := json.Marshal(req)
		return tx.Bucket(brokerRequests).Put([]byte(input.EventID), encoded)
	})
	if err != nil {
		return authorityError(err)
	}
	raw, err := e.exchange(ctx, c, input.Code, input.PKCEVerifier)
	if err != nil {
		return err
	}
	token, err := verifyBrokerIDToken(ctx, c.Settings.Issuer, OIDCConfiguration{ClientID: c.Settings.ClientID, SigningAlgorithm: c.Settings.SigningAlgorithm, JWKS: c.BrokerJWKS, ValidUntil: c.ValidUntil}, raw, req.Request.NonceDigest, req.Request.CreatedAt, e.cfg.Now(), e.cfg.MaxLifetime)
	if err != nil {
		return err
	}
	if !digestPattern.MatchString(token.EvidenceDigest) || token.EvidenceDigest != capture.Digest {
		return ErrUnverified
	}
	a := capture.Assurance
	a.ExpiresAt = minimum(a.ExpiresAt, token.ExpiresAt)
	mapped, err := e.cfg.Mapper.MapAssurance(ctx, s, capture.Principal, a)
	if err != nil {
		return authorityError(err)
	}
	compare := mapped
	compare.MappingStatus = a.MappingStatus
	compare.Level = a.Level
	compare.MappingEvidenceReference = a.MappingEvidenceReference
	compare.ExpiresAt = a.ExpiresAt
	before, _ := json.Marshal(a)
	after, _ := json.Marshal(compare)
	if !bytes.Equal(before, after) || mapped.ExpiresAt.After(a.ExpiresAt) || ValidateBundle(Bundle{s.Trust, capture.Principal, mapped}) != nil {
		return ErrInvalid
	}
	current, err := e.configuration(ctx, s)
	if err != nil || brokerDigest(current) != brokerDigest(c) {
		return ErrUnverified
	}
	event := storedEvent{s.SnapshotID, s.ApprovedRevision, Bundle{s.Trust, capture.Principal, mapped}, false}
	encoded, _ := json.Marshal(event)
	return authorityErrorUnlessNil(e.db.Update(func(tx ledgerTx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil || !e.cfg.Now().Before(mapped.ExpiresAt) {
			return ErrDenied
		}
		if tx.Bucket(brokerVerified).Get([]byte(input.EventID)) != nil {
			return ErrDenied
		}
		return tx.Bucket(brokerVerified).Put([]byte(input.EventID), encoded)
	}))
}

func (e *BrokerEvents) Verify(ctx context.Context, id string, s TrustSnapshot) (ExternalPrincipal, Assurance, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) {
		return ExternalPrincipal{}, Assurance{}, ErrInvalid
	}
	var event storedEvent
	err := e.db.Update(func(tx ledgerTx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		if decodeAuthority(tx.Bucket(brokerVerified).Get([]byte(id)), &event) != nil || event.Consumed || event.SnapshotID != s.SnapshotID || event.Revision != s.ApprovedRevision || !sameTrust(event.Bundle.Trust, s.Trust) || !activeSnapshot(s, e.cfg.Now()) || !e.cfg.Now().Before(event.Bundle.Assurance.ExpiresAt) {
			return ErrDenied
		}
		event.Consumed = true
		data, _ := json.Marshal(event)
		return tx.Bucket(brokerVerified).Put([]byte(id), data)
	})
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, authorityError(err)
	}
	return event.Bundle.ExternalPrincipal, event.Bundle.Assurance, nil
}

func (e *BrokerEvents) Preview(ctx context.Context, id string, s TrustSnapshot) (ExternalPrincipal, Assurance, error) {
	c, err := e.configuration(ctx, s)
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, err
	}
	var capture brokerCapture
	err = e.db.View(func(tx ledgerTx) error {
		if _, err := e.request(tx, id, s, c); err != nil {
			return err
		}
		if decodeAuthority(tx.Bucket(brokerCaptures).Get([]byte(id)), &capture) != nil || !e.cfg.Now().Before(capture.Assurance.ExpiresAt) {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, authorityError(err)
	}
	return capture.Principal, capture.Assurance, nil
}
func (e *BrokerEvents) Ready(ctx context.Context, s TrustSnapshot) error {
	_, err := e.configuration(ctx, s)
	return err
}

var _ EventVerifier = (*BrokerEvents)(nil)
