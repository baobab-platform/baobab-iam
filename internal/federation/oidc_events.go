package federation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	bolt "go.etcd.io/bbolt"
)

// OIDCConfiguration is a resolved APPROVED native configuration target and
// public trust material, never an ID-token-derived discovery URL. Approval of
// exact bytes and the current trust snapshot is the source's responsibility.
type OIDCConfiguration struct {
	TrustID, SnapshotID, ClientID string
	Revision                      uint64
	Binding                       Binding
	SigningAlgorithm              string // this bounded verifier supports RS256 or ES256
	JWKS                          json.RawMessage
	ValidUntil                    time.Time
}
type OIDCConfigurationAuthority interface {
	OIDCConfiguration(context.Context, TrustSnapshot) (OIDCConfiguration, error)
}

// AssuranceMapper applies the CURRENT approved assurance policy to normalized
// verified evidence, producing event-bound non-secret decision evidence. It
// cannot turn UNKNOWN into a level merely because a token was signed.
type AssuranceMapper interface {
	MapAssurance(context.Context, TrustSnapshot, ExternalPrincipal, Assurance) (Assurance, error)
}
type AuthenticationRequest struct {
	ID, State, Nonce string
	ExpiresAt        time.Time
}
type storedRequest struct {
	ID, TrustID, SnapshotID                 string
	Revision                                uint64
	SessionDigest, StateDigest, NonceDigest string
	CreatedAt, ExpiresAt                    time.Time
	Consumed                                bool
}
type storedEvent struct {
	SnapshotID string
	Revision   uint64
	Bundle     Bundle
	Consumed   bool
}

// OIDCEvents holds only hashed browser binding, protocol correlation and
// normalized evidence. Raw tokens and keys/secrets never enter this ledger.
// It persists replay fences across restart; callers must use one shared writer
// and preserve revocation/replay state during restore (see operational gate).
type OIDCEvents struct {
	db          *bolt.DB
	config      OIDCConfigurationAuthority
	mapper      AssuranceMapper
	now         func() time.Time
	maxLifetime time.Duration
}

var requestsBucket = []byte("oidc-requests-v1")
var eventsBucket = []byte("oidc-events-v1")
var replayBucket = []byte("oidc-token-replay-v1")

func OpenOIDCEvents(path string, config OIDCConfigurationAuthority, mapper AssuranceMapper, now func() time.Time, maxLifetime time.Duration) (*OIDCEvents, error) {
	if path == "" || absent(config) || absent(mapper) || now == nil || maxLifetime <= 0 || maxLifetime > 15*time.Minute {
		return nil, ErrInvalid
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: privateLedgerFile})
	if err != nil {
		return nil, ErrUnavailable
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{requestsBucket, eventsBucket, replayBucket} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	return &OIDCEvents{db, config, mapper, now, maxLifetime}, nil
}
func (e *OIDCEvents) Close() error {
	if e == nil || e.db == nil {
		return ErrUnavailable
	}
	return e.db.Close()
}
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func secretDigest(s string) string {
	d := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(d[:])
}
func equalSecret(s, digest string) bool {
	return subtle.ConstantTimeCompare([]byte(secretDigest(s)), []byte(digest)) == 1
}
func activeSnapshot(s TrustSnapshot, now time.Time) bool {
	return s.Trust.Status == "ACTIVE" && uuidPattern.MatchString(s.Trust.ID) && s.SnapshotID != "" && s.ApprovedRevision == s.Trust.Revision && s.Trust.Revision > 0 && now.Before(s.ValidUntil) && !s.Trust.UpdatedAt.After(now)
}

// Begin is called only by the trusted BFF login root. sessionDigest comes from
// a server-generated, secure browser-session secret; it is not a token claim.
// Return State/Nonce only to the associated browser flow, never to an audit log.
func (e *OIDCEvents) Begin(ctx context.Context, s TrustSnapshot, sessionDigest string) (AuthenticationRequest, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || !digestPattern.MatchString(sessionDigest) || !activeSnapshot(s, e.now()) || s.Trust.Protocol != "OIDC" {
		return AuthenticationRequest{}, ErrDenied
	}
	id, err := randomUUID()
	if err != nil {
		return AuthenticationRequest{}, err
	}
	state, err := randomString()
	if err != nil {
		return AuthenticationRequest{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return AuthenticationRequest{}, err
	}
	now := e.now()
	until := minimum(s.ValidUntil, now.Add(5*time.Minute))
	r := storedRequest{id, s.Trust.ID, s.SnapshotID, s.ApprovedRevision, sessionDigest, secretDigest(state), secretDigest(nonce), now, until, false}
	data, _ := json.Marshal(r)
	err = e.db.Update(func(tx *bolt.Tx) error {
		if ctx.Err() != nil || !e.now().Before(until) {
			return ErrDenied
		}
		return tx.Bucket(requestsBucket).Put([]byte(id), data)
	})
	if err != nil {
		return AuthenticationRequest{}, authorityError(err)
	}
	return AuthenticationRequest{id, state, nonce, until}, nil
}

func publicOIDCKeys(c OIDCConfiguration) ([]crypto.PublicKey, error) {
	if c.SigningAlgorithm != "RS256" && c.SigningAlgorithm != "ES256" || len(c.JWKS) > 32768 {
		return nil, ErrUnsupported
	}
	d := json.NewDecoder(bytes.NewReader(c.JWKS))
	if uniqueJSON(d) != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	var raw struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(c.JWKS))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&raw) != nil || len(raw.Keys) < 1 || len(raw.Keys) > 8 {
		return nil, ErrInvalid
	}
	for _, k := range raw.Keys {
		for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u"} {
			if _, ok := k[field]; ok {
				return nil, ErrInvalid
			}
		}
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(c.JWKS, &set) != nil {
		return nil, ErrInvalid
	}
	keys := make([]crypto.PublicKey, 0, len(set.Keys))
	seen := map[string]bool{}
	for _, k := range set.Keys {
		if !k.Valid() || !k.IsPublic() || !exact(k.KeyID) || seen[k.KeyID] || k.Use != "sig" || k.Algorithm != c.SigningAlgorithm {
			return nil, ErrInvalid
		}
		seen[k.KeyID] = true
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if c.SigningAlgorithm != "RS256" || pub.N.BitLen() < 2048 || pub.E < 65537 {
				return nil, ErrInvalid
			}
		case *ecdsa.PublicKey:
			if c.SigningAlgorithm != "ES256" || pub.Curve != elliptic.P256() {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrUnsupported
		}
		keys = append(keys, k.Key)
	}
	return keys, nil
}

// Complete verifies an ID token (never an access token) with approved public
// keys. It burns a valid correlated callback before verification; a rejected
// assertion cannot be retried as a different identity/assurance result.
func (e *OIDCEvents) Complete(ctx context.Context, id, state, sessionSecret, rawToken string, s TrustSnapshot) error {
	if e == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) || len(rawToken) == 0 || len(rawToken) > 32768 || len(sessionSecret) < 32 || len(sessionSecret) > 512 || len(state) > 512 || !activeSnapshot(s, e.now()) {
		return ErrDenied
	}
	if s.Trust.Protocol != "OIDC" {
		return ErrUnsupported
	}
	var req storedRequest
	err := e.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(requestsBucket)
		if decodeAuthority(b.Get([]byte(id)), &req) != nil || req.Consumed || req.TrustID != s.Trust.ID || req.SnapshotID != s.SnapshotID || req.Revision != s.ApprovedRevision || !fresh(req.CreatedAt, req.ExpiresAt, e.now()) || !equalSecret(state, req.StateDigest) || !equalSecret(sessionSecret, req.SessionDigest) {
			return ErrDenied
		}
		req.Consumed = true
		data, _ := json.Marshal(req)
		return b.Put([]byte(id), data)
	})
	if err != nil {
		return authorityError(err)
	}
	c, err := e.config.OIDCConfiguration(ctx, s)
	if err != nil {
		return authorityError(err)
	}
	if c.TrustID != s.Trust.ID || c.SnapshotID != s.SnapshotID || c.Revision != s.ApprovedRevision || c.Binding != s.Trust.ProviderBinding || !exact(c.ClientID) || !e.now().Before(c.ValidUntil) {
		return ErrUnverified
	}
	keys, err := publicOIDCKeys(c)
	if err != nil {
		return err
	}
	jws, err := jose.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(c.SigningAlgorithm)})
	if err != nil || len(jws.Signatures) != 1 {
		return ErrDenied
	}
	if typ, exists := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType]; exists && typ != "JWT" {
		return ErrDenied
	}
	v := oidc.NewVerifier(s.Trust.UpstreamIssuer, &oidc.StaticKeySet{PublicKeys: keys}, &oidc.Config{ClientID: c.ClientID, SupportedSigningAlgs: []string{c.SigningAlgorithm}, Now: e.now})
	t, err := v.Verify(ctx, rawToken)
	if err != nil {
		return ErrDenied
	}
	// Enforce exact issuer ourselves (including library compatibility aliases),
	// a single intended client audience, azp, strict nbf and bounded iat/auth_time.
	var payload json.RawMessage
	if t.Claims(&payload) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	if uniqueJSON(d) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	var claims struct {
		AZP       string   `json:"azp"`
		AuthTime  int64    `json:"auth_time"`
		NBF       int64    `json:"nbf"`
		ACR       string   `json:"acr"`
		AMR       []string `json:"amr"`
		TokenType string   `json:"typ"`
	}
	if t.Claims(&claims) != nil {
		return ErrInvalid
	}
	now := e.now()
	authenticated := time.Unix(claims.AuthTime, 0).UTC()
	if t.Issuer != s.Trust.UpstreamIssuer || !exact(t.Subject) || len(t.Audience) != 1 || t.Audience[0] != c.ClientID || claims.AZP != "" && claims.AZP != c.ClientID || claims.TokenType != "" && claims.TokenType != "ID" || !equalSecret(t.Nonce, req.NonceDigest) || !now.Before(t.Expiry) || t.IssuedAt.IsZero() || t.IssuedAt.After(now) || t.Expiry.Sub(t.IssuedAt) > e.maxLifetime || t.IssuedAt.Before(req.CreatedAt.Add(-time.Second)) || claims.AuthTime <= 0 || authenticated.After(t.IssuedAt) || now.Sub(authenticated) > e.maxLifetime || claims.NBF > now.Unix() || !exact(claims.ACR) {
		return ErrDenied
	}
	until := minimum(t.Expiry, s.ValidUntil, c.ValidUntil, req.ExpiresAt, now.Add(e.maxLifetime))
	p := ExternalPrincipal{AuthenticationEventID: id, TrustID: s.Trust.ID, ProviderID: c.Binding.ProviderID, EngineInstanceID: c.Binding.EngineInstanceID, Protocol: "OIDC", Issuer: t.Issuer, Subject: t.Subject, ActorType: "human", ObservedAt: now, ExpiresAt: until, Resolution: Resolution{Status: "UNRESOLVED"}}
	a := Assurance{AuthenticationEventID: id, TrustID: s.Trust.ID, ProviderID: p.ProviderID, EngineInstanceID: p.EngineInstanceID, Protocol: "OIDC", Issuer: p.Issuer, Subject: p.Subject, UpstreamEvidence: UpstreamEvidence{OIDC: &OIDCAssurance{ActorType: "human", ACR: claims.ACR, AMR: claims.AMR, AuthenticatedAt: authenticated, Issuer: p.Issuer, ClientID: c.ClientID}}, MappingStatus: "UNKNOWN", AssurancePolicyReference: s.Trust.AssurancePolicyReference, EvaluatedAt: now, ExpiresAt: until}
	if ValidateBundle(Bundle{s.Trust, p, a}) != nil {
		return ErrInvalid
	}
	mapped, err := e.mapper.MapAssurance(ctx, s, p, a)
	if err != nil {
		return authorityError(err)
	}
	// A mapper may only supply its governed mapping result and shorten expiry.
	copyMapped := mapped
	copyMapped.MappingStatus = a.MappingStatus
	copyMapped.Level = a.Level
	copyMapped.MappingEvidenceReference = a.MappingEvidenceReference
	copyMapped.ExpiresAt = a.ExpiresAt
	original, _ := json.Marshal(a)
	actual, _ := json.Marshal(copyMapped)
	if !bytes.Equal(original, actual) || mapped.ExpiresAt.After(a.ExpiresAt) || ValidateBundle(Bundle{s.Trust, p, mapped}) != nil {
		return ErrInvalid
	}
	event := storedEvent{s.SnapshotID, s.ApprovedRevision, Bundle{s.Trust, p, mapped}, false}
	data, _ := json.Marshal(event)
	return authorityErrorUnlessNil(e.db.Update(func(tx *bolt.Tx) error {
		if ctx.Err() != nil || !e.now().Before(mapped.ExpiresAt) {
			return ErrDenied
		}
		replay := tx.Bucket(replayBucket)
		key := []byte(secretDigest(rawToken))
		if replay.Get(key) != nil || tx.Bucket(eventsBucket).Get([]byte(id)) != nil {
			return ErrDenied
		}
		if err := replay.Put(key, []byte(t.Expiry.Format(time.RFC3339Nano))); err != nil {
			return err
		}
		return tx.Bucket(eventsBucket).Put([]byte(id), data)
	}))
}

// Verify consumes persisted verified evidence exactly once. The consumer still
// performs current trust/platform/CP canonical/approval checks independently.
func (e *OIDCEvents) Verify(ctx context.Context, id string, s TrustSnapshot) (ExternalPrincipal, Assurance, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) {
		return ExternalPrincipal{}, Assurance{}, ErrInvalid
	}
	if s.Trust.Protocol != "OIDC" {
		return ExternalPrincipal{}, Assurance{}, ErrUnsupported
	}
	var event storedEvent
	err := e.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(eventsBucket)
		if decodeAuthority(b.Get([]byte(id)), &event) != nil || event.Consumed || event.SnapshotID != s.SnapshotID || event.Revision != s.ApprovedRevision || event.Bundle.Trust.ID != s.Trust.ID || !activeSnapshot(s, e.now()) || !e.now().Before(event.Bundle.Assurance.ExpiresAt) {
			return ErrDenied
		}
		// Same snapshot must carry identical trust contents; ID/revision alone
		// must not allow configuration substitution after verification.
		left, _ := json.Marshal(event.Bundle.Trust)
		right, _ := json.Marshal(s.Trust)
		if !bytes.Equal(left, right) {
			return ErrUnverified
		}
		event.Consumed = true
		data, _ := json.Marshal(event)
		return b.Put([]byte(id), data)
	})
	if err != nil {
		return ExternalPrincipal{}, Assurance{}, authorityError(err)
	}
	return event.Bundle.ExternalPrincipal, event.Bundle.Assurance, nil
}

var _ EventVerifier = (*OIDCEvents)(nil)
