package nativebff

// A3 origin/RP/user-verification witness for a second, server-issued WebAuthn
// ceremony. Neither a browser-supplied assurance level nor Kratos "webauthn"
// method string by itself is an A3 proof. Credential keys and counter state
// MUST be read from the real Kratos credential record by an IAM-owned port.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

var errA3Denied = errors.New("N06 RP-bound WebAuthn proof denied")

type WebAuthnAssertion struct {
	ChallengeID string
	CredentialID string
	ClientDataJSON []byte
	AuthenticatorData []byte
	SignatureDER []byte
}

// A challenge is minted and durably consumed by a trusted IAM server. The
// browser may only submit ChallengeID; it NEVER selects RP ID, origin, expiry,
// principal, session or assurance. Consume MUST be atomic and one-use.
type WebAuthnChallenge struct {
	ID string
	Session assurance.CurrentSessionKey
	RPID string
	Origin string
	Nonce []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	DevelopmentLoopback bool
}
type WebAuthnChallengeStore interface {
	Consume(context.Context, string) (WebAuthnChallenge, error)
}
type KratosWebAuthnCredential struct {
	ID string
	Issuer string
	Subject string
	PublicKeyDER []byte
	SignCount uint32
}
type KratosCredentialReader interface {
	// This reads the credential from the trusted current Kratos identity,
	// NEVER from the browser registration payload.
	CurrentKratosCredential(context.Context, assurance.CurrentSessionKey, string) (KratosWebAuthnCredential, error)
	// Compare-and-swap counter. A concurrent duplicate MUST lose.
	AdvanceKratosSignCounter(context.Context, KratosWebAuthnCredential, uint32) error
}

// WebAuthnA3Verifier produces a short-lived authentication-only A3 evidence
// result after an actual Kratos AAL2+WebAuthn session and independent ES256
// RP-bound assertion. A4 hardware provenance and CP privileges are NOT inferred.
type WebAuthnA3Verifier struct {
	Kratos N06ProviderProof
	Challenges WebAuthnChallengeStore
	Credentials KratosCredentialReader
	Now func() time.Time
}

func (v *WebAuthnA3Verifier) Verify(
	ctx context.Context, cookie ory.NativeSessionCredential, a WebAuthnAssertion,
) (assurance.Evidence, error) {
	none := assurance.Evidence{}
	if ctx == nil || ctx.Err() != nil || v == nil || v.Now == nil ||
		v.Kratos == nil || v.Challenges == nil || v.Credentials == nil ||
		cookie.Cookie == "" || cookie.SessionToken != "" ||
		len(a.ChallengeID) < 12 || len(a.ChallengeID) > 160 ||
		len(a.CredentialID) < 16 || len(a.CredentialID) > 1024 ||
		len(a.ClientDataJSON) < 60 || len(a.ClientDataJSON) > 4096 ||
		len(a.AuthenticatorData) < 37 || len(a.AuthenticatorData) > 512 ||
		len(a.SignatureDER) < 60 || len(a.SignatureDER) > 144 {
		return none, errA3Denied
	}
	key, kratos, err := v.Kratos.CurrentNativeAuthentication(ctx, cookie)
	if err != nil || key.Issuer == "" || key.Subject == "" || key.SessionID == "" ||
		kratos.AAL != "aal2" || !hasWebAuthn(kratos.Methods) {
		return none, errA3Denied
	}
	challenge, err := v.Challenges.Consume(ctx, a.ChallengeID)
	if err != nil { return none, errA3Denied }
	now := v.Now().UTC()
	if challenge.ID != a.ChallengeID || challenge.Session != key ||
		challenge.CreatedAt.IsZero() || challenge.ExpiresAt.IsZero() ||
		challenge.CreatedAt.After(now) || !now.Before(challenge.ExpiresAt) ||
		now.Sub(challenge.CreatedAt) > 2*time.Minute ||
		challenge.ExpiresAt.Sub(challenge.CreatedAt) > 2*time.Minute ||
		len(challenge.Nonce) != 32 || !validRelyingParty(challenge) {
		return none, errA3Denied
	}
	client, err := decodeBoundWebAuthnClientData(a.ClientDataJSON)
	if err != nil || client.Type != "webauthn.get" || client.Origin != challenge.Origin ||
		client.CrossOrigin || client.TopOrigin != "" ||
		subtle.ConstantTimeCompare(client.Challenge, challenge.Nonce) != 1 {
		return none, errA3Denied
	}
	rp := sha256.Sum256([]byte(challenge.RPID))
	if subtle.ConstantTimeCompare(a.AuthenticatorData[:32], rp[:]) != 1 ||
		// Flags: user-present bit0 and user-verified bit2. Attested/
		// credential-data/extensions are not permitted in assertions.
		a.AuthenticatorData[32]&0x05 != 0x05 ||
		a.AuthenticatorData[32]&0xC0 != 0 {
		return none, errA3Denied
	}
	counter := binary.BigEndian.Uint32(a.AuthenticatorData[33:37])
	credential, err := v.Credentials.CurrentKratosCredential(ctx, key, a.CredentialID)
	if err != nil || credential.ID != a.CredentialID ||
		credential.Issuer != key.Issuer || credential.Subject != key.Subject ||
		len(credential.PublicKeyDER) > 1024 || counter == 0 ||
		counter <= credential.SignCount {
		return none, errA3Denied
	}
	keyValue, err := x509.ParsePKIXPublicKey(credential.PublicKeyDER)
	pub, valid := keyValue.(*ecdsa.PublicKey)
	if err != nil || !valid || pub.Curve != elliptic.P256() {
		return none, errA3Denied
	}
	clientDigest := sha256.Sum256(a.ClientDataJSON)
	signed := make([]byte, 0, len(a.AuthenticatorData)+len(clientDigest))
	signed = append(signed, a.AuthenticatorData...)
	signed = append(signed, clientDigest[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], a.SignatureDER) {
		return none, errA3Denied
	}
	if v.Credentials.AdvanceKratosSignCounter(ctx, credential, counter) != nil {
		return none, errA3Denied
	}
	return assurance.Evidence{
		Issuer:key.Issuer, Subject:key.Subject, SessionID:key.SessionID,
		ObservedAt:now, AuthenticatedAt:now, AAL:"aal2",
		Methods:[]string{"webauthn"}, PasskeyUsed:true,
		UserVerified:true, OriginBound:true, HardwareBound:false,
	}, nil
}

func hasWebAuthn(methods []string) bool {
	for _, method := range methods {
		if method == "webauthn" || method == "passkey" { return true }
	}
	return false
}
func validRelyingParty(c WebAuthnChallenge) bool {
	u, err := url.Parse(c.Origin)
	if err != nil || u == nil || u.User != nil ||
		u.Fragment != "" || u.RawQuery != "" || u.Path != "" ||
		u.Hostname() != c.RPID || strings.ContainsAny(c.RPID, "\r\n/@:") {
		return false
	}
	if u.Scheme == "https" && u.Port() != "0" { return true }
	return c.DevelopmentLoopback && c.RPID == "127.0.0.1" &&
		c.Origin == "http://127.0.0.1:4455"
}

type webAuthnClientData struct {
	Type string
	Challenge []byte
	Origin string
	CrossOrigin bool
	TopOrigin string
}
func decodeBoundWebAuthnClientData(raw []byte) (webAuthnClientData, error) {
	var value webAuthnClientData
	var shape map[string]json.RawMessage
	d := json.NewDecoder(strings.NewReader(string(raw)))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') { return value, errA3Denied }
	seen := map[string]bool{}
	shape = map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		k, ok := t.(string)
		if err != nil || !ok || seen[k] || len(seen) >= 7 {
			return value, errA3Denied
		}
		seen[k] = true
		switch k {
		case "type","challenge","origin","crossOrigin","topOrigin":
		default:
			return value, errA3Denied
		}
		var v json.RawMessage
		if d.Decode(&v) != nil { return value, errA3Denied }
		shape[k] = v
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return value, errA3Denied
	}
	if _, err = d.Token(); err != io.EOF { return value, errA3Denied }
	var encodedChallenge string
	if json.Unmarshal(shape["type"], &value.Type) != nil ||
		json.Unmarshal(shape["challenge"], &encodedChallenge) != nil ||
		json.Unmarshal(shape["origin"], &value.Origin) != nil ||
		len(encodedChallenge) < 40 || len(encodedChallenge) > 90 {
		return value, errA3Denied
	}
	value.Challenge, err = base64.RawURLEncoding.DecodeString(encodedChallenge)
	if err != nil { return value, errA3Denied }
	if rawCross, ok := shape["crossOrigin"]; ok {
		if json.Unmarshal(rawCross, &value.CrossOrigin) != nil {
			return value, errA3Denied
		}
	}
	if rawTop, ok := shape["topOrigin"]; ok {
		if json.Unmarshal(rawTop, &value.TopOrigin) != nil { return value, errA3Denied }
	}
	return value, nil
}
