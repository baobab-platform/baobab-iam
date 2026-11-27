package nativebff

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/fxamacker/cbor/v2"
)

var kratosIdentityID = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

// KratosWebAuthnReader reads only WebAuthn credentials on a private Kratos
// admin origin. Callers must supply a session key verified by the issuer.
type KratosWebAuthnReader struct {
	issuer string
	admin  string
	client *http.Client
	cose   cbor.DecMode
}

func NewKratosWebAuthnReader(issuer, admin string, roots *x509.CertPool) (*KratosWebAuthnReader, error) {
	issuerURL, issuerErr := originURL(issuer, false)
	adminURL, adminErr := originURL(admin, false)
	if issuerErr != nil || adminErr != nil || roots == nil || len(roots.Subjects()) == 0 ||
		issuerURL.ForceQuery || adminURL.ForceQuery || strings.ContainsAny(issuer+admin, "#") {
		return nil, errA3Denied
	}
	issuerOrigin := strings.TrimRight(issuerURL.String(), "/")
	adminOrigin := strings.TrimRight(adminURL.String(), "/")
	if issuerOrigin == adminOrigin {
		return nil, errA3Denied
	}
	mode, err := (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
		MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
	}).DecMode()
	if err != nil {
		return nil, errA3Denied
	}
	return &KratosWebAuthnReader{issuer: issuerOrigin, admin: adminOrigin, client: n06KratosTLSClient(roots.Clone()), cose: mode}, nil
}

func (r *KratosWebAuthnReader) CurrentKratosCredential(ctx context.Context, session assurance.CurrentSessionKey, credentialID string) (KratosWebAuthnCredential, error) {
	var none KratosWebAuthnCredential
	if r == nil || r.client == nil || r.cose == nil || ctx == nil || ctx.Err() != nil ||
		session.Issuer != r.issuer || session.SessionID == "" || !kratosIdentityID.MatchString(session.Subject) ||
		len(credentialID) < 16 || len(credentialID) > 1024 {
		return none, errA3Denied
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(credentialID)
	if err != nil || base64.RawURLEncoding.EncodeToString(id) != credentialID {
		return none, errA3Denied
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.admin+"/admin/identities/"+session.Subject+"?include_credential=webauthn", nil)
	if err != nil {
		return none, errA3Denied
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	res, err := r.client.Do(req)
	if err != nil {
		return none, errA3Denied
	}
	defer res.Body.Close()
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || res.StatusCode != http.StatusOK || res.Header.Get("Link") != "" {
		return none, errA3Denied
	}
	const maxResponse = 128 * 1024
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return none, errA3Denied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if n06UniqueJSON(d) != nil || d.Decode(new(any)) != io.EOF {
		return none, errA3Denied
	}
	var row struct {
		ID          string `json:"id"`
		State       string `json:"state"`
		Credentials map[string]struct {
			Config struct {
				Credentials []struct {
					ID            []byte `json:"id"`
					PublicKey     []byte `json:"public_key"`
					Authenticator struct {
						SignCount    *uint32 `json:"sign_count"`
						CloneWarning bool    `json:"clone_warning"`
					} `json:"authenticator"`
				} `json:"credentials"`
			} `json:"config"`
		} `json:"credentials"`
	}
	if json.Unmarshal(raw, &row) != nil || row.ID != session.Subject || row.State != "active" {
		return none, errA3Denied
	}
	var found KratosWebAuthnCredential
	for _, saved := range row.Credentials["webauthn"].Config.Credentials {
		if !bytes.Equal(saved.ID, id) {
			continue
		}
		if found.ID != "" || saved.Authenticator.SignCount == nil || saved.Authenticator.CloneWarning {
			return none, errA3Denied
		}
		key, err := r.es256PublicKey(saved.PublicKey)
		if err != nil {
			return none, errA3Denied
		}
		found = KratosWebAuthnCredential{ID: credentialID, Issuer: session.Issuer, Subject: row.ID,
			PublicKeyDER: key, SignCount: *saved.Authenticator.SignCount}
	}
	if found.ID == "" {
		return none, errA3Denied
	}
	return found, nil
}

func (r *KratosWebAuthnReader) es256PublicKey(encoded []byte) ([]byte, error) {
	// COSE EC2, ES256, P-256 and two exact unsigned 32-byte coordinates.
	var key struct {
		Kind      int    `cbor:"1,keyasint"`
		Algorithm int    `cbor:"3,keyasint"`
		Curve     int    `cbor:"-1,keyasint"`
		X         []byte `cbor:"-2,keyasint"`
		Y         []byte `cbor:"-3,keyasint"`
	}
	if len(encoded) == 0 || len(encoded) > 512 || r.cose.Unmarshal(encoded, &key) != nil ||
		key.Kind != 2 || key.Algorithm != -7 || key.Curve != 1 || len(key.X) != 32 || len(key.Y) != 32 {
		return nil, errA3Denied
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(key.X), Y: new(big.Int).SetBytes(key.Y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, errA3Denied
	}
	return x509.MarshalPKIXPublicKey(public)
}
