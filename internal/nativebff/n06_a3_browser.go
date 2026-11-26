package nativebff

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

type A3BrowserStepUp struct {
	verifier     *WebAuthnA3Verifier
	challenges   *PGWebAuthnChallengeStore
	store        *PostgresStore
	rpID, origin string
}

func NewA3BrowserStepUp(ctx context.Context, verifier *WebAuthnA3Verifier, challenges *PGWebAuthnChallengeStore, store *PostgresStore, origin string) (*A3BrowserStepUp, error) {
	u, err := originURL(origin, false)
	if err != nil || ctx == nil || ctx.Err() != nil || verifier == nil || verifier.Kratos == nil ||
		verifier.Credentials == nil || verifier.Counters == nil || verifier.Now == nil || challenges == nil ||
		verifier.Challenges != challenges || store == nil || store.pool == nil ||
		!validRelyingParty(WebAuthnChallenge{RPID: u.Hostname(), Origin: origin}) {
		return nil, errA3Denied
	}
	var exists bool
	if store.pool.QueryRow(ctx, `SELECT to_regclass('native_bff_a3_proofs') IS NOT NULL`).Scan(&exists) != nil || !exists {
		return nil, errA3Denied
	}
	return &A3BrowserStepUp{verifier: verifier, challenges: challenges, store: store, rpID: u.Hostname(), origin: origin}, nil
}

// This route verifies a server-owned A3 operation. CP still determines whether
// any actual resource operation can be performed.
const a3BrowserOperation = assurance.HighValueApproval

type a3BrowserRequest struct {
	CredentialID      string `json:"credential_id"`
	ChallengeID       string `json:"challenge_id,omitempty"`
	ClientDataJSON    []byte `json:"client_data_json,omitempty"`
	AuthenticatorData []byte `json:"authenticator_data,omitempty"`
	SignatureDER      []byte `json:"signature_der,omitempty"`
}

func (h *Handler) a3BrowserRequest(w http.ResponseWriter, r *http.Request) (a3BrowserRequest, string, Session, ory.NativeSessionCredential, bool) {
	var body a3BrowserRequest
	var empty ory.NativeSessionCredential
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if !h.postOrigin(r) || r.URL.RawQuery != "" || err != nil || media != "application/json" {
		h.fail(w, http.StatusForbidden)
		return body, "", Session{}, empty, false
	}
	id, session, err := h.authenticated(r)
	kratos, providerErr := h.kratos(r)
	if err != nil || providerErr != nil || session.CSRF == "" ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRF)) != 1 {
		h.fail(w, http.StatusForbidden)
		return body, "", Session{}, empty, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	unique := json.NewDecoder(bytes.NewReader(raw))
	if err != nil || n06UniqueJSON(unique) != nil || unique.Decode(new(any)) != io.EOF {
		h.fail(w, http.StatusBadRequest)
		return body, "", Session{}, empty, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF || body.CredentialID == "" {
		h.fail(w, http.StatusBadRequest)
		return body, "", Session{}, empty, false
	}
	return body, id, session, kratos, true
}

func (h *Handler) a3Challenge(w http.ResponseWriter, r *http.Request) {
	body, id, session, kratos, ok := h.a3BrowserRequest(w, r)
	if !ok {
		return
	}
	if body.ChallengeID != "" || len(body.ClientDataJSON)+len(body.AuthenticatorData)+len(body.SignatureDER) != 0 {
		h.fail(w, http.StatusBadRequest)
		return
	}
	step := h.c.A3StepUp
	key, evidence, err := step.verifier.Kratos.CurrentNativeAuthentication(r.Context(), kratos)
	if err != nil || key.Subject != session.Subject || evidence.AAL != assurance.A2 || !hasWebAuthn(evidence.Methods) {
		h.fail(w, http.StatusForbidden)
		return
	}
	credential, err := step.verifier.Credentials.CurrentKratosCredential(r.Context(), key, body.CredentialID)
	if err != nil {
		h.fail(w, http.StatusForbidden)
		return
	}
	nonce := make([]byte, 32)
	challengeID, idErr := randomValue()
	if _, randErr := rand.Read(nonce); randErr != nil || idErr != nil {
		h.fail(w, http.StatusServiceUnavailable)
		return
	}
	now := h.c.Now().UTC()
	if evidence.AuthenticatedAt.IsZero() || evidence.AuthenticatedAt.After(now) ||
		now.Sub(evidence.AuthenticatedAt) >= 2*time.Minute || !evidence.ExpiresAt.After(now) {
		h.fail(w, http.StatusForbidden)
		return
	}
	challenge := WebAuthnChallenge{ID: challengeID, Session: key, Operation: a3BrowserOperation,
		RPID: step.rpID, Origin: step.origin, Nonce: nonce, CreatedAt: now,
		ExpiresAt:          minInstant(now.Add(90*time.Second), minInstant(session.ExpiresAt, evidence.ExpiresAt)),
		BrowserSessionHash: sha256.Sum256([]byte(id)), CredentialID: credential.ID}
	if step.challenges.Create(r.Context(), challenge) != nil {
		h.fail(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"challenge_id": challengeID,
		"challenge": base64.RawURLEncoding.EncodeToString(nonce), "rp_id": step.rpID, "credential_id": credential.ID})
}

func (h *Handler) a3Verify(w http.ResponseWriter, r *http.Request) {
	body, id, session, kratos, ok := h.a3BrowserRequest(w, r)
	if !ok {
		return
	}
	step := h.c.A3StepUp
	proof, err := step.verifier.verifyBound(r.Context(), kratos, a3BrowserOperation,
		sha256.Sum256([]byte(id)), WebAuthnAssertion{ChallengeID: body.ChallengeID, CredentialID: body.CredentialID,
			ClientDataJSON: body.ClientDataJSON, AuthenticatorData: body.AuthenticatorData, SignatureDER: body.SignatureDER})
	if err != nil || proof.Subject != session.Subject {
		h.fail(w, http.StatusForbidden)
		return
	}
	current, evidence, err := step.verifier.Kratos.CurrentNativeAuthentication(r.Context(), kratos)
	if err != nil || current.Issuer != proof.Issuer || current.Subject != proof.Subject ||
		current.SessionID != proof.SessionID || evidence.AAL != assurance.A2 || !hasWebAuthn(evidence.Methods) {
		h.fail(w, http.StatusForbidden)
		return
	}
	proof.ExpiresAt = minInstant(proof.AuthenticatedAt.Add(30*time.Second),
		minInstant(evidence.ExpiresAt, minInstant(proof.ExpiresAt, session.ExpiresAt)))
	if step.store.putA3Proof(r.Context(), id, proof) != nil {
		h.fail(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func minInstant(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *PostgresStore) putA3Proof(ctx context.Context, id string, proof assurance.NativeEvidence) error {
	hash, err := hashID(id)
	if err != nil || s == nil || s.pool == nil || ctx == nil || ctx.Err() != nil ||
		proof.Operation != a3BrowserOperation || proof.Issuer == "" || proof.Subject == "" || proof.SessionID == "" ||
		proof.AAL != assurance.A2 || !hasWebAuthn(proof.Methods) ||
		proof.AuthenticatedAt.IsZero() || proof.ExpiresAt.IsZero() ||
		!proof.ExpiresAt.After(proof.AuthenticatedAt) || proof.ExpiresAt.Sub(proof.AuthenticatedAt) > 30*time.Second ||
		!proof.PasskeyUsed || !proof.UserVerified || !proof.OriginBound || proof.HardwareBound {
		return errA3Denied
	}
	// PostgreSQL stores microsecond precision. Seal the exact same instant
	// that is persisted so authenticated readback can compare it exactly.
	proof.ExpiresAt = proof.ExpiresAt.UTC().Truncate(time.Microsecond)
	sealed, err := s.seal("a3", id, proof)
	if err != nil {
		return errA3Denied
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO native_bff_a3_proofs AS ledger (id_hash,operation,sealed,expires_at)
 SELECT id_hash,$2,$3,$4 FROM native_bff_sessions WHERE id_hash=$1
   AND expires_at>clock_timestamp() AND $4>clock_timestamp() AND $4<=expires_at
 ON CONFLICT (id_hash,operation) DO UPDATE SET sealed=EXCLUDED.sealed,expires_at=EXCLUDED.expires_at
 WHERE ledger.expires_at<=clock_timestamp()`, hash, proof.Operation, sealed, proof.ExpiresAt)
	if err != nil || result.RowsAffected() != 1 {
		return errA3Denied
	}
	return nil
}

// takeA3Proof is the one-use BFF proof-consumption fence. The opaque browser
// session ID is the AEAD context and row key; the current Kratos session and
// operation are checked after the atomic DELETE. A mismatch consumes the
// stale proof rather than allowing it to be retried after identity changes.
func (s *PostgresStore) takeA3Proof(ctx context.Context, id string, operation assurance.Operation, current assurance.CurrentSessionKey) (assurance.NativeEvidence, error) {
	var none assurance.NativeEvidence
	hash, err := hashID(id)
	if err != nil || s == nil || s.pool == nil || ctx == nil || ctx.Err() != nil ||
		operation != a3BrowserOperation || current.Issuer == "" || current.Subject == "" || current.SessionID == "" {
		return none, errA3Denied
	}
	var sealed []byte
	var expires time.Time
	err = s.pool.QueryRow(ctx, `DELETE FROM native_bff_a3_proofs AS proof
USING native_bff_sessions AS session
WHERE proof.id_hash=$1 AND proof.operation=$2 AND proof.expires_at>clock_timestamp()
  AND session.id_hash=proof.id_hash AND session.expires_at>clock_timestamp()
RETURNING proof.sealed,proof.expires_at`, hash, operation).Scan(&sealed, &expires)
	if err != nil {
		return none, errA3Denied
	}
	var evidence assurance.NativeEvidence
	if s.open("a3", id, sealed, &evidence) != nil ||
		evidence.Operation != operation || evidence.Issuer != current.Issuer ||
		evidence.Subject != current.Subject || evidence.SessionID != current.SessionID ||
		evidence.AAL != assurance.A2 || !hasWebAuthn(evidence.Methods) ||
		!evidence.PasskeyUsed || !evidence.UserVerified || !evidence.OriginBound || evidence.HardwareBound ||
		evidence.AuthenticatedAt.IsZero() ||
		!evidence.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expires.UTC()) {
		return none, errA3Denied
	}
	return evidence, nil
}
