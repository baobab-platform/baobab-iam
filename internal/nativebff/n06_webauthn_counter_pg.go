package nativebff

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/002_n06_webauthn_counter.sql
var n06WebAuthnCounterDDL string

// PGWebAuthnCounterStore persists IAM-observed counters under keyed references.
// The server-owned key must be stable for the lifetime of the ledger.
type PGWebAuthnCounterStore struct {
	pool *pgxpool.Pool
	key  [32]byte
}

func NewPGWebAuthnCounterStore(ctx context.Context, pool *pgxpool.Pool, key []byte) (*PGWebAuthnCounterStore, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil || len(key) != 32 {
		return nil, errA3Denied
	}
	store := &PGWebAuthnCounterStore{pool: pool, key: [32]byte(key)}
	if store.key == [32]byte{} {
		return nil, errA3Denied
	}
	commitment := store.reference("n06-counter-ledger-key", nil)
	result, err := pool.Exec(ctx, `INSERT INTO iam_security.webauthn_counter_key AS ledger
 (singleton, key_commitment) VALUES (true, $1)
 ON CONFLICT (singleton) DO UPDATE SET key_commitment = EXCLUDED.key_commitment
 WHERE ledger.key_commitment = EXCLUDED.key_commitment`, commitment)
	if err != nil || result.RowsAffected() != 1 {
		return nil, errA3Denied
	}
	return store, nil
}

func (s *PGWebAuthnCounterStore) RecordAssertionCounter(ctx context.Context, credential KratosWebAuthnCredential, next uint32) error {
	if s == nil || s.pool == nil || ctx == nil || ctx.Err() != nil ||
		credential.Issuer == "" || credential.Subject == "" || credential.ID == "" || len(credential.PublicKeyDER) == 0 ||
		!counterAdmissible(credential.SignCount, next) {
		return errA3Denied
	}

	// Encode the issuer, subject and credential separately to preserve their
	// boundaries. Keep the key fingerprint out of the credential lookup so a
	// changed key for an existing credential ID cannot reset the ledger.
	parts, err := json.Marshal([3]string{credential.Issuer, credential.Subject, credential.ID})
	if err != nil {
		return errA3Denied
	}
	ref := s.reference("n06-credential-reference", parts)
	keyRef := s.reference("n06-key-reference", credential.PublicKeyDER)
	result, err := s.pool.Exec(ctx, `INSERT INTO iam_security.webauthn_counter AS ledger
 (credential_ref, key_ref, sign_count) VALUES ($1, $2, $3)
 ON CONFLICT (credential_ref) DO UPDATE SET sign_count = EXCLUDED.sign_count
 WHERE ledger.key_ref = EXCLUDED.key_ref
   AND (ledger.sign_count < EXCLUDED.sign_count
        OR (ledger.sign_count = 0 AND EXCLUDED.sign_count = 0))`, ref, keyRef, int64(next))
	if err != nil || result.RowsAffected() != 1 {
		return errA3Denied
	}
	return nil
}

func (s *PGWebAuthnCounterStore) reference(domain string, value []byte) []byte {
	mac := hmac.New(sha256.New, s.key[:])
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(value)
	return mac.Sum(nil)
}

var _ WebAuthnCounterStore = (*PGWebAuthnCounterStore)(nil)
