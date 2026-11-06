package nativebff

// IAM-N06 WebAuthn challenges are encrypted and consumed atomically by a
// real PostgreSQL 17 authority, never by an in-memory instance-local cache.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_n06_webauthn.sql
var n06WebAuthnDDL string

// InstallN06WebAuthnSchema must run only in a reviewed disposable or approved
// IAM migration transaction; creating a store never applies DDL.
func InstallN06WebAuthnSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if ctx == nil || ctx.Err() != nil || pool == nil {
		return errA3Denied
	}
	_, err := pool.Exec(ctx, n06WebAuthnDDL)
	return err
}

var n06ChallengeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{12,160}$`)
type PGWebAuthnChallengeStore struct {
	pool *pgxpool.Pool
	aead cipher.AEAD
	now func() time.Time
}

func NewPGWebAuthnChallengeStore(ctx context.Context, pool *pgxpool.Pool, key []byte, now func() time.Time) (*PGWebAuthnChallengeStore, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil || now == nil || len(key) != 32 {
		return nil, errA3Denied
	}
	initialized := false
	for _, b := range key {
		if b != 0 { initialized = true; break }
	}
	if !initialized { return nil, errA3Denied }
	var exists bool
	if err := pool.QueryRow(ctx,`SELECT to_regclass('iam_security.webauthn_challenge') IS NOT NULL`).Scan(&exists);err!=nil || !exists {
		return nil, errA3Denied
	}
	block,err := aes.NewCipher(key)
	if err != nil { return nil, errA3Denied }
	gcm,err := cipher.NewGCM(block)
	if err != nil { return nil, errA3Denied }
	return &PGWebAuthnChallengeStore{pool:pool,aead:gcm,now:now},nil
}
func (s *PGWebAuthnChallengeStore) Create(ctx context.Context, challenge WebAuthnChallenge) error {
	if s == nil || s.pool == nil || s.aead == nil || ctx == nil || ctx.Err()!=nil ||
		!n06ChallengeID.MatchString(challenge.ID) ||
		challenge.Session.Issuer == "" || challenge.Session.Subject == "" ||
		challenge.Session.SessionID == "" || len(challenge.Nonce)!=32 ||
		!validRelyingParty(challenge) {
		return errA3Denied
	}
	now:=s.now().UTC()
	if challenge.CreatedAt.IsZero() || challenge.CreatedAt.After(now) ||
		now.Sub(challenge.CreatedAt)>30*time.Second ||
		!challenge.ExpiresAt.After(now) ||
		challenge.ExpiresAt.Sub(challenge.CreatedAt)>2*time.Minute {
		return errA3Denied
	}
	plaintext,err:=json.Marshal(challenge)
	if err!=nil || len(plaintext)>8192 {return errA3Denied}
	iv:=make([]byte,s.aead.NonceSize())
	if _,err=io.ReadFull(rand.Reader,iv);err!=nil {return errA3Denied}
	encrypted:=s.aead.Seal(nil,iv,plaintext,[]byte(challenge.ID))
	_,err=s.pool.Exec(ctx,`INSERT INTO iam_security.webauthn_challenge
(challenge_id,nonce,ciphertext,created_at,expires_at)
VALUES($1,$2,$3,$4,$5)`,challenge.ID,iv,encrypted,challenge.CreatedAt,challenge.ExpiresAt)
	if err!=nil {return errA3Denied}
	return nil
}
func (s *PGWebAuthnChallengeStore) Consume(ctx context.Context, id string) (WebAuthnChallenge,error) {
	none:=WebAuthnChallenge{}
	if s==nil||s.aead==nil||s.pool==nil||ctx==nil||ctx.Err()!=nil||
		!n06ChallengeID.MatchString(id) {return none,errA3Denied}
	tx,err:=s.pool.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.Serializable})
	if err!=nil{return none,errA3Denied}
	defer tx.Rollback(ctx)
	var iv,encrypted []byte
	var expiry time.Time
	err=tx.QueryRow(ctx,`DELETE FROM iam_security.webauthn_challenge
WHERE challenge_id=$1 AND expires_at>statement_timestamp()
RETURNING nonce,ciphertext,expires_at`,id).Scan(&iv,&encrypted,&expiry)
	if err!=nil{return none,errA3Denied}
	if len(iv)!=s.aead.NonceSize() || len(encrypted)>8192+s.aead.Overhead() {
		return none,errA3Denied
	}
	plaintext,err:=s.aead.Open(nil,iv,encrypted,[]byte(id))
	if err!=nil || len(plaintext)>8192 {return none,errA3Denied}
	var value WebAuthnChallenge
	if json.Unmarshal(plaintext,&value)!=nil || value.ID!=id || !value.ExpiresAt.Equal(expiry) {
		return none,errA3Denied
	}
	// A durable DELETE is the exactly-once fence. A failed commit is UNKNOWN:
	// never claim the assertion consumed or issue A3 from it.
	if tx.Commit(ctx)!=nil {return none,errors.New("N06 WebAuthn challenge consumption unverified")}
	return value,nil
}
