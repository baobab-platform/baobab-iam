package nativebff

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestN06RealPGA3BrowserProofIsSingleUseAndFollowsSessionRevocation(t *testing.T) {
	_, pool := n06PGChallengeStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, migration := range []string{"001_native_browser_bff.sql", "002_subject_session_revocation.sql", "003_n06_a3_browser_proof.sql"} {
		ddl, err := os.ReadFile("migrations/" + migration)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(ddl)); err != nil {
			t.Fatalf("%s: %v", migration, err)
		}
	}
	key, idErr := randomValue()
	if idErr != nil {
		t.Fatal(idErr)
	}
	keyBytes := sha256.Sum256([]byte(key))
	store, err := NewPostgresStore(pool, keyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	otherReplica, err := NewPostgresStore(pool, keyBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := randomValue()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session := Session{Subject: "synthetic-n06-browser-proof-subject", Issuer: "https://issuer.invalid",
		PrincipalID: "11111111-1111-4111-8111-111111111111", CSRF: sessionID, ExpiresAt: now.Add(time.Minute),
		Tokens: humanauth.Response{AccessToken: key, TokenType: "Bearer", ExpiresIn: 60, IDToken: key}}
	current := assurance.CurrentSessionKey{Issuer: session.Issuer, Subject: session.Subject, SessionID: "synthetic-kratos-session"}
	proof := assurance.NativeEvidence{Issuer: current.Issuer, Subject: current.Subject, SessionID: current.SessionID,
		Operation: a3BrowserOperation, AAL: assurance.A2, Methods: []string{"webauthn"},
		AuthenticatedAt: now, ObservedAt: now, ExpiresAt: now.Add(30 * time.Second),
		PasskeyUsed: true, UserVerified: true, OriginBound: true}
	if err := store.putA3Proof(ctx, sessionID, proof); err == nil {
		t.Fatal("proof written before a browser session exists")
	}
	if err := store.PutSession(ctx, sessionID, session); err != nil {
		t.Fatal(err)
	}
	if err := store.putA3Proof(ctx, sessionID, proof); err != nil {
		t.Fatal(err)
	}
	if err := otherReplica.putA3Proof(ctx, sessionID, proof); err == nil {
		t.Fatal("a second unexpired proof overwrote the existing operation proof")
	}
	var ciphertext []byte
	idHash, _ := hashID(sessionID)
	if err := pool.QueryRow(ctx, `SELECT sealed FROM native_bff_a3_proofs WHERE id_hash=$1`, idHash).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(session.Subject)) {
		t.Fatal("proof subject visible in the database")
	}
	if _, err := store.takeA3Proof(ctx, sessionID, assurance.Login, current); err == nil {
		t.Fatal("proof consumed for an operation below the A3 floor")
	}
	const parallel = 16
	var wg sync.WaitGroup
	outcomes := make(chan assurance.NativeEvidence, parallel)
	failures := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			replica := store
			if i%2 == 1 {
				replica = otherReplica
			}
			got, takeErr := replica.takeA3Proof(ctx, sessionID, a3BrowserOperation, current)
			if takeErr != nil {
				failures <- takeErr
				return
			}
			outcomes <- got
		}(i)
	}
	wg.Wait()
	close(outcomes)
	close(failures)
	success := 0
	for got := range outcomes {
		success++
		if got.Subject != current.Subject || got.SessionID != current.SessionID ||
			got.Operation != a3BrowserOperation || !got.PasskeyUsed || !got.UserVerified || !got.OriginBound {
			t.Fatal("consumed A3 proof did not retain exact provider/session/operation evidence")
		}
	}
	for range failures {
	}
	if success != 1 {
		t.Fatalf("cross-replica A3 proof consumption had %d winners, want exactly one", success)
	}
	if _, err := otherReplica.takeA3Proof(ctx, sessionID, a3BrowserOperation, current); err == nil {
		t.Fatal("consumed A3 proof was replayed")
	}
	// A proof for a different current Kratos session is consumed and denied;
	// it cannot be retried after the provider session has changed.
	proof.AuthenticatedAt = time.Now().UTC()
	proof.ExpiresAt = proof.AuthenticatedAt.Add(30 * time.Second)
	if err := store.putA3Proof(ctx, sessionID, proof); err != nil {
		t.Fatal("fresh proof after prior one-use consumption was refused", err)
	}
	changedSession := current
	changedSession.SessionID = "different-kratos-session"
	if _, err := otherReplica.takeA3Proof(ctx, sessionID, a3BrowserOperation, changedSession); err == nil {
		t.Fatal("proof for a different current Kratos session was accepted")
	}
	if _, err := store.takeA3Proof(ctx, sessionID, a3BrowserOperation, current); err == nil {
		t.Fatal("mismatched-session proof remained available for replay")
	}
	// A fresh assertion may create a new short-lived proof, but BFF session
	// revocation must cascade-delete that proof before it can be consumed.
	proof.AuthenticatedAt = time.Now().UTC()
	proof.ExpiresAt = proof.AuthenticatedAt.Add(30 * time.Second)
	if err := store.putA3Proof(ctx, sessionID, proof); err != nil {
		t.Fatal("fresh proof before session revocation was refused", err)
	}
	if err := store.DeleteSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM native_bff_a3_proofs WHERE id_hash=$1)`, idHash).Scan(&retained); err != nil || retained {
		t.Fatalf("revoked session retained proof: %v", err)
	}
	if _, err := store.takeA3Proof(ctx, sessionID, a3BrowserOperation, current); err == nil {
		t.Fatal("revoked session proof was consumed")
	}
	if err := store.putA3Proof(ctx, sessionID, proof); err == nil {
		t.Fatal("revoked session accepted a new proof")
	}
}

func n06PGChallengeStore(t *testing.T) (*PGWebAuthnChallengeStore, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("IAM_N06_DISPOSABLE_PG") != "1" {
		t.Skip("requires isolated PostgreSQL 17 CI")
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("IAM_N06_TEST_DATABASE_URL"))
	if err != nil || cfg.ConnConfig.Database != "n06_ci" ||
		(cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost") {
		t.Fatal("refuse non-disposable WebAuthn challenge database")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var version string
	if pool.QueryRow(ctx, "SHOW server_version_num").Scan(&version) != nil ||
		len(version) != 6 || version[:2] != "17" {
		t.Fatal("N06 WebAuthn requires real PostgreSQL 17")
	}
	if err := InstallN06WebAuthnSchema(ctx, pool); err != nil {
		t.Fatal("install independently reviewed N06 challenge DDL", err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal("crypto fixture key unavailable")
	}
	store, err := NewPGWebAuthnChallengeStore(ctx, pool, key[:], time.Now)
	if err != nil {
		t.Fatal("real PG challenge store initialization", err)
	}
	return store, pool
}

func TestN06RealPGWebAuthnOneUseAndEncryptedSessionCustody(t *testing.T) {
	store, pool := n06PGChallengeStore(t)
	f := makeA3Fixture(t)
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		t.Fatal(err)
	}
	challenge := f.challenges.item
	challenge.ID = "n06-real-" + hex.EncodeToString(idBytes)
	now := time.Now().UTC()
	challenge.CreatedAt = now.Add(-time.Second)
	challenge.ExpiresAt = now.Add(60 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lowFloor := challenge
	lowFloor.Operation = assurance.Login
	if err := store.Create(ctx, lowFloor); err == nil {
		t.Fatal("durable WebAuthn challenge accepted an operation below the A3 floor")
	}
	if err := store.Create(ctx, challenge); err != nil {
		t.Fatal("durable challenge insert", err)
	}
	if err := store.Create(ctx, challenge); err == nil {
		t.Fatal("same WebAuthn challenge inserted twice")
	}
	var raw []byte
	if err := pool.QueryRow(ctx,
		"SELECT ciphertext FROM iam_security.webauthn_challenge WHERE challenge_id=$1",
		challenge.ID).Scan(&raw); err != nil {
		t.Fatal("private durable ciphertext missing", err)
	}
	if bytes.Contains(raw, []byte(challenge.Session.Subject)) ||
		bytes.Contains(raw, []byte(challenge.Session.SessionID)) ||
		bytes.Contains(raw, challenge.Nonce) {
		t.Fatal("stored current issuer/subject/session/challenge was not encrypted")
	}
	const parallel = 12
	var wg sync.WaitGroup
	wg.Add(parallel)
	outcomes := make(chan bool, parallel)
	for i := 0; i < parallel; i++ {
		go func() {
			defer wg.Done()
			read, err := store.Consume(ctx, challenge.ID)
			if err == nil && read.Session == challenge.Session &&
				read.RPID == challenge.RPID && bytes.Equal(read.Nonce, challenge.Nonce) {
				outcomes <- true
			} else {
				outcomes <- false
			}
		}()
	}
	wg.Wait()
	close(outcomes)
	success := 0
	for v := range outcomes {
		if v {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("durable same-session nonce replay fence changed: successes=%d", success)
	}
	if _, err := store.Consume(ctx, challenge.ID); err == nil {
		t.Fatal("committed WebAuthn replay accepted")
	}
}

func TestN06RealPGWebAuthnWrongSecretCannotImpersonate(t *testing.T) {
	store, pool := n06PGChallengeStore(t)
	f := makeA3Fixture(t)
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		t.Fatal(err)
	}
	challenge := f.challenges.item
	challenge.ID = "n06-wrong-" + hex.EncodeToString(idBytes)
	now := time.Now().UTC()
	challenge.CreatedAt = now.Add(-time.Second)
	challenge.ExpiresAt = now.Add(60 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := store.Create(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	alternateKey := make([]byte, 32)
	if _, err := rand.Read(alternateKey); err != nil {
		t.Fatal(err)
	}
	impostor, err := NewPGWebAuthnChallengeStore(ctx, pool, alternateKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := impostor.Consume(ctx, challenge.ID); err == nil {
		t.Fatal("wrong IAM AES-GCM key decrypted current challenge")
	}
	if read, err := store.Consume(ctx, challenge.ID); err != nil ||
		read.Session != challenge.Session {
		t.Fatal("failed wrong-key read must roll back without consuming real original")
	}
}

func TestN06RealPGWebAuthnCounterSerializesAndPreservesHighWaterMark(t *testing.T) {
	_, pool := n06PGChallengeStore(t)
	f := makeA3Fixture(t)
	credential := f.credentials.item
	// The disposable ledger key is stable across test invocations. Each
	// invocation uses a different credential to keep concurrent cases isolated.
	salt := sha256.Sum256([]byte("disposable IAM N06 ledger key"))
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	credential.ID = hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := NewPGWebAuthnCounterStore(ctx, pool, salt[:])
	if err != nil {
		t.Fatal(err)
	}
	credential.SignCount = 0
	for i := 0; i < 2; i++ {
		if err := store.RecordAssertionCounter(ctx, credential, 0); err != nil {
			t.Fatal("different valid challenges may report zero", err)
		}
	}
	const writers = 12
	outcomes := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func() { outcomes <- store.RecordAssertionCounter(ctx, credential, 3) }()
	}
	accepted := 0
	for i := 0; i < writers; i++ {
		if <-outcomes == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("same nonzero counter had %d concurrent winners", accepted)
	}
	// A new store instance must observe the same durable ledger.
	reopened, err := NewPGWebAuthnCounterStore(ctx, pool, salt[:])
	if err != nil {
		t.Fatal(err)
	}
	otherSalt := salt
	otherSalt[0] ^= 1
	if _, err := NewPGWebAuthnCounterStore(ctx, pool, otherSalt[:]); err == nil {
		t.Fatal("replacement key reset the counter namespace")
	}
	for _, count := range []uint32{0, 2, 3} {
		if reopened.RecordAssertionCounter(ctx, credential, count) == nil {
			t.Fatalf("zero reset or rollback accepted: %d", count)
		}
	}
	changedKey := credential
	changedKey.PublicKeyDER = []byte("other-public-key")
	if reopened.RecordAssertionCounter(ctx, changedKey, 4) == nil {
		t.Fatal("same credential ID admitted a replacement public key")
	}
	if err := reopened.RecordAssertionCounter(ctx, credential, 4); err != nil {
		t.Fatal("advancing counter denied", err)
	}
}
