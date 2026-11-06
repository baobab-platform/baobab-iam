package nativebff

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func n06PGChallengeStore(t *testing.T) (*PGWebAuthnChallengeStore, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("IAM_N06_DISPOSABLE_PG") != "1" {
		t.Skip("requires isolated PostgreSQL 17 CI")
	}
	cfg,err:=pgxpool.ParseConfig(os.Getenv("IAM_N06_TEST_DATABASE_URL"))
	if err!=nil || cfg.ConnConfig.Database!="n06_ci" ||
		(cfg.ConnConfig.Host!="127.0.0.1" && cfg.ConnConfig.Host!="localhost") {
		t.Fatal("refuse non-disposable WebAuthn challenge database")
	}
	pool,err:=pgxpool.NewWithConfig(context.Background(),cfg)
	if err!=nil {t.Fatal(err)}
	t.Cleanup(pool.Close)
	ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
	defer cancel()
	var version string
	if pool.QueryRow(ctx,"SHOW server_version_num").Scan(&version)!=nil ||
		len(version)!=6 || version[:2]!="17" {
		t.Fatal("N06 WebAuthn requires real PostgreSQL 17")
	}
	if err:=InstallN06WebAuthnSchema(ctx,pool);err!=nil {
		t.Fatal("install independently reviewed N06 challenge DDL",err)
	}
	var key [32]byte
	if _,err:=rand.Read(key[:]);err!=nil {t.Fatal("crypto fixture key unavailable")}
	store,err:=NewPGWebAuthnChallengeStore(ctx,pool,key[:],time.Now)
	if err!=nil {t.Fatal("real PG challenge store initialization",err)}
	return store,pool
}

func TestN06RealPGWebAuthnOneUseAndEncryptedSessionCustody(t *testing.T) {
	store,pool:=n06PGChallengeStore(t)
	f:=makeA3Fixture(t)
	idBytes:=make([]byte,12)
	if _,err:=rand.Read(idBytes);err!=nil {t.Fatal(err)}
	challenge:=f.challenges.item
	challenge.ID="n06-real-"+hex.EncodeToString(idBytes)
	now:=time.Now().UTC()
	challenge.CreatedAt=now.Add(-time.Second)
	challenge.ExpiresAt=now.Add(60*time.Second)
	ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
	defer cancel()
	if err:=store.Create(ctx,challenge);err!=nil {t.Fatal("durable challenge insert",err)}
	if err:=store.Create(ctx,challenge);err==nil {
		t.Fatal("same WebAuthn challenge inserted twice")
	}
	var raw []byte
	if err:=pool.QueryRow(ctx,
		"SELECT ciphertext FROM iam_security.webauthn_challenge WHERE challenge_id=$1",
		challenge.ID).Scan(&raw);err!=nil {t.Fatal("private durable ciphertext missing",err)}
	if bytes.Contains(raw,[]byte(challenge.Session.Subject))||
		bytes.Contains(raw,[]byte(challenge.Session.SessionID)) ||
		bytes.Contains(raw,challenge.Nonce) {
		t.Fatal("stored current issuer/subject/session/challenge was not encrypted")
	}
	const parallel=12
	var wg sync.WaitGroup
	wg.Add(parallel)
	outcomes:=make(chan bool,parallel)
	for i:=0;i<parallel;i++{
		go func(){
			defer wg.Done()
			read,err:=store.Consume(ctx,challenge.ID)
			if err==nil && read.Session==challenge.Session &&
				read.RPID==challenge.RPID && bytes.Equal(read.Nonce,challenge.Nonce) {
				outcomes<-true
			}else{outcomes<-false}
		}()
	}
	wg.Wait()
	close(outcomes)
	success:=0
	for v:=range outcomes{if v{success++}}
	if success!=1 {t.Fatalf("durable same-session nonce replay fence changed: successes=%d",success)}
	if _,err:=store.Consume(ctx,challenge.ID);err==nil {t.Fatal("committed WebAuthn replay accepted")}
}

func TestN06RealPGWebAuthnWrongSecretCannotImpersonate(t *testing.T) {
	store,pool:=n06PGChallengeStore(t)
	f:=makeA3Fixture(t)
	idBytes:=make([]byte,12)
	if _,err:=rand.Read(idBytes);err!=nil {t.Fatal(err)}
	challenge:=f.challenges.item
	challenge.ID="n06-wrong-"+hex.EncodeToString(idBytes)
	now:=time.Now().UTC()
	challenge.CreatedAt=now.Add(-time.Second)
	challenge.ExpiresAt=now.Add(60*time.Second)
	ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
	defer cancel()
	if err:=store.Create(ctx,challenge);err!=nil {t.Fatal(err)}
	alternateKey:=make([]byte,32)
	if _,err:=rand.Read(alternateKey);err!=nil {t.Fatal(err)}
	impostor,err:=NewPGWebAuthnChallengeStore(ctx,pool,alternateKey,time.Now)
	if err!=nil {t.Fatal(err)}
	if _,err:=impostor.Consume(ctx,challenge.ID);err==nil {
		t.Fatal("wrong IAM AES-GCM key decrypted current challenge")
	}
	if read,err:=store.Consume(ctx,challenge.ID);err!=nil ||
		read.Session!=challenge.Session {
		t.Fatal("failed wrong-key read must roll back without consuming real original")
	}
}
