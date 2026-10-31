package nativebff

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/humanauth"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSealedRecordNoPlaintextAndWrongAADDenied(t *testing.T) {
	ctx := context.Background()
	_ = ctx
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	// The cipher is usable before DB migration, but Store needs a live pool.
	s, err := NewPostgresStore(&pgxpool.Pool{}, key)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("x", 43)
	record := Transaction{
		Intent: humanauth.Request{GrantType: "authorization_code", ClientID: "synthetic-bff",
			RedirectURI: "https://estate.invalid/auth/callback", CodeChallenge: strings.Repeat("v", 43),
			CodeChallengeMethod: "S256", Scope: "openid", State: strings.Repeat("s", 32), Nonce: strings.Repeat("n", 32)},
		Verifier: strings.Repeat("secret-verifier-", 4), CSRF: strings.Repeat("c", 43),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	sealed, err := s.seal("txn", id, record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(record.Verifier)) {
		t.Fatal("plaintext stored in ciphertext")
	}
	var out Transaction
	if s.open("txn", id, sealed, &out) != nil || out.Verifier != record.Verifier {
		t.Fatal("cannot decrypt exact AAD")
	}
	if s.open("txn", strings.Repeat("y", 43), sealed, &out) == nil {
		t.Fatal("wrong row identity accepted")
	}
	if s.open("sess", id, sealed, &out) == nil {
		t.Fatal("cross-kind ciphertext accepted")
	}
}
func TestPostgresNativeBrowserAtomicConsumption(t *testing.T) {
	dsn := os.Getenv("TEST_NATIVE_BFF_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL 17 test environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sql, err := os.ReadFile("migrations/001_native_browser_bff.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(sql), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err = pool.Exec(ctx, statement); err != nil {
			t.Fatalf("migration: %v", err)
		}
	}
	// Migration 002 drains old unindexed sessions and atomically enables
	// deployment-wide HMAC lookup; it is idempotent on repeated startup.
	indexMigration,err:=os.ReadFile("migrations/002_subject_session_revocation.sql")
	if err!=nil{t.Fatal(err)}
	for _,statement:=range strings.Split(string(indexMigration),";"){
		if strings.TrimSpace(statement)==""{continue}
		if _,err=pool.Exec(ctx,statement);err!=nil{t.Fatalf("global logout migration: %v",err)}
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := NewPostgresStore(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPostgresStore(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomValue()
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("private-verifier-", 4)
	tx := Transaction{
		Intent: humanauth.Request{GrantType: "authorization_code", ClientID: "synthetic-bff", RedirectURI: "https://estate.invalid/auth/callback",
			CodeChallenge: strings.Repeat("v", 43), CodeChallengeMethod: "S256", Scope: "openid", State: strings.Repeat("s", 32), Nonce: strings.Repeat("n", 32)},
		Verifier: verifier, CSRF: strings.Repeat("c", 43), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err = a.PutTransaction(ctx, id, tx); err != nil {
		t.Fatal(err)
	}
	h, _ := hashID(id)
	var ciphertext []byte
	if err = pool.QueryRow(ctx, "SELECT sealed FROM native_bff_transactions WHERE id_hash=$1", h).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(verifier)) {
		t.Fatal("DB leaked verifier")
	}
	var wg sync.WaitGroup
	wins := make(chan bool, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := a
			if i%2 == 1 {
				v = b
			}
			_, e := v.TakeTransaction(ctx, id)
			wins <- e == nil
		}(i)
	}
	wg.Wait()
	close(wins)
	n := 0
	for success := range wins {
		if success {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("cross-replica one-time code accepted %d times", n)
	}
	sid, err := randomValue()
	if err != nil {
		t.Fatal(err)
	}
	sess := Session{Subject: "synthetic-subject", Issuer: "https://issuer.invalid", PrincipalID: "11111111-1111-4111-8111-111111111111", CSRF: strings.Repeat("c", 43),
		ExpiresAt: time.Now().Add(time.Minute), Tokens: humanauth.Response{AccessToken: strings.Repeat("a", 40), TokenType: "Bearer", ExpiresIn: 120, IDToken: strings.Repeat("i", 40)}}
	if err = a.PutSession(ctx, sid, sess); err != nil {
		t.Fatal(err)
	}
	read, err := b.ReadSession(ctx, sid)
	if err != nil || read.Subject != sess.Subject {
		t.Fatalf("cross-replica encrypted read: %v", err)
	}
	if err = b.DeleteSession(ctx, sid); err != nil {
		t.Fatal(err)
	}
	if _, err = a.ReadSession(ctx, sid); err == nil {
		t.Fatal("session restored after revoke")
	}
	if err = a.PutSession(ctx, sid, sess); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	if _, err = rand.Read(other); err != nil {
		t.Fatal(err)
	}
	c, err := NewPostgresStore(pool, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ReadSession(ctx, sid); err == nil {
		t.Fatal("wrong encryption key admitted session")
	}
	if err = a.DeleteSession(ctx, sid); err != nil {
		t.Fatal(err)
	}
	first,err:=randomValue();if err!=nil{t.Fatal(err)}
	second,err:=randomValue();if err!=nil{t.Fatal(err)}
	otherID,err:=randomValue();if err!=nil{t.Fatal(err)}
	if err=a.PutSession(ctx,first,sess);err!=nil{t.Fatal(err)}
	if err=b.PutSession(ctx,second,sess);err!=nil{t.Fatal(err)}
	otherSession:=sess
	otherSession.Subject="unrelated-other-tenant-subject"
	if err=b.PutSession(ctx,otherID,otherSession);err!=nil{t.Fatal(err)}
	if err=a.DeleteHumanSessions(ctx,sess.Issuer,sess.Subject);err!=nil{t.Fatal(err)}
	for _,id:=range []string{first,second}{
		if _,err=b.ReadSession(ctx,id);err==nil{t.Fatal("global logout left another BFF session active")}
	}
	if _,err=b.ReadSession(ctx,otherID);err!=nil{t.Fatal("global logout erased unrelated identity")}
	if err=b.DeleteSession(ctx,otherID);err!=nil{t.Fatal(err)}
}
