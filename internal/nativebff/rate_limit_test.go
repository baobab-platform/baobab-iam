package nativebff

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAdmissionRequiresPrivatePostgresAndKey(t *testing.T) {
	if _, err := NewPostgresAdmissionLimiter(nil, make([]byte, 32)); err == nil {
		t.Fatal("nil admission PostgreSQL accepted")
	}
	if _, err := NewPostgresAdmissionLimiter(&pgxpool.Pool{}, make([]byte, 12)); err == nil {
		t.Fatal("short admission HMAC key accepted")
	}
}

func TestPostgresAdmissionAtomicAcrossReplicas(t *testing.T) {
	dsn := os.Getenv("TEST_NATIVE_BFF_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires actual PostgreSQL 17 test environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	migration, err := os.ReadFile("migrations/001_native_browser_bff.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(migration), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("native browser migration: %v", err)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	a, err := NewPostgresAdmissionLimiter(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPostgresAdmissionLimiter(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		limiter := a
		if i%2 == 1 {
			limiter = b
		}
		if err := limiter.Admit(ctx, "POST /auth/start", "192.0.2.1:1234"); err != nil {
			t.Fatalf("allowed admission %d failed: %v", i, err)
		}
	}
	if err := b.Admit(ctx, "POST /auth/start", "192.0.2.1:5678"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-replica same-peer ceiling bypassed: %v", err)
	}
	if err := b.Admit(ctx, "POST /auth/start", "192.0.2.2:1234"); err != nil {
		t.Fatalf("distinct TCP peer incorrectly denied: %v", err)
	}
	if err := a.Admit(ctx, "GET /auth/session", "192.0.2.1:1234"); err != nil {
		t.Fatalf("independent authentication operation incorrectly denied: %v", err)
	}
	if err := a.Admit(ctx, "POST /auth/start", "forged-X-Forwarded-For"); err == nil {
		t.Fatal("untrusted forwarded source spoof admitted")
	}
	if err := a.Admit(ctx, "POST /unreviewed", "192.0.2.1:1234"); err == nil {
		t.Fatal("unreviewed authentication operation admitted")
	}
}
