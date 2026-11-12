package privacy

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresRestrictionTombstoneReal(t *testing.T) {
	if os.Getenv("IAM_N05_DISPOSABLE_PG") != "1" {
		t.Skip("requires exclusively disposable PostgreSQL 17 fixture")
	}
	dsn := os.Getenv("IAM_N05_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("disposable PG DSN missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migration, err := os.ReadFile("migrations/001_restriction_tombstone.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	repo := PostgresRepository{Pool: pool}
	record := Restriction{
		Subject:    provider.ExternalSubject{Issuer: "https://iam.example.test", Subject: "disposable-erasure-test-01"},
		DecisionID: "privacy-decision-test-0001",
	}
	_, _ = pool.Exec(ctx, `DELETE FROM iam_privacy.restriction_tombstone
WHERE issuer=$1 AND subject=$2`, record.Subject.Issuer, record.Subject.Subject)
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = pool.Exec(c, `DELETE FROM iam_privacy.restriction_tombstone
WHERE issuer=$1 AND subject=$2`, record.Subject.Issuer, record.Subject.Subject)
	})
	if restricted, err := repo.IsRestricted(ctx, record.Subject); err != nil || restricted {
		t.Fatalf("precondition restricted=%v err=%v", restricted, err)
	}
	if err := repo.PutRestricted(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutRestricted(ctx, record); err != nil {
		t.Fatalf("exact idempotent restriction should succeed: %v", err)
	}
	if restricted, err := repo.IsRestricted(ctx, record.Subject); err != nil || !restricted {
		t.Fatalf("restriction not durable restricted=%v err=%v", restricted, err)
	}
	changed := record
	changed.DecisionID = "privacy-decision-test-0002"
	if !errors.Is(repo.PutRestricted(ctx, changed), ErrPrivacyHold) {
		t.Fatal("new decision silently overwrote restrictive tombstone")
	}
	subjects, err := repo.ListRestricted(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range subjects {
		if item == record.Subject {
			found = true
		}
	}
	if !found {
		t.Fatal("restricted identity missing from recovery replay snapshot")
	}
}
