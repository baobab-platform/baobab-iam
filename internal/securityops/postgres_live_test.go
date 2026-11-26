package securityops

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresIncidentJournalReal(t *testing.T) {
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
	migration, err := os.ReadFile("migrations/001_incident_containment.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	journal := PostgresJournal{Pool: pool}
	intent := Intent{
		OperationID: "incident-pg-test-0001",
		IncidentID:  "incident-pg-case-0001",
		Subject:     provider.ExternalSubject{Issuer: "https://iam.example.test", Subject: "disposable-human-01"},
	}
	_, _ = pool.Exec(ctx, "DELETE FROM iam_security.incident_containment WHERE operation_id=$1", intent.OperationID)
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = pool.Exec(c, "DELETE FROM iam_security.incident_containment WHERE operation_id=$1", intent.OperationID)
	})
	phase, err := journal.Reserve(ctx, intent)
	if err != nil || phase != PhaseFenced {
		t.Fatalf("durable reservation phase=%v err=%v", phase, err)
	}
	if _, err := journal.Reserve(ctx, Intent{
		OperationID: intent.OperationID,
		IncidentID:  intent.IncidentID,
		Subject:     provider.ExternalSubject{Issuer: intent.Subject.Issuer, Subject: "substituted"},
	}); err == nil {
		t.Fatal("idempotent replay accepted a different identity")
	}
	if err := journal.Mark(ctx, intent.OperationID, PhaseVerified); err == nil {
		t.Fatal("journal skipped native/readback phases")
	}
	for _, step := range []Phase{PhaseDisabled, PhaseRevoked, PhaseVerified} {
		if err := journal.Mark(ctx, intent.OperationID, step); err != nil {
			t.Fatalf("phase %v: %v", step, err)
		}
	}
	if err := journal.Mark(ctx, intent.OperationID, PhaseDisabled); err == nil {
		t.Fatal("verified incident silently rolled back to DISABLED")
	}
	if err := journal.Mark(ctx, intent.OperationID, PhaseVerified); err != nil {
		t.Fatalf("verified receipt replay should be idempotent: %v", err)
	}
	if err := journal.Mark(ctx, intent.OperationID, PhaseUnknown); err != nil {
		t.Fatalf("current-state drift must be markable UNKNOWN: %v", err)
	}
	phase, err = journal.Reserve(ctx, intent)
	if err != nil || phase != PhaseUnknown {
		t.Fatalf("current incident drift lost after replay phase=%v err=%v", phase, err)
	}
}
