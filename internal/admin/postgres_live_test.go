package admin

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresEmergencyLeaseTransitionsReal(t *testing.T) {
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
	migration, err := os.ReadFile("migrations/001_breakglass_lease.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	journal := PostgresLeaseJournal{Pool: pool}
	at := time.Now().UTC().Truncate(time.Microsecond)
	lease := Lease{
		Request: Request{
			LeaseID:    "9e1038e8-53e9-4c34-a48b-5808c24cfa7a",
			IncidentID: "387c2e18-ce10-47b8-a15a-e9845e364e49",
			Action:     "SUSPEND_FEDERATION",
			ScopeType:  "FEDERATION",
			ScopeID:    "a7aef8d3-2c86-4b52-857c-1737359605bd",
			Reason:     "INCIDENT_CONTAINMENT",
		},
		Witness: Witness{
			ActorID:              "25e70762-3a8c-4703-aee8-232d1ccf72b6",
			ApproverID:           "d72bb278-8024-48d2-a985-bd6624b78ccc",
			ApprovedAt:           at,
			ExpiresAt:            at.Add(10 * time.Minute),
			IndependentAuthRef:   "disposable-auth-receipt",
			IndependentReviewRef: "disposable-security-receipt",
		},
		Status: StatePending,
	}
	_, _ = pool.Exec(ctx, `DELETE FROM iam_admin.breakglass_lease WHERE lease_id=$1`, lease.Request.LeaseID)
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = pool.Exec(c, `DELETE FROM iam_admin.breakglass_lease WHERE lease_id=$1`, lease.Request.LeaseID)
	})
	if err := journal.Reserve(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.Reserve(ctx, lease); err != nil {
		t.Fatalf("exact pending lease replay must be consistent: %v", err)
	}
	changed := lease
	changed.Request.ScopeID = "2485d600-099c-4f07-9594-6e8d9c935bfe"
	if err := journal.Reserve(ctx, changed); err == nil {
		t.Fatal("scope substitution accepted")
	}
	if err := journal.Activate(ctx, lease.Request.LeaseID); err != nil {
		t.Fatal(err)
	}
	active, err := journal.Read(ctx, lease.Request.LeaseID)
	if err != nil || active.Status != StateActive || active.Request != lease.Request {
		t.Fatalf("current lease status=%v err=%v", active.Status, err)
	}
	if err := journal.Activate(ctx, lease.Request.LeaseID); err == nil {
		t.Fatal("previous activation replayed")
	}
	if err := journal.Terminate(ctx, lease.Request.LeaseID); err != nil {
		t.Fatal(err)
	}
	final, err := journal.Read(ctx, lease.Request.LeaseID)
	if err != nil || final.Status != StateTerminated {
		t.Fatalf("terminated lease was not durable status=%v err=%v", final.Status, err)
	}
	if err := journal.Activate(ctx, lease.Request.LeaseID); err == nil {
		t.Fatal("terminated emergency authority resurrected")
	}
}
