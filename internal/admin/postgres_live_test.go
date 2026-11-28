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

func TestPostgresWorkloadExecutionOnlyOneReservation(t *testing.T) {
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
	defer pool.Close()
	for _, name := range []string{"001_breakglass_lease.sql", "002_breakglass_workload_execution.sql"} {
		migration, err := os.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(migration), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, _, verifier, _, _, request := setup(now)
	request.Action, request.ScopeType = revokeOAuthClient, "OAUTH_CLIENT"
	request.LeaseID = "8dcdd517-0b86-49b4-82f3-bdb136829351"
	journal := PostgresLeaseJournal{Pool: pool}
	clear := func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := pool.Exec(cleanup, "DELETE FROM iam_admin.breakglass_workload_execution WHERE lease_id=$1", request.LeaseID); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(cleanup, "DELETE FROM iam_admin.breakglass_lease WHERE lease_id=$1", request.LeaseID); err != nil {
			t.Error(err)
		}
	}
	clear()
	defer clear()
	if err := journal.Reserve(ctx, Lease{Request: request, Witness: verifier.proof, Status: StatePending}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Activate(ctx, request.LeaseID); err != nil {
		t.Fatal(err)
	}
	target := WorkloadTarget{ScopeID: request.ScopeID, Revision: 3, ValidUntil: now.Add(time.Minute)}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- journal.ReserveWorkloadExecution(ctx, request, target) }()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("expected exactly one reservation, got %v and %v", first, second)
	}
	proof := WorkloadDenial{Target: target, ObservedAt: time.Now().UTC(), Reference: "ref_native_denial"}
	proof.Target.Revision++
	if err := journal.VerifyWorkloadExecution(ctx, request, proof); err == nil {
		t.Fatal("different target revision accepted")
	}
	proof.Target = target
	if err := journal.VerifyWorkloadExecution(ctx, request, proof); err != nil {
		t.Fatal(err)
	}
	if err := journal.VerifyWorkloadExecution(ctx, request, proof); err == nil {
		t.Fatal("verified receipt replay accepted")
	}
}
