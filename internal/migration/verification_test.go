package migration_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func TestVerificationStage_ProgressesToVerified(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, err := migration.NewVerificationStage(svc)
	if err != nil {
		t.Fatal(err)
	}

	r := provisionedRecord("verify-flow", migration.StrategyNoCredentialRequired, migration.ClassWorkload)
	r.MigrationState = migration.StateCredentialReady
	if err := store.Put(ctx, r); err != nil {
		t.Fatal(err)
	}

	res, err := stage.Apply(ctx, "verify-flow")
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.MigrationState != migration.StateVerificationPending {
		t.Fatalf("state=%s want VERIFICATION_PENDING", res.Record.MigrationState)
	}

	res2, err := stage.MarkVerified(ctx, "verify-flow")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Record.MigrationState != migration.StateVerified {
		t.Fatalf("state=%s want VERIFIED", res2.Record.MigrationState)
	}
}

func TestVerificationStage_RejectsWrongState(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, _ := migration.NewVerificationStage(svc)

	r := provisionedRecord("verify-early", migration.StrategyNoCredentialRequired, migration.ClassWorkload)
	r.MigrationState = migration.StateProvisioned
	if err := store.Put(ctx, r); err != nil {
		t.Fatal(err)
	}

	if _, err := stage.Apply(ctx, "verify-early"); err == nil {
		t.Fatal("expected error from PROVISIONED state")
	}
}
