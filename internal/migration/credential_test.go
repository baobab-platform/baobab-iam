package migration_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func provisionedRecord(id string, strategy migration.CredentialStrategy, class migration.IdentityClass) *migration.Record {
	return &migration.Record{
		MigrationID:         id,
		CanonicalIdentityID: "ci_" + id,
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "src-" + id,
		},
		Target: migration.ProviderBinding{
			Provider: "ory",
			Issuer:   "http://127.0.0.1:4444",
			Subject:  "tgt-" + id,
		},
		IdentityClass:      class,
		CredentialStrategy: strategy,
		MigrationState:     migration.StateProvisioned,
	}
}

func TestCredentialStage_NoCredentialRequired(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, err := migration.NewCredentialStage(svc)
	if err != nil {
		t.Fatal(err)
	}
	r := provisionedRecord("cred-wl", migration.StrategyNoCredentialRequired, migration.ClassWorkload)
	_ = store.Put(ctx, r)

	res, err := stage.Apply(ctx, "cred-wl")
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.MigrationState != migration.StateCredentialReady {
		t.Fatalf("state=%s", res.Record.MigrationState)
	}
	if res.Outcome != "no_credential_required" {
		t.Fatalf("outcome=%s", res.Outcome)
	}
}

func TestCredentialStage_FirstLoginStaysPending(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, _ := migration.NewCredentialStage(svc)
	r := provisionedRecord("cred-human", migration.StrategyFirstLoginMigration, migration.ClassHuman)
	_ = store.Put(ctx, r)

	res, err := stage.Apply(ctx, "cred-human")
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.MigrationState != migration.StateCredentialPending {
		t.Fatalf("state=%s want CREDENTIAL_PENDING", res.Record.MigrationState)
	}
	res2, err := stage.MarkReady(ctx, "cred-human")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Record.MigrationState != migration.StateCredentialReady {
		t.Fatalf("state=%s", res2.Record.MigrationState)
	}
}

func TestCredentialStage_DirectImportPendingNoSecrets(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, _ := migration.NewCredentialStage(svc)
	r := provisionedRecord("cred-import", migration.StrategyDirectImport, migration.ClassHuman)
	_ = store.Put(ctx, r)

	res, err := stage.Apply(ctx, "cred-import")
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.MigrationState != migration.StateCredentialPending {
		t.Fatalf("state=%s", res.Record.MigrationState)
	}
	if err := migration.RejectCredentialMaterial(ctx, "cred-import", "password_hash"); err == nil {
		t.Fatal("expected reject")
	}
}

func TestCredentialStage_WrongState(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	stage, _ := migration.NewCredentialStage(svc)
	r := provisionedRecord("cred-early", migration.StrategyNoCredentialRequired, migration.ClassWorkload)
	r.MigrationState = migration.StateDiscovered
	_ = store.Put(ctx, r)
	if _, err := stage.Apply(ctx, "cred-early"); err == nil {
		t.Fatal("expected error from DISCOVERED")
	}
}
