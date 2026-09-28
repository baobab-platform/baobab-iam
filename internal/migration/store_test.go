package migration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func sampleRecord(id string) *migration.Record {
	return &migration.Record{
		MigrationID:         id,
		CanonicalIdentityID: "ci_" + id,
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "sub-" + id,
		},
		IdentityClass:      migration.ClassHuman,
		CredentialStrategy: migration.StrategyFirstLoginMigration,
		MigrationState:     migration.StateDiscovered,
		CreatedAt:          time.Now().UTC(),
	}
}

func TestMemoryStorePutGet(t *testing.T) {
	ctx := context.Background()
	s := migration.NewMemoryStore()
	r := sampleRecord("m1")
	if err := s.Put(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CanonicalIdentityID != r.CanonicalIdentityID {
		t.Fatalf("got %+v", got)
	}
	// Mutating returned copy must not affect store.
	got.CanonicalIdentityID = "tampered"
	again, _ := s.Get(ctx, "m1")
	if again.CanonicalIdentityID == "tampered" {
		t.Fatal("store leaked mutable reference")
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	_, err := migration.NewMemoryStore().Get(context.Background(), "missing")
	if !errors.Is(err, migration.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestMemoryStoreListByState(t *testing.T) {
	ctx := context.Background()
	s := migration.NewMemoryStore()
	_ = s.Put(ctx, sampleRecord("a"))
	b := sampleRecord("b")
	b.MigrationState = migration.StateReady
	_ = s.Put(ctx, b)
	ready, err := s.ListByState(ctx, migration.StateReady)
	if err != nil || len(ready) != 1 || ready[0].MigrationID != "b" {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
}
