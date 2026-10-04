package migration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func TestBatchMigrationIDPreservesTupleBoundaries(t *testing.T) {
	a := migration.ProviderBinding{Provider: "keycloak", Issuer: "https://issuer/a", Subject: "b:c"}
	b := migration.ProviderBinding{Provider: "keycloak", Issuer: "https://issuer/a:b", Subject: "c"}
	if migration.BatchMigrationID("batch", a) == migration.BatchMigrationID("batch", b) {
		t.Fatal("distinct tuples must not collide")
	}
	b = a
	b.Issuer = "https://issuer/b"
	if migration.BatchMigrationID("batch", a) == migration.BatchMigrationID("batch", b) {
		t.Fatal("same subject under distinct issuers must not collide")
	}
	if migration.BatchMigrationID("batch", a) != migration.BatchMigrationID("batch", a) {
		t.Fatal("migration keys must be deterministic")
	}
}

func TestOrphanCannotAdvanceOrMutateOnRejectedTransition(t *testing.T) {
	r := &migration.Record{
		MigrationID: "orphan", Source: migration.ProviderBinding{Provider: "keycloak", Issuer: "https://issuer", Subject: "subject"},
		IdentityClass: migration.ClassOrphanCandidate, CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState: migration.StateDiscovered,
	}
	if err := r.Transition(migration.StateValidated); err == nil {
		t.Fatal("orphan advanced without authoritative mapping")
	}
	if r.MigrationState != migration.StateDiscovered || r.AttemptCount != 0 {
		t.Fatal("rejected transition changed the record")
	}
	if err := r.Transition(migration.StateBlocked); err != nil {
		t.Fatal(err)
	}
	if err := r.Transition(migration.StateReady); err == nil {
		t.Fatal("blocked orphan re-entered execution")
	}
}

type unavailableStore struct {
	migration.RecordStore
	err error
	writes int
}

func (s *unavailableStore) Get(context.Context, string) (*migration.Record, error) { return nil, s.err }
func (s *unavailableStore) Put(context.Context, *migration.Record) error { s.writes++; return nil }

func TestRegistrationPropagatesStorageFailure(t *testing.T) {
	failure := errors.New("storage unavailable")
	store := &unavailableStore{err: failure}
	svc := &migration.Service{Store: store}
	r := &migration.Record{
		MigrationID: "mapped", CanonicalIdentityID: "ci-1",
		Source: migration.ProviderBinding{Provider: "keycloak", Issuer: "https://issuer", Subject: "subject"},
		IdentityClass: migration.ClassHuman, CredentialStrategy: migration.StrategyFirstLoginMigration,
		MigrationState: migration.StateDiscovered,
	}
	if err := svc.Register(context.Background(), r); !errors.Is(err, failure) {
		t.Fatalf("storage failure lost: %v", err)
	}
	_, err := svc.RegisterBatch(context.Background(), migration.FixtureDiscovery{Bindings: []migration.SourceBinding{
		{Provider: "keycloak", Issuer: "https://issuer", Subject: "subject"},
	}}, migration.MapCanonicalResolver{}, migration.BatchRegisterRequest{BatchID: "batch"})
	if !errors.Is(err, failure) || store.writes != 0 {
		t.Fatalf("batch must fail without writing: err=%v writes=%d", err, store.writes)
	}
}
