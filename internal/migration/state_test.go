package migration_test

import (
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func TestHappyPathTransitions(t *testing.T) {
	path := []migration.MigrationState{
		migration.StateDiscovered,
		migration.StateValidated,
		migration.StateReady,
		migration.StateProvisioning,
		migration.StateProvisioned,
		migration.StateCredentialPending,
		migration.StateCredentialReady,
		migration.StateVerificationPending,
		migration.StateVerified,
		migration.StateCutoverReady,
		migration.StateCutover,
		migration.StateLegacyRetired,
	}
	for i := 0; i < len(path)-1; i++ {
		if !migration.CanTransition(path[i], path[i+1]) {
			t.Fatalf("expected %s → %s", path[i], path[i+1])
		}
	}
}

func TestIllegalTransition(t *testing.T) {
	if migration.CanTransition(migration.StateDiscovered, migration.StateCutover) {
		t.Fatal("DISCOVERED → CUTOVER must be illegal")
	}
}

func TestRecordTransition(t *testing.T) {
	r := &migration.Record{
		MigrationID:         "mig-2",
		CanonicalIdentityID: "ci_002",
		Source: migration.ProviderBinding{
			Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "s2",
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateReady,
		CreatedAt:          time.Now().UTC(),
	}
	if err := r.Transition(migration.StateProvisioning); err != nil {
		t.Fatal(err)
	}
	if r.AttemptCount != 1 {
		t.Fatalf("AttemptCount: got %d want 1", r.AttemptCount)
	}
	// Still no target — structural check should fail once past early states.
	r.MigrationState = migration.StateProvisioned
	if err := r.ValidateStructural(); err == nil {
		t.Fatal("expected target required in PROVISIONED")
	}
	r.Target = migration.ProviderBinding{Provider: "ory", Issuer: "http://127.0.0.1:4444", Subject: "baobab-trade-workload"}
	if err := r.ValidateStructural(); err != nil {
		t.Fatal(err)
	}
}
