package migration_test

import (
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

func TestIdentityClassValid(t *testing.T) {
	if !migration.ClassHuman.Valid() {
		t.Fatal("HUMAN should be valid")
	}
	if migration.IdentityClass("not-a-class").Valid() {
		t.Fatal("unknown class must be invalid")
	}
}

func TestRecordValidateStructural(t *testing.T) {
	now := time.Now().UTC()
	ok := &migration.Record{
		MigrationID:          "mig-1",
		CanonicalIdentityID:  "ci_001",
		Source:               migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "sub-1"},
		IdentityClass:        migration.ClassHuman,
		CredentialStrategy:   migration.StrategyFirstLoginMigration,
		MigrationState:       migration.StateDiscovered,
		CreatedAt:            now,
	}
	if err := ok.ValidateStructural(); err != nil {
		t.Fatalf("expected valid record: %v", err)
	}

	missingCI := *ok
	missingCI.CanonicalIdentityID = ""
	if err := missingCI.ValidateStructural(); err == nil {
		t.Fatal("expected error without canonical_identity_id")
	}
}

func TestResolveCanonicalByEmailAloneRejected(t *testing.T) {
	_, err := migration.ResolveCanonicalByEmailAlone("alice@example.com")
	if err == nil {
		t.Fatal("email-only resolution must be rejected")
	}
}
