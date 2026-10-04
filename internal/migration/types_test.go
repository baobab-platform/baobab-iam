package migration_test

import (
	"context"
	"strings"
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
		MigrationID:         "mig-1",
		CanonicalIdentityID: "ci_001",
		Source:              migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "sub-1"},
		IdentityClass:       migration.ClassHuman,
		CredentialStrategy:  migration.StrategyFirstLoginMigration,
		MigrationState:      migration.StateDiscovered,
		CreatedAt:           now,
	}
	if err := ok.ValidateStructural(); err != nil {
		t.Fatalf("expected valid record: %v", err)
	}

	missingCI := *ok
	missingCI.CanonicalIdentityID = ""
	if err := missingCI.ValidateStructural(); err == nil {
		t.Fatal("expected error without canonical_identity_id")
	}

	unknownState := *ok
	unknownState.MigrationState = migration.MigrationState("TYPO")
	if err := unknownState.ValidateStructural(); err == nil {
		t.Fatal("expected unknown migration state to be rejected")
	}
}

func TestResolveCanonicalByEmailAloneRejected(t *testing.T) {
	_, err := migration.ResolveCanonicalByEmailAlone("alice@example.com")
	if err == nil {
		t.Fatal("email-only resolution must be rejected")
	}
}

func TestRecordRejectsSensitiveSnapshotReference(t *testing.T) {
	now := time.Now().UTC()
	r := &migration.Record{
		MigrationID:             "mig-sec",
		CanonicalIdentityID:     "ci_001",
		Source:                  migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "sub-1"},
		IdentityClass:           migration.ClassHuman,
		CredentialStrategy:      migration.StrategyFirstLoginMigration,
		MigrationState:          migration.StateDiscovered,
		SourceSnapshotReference: "export://batch?password=super-secret",
		CreatedAt:               now,
	}
	if err := r.ValidateStructural(); err == nil {
		t.Fatal("expected rejection of password marker in snapshot reference")
	}
}

func TestRecordRejectsWhitespaceOnlyFields(t *testing.T) {
	now := time.Now().UTC()
	r := &migration.Record{
		MigrationID:         "   ",
		CanonicalIdentityID: " \t ",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "   ",
			Subject:  "sub-1",
		},
		IdentityClass:      migration.ClassHuman,
		CredentialStrategy: migration.StrategyFirstLoginMigration,
		MigrationState:     migration.StateDiscovered,
		CreatedAt:          now,
	}
	if err := r.ValidateStructural(); err == nil {
		t.Fatal("expected rejection of whitespace-only required fields")
	}
}

func TestRegisterBatchRejectsWhitespaceOnlyBatchID(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	_, err := svc.RegisterBatch(ctx, migration.FixtureDiscovery{Bindings: []migration.SourceBinding{{
		Provider: "keycloak",
		Issuer:   "https://kc.example/realms/baobab",
		Subject:  "sub-1",
	}}}, migration.MapCanonicalResolver{Mapping: map[string]string{
		"https://kc.example/realms/baobab\x00sub-1": "ci_123",
	}}, migration.BatchRegisterRequest{BatchID: " \t "})
	if err == nil {
		t.Fatal("expected whitespace-only BatchID to be rejected")
	}
	if !strings.Contains(err.Error(), "BatchID is required") {
		t.Fatalf("expected required-field error, got %v", err)
	}
}

func TestResolveCanonicalRejectsWhitespaceOnlyFields(t *testing.T) {
	resolver := migration.MapCanonicalResolver{Mapping: map[string]string{
		"https://kc.example/realms/baobab\x00sub-1": "ci_123",
	}}
	_, err := resolver.ResolveCanonical(context.Background(), migration.ProviderBinding{
		Issuer:  " \t ",
		Subject: "sub-1",
	})
	if err == nil {
		t.Fatal("expected whitespace-only issuer to be rejected")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required-field error, got %v", err)
	}
}

func TestNormalizeAllowedScopesTrimsWhitespaceAndAliases(t *testing.T) {
	got := migration.NormalizeAllowedScopes([]string{" context-resolve ", " context:resolve ", "", "  ", "openid"})
	want := []string{"context:resolve", "openid"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

// TestSyntheticPathDiscoveredToVerified exercises the Phase C unit-level
// happy path without network I/O (memory store + service). CUTOVER is not applied.
func TestSyntheticPathDiscoveredToVerified(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}

	r := &migration.Record{
		MigrationID:         "mig-synth-1",
		MigrationBatchID:    "batch-phase-c",
		CanonicalIdentityID: "ci_synth",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "kc-sub-1",
		},
		IdentityClass:      migration.ClassTestOrNonProd,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Advance through pre-cutover states used in greenfield design tests.
	steps := []migration.MigrationState{
		migration.StateValidated,
		migration.StateReady,
		migration.StateProvisioning,
		migration.StateProvisioned,
		migration.StateCredentialPending,
		migration.StateCredentialReady,
		migration.StateVerificationPending,
		migration.StateVerified,
	}
	// Target binding required once provisioned.
	for _, st := range steps {
		if st == migration.StateProvisioned {
			if _, err := svc.SetTargetBinding(ctx, r.MigrationID, migration.ProviderBinding{
				Provider: "ory",
				Issuer:   "http://127.0.0.1:4444",
				Subject:  "kratos-id-1",
			}); err != nil {
				t.Fatalf("SetTargetBinding: %v", err)
			}
		}
		got, err := svc.ApplyTransition(ctx, r.MigrationID, st)
		if err != nil {
			t.Fatalf("transition to %s: %v", st, err)
		}
		if got.MigrationState != st {
			t.Fatalf("state=%s want %s", got.MigrationState, st)
		}
	}
}
