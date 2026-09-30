package migration_test

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/migration"
)

// TestPhaseCPolicyDeniesCutover ensures production cutover is blocked by default
// even when the state machine edge CUTOVER_READY → CUTOVER is legal.
func TestPhaseCPolicyDeniesCutover(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	// AllowAll only to reach CUTOVER_READY; then swap to default Phase C policy.
	svc := &migration.Service{Store: store, Policy: migration.AllowAllPolicyGate{}}

	r := &migration.Record{
		MigrationID:         "mig-cutover-deny",
		CanonicalIdentityID: "ci_1",
		Source:              migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/b", Subject: "s1"},
		Target:              migration.ProviderBinding{Provider: "ory", Issuer: "http://127.0.0.1:4444", Subject: "t1"},
		IdentityClass:       migration.ClassTestOrNonProd,
		CredentialStrategy:  migration.StrategyNoCredentialRequired,
		MigrationState:      migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	steps := []migration.MigrationState{
		migration.StateValidated, migration.StateReady, migration.StateProvisioning,
		migration.StateProvisioned, migration.StateCredentialReady,
		migration.StateVerificationPending, migration.StateVerified, migration.StateCutoverReady,
	}
	// Skip credential pending (allowed from PROVISIONED).
	for _, st := range steps {
		if _, err := svc.ApplyTransition(ctx, r.MigrationID, st); err != nil {
			t.Fatalf("to %s: %v", st, err)
		}
	}

	// Now use default Phase C policy (nil → PhaseCPolicyGate).
	svc.Policy = nil
	if _, err := svc.ApplyTransition(ctx, r.MigrationID, migration.StateCutover); err == nil {
		t.Fatal("expected Phase C policy to deny CUTOVER")
	}
}

// TestRegisterBatch_MapsAndOrphans exercises DiscoveryPort + CanonicalResolver
// without network I/O.
func TestRegisterBatch_MapsAndOrphans(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}

	discovery := migration.FixtureDiscovery{
		Bindings: []migration.SourceBinding{
			{
				Provider:       "keycloak",
				Issuer:         "https://kc.example/realms/baobab",
				Subject:        "mapped-user-1",
				SuggestedClass: migration.ClassHuman,
			},
			{
				Provider: "keycloak",
				Issuer:   "https://kc.example/realms/baobab",
				Subject:  "orphan-user-9",
			},
		},
	}
	resolver := migration.MapCanonicalResolver{
		Mapping: map[string]string{
			"https://kc.example/realms/baobab\x00mapped-user-1": "ci_mapped_1",
		},
	}

	res, err := svc.RegisterBatch(ctx, discovery, resolver, migration.BatchRegisterRequest{
		BatchID:         "batch-phase-c-1",
		DefaultStrategy: migration.StrategyFirstLoginMigration,
		DefaultClass:    migration.ClassHuman,
	})
	if err != nil {
		t.Fatalf("RegisterBatch: %v", err)
	}
	if res.Registered != 2 {
		t.Fatalf("Registered=%d want 2", res.Registered)
	}
	if res.Orphans != 1 {
		t.Fatalf("Orphans=%d want 1", res.Orphans)
	}

	// Mapped row
	mappedID := "batch-phase-c-1:keycloak:mapped-user-1"
	mapped, err := store.Get(ctx, mappedID)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.CanonicalIdentityID != "ci_mapped_1" {
		t.Fatalf("canonical=%q", mapped.CanonicalIdentityID)
	}
	if mapped.IdentityClass != migration.ClassHuman {
		t.Fatalf("class=%s", mapped.IdentityClass)
	}
	if mapped.MigrationState != migration.StateDiscovered {
		t.Fatalf("state=%s", mapped.MigrationState)
	}

	// Orphan row
	orphanID := "batch-phase-c-1:keycloak:orphan-user-9"
	orphan, err := store.Get(ctx, orphanID)
	if err != nil {
		t.Fatal(err)
	}
	if orphan.CanonicalIdentityID != "orphan:pending-review" {
		t.Fatalf("orphan canonical=%q", orphan.CanonicalIdentityID)
	}
	if orphan.IdentityClass != migration.ClassOrphanCandidate {
		t.Fatalf("orphan class=%s", orphan.IdentityClass)
	}

	// Idempotent second run
	res2, err := svc.RegisterBatch(ctx, discovery, resolver, migration.BatchRegisterRequest{
		BatchID: "batch-phase-c-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.SkippedExists != 2 || res2.Registered != 0 {
		t.Fatalf("second run: %+v", res2)
	}
}

// TestFixtureDiscoveryRequiresBatchID guards the discovery contract.
func TestFixtureDiscoveryRequiresBatchID(t *testing.T) {
	d := migration.FixtureDiscovery{}
	if _, err := d.ListSourceBindings(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty batchID")
	}
}
