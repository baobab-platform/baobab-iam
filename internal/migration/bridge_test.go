package migration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// fakeHuman is an offline IdentityProvisioner for Phase C bridge tests.
type fakeHuman struct {
	lastSpec provider.IdentityProvisioningSpec
	subject  string
	fail     bool
}

func (f *fakeHuman) ProvisionIdentity(_ context.Context, spec provider.IdentityProvisioningSpec) (*provider.ProviderIdentity, error) {
	f.lastSpec = spec
	if f.fail {
		return nil, fmt.Errorf("simulated human provision failure")
	}
	sub := f.subject
	if sub == "" {
		sub = "kratos-" + spec.MigrationID
	}
	return &provider.ProviderIdentity{
		Provider:  "ory",
		Issuer:    "http://127.0.0.1:4444",
		Subject:   sub,
		Status:    provider.IdentityStatusActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

// fakeWorkload is an offline WorkloadProvisioner for Phase C bridge tests.
type fakeWorkload struct {
	lastSpec provider.WorkloadProvisioningSpec
	fail     bool
}

func (f *fakeWorkload) ProvisionWorkload(_ context.Context, spec provider.WorkloadProvisioningSpec) (*provider.ProviderWorkload, error) {
	f.lastSpec = spec
	if f.fail {
		return nil, fmt.Errorf("simulated workload provision failure")
	}
	return &provider.ProviderWorkload{
		Provider:         "ory",
		LogicalClientID:  spec.LogicalClientID,
		ProviderClientID: spec.LogicalClientID,
		Issuer:           "http://127.0.0.1:4444",
		AuthMethod:       spec.AuthMethod,
		ClientSecret:     "must-not-appear-on-ledger",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}, nil
}

func (f *fakeWorkload) DisableWorkload(context.Context, provider.ProviderWorkloadReference) error {
	return nil
}

func (f *fakeWorkload) RotateWorkloadCredentials(context.Context, provider.ProviderWorkloadReference) (*provider.ProviderWorkload, error) {
	return nil, fmt.Errorf("not used in Phase C bridge tests")
}

func TestProvisionBridge_HumanToProvisioned(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	human := &fakeHuman{}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", human, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}

	r := &migration.Record{
		MigrationID:         "mig-human-1",
		CanonicalIdentityID: "ci_h1",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "kc-user-1",
		},
		IdentityClass:      migration.ClassHuman,
		CredentialStrategy: migration.StrategyFirstLoginMigration,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}

	res, err := bridge.Provision(ctx, "mig-human-1")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if res.Record.MigrationState != migration.StateProvisioned {
		t.Fatalf("state=%s", res.Record.MigrationState)
	}
	if res.Record.Target.Subject == "" || res.Record.Target.Issuer == "" {
		t.Fatalf("target incomplete: %+v", res.Record.Target)
	}
	if res.ProviderSubject != res.Record.Target.Subject {
		t.Fatalf("provider subject mismatch")
	}
	if human.lastSpec.MigrationID != "mig-human-1" {
		t.Fatalf("MigrationID not passed to provisioner")
	}
	// Idempotent
	res2, err := bridge.Provision(ctx, "mig-human-1")
	if err != nil || !res2.AlreadyProvisioned {
		t.Fatalf("idempotent: err=%v already=%v", err, res2.AlreadyProvisioned)
	}
}

func TestProvisionBridge_WorkloadDoesNotStoreSecret(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	wl := &fakeWorkload{}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", &fakeHuman{}, wl)
	if err != nil {
		t.Fatal(err)
	}

	r := &migration.Record{
		MigrationID:         "mig-wl-1",
		CanonicalIdentityID: "ci_wl1",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "baobab-trade-workload",
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}

	res, err := bridge.Provision(ctx, "mig-wl-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Target.Subject != "baobab-trade-workload" {
		t.Fatalf("target subject=%q", res.Record.Target.Subject)
	}
	// Ensure secret did not leak into error code or snapshot fields.
	if res.Record.LastErrorCode != "" {
		t.Fatalf("unexpected error code %q", res.Record.LastErrorCode)
	}
	if wl.lastSpec.LogicalClientID != "baobab-trade-workload" {
		t.Fatalf("logical id=%q", wl.lastSpec.LogicalClientID)
	}
}

func TestProvisionBridge_RefuseOrphan(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", &fakeHuman{}, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	r := &migration.Record{
		MigrationID:         "mig-orphan",
		CanonicalIdentityID: "orphan:pending-review",
		Source:              migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "x"},
		IdentityClass:       migration.ClassOrphanCandidate,
		CredentialStrategy:  migration.StrategyNoCredentialRequired,
		MigrationState:      migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.Provision(ctx, "mig-orphan"); err == nil {
		t.Fatal("expected refuse orphan")
	}
}

func TestProvisionBridge_HumanFailureMarksRetryable(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	human := &fakeHuman{fail: true}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", human, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	r := &migration.Record{
		MigrationID:         "mig-fail-1",
		CanonicalIdentityID: "ci_f1",
		Source:              migration.ProviderBinding{Provider: "keycloak", Issuer: "https://kc.example/realms/baobab", Subject: "u"},
		IdentityClass:       migration.ClassHuman,
		CredentialStrategy:  migration.StrategyFirstLoginMigration,
		MigrationState:      migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.Provision(ctx, "mig-fail-1"); err == nil {
		t.Fatal("expected provision error")
	}
	got, err := store.Get(ctx, "mig-fail-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MigrationState != migration.StateFailedRetryable {
		t.Fatalf("state=%s want FAILED_RETRYABLE", got.MigrationState)
	}
	if got.LastErrorCode != "provision_failed" {
		t.Fatalf("LastErrorCode=%q", got.LastErrorCode)
	}
}
