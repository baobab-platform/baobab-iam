package migration_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

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

type fakeFederated struct {
	lastSpec provider.FederatedWorkloadTrustSpec
	fail     bool
}

func (f *fakeFederated) ProvisionFederatedWorkload(_ context.Context, spec provider.FederatedWorkloadTrustSpec) (*provider.FederatedWorkloadTrust, error) {
	f.lastSpec = spec
	if f.fail {
		return nil, fmt.Errorf("simulated federated provision failure")
	}
	return &provider.FederatedWorkloadTrust{
		Provider:          "ory",
		LogicalClientID:   spec.LogicalClientID,
		ProviderClientID:  spec.LogicalClientID,
		TrustID:           "trust-" + spec.LogicalClientID,
		Issuer:            "http://127.0.0.1:4444",
		AuthMethod:        provider.WorkloadAuthFederatedJWTBearer,
		AssertionIssuer:   spec.AssertionIssuer,
		AssertionSubject:  spec.AssertionSubject,
		AllowedScopes:     append([]string(nil), spec.AllowedScopes...),
		IntendedAudiences: append([]string(nil), spec.IntendedAudiences...),
		TrustExpiresAt:    spec.TrustExpiresAt,
	}, nil
}

func publicTestJWK() map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": "test-platform-key-1",
		"use": "sig",
		"alg": "RS256",
		"n":   "sXCH5examplemodulusvalueforunittestsOnlyNotARealKeyValuePad",
		"e":   "AQAB",
	}
}

func federatedTemplate(logicalID string, scopes, audiences []string) migration.FederatedTrustTemplate {
	return migration.FederatedTrustTemplate{
		AssertionIssuer: "https://platform.baobab.example/token",
		AssertionJWK:    publicTestJWK(),
		TrustTTL:        time.Hour,
		ScopesByLogicalID: map[string][]string{
			logicalID: scopes,
		},
		AudiencesByLogicalID: map[string][]string{
			logicalID: audiences,
		},
	}
}

// assertKratosSchemaTraits checks traits against config/ory/kratos/identity.schema.json:
// required email; additionalProperties false (only email and name allowed).
func assertKratosSchemaTraits(t *testing.T, traits map[string]any) string {
	t.Helper()
	if traits == nil {
		t.Fatal("traits is nil")
	}
	email, ok := traits["email"].(string)
	if !ok || strings.TrimSpace(email) == "" {
		t.Fatalf("traits.email missing or empty: %#v", traits)
	}
	for k := range traits {
		switch k {
		case "email", "name":
			// allowed by identity.schema.json
		default:
			t.Fatalf("traits contains forbidden key %q (schema additionalProperties: false); got %#v", k, traits)
		}
	}
	if _, has := traits["legacy_subject"]; has {
		t.Fatal("traits must not contain legacy_subject")
	}
	return email
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
	if human.lastSpec.MigrationID != "mig-human-1" {
		t.Fatalf("MigrationID not passed")
	}

	// P1-2: traits must satisfy configured Kratos schema; no legacy_subject.
	email := assertKratosSchemaTraits(t, human.lastSpec.Traits)
	if !strings.HasSuffix(email, "@users.migration.invalid") {
		t.Fatalf("expected non-authoritative migration placeholder email, got %q", email)
	}
	if !strings.Contains(email, "kc-user-1") && !strings.Contains(email, "kc-user") {
		t.Fatalf("placeholder should embed sanitized source subject, got %q", email)
	}
	if human.lastSpec.Metadata["email_role"] != "kratos_schema_identifier_only" {
		t.Fatalf("email_role metadata missing: %#v", human.lastSpec.Metadata)
	}
	if human.lastSpec.Metadata["source_subject"] != "kc-user-1" {
		t.Fatalf("source_subject metadata: %#v", human.lastSpec.Metadata)
	}
	if human.lastSpec.Metadata["migration_id"] != "mig-human-1" {
		t.Fatalf("migration_id metadata: %#v", human.lastSpec.Metadata)
	}

	res2, err := bridge.Provision(ctx, "mig-human-1")
	if err != nil || !res2.AlreadyProvisioned {
		t.Fatalf("idempotent: err=%v already=%v", err, res2.AlreadyProvisioned)
	}
}

// TestProvisionBridge_HumanMailtoSnapshot prefers an authorized source email
// from SourceSnapshotReference (mailto:) over the migration placeholder.
// Email still is not CanonicalIdentity authority.
func TestProvisionBridge_HumanMailtoSnapshot(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	human := &fakeHuman{}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", human, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	r := &migration.Record{
		MigrationID:             "mig-human-mailto",
		CanonicalIdentityID:     "ci_h2",
		SourceSnapshotReference: "mailto:alice@example.com",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "kc-alice",
		},
		IdentityClass:      migration.ClassHuman,
		CredentialStrategy: migration.StrategyFirstLoginMigration,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.Provision(ctx, "mig-human-mailto"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	email := assertKratosSchemaTraits(t, human.lastSpec.Traits)
	if email != "alice@example.com" {
		t.Fatalf("expected mailto source email, got %q", email)
	}
	if human.lastSpec.Metadata["canonical_identity_id"] != "ci_h2" {
		t.Fatalf("canonical_identity_id should remain on metadata, not traits: %#v", human.lastSpec.Metadata)
	}
	if _, has := human.lastSpec.Traits["legacy_subject"]; has {
		t.Fatal("legacy_subject must not appear in traits")
	}
}

func TestProvisionBridge_FederatedWorkloadDefault(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	fed := &fakeFederated{}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", &fakeHuman{}, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	logicalID := "baobab-cp-workload"
	bridge.WithFederated(fed, federatedTemplate(logicalID, []string{"billing:manage", "billing:read"}, []string{"baobab-subscriptions"}))
	r := &migration.Record{
		MigrationID:         "mig-fed-1",
		CanonicalIdentityID: "ci_cp",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  logicalID,
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	res, err := bridge.Provision(ctx, "mig-fed-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.WorkloadProfile != migration.WorkloadProfileFederated {
		t.Fatalf("profile=%s", res.WorkloadProfile)
	}
	if res.Record.Target.Subject != logicalID {
		t.Fatalf("target subject=%q", res.Record.Target.Subject)
	}
	if fed.lastSpec.Metadata["baobab_credential_type"] != "federated_workload_token" {
		t.Fatalf("metadata=%v", fed.lastSpec.Metadata)
	}
	if fed.lastSpec.AssertionSubject != "system:serviceaccount:baobab:"+logicalID {
		t.Fatalf("assertion subject=%q", fed.lastSpec.AssertionSubject)
	}
}

func TestProvisionBridge_WorkloadWithoutFederatedFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", &fakeHuman{}, &fakeWorkload{})
	if err != nil {
		t.Fatal(err)
	}
	r := &migration.Record{
		MigrationID:         "mig-wl-no-fed",
		CanonicalIdentityID: "ci_x",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "baobab-cp-workload",
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	_ = svc.Register(ctx, r)
	if _, err := bridge.Provision(ctx, "mig-wl-no-fed"); err == nil {
		t.Fatal("expected fail closed without federated provisioner")
	}
}

func TestProvisionBridge_ClientSecretOnlyWhenAllowListed(t *testing.T) {
	ctx := context.Background()
	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	wl := &fakeWorkload{}
	bridge, err := migration.NewProvisionBridge(svc, "http://127.0.0.1:4444", &fakeHuman{}, wl)
	if err != nil {
		t.Fatal(err)
	}
	bridge.AllowClientSecret("lab-batch-job", []string{"context-resolve", "provider-migration:task"})
	r := &migration.Record{
		MigrationID:         "mig-m4c-1",
		CanonicalIdentityID: "ci_lab",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://kc.example/realms/baobab",
			Subject:  "lab-batch-job",
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	res, err := bridge.Provision(ctx, "mig-m4c-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.WorkloadProfile != migration.WorkloadProfileClientSecret {
		t.Fatalf("profile=%s", res.WorkloadProfile)
	}
	if wl.lastSpec.AuthMethod != provider.WorkloadAuthClientSecret {
		t.Fatalf("auth=%s", wl.lastSpec.AuthMethod)
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
	// Orphans must not fabricate CanonicalIdentityID (ADR-IAM-0022).
	r := &migration.Record{
		MigrationID:         "mig-orphan",
		CanonicalIdentityID: "",
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
		t.Fatalf("state=%s", got.MigrationState)
	}
	if got.LastErrorCode != "provision_failed" {
		t.Fatalf("LastErrorCode=%q", got.LastErrorCode)
	}
}
