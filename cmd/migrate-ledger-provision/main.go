// Command migrate-ledger-provision runs Phase C ProvisionBridge + CredentialStage
// against a live local Ory stack (Kratos + Hydra).
//
// Opt-in only:
//
//	export ORY_PROVISION=1
//	export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
//	export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
//	export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
//	go run ./cmd/migrate-ledger-provision/
//
// Non-goals: production cutover, durable ledger, secret persistence on rows.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func main() {
	if os.Getenv("ORY_PROVISION") != "1" {
		fmt.Fprintln(os.Stderr, "migrate-ledger-provision: set ORY_PROVISION=1 to run (non-prod only)")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := ory.Config{
		KratosAdminURL: envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434"),
		HydraAdminURL:  envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445"),
		PublicIssuer:   envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444"),
	}
	adapter, err := ory.NewAdapter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: NewAdapter: %v\n", err)
		os.Exit(1)
	}
	st, err := adapter.CheckReady(ctx)
	if err != nil || !st.OK() {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: CheckReady: status=%+v err=%v (is Compose up?)\n", st, err)
		os.Exit(1)
	}

	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	bridge, err := migration.NewProvisionBridge(svc, cfg.PublicIssuer, adapter, adapter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: NewProvisionBridge: %v\n", err)
		os.Exit(1)
	}
	stage, err := migration.NewCredentialStage(svc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: NewCredentialStage: %v\n", err)
		os.Exit(1)
	}

	// Demo workload row (M4 primary) — no human credential material.
	logicalID := envOr("ORY_LOGICAL_CLIENT_ID", "baobab-trade-workload")
	rec := &migration.Record{
		MigrationID:         "live:" + logicalID,
		MigrationBatchID:    "live-ory-provision",
		CanonicalIdentityID: "ci_live_" + logicalID,
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   envOr("SOURCE_ISSUER", "https://keycloak.example/realms/baobab"),
			Subject:  logicalID,
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, rec); err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: Register: %v\n", err)
		os.Exit(1)
	}

	pres, err := bridge.Provision(ctx, rec.MigrationID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: Provision: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("provisioned migration_id=%s state=%s target_subject=%s\n",
		pres.Record.MigrationID, pres.Record.MigrationState, pres.ProviderSubject)

	cres, err := stage.Apply(ctx, rec.MigrationID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: CredentialStage: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("credential migration_id=%s state=%s outcome=%s\n",
		cres.Record.MigrationID, cres.Record.MigrationState, cres.Outcome)
	fmt.Println("done (no secrets written to ledger; CUTOVER not attempted)")
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
