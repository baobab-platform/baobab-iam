package migration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// TestLive_ProvisionBridgeAndCredentialStage wires real Ory adapters when
// ORY_PROVISION=1 and a local stack is healthy. Skips otherwise.
func TestLive_ProvisionBridgeAndCredentialStage(t *testing.T) {
	if os.Getenv("ORY_PROVISION") != "1" {
		t.Skip("set ORY_PROVISION=1 with local Kratos/Hydra to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cfg := ory.Config{
		KratosAdminURL: envOrTest("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434"),
		HydraAdminURL:  envOrTest("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445"),
		PublicIssuer:   envOrTest("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444"),
	}
	adapter, err := ory.NewAdapter(cfg)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	st, err := adapter.CheckReady(ctx)
	if err != nil || !st.OK() {
		t.Fatalf("CheckReady: status=%+v err=%v", st, err)
	}

	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	bridge, err := migration.NewProvisionBridge(svc, cfg.PublicIssuer, adapter, adapter)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := migration.NewCredentialStage(svc)
	if err != nil {
		t.Fatal(err)
	}

	id := "live-test-baobab-trade-workload"
	rec := &migration.Record{
		MigrationID:         id,
		CanonicalIdentityID: "ci_live_trade",
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://keycloak.example/realms/baobab",
			Subject:  "baobab-trade-workload",
		},
		IdentityClass:      migration.ClassWorkload,
		CredentialStrategy: migration.StrategyNoCredentialRequired,
		MigrationState:     migration.StateDiscovered,
	}
	if err := svc.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	pres, err := bridge.Provision(ctx, id)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if pres.Record.MigrationState != migration.StateProvisioned {
		t.Fatalf("state=%s", pres.Record.MigrationState)
	}
	if pres.Record.Target.Subject == "" {
		t.Fatal("empty target subject")
	}
	cres, err := stage.Apply(ctx, id)
	if err != nil {
		t.Fatalf("CredentialStage: %v", err)
	}
	if cres.Record.MigrationState != migration.StateCredentialReady {
		t.Fatalf("credential state=%s", cres.Record.MigrationState)
	}
}

func envOrTest(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
