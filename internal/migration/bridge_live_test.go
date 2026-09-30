package migration_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/migration"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// TestLive_ProvisionBridgeFederatedWorkload wires real Ory adapters for M4-F
// when ORY_PROVISION=1 and federated trust env is complete. Skips otherwise.
//
// Required env (in addition to ORY_* admin URLs):
//
//	ORY_ASSERTION_ISSUER
//	ORY_ASSERTION_JWK_JSON   public JWK object JSON
//	ORY_LOGICAL_CLIENT_ID    default baobab-cp-workload
//	ORY_ALLOWED_SCOPES       CSV from Shared registry
//	ORY_INTENDED_AUDIENCES   CSV from Shared registry
func TestLive_ProvisionBridgeFederatedWorkload(t *testing.T) {
	if os.Getenv("ORY_PROVISION") != "1" {
		t.Skip("set ORY_PROVISION=1 with local Kratos/Hydra to run")
	}
	issuer := os.Getenv("ORY_ASSERTION_ISSUER")
	jwkJSON := os.Getenv("ORY_ASSERTION_JWK_JSON")
	scopesCSV := os.Getenv("ORY_ALLOWED_SCOPES")
	audCSV := os.Getenv("ORY_INTENDED_AUDIENCES")
	if issuer == "" || jwkJSON == "" || scopesCSV == "" || audCSV == "" {
		t.Skip("federated live test requires ORY_ASSERTION_ISSUER, ORY_ASSERTION_JWK_JSON, ORY_ALLOWED_SCOPES, ORY_INTENDED_AUDIENCES")
	}
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("ORY_ASSERTION_JWK_JSON: %v", err)
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

	logicalID := envOrTest("ORY_LOGICAL_CLIENT_ID", "baobab-cp-workload")
	scopes := splitCSVTest(scopesCSV)
	audiences := splitCSVTest(audCSV)

	store := migration.NewMemoryStore()
	svc := &migration.Service{Store: store}
	bridge, err := migration.NewProvisionBridge(svc, cfg.PublicIssuer, adapter, adapter)
	if err != nil {
		t.Fatal(err)
	}
	bridge.WithFederated(adapter, migration.FederatedTrustTemplate{
		AssertionIssuer: issuer,
		AssertionJWK:    jwk,
		TrustTTL:        time.Hour,
		ScopesByLogicalID: map[string][]string{
			logicalID: scopes,
		},
		AudiencesByLogicalID: map[string][]string{
			logicalID: audiences,
		},
	})
	stage, err := migration.NewCredentialStage(svc)
	if err != nil {
		t.Fatal(err)
	}

	id := "live-test-" + logicalID
	rec := &migration.Record{
		MigrationID:         id,
		CanonicalIdentityID: "ci_live_" + logicalID,
		Source: migration.ProviderBinding{
			Provider: "keycloak",
			Issuer:   "https://keycloak.example/realms/baobab",
			Subject:  logicalID,
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
	if pres.WorkloadProfile != migration.WorkloadProfileFederated {
		t.Fatalf("profile=%s", pres.WorkloadProfile)
	}
	if pres.Record.MigrationState != migration.StateProvisioned {
		t.Fatalf("state=%s", pres.Record.MigrationState)
	}
	cres, err := stage.Apply(ctx, id)
	if err != nil {
		t.Fatalf("CredentialStage: %v", err)
	}
	if cres.Record.MigrationState != migration.StateCredentialReady {
		t.Fatalf("credential state=%s", cres.Record.MigrationState)
	}
}

func splitCSVTest(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			for len(part) > 0 && part[len(part)-1] == ' ' {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func envOrTest(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
