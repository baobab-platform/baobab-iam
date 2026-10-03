// Command migrate-ledger-provision runs Phase C ProvisionBridge + CredentialStage
// against a live local Ory stack.
//
// Default path is M4-F federated_workload_token (ADR-IAM-0021). Opt-in only:
//
//	export ORY_PROVISION=1
//	export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
//	export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
//	export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
//	export ORY_ASSERTION_ISSUER=https://platform.example/token
//	export ORY_ASSERTION_JWK_JSON='{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}'
//	export ORY_LOGICAL_CLIENT_ID=baobab-cp-workload
//	export ORY_ALLOWED_SCOPES=billing:manage,billing:read
//	export ORY_INTENDED_AUDIENCES=baobab-subscriptions
//	go run ./cmd/migrate-ledger-provision/
//
// M4-C client_secret lab path (explicit only):
//
//	export ORY_WORKLOAD_PROFILE=client_secret
//	export ORY_LOGICAL_CLIENT_ID=lab-batch-job
//	export ORY_ALLOWED_SCOPES=context-resolve,provider-migration:task
//
// Non-goals: production cutover, durable ledger, Shared ACTIVE lifecycle,
// private JWK material, secret persistence on ledger rows.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	logicalID, err := envRequired("ORY_LOGICAL_CLIENT_ID")
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: invalid ORY_LOGICAL_CLIENT_ID: %v\n", err)
		os.Exit(1)
	}
	if logicalID == "" {
		logicalID = "baobab-cp-workload"
	}
	profile := strings.TrimSpace(os.Getenv("ORY_WORKLOAD_PROFILE"))
	if profile == "" || profile == string(migration.WorkloadProfileFederated) {
		if err := configureFederated(bridge, adapter, logicalID); err != nil {
			fmt.Fprintf(os.Stderr, "migrate-ledger-provision: federated config: %v\n", err)
			os.Exit(1)
		}
	} else if profile == string(migration.WorkloadProfileClientSecret) {
		scopes := splitCSV(os.Getenv("ORY_ALLOWED_SCOPES"))
		if len(scopes) == 0 {
			fmt.Fprintln(os.Stderr, "migrate-ledger-provision: ORY_ALLOWED_SCOPES required for client_secret profile (Shared-authorized)")
			os.Exit(1)
		}
		bridge.AllowClientSecret(logicalID, scopes)
	} else {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: unknown ORY_WORKLOAD_PROFILE %q\n", profile)
		os.Exit(2)
	}

	stage, err := migration.NewCredentialStage(svc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: NewCredentialStage: %v\n", err)
		os.Exit(1)
	}

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
	fmt.Printf("provisioned migration_id=%s state=%s target_subject=%s workload_profile=%s\n",
		pres.Record.MigrationID, pres.Record.MigrationState, pres.ProviderSubject, pres.WorkloadProfile)

	cres, err := stage.Apply(ctx, rec.MigrationID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate-ledger-provision: CredentialStage: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("credential migration_id=%s state=%s outcome=%s\n",
		cres.Record.MigrationID, cres.Record.MigrationState, cres.Outcome)
	fmt.Println("done (no secrets on ledger; Shared ACTIVE not set; CUTOVER not attempted)")
}

func configureFederated(bridge *migration.ProvisionBridge, adapter *ory.Adapter, logicalID string) error {
	assertionIssuer, err := envRequired("ORY_ASSERTION_ISSUER")
	if err != nil {
		return fmt.Errorf("ORY_ASSERTION_ISSUER: %w", err)
	}
	jwkJSON, err := envRequired("ORY_ASSERTION_JWK_JSON")
	if err != nil {
		return fmt.Errorf("ORY_ASSERTION_JWK_JSON: %w", err)
	}
	scopes := splitCSV(os.Getenv("ORY_ALLOWED_SCOPES"))
	audiences := splitCSV(os.Getenv("ORY_INTENDED_AUDIENCES"))
	if len(scopes) == 0 {
		return fmt.Errorf("ORY_ALLOWED_SCOPES required from Shared registry")
	}
	if len(audiences) == 0 {
		return fmt.Errorf("ORY_INTENDED_AUDIENCES required from Shared registry")
	}
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return fmt.Errorf("ORY_ASSERTION_JWK_JSON: %w", err)
	}
	bridge.WithFederated(adapter, migration.FederatedTrustTemplate{
		AssertionIssuer: assertionIssuer,
		AssertionJWK:    jwk,
		TrustTTL:        24 * time.Hour,
		ScopesByLogicalID: map[string][]string{
			logicalID: scopes,
		},
		AudiencesByLogicalID: map[string][]string{
			logicalID: audiences,
		},
	})
	return nil
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func envRequired(k string) (string, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return "", fmt.Errorf("%s is required", k)
	}
	return v, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
