// Command provision-workload provisions a single non-production Hydra OAuth
// client via the Ory WorkloadProvisioner (Gate IAM-M4).
//
// Default target: baobab-trade-workload (see gate-iam-m4-client-inventory.md).
//
// Opt-in only — requires ORY_PROVISION=1 and reachable admin URLs:
//
//	export ORY_PROVISION=1
//	export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
//	export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
//	export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
//	go run ./cmd/provision-workload/
//
// Does not touch production Keycloak or dual-issuer configuration.
// Client secrets are never printed in full.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

const defaultLogicalClientID = "baobab-trade-workload"

func main() {
	if os.Getenv("ORY_PROVISION") != "1" {
		fmt.Fprintln(os.Stderr, "provision-workload: set ORY_PROVISION=1 to run (non-prod only)")
		os.Exit(0)
	}

	kratosAdmin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	hydraAdmin := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	logicalID := envOr("ORY_LOGICAL_CLIENT_ID", defaultLogicalClientID)

	// Freeze-list scopes for M4-PRIMARY workloads (M0 §5 / M4 inventory).
	// context-resolve is the Baobab name (normalize from Keycloak context:resolve).
	scopes := []string{"actor-type-workload", "context-resolve"}
	if s := os.Getenv("ORY_ALLOWED_SCOPES"); s != "" {
		scopes = splitCSV(s)
	}

	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: logicalID,
		DisplayName:     envOr("ORY_DISPLAY_NAME", "Baobab Trade Workload"),
		AllowedScopes:   scopes,
		AuthMethod:      provider.WorkloadAuthClientSecret,
		Metadata: map[string]string{
			"gate":       "IAM-M4",
			"environment": "non-prod-local",
		},
	}
	if err := spec.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "provision-workload: invalid spec: %v\n", err)
		os.Exit(2)
	}

	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: kratosAdmin,
		HydraAdminURL:  hydraAdmin,
		PublicIssuer:   issuer,
		RequestTimeout: 15 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-workload: adapter: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	w, err := adapter.ProvisionWorkload(ctx, spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-workload: ProvisionWorkload failed (is Hydra up?): %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("provider=%s logical_client_id=%s provider_client_id=%s issuer=%s auth_method=%s secret=%s\n",
		w.Provider, w.LogicalClientID, w.ProviderClientID, w.Issuer, w.AuthMethod, redactSecret(w.ClientSecret))
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func redactSecret(s string) string {
	if s == "" {
		return "(none)"
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "…" + s[len(s)-2:] + " (redacted; length=" + fmt.Sprintf("%d", len(s)) + ")"
}
