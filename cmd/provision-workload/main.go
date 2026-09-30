// Command provision-workload manages non-production Hydra OAuth workload
// clients via the Ory WorkloadProvisioner (Gate IAM-M4).
//
// Opt-in: ORY_PROVISION=1
//
// Actions (ORY_ACTION):
//
//	provision     — create/update one client (default: baobab-trade-workload)
//	disable       — clear grants on one client
//	rotate        — rotate client secret
//	all-primary   — provision every M4-PRIMARY logical client id
//
//	export ORY_PROVISION=1
//	export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
//	export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
//	export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
//	export ORY_ACTION=provision
//	go run ./cmd/provision-workload/
//
// Does not touch production Keycloak. Newly generated client secrets are never
// printed; set ORY_SECRET_OUTPUT_DIR to a private directory so create/rotate can
// atomically hand the cleartext secret to the workload deployment process.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// M4-PRIMARY logical client IDs (gate-iam-m4-client-inventory.md).
var m4Primary = []string{
	"baobab-trade-workload",
	"baobab-cms-workload",
	"baobab-erp-workload",
	"baobab-pulse-workload",
	"thamani-backend-workload",
	"zuribeans-backend-workload",
}

var displayNames = map[string]string{
	"baobab-trade-workload":      "Baobab Trade Workload",
	"baobab-cms-workload":        "Baobab CMS Workload",
	"baobab-erp-workload":        "Baobab ERP Workload",
	"baobab-pulse-workload":      "Baobab Pulse Workload",
	"thamani-backend-workload":   "Thamani Backend Workload",
	"zuribeans-backend-workload": "ZuriBeans Backend Workload",
}

func main() {
	if os.Getenv("ORY_PROVISION") != "1" {
		fmt.Fprintln(os.Stderr, "provision-workload: set ORY_PROVISION=1 to run (non-prod only)")
		os.Exit(0)
	}

	action := strings.ToLower(envOr("ORY_ACTION", "provision"))
	kratosAdmin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	hydraAdmin := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")
	logicalID := envOr("ORY_LOGICAL_CLIENT_ID", "baobab-trade-workload")
	secretOutputDir := os.Getenv("ORY_SECRET_OUTPUT_DIR")

	// Default scopes use freeze spelling (context-resolve). Keycloak JSON may
	// still list context:resolve — NormalizeAllowedScopes TRANSLATEs either form.
	scopes := provider.NormalizeAllowedScopes([]string{"actor-type-workload", "context-resolve"})
	if s := os.Getenv("ORY_ALLOWED_SCOPES"); s != "" {
		scopes = provider.NormalizeAllowedScopes(splitCSV(s))
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Fail fast if Hydra admin is not reachable (ADR-0021 admin plane).
	// Kratos is still required by the adapter config but is unused for pure workload ops.
	if ready, err := adapter.CheckReady(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "provision-workload: foundation not ready: %v (%s)\n", err, ready.Detail)
		os.Exit(1)
	}

	switch action {
	case "provision":
		if err := provisionOne(ctx, adapter, logicalID, scopes, secretOutputDir); err != nil {
			fmt.Fprintf(os.Stderr, "provision-workload: %v\n", err)
			os.Exit(1)
		}
	case "disable":
		if err := adapter.DisableWorkload(ctx, provider.ProviderWorkloadReference{LogicalClientID: logicalID}); err != nil {
			fmt.Fprintf(os.Stderr, "provision-workload: disable: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("disabled logical_client_id=%s\n", logicalID)
	case "rotate":
		w, err := adapter.RotateWorkloadCredentials(ctx, provider.ProviderWorkloadReference{LogicalClientID: logicalID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "provision-workload: rotate: %v\n", err)
			os.Exit(1)
		}
		secretPath, err := persistGeneratedSecret(secretOutputDir, w)
		if err != nil {
			fmt.Fprintf(os.Stderr, "provision-workload: rotate secret handoff: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("rotated logical_client_id=%s secret_output=%s\n", w.LogicalClientID, secretPath)
	case "all-primary":
		for _, id := range m4Primary {
			if err := provisionOne(ctx, adapter, id, scopes, secretOutputDir); err != nil {
				fmt.Fprintf(os.Stderr, "provision-workload: %s: %v\n", id, err)
				os.Exit(1)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "provision-workload: unknown ORY_ACTION %q (want provision|disable|rotate|all-primary)\n", action)
		os.Exit(2)
	}
}

func provisionOne(ctx context.Context, adapter *ory.Adapter, logicalID string, scopes []string, secretOutputDir string) error {
	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: logicalID,
		DisplayName:     displayNames[logicalID],
		AllowedScopes:   scopes,
		AuthMethod:      provider.WorkloadAuthClientSecret,
		Metadata: map[string]string{
			"gate":        "IAM-M4",
			"environment": "non-prod-local",
		},
	}
	if spec.DisplayName == "" {
		spec.DisplayName = logicalID
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	w, err := adapter.ProvisionWorkload(ctx, spec)
	if err != nil {
		return fmt.Errorf("ProvisionWorkload %s (is Hydra up?): %w", logicalID, err)
	}
	secretPath, err := persistGeneratedSecret(secretOutputDir, w)
	if err != nil {
		return fmt.Errorf("secret handoff: %w", err)
	}
	fmt.Printf("provider=%s logical_client_id=%s provider_client_id=%s issuer=%s auth_method=%s secret_output=%s\n",
		w.Provider, w.LogicalClientID, w.ProviderClientID, w.Issuer, w.AuthMethod, secretPath)
	return nil
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

func persistGeneratedSecret(dir string, w *provider.ProviderWorkload) (string, error) {
	if w == nil || w.ClientSecret == "" {
		return "(unchanged)", nil
	}
	if dir == "" {
		return "", fmt.Errorf("ORY_SECRET_OUTPUT_DIR is required when Hydra creates or rotates a client secret")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create secret output directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure secret output directory: %w", err)
	}
	finalPath := filepath.Join(dir, w.LogicalClientID+".client-secret")
	tmp, err := os.CreateTemp(dir, "."+w.LogicalClientID+".client-secret-*")
	if err != nil {
		return "", fmt.Errorf("create temporary secret file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("secure temporary secret file: %w", err)
	}
	if _, err := tmp.WriteString(w.ClientSecret + "\n"); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write workload secret: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sync workload secret: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close workload secret: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", fmt.Errorf("publish workload secret: %w", err)
	}
	if err := os.Chmod(finalPath, 0o600); err != nil {
		return "", fmt.Errorf("secure workload secret: %w", err)
	}
	return finalPath, nil
}
