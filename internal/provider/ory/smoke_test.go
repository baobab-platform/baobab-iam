//go:build !skip_ory_smoke

package ory_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

// TestSmoke_ProviderInfoAgainstLocalStack exercises the Ory adapter against
// the non-production foundation stack (docker-compose.ory.yml).
//
// Opt-in only: set ORY_SMOKE=1 after:
//
//	docker compose -f docker-compose.ory.yml up -d
//
// Default CI / offline `go test ./...` skips this test — no network required.
//
// ADR references:
//   - ADR-0020 Category B: admin-plane only (Kratos/Hydra admin URLs)
//   - ADR-0021 §8 / §10: admin endpoints are for baobab-iam tooling
//   - ADR-0021 foundation issuer matches config/ory/hydra/hydra.yml
//
// Phase B (M2/M3-C evidence): probes CheckReady on both admin planes first,
// then ProviderInfo. Live Docker was unavailable in the agent sandbox;
// operators record evidence with ORY_SMOKE=1 on a workstation.
func TestSmoke_ProviderInfoAgainstLocalStack(t *testing.T) {
	if os.Getenv("ORY_SMOKE") != "1" {
		t.Skip("set ORY_SMOKE=1 with local Ory foundation running to enable")
	}

	// Defaults match docker-compose.ory.yml localhost binds (ADR-0021 admin plane).
	kratosAdmin := envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434")
	hydraAdmin := envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445")
	issuer := envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	a, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: kratosAdmin,
		HydraAdminURL:  hydraAdmin,
		PublicIssuer:   issuer,
		RequestTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}

	// 1) Both admin planes must be ready before treating the stack as usable.
	ready, err := a.CheckReady(ctx)
	if err != nil {
		t.Fatalf("CheckReady: %v (detail=%s; is docker-compose.ory.yml up?)", err, ready.Detail)
	}
	if !ready.OK() {
		t.Fatalf("CheckReady not OK: %+v", ready)
	}
	t.Logf("foundation ready: %s", ready.Detail)

	// 2) Provider metadata and capability declaration (ADR-0020).
	info, err := a.ProviderInfo(ctx)
	if err != nil {
		t.Fatalf("ProviderInfo: %v", err)
	}
	if info.Name != "ory" {
		t.Fatalf("Name: got %q want ory", info.Name)
	}
	if info.Issuer != issuer {
		t.Fatalf("Issuer: got %q want %q", info.Issuer, issuer)
	}
	if !info.Capabilities.HumanIdentity || !info.Capabilities.WorkloadIdentity {
		t.Fatalf("capabilities incomplete: %+v", info.Capabilities)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
