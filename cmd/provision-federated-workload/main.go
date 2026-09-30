// Command provision-federated-workload establishes provider-side Hydra trust
// for a Shared credential_type=federated_workload_token workload.
//
// It does not mint a projected assertion and does not mark the Shared workload
// ACTIVE. Those are separate runtime/evidence steps.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/baobab-platform/baobab-iam/internal/provider/ory"
)

func main() {
	if os.Getenv("ORY_FEDERATED_PROVISION") != "1" {
		fmt.Fprintln(os.Stderr, "provision-federated-workload: set ORY_FEDERATED_PROVISION=1 to acknowledge provider-side mutation")
		os.Exit(2)
	}

	logicalID := strings.TrimSpace(os.Getenv("ORY_LOGICAL_CLIENT_ID"))
	scopes := provider.NormalizeAllowedScopes(splitCSV(os.Getenv("ORY_ALLOWED_SCOPES")))
	audiences := splitCSV(os.Getenv("ORY_INTENDED_AUDIENCES"))
	assertionIssuer := strings.TrimSpace(os.Getenv("ORY_ASSERTION_ISSUER"))
	assertionSubject := strings.TrimSpace(os.Getenv("ORY_ASSERTION_SUBJECT"))
	jwkPath := strings.TrimSpace(os.Getenv("ORY_ASSERTION_JWK_FILE"))
	expiresRaw := strings.TrimSpace(os.Getenv("ORY_TRUST_EXPIRES_AT"))

	if logicalID == "" || len(scopes) == 0 || len(audiences) == 0 || assertionIssuer == "" || assertionSubject == "" || jwkPath == "" || expiresRaw == "" {
		fmt.Fprintln(os.Stderr, "provision-federated-workload: logical id, scopes, intended audiences, assertion issuer/subject, public JWK file and trust expiry are required")
		os.Exit(2)
	}

	jwk, err := readPublicJWK(jwkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-federated-workload: JWK: %v\n", err)
		os.Exit(2)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-federated-workload: ORY_TRUST_EXPIRES_AT: %v\n", err)
		os.Exit(2)
	}

	adapter, err := ory.NewAdapter(ory.Config{
		KratosAdminURL: envOr("ORY_KRATOS_ADMIN_URL", "http://127.0.0.1:4434"),
		HydraAdminURL:  envOr("ORY_HYDRA_ADMIN_URL", "http://127.0.0.1:4445"),
		PublicIssuer:   envOr("ORY_PUBLIC_ISSUER", "http://127.0.0.1:4444/"),
		RequestTimeout: 15 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-federated-workload: adapter: %v\n", err)
		os.Exit(1)
	}

	trust, err := adapter.ProvisionFederatedWorkload(context.Background(), provider.FederatedWorkloadTrustSpec{
		LogicalClientID:   logicalID,
		DisplayName:       os.Getenv("ORY_DISPLAY_NAME"),
		AllowedScopes:     scopes,
		IntendedAudiences: audiences,
		AssertionIssuer:   assertionIssuer,
		AssertionSubject:  assertionSubject,
		AssertionJWK:      jwk,
		TrustExpiresAt:     expiresAt,
		Metadata: map[string]string{
			"gate":            "IAM-M4-F",
			"canonical_state": "PROVISIONED",
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "provision-federated-workload: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("provider=%s logical_client_id=%s provider_client_id=%s trust_id=%s auth_method=%s assertion_issuer=%s assertion_subject=%s trust_expires_at=%s canonical_state=PROVISIONED\n",
		trust.Provider,
		trust.LogicalClientID,
		trust.ProviderClientID,
		trust.TrustID,
		trust.AuthMethod,
		trust.AssertionIssuer,
		trust.AssertionSubject,
		trust.TrustExpiresAt.Format(time.RFC3339),
	)
}

func readPublicJWK(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jwk map[string]any
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, err
	}
	// Structural/security validation is centralized in FederatedWorkloadTrustSpec.
	return jwk, nil
}

func splitCSV(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
