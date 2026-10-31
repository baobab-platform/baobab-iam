package workloadresource

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// n04LiveProviderComponentFixture combines a genuine Hydra-signed bearer and
// N03's real CP-router fixture with CP's EXACT private runtime binding HTTP
// wire shape under local TLS. The registration state is local synthetic data:
// it DOES NOT prove actual CP PostgreSQL support, verified observer, CP
// AdministrativeGrant, deployed engine, or DEV-N04 acceptance.
func n04LiveProviderComponentFixture(t *testing.T, ctx context.Context,
	bearer, validatorBearer, issuer string, resource *Gate, op Operation,
	client *http.Client) {
	t.Helper()
	// Verify the CP fixture caller is genuinely signed for the CP audience,
	// while explicitly retaining that the fake binding endpoint is NOT CP.
	issuerVerifier, err := newSignedVerifier(issuer, "baobab-control-plane", client, true)
	if err != nil {
		t.Fatal("live CP-audience JWT verifier unavailable")
	}
	issuerClaims, err := issuerVerifier.VerifySigned(ctx, validatorBearer)
	if err != nil || issuerClaims.ClientID != "m4-ci-validator" ||
		issuerClaims.ActorType != "workload" {
		t.Fatal("real signed CP-audience fixture caller missing")
	}
	target := CPBindingTarget{
		ProviderID: "provider_aaaaaaaa",
		EngineInstanceID: "ei_aaaaaaaa",
		OrganisationID: "org_fixture",
		EstateID: "estate_nabhold",
		ConfigurationReference: "ref_cfgfixture",
		SecurityDomainReference: "ref_secfixture",
	}
	mode := ""
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/internal/identity-runtime/v1/binding" ||
			r.Header.Get("Authorization") != "Bearer "+validatorBearer {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input map[string]string
		if json.NewDecoder(r.Body).Decode(&input) != nil ||
			input["provider_id"] != target.ProviderID ||
			input["engine_instance_id"] != target.EngineInstanceID ||
			input["organisation_id"] != target.OrganisationID ||
			input["estate_id"] != target.EstateID ||
			input["configuration_reference"] != target.ConfigurationReference ||
			input["security_domain_reference"] != target.SecurityDomainReference ||
			input["runtime_capability"] != "WORKLOAD_TOKEN_ISSUANCE" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if mode == "withdraw-second" && calls%2 == 0 ||
			mode == "withdraw-first" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		payload := map[string]any{
			"provider_id": target.ProviderID,
			"engine_instance_id": target.EngineInstanceID,
			"scope": map[string]string{
				"organisation_id": target.OrganisationID, "estate_id": target.EstateID,
			},
			"provider_status": "ACTIVE", "instance_status": "ACTIVE",
			"binding_status": "ACTIVE",
			"runtime_capability": "WORKLOAD_TOKEN_ISSUANCE",
			"support_status": "VERIFIED",
			"artifact_digest": "sha256:" + strings.Repeat("a", 64),
			"deployed_artifact_digest": "sha256:" + strings.Repeat("a", 64),
			"profile_revision": 2,
			"evidence_expires_at": time.Now().Add(time.Minute),
			"configuration_reference": target.ConfigurationReference,
			"security_domain_reference": target.SecurityDomainReference,
		}
		switch mode {
		case "wrong-tenant":
			payload["scope"] = map[string]string{"organisation_id": "org_foreign", "estate_id": target.EstateID}
		case "stale-source":
			payload["evidence_expires_at"] = time.Now().Add(-time.Second)
		case "changed-artifact":
			payload["deployed_artifact_digest"] = "sha256:" + strings.Repeat("b", 64)
		case "unverified":
			payload["support_status"] = "PARTIAL"
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	reader, err := NewCPRegisteredBinding(srv.URL, roots, target,
		func(context.Context) (string, error) { return validatorBearer, nil })
	if err != nil {
		t.Fatal("TLS CP registered-read fixture could not be built")
	}
	registered, err := NewRegisteredGate(resource, reader)
	if err != nil {
		t.Fatal("native N03+N04 gate refused")
	}
	t.Run("N04-real-Hydra-and-CP-source-fixture-accepted", func(t *testing.T) {
		mode, calls = "", 0
		if err := registered.Authorize(ctx, bearer, op); err != nil || calls != 2 {
			t.Fatal("real issuer plus N04 registered binding fixture denied", err, calls)
		}
	})
	for _, scenario := range []string{
		"withdraw-first", "withdraw-second", "wrong-tenant",
		"stale-source", "changed-artifact", "unverified",
	} {
		t.Run("N04-real-Hydra-CP-binding-"+scenario+"-denied", func(t *testing.T) {
			mode, calls = scenario, 0
			if err := registered.Authorize(ctx, bearer, op); err == nil {
				t.Fatal("N04 runtime authority failure reached native engine", scenario)
			}
			if scenario == "withdraw-second" && calls != 2 {
				t.Fatal("CP revoked between resource and delivery was not checked twice")
			}
		})
	}
}
