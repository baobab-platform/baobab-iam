package provider_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestExternalSubjectValidate(t *testing.T) {
	if err := (provider.ExternalSubject{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("empty subject: %v", err)
	}
	if err := (provider.ExternalSubject{Issuer: "   ", Subject: "sub"}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("whitespace issuer should be rejected: %v", err)
	}
	if err := (provider.ExternalSubject{Issuer: "https://id.example", Subject: "sub"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadProvisioningSpecValidate(t *testing.T) {
	if err := (provider.WorkloadProvisioningSpec{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("empty: %v", err)
	}
	if err := (provider.WorkloadProvisioningSpec{LogicalClientID: "   ", AllowedScopes: []string{"openid"}, AuthMethod: provider.WorkloadAuthClientSecret}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("whitespace logical client id should be rejected: %v", err)
	}
	ok := provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		AllowedScopes:   []string{"context:resolve", "openid"},
		AuthMethod:      provider.WorkloadAuthClientSecret,
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	missingScopes := ok
	missingScopes.AllowedScopes = nil
	if err := missingScopes.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("missing scopes: %v", err)
	}
	federated := ok
	federated.AuthMethod = provider.WorkloadAuthFederatedJWTBearer
	if err := federated.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("federated-auth workload should use ProvisionFederatedWorkload: %v", err)
	}
	bad := ok
	bad.AuthMethod = "not-a-method"
	if err := bad.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("bad auth: %v", err)
	}
}

// TestWorkloadAuthMethodRejectsPaddedEnum proves private_key_jwt cannot
// silently degrade into a generated client secret via whitespace padding.
func TestWorkloadAuthMethodRejectsPaddedEnum(t *testing.T) {
	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		AllowedScopes:   []string{"context:resolve"},
		AuthMethod:      provider.WorkloadAuthenticationMethod(" private_key_jwt "),
	}
	if err := spec.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("padded private_key_jwt must be rejected fail-closed: %v", err)
	}
}

func TestWorkloadLifecycleStatusRejectsActiveOnProvision(t *testing.T) {
	spec := provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		AllowedScopes:   []string{"context:resolve"},
		AuthMethod:      provider.WorkloadAuthClientSecret,
		LifecycleStatus: provider.WorkloadStatusActive,
	}
	if err := spec.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("ACTIVE on provision must be rejected (Shared owns activation): %v", err)
	}
}

func TestIdentityProvisioningSpecValidate(t *testing.T) {
	if err := (provider.IdentityProvisioningSpec{
		Traits: map[string]any{"email": "a@b.c", "tenant": "t1"},
	}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("forbidden trait: %v", err)
	}
	if err := (provider.IdentityProvisioningSpec{
		Traits: map[string]any{"email": "a@b.c"},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityProvisioningRejectsNestedAuthoritySmuggling(t *testing.T) {
	for _, tc := range []struct {
		name     string
		traits   map[string]any
		metadata map[string]string
	}{
		{"nested ERP role", map[string]any{"profile": map[string]any{"AD_Role": "System Admin"}}, nil},
		{"nested tenant", map[string]any{"identity": []any{map[string]any{"tenant_id": "other"}}}, nil},
		{"nested market", map[string]any{"email": "a@b.c", "attributes": map[string]any{"market": "UG"}}, nil},
		{"nested supplier approval", map[string]any{"email": "a@b.c", "roles": map[string]any{"supplier-approval": true}}, nil},
		{"metadata capability", map[string]any{"email": "a@b.c"}, map[string]string{"capability.grant": "allow"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := (provider.IdentityProvisioningSpec{Traits: tc.traits, Metadata: tc.metadata}).Validate(); !provider.IsInvalidArgument(err) {
				t.Fatalf("identity business authority accepted: %v", err)
			}
		})
	}
	// The exact wire JSON, not the Go dynamic type, controls whether
	// nested identity attributes launder CP/ERP/supplier authority.
	for label, traits := range map[string]map[string]any{
		"typed nested map":   {"profile": map[string]string{"AD_Client": "System"}},
		"typed map in slice": {"profile": []map[string]string{{"supplier-approval": "yes"}}},
		"raw JSON traits":    {"profile": json.RawMessage(`{"market_id":"UG"}`)},
	} {
		t.Run(label, func(t *testing.T) {
			if err := (provider.IdentityProvisioningSpec{Traits: traits}).Validate(); !provider.IsInvalidArgument(err) {
				t.Fatalf("serialized business authority accepted: %v", err)
			}
		})
	}
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	if err := (provider.IdentityProvisioningSpec{Traits: cyclic}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("non-serializable cyclic identity claims accepted: %v", err)
	}
	good := provider.IdentityProvisioningSpec{
		Traits:   map[string]any{"email": "person@example.test", "name": map[string]any{"given": "Amina", "family": "Nab"}},
		Metadata: map[string]string{"migration_id": "migration_01"},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("ordinary identity attributes rejected: %v", err)
	}
}

func TestWorkloadLifecycleStatusValidate(t *testing.T) {
	for _, status := range []provider.WorkloadLifecycleStatus{
		provider.WorkloadStatusProvisioned,
		provider.WorkloadStatusActive,
		provider.WorkloadStatusSuspended,
		provider.WorkloadStatusRevoked,
		provider.WorkloadStatusRetired,
	} {
		if err := status.Validate(); err != nil {
			t.Fatalf("valid status %q: %v", status, err)
		}
	}
	if err := provider.WorkloadLifecycleStatus("   ").Validate(); !provider.IsInvalidArgument(err) {
		t.Fatal("whitespace workload status should be rejected")
	}
	if err := provider.WorkloadLifecycleStatus("unknown").Validate(); !provider.IsInvalidArgument(err) {
		t.Fatal("unknown workload status should be rejected")
	}
}

func TestFederatedWorkloadTrustSpecValidateRejectsWhitespace(t *testing.T) {
	trust := provider.FederatedWorkloadTrustSpec{
		LogicalClientID:   "   ",
		AllowedScopes:     []string{"context:resolve"},
		IntendedAudiences: []string{"baobab-control-plane"},
		AssertionIssuer:   "https://issuer.example",
		AssertionSubject:  "service-account",
		AssertionJWK: map[string]any{
			"kty": "RSA",
			"kid": "k1",
			"n":   "AQAB",
			"e":   "AQAB",
		},
		TrustExpiresAt: time.Now().Add(time.Hour),
	}
	if err := trust.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("whitespace logical client id should be rejected: %v", err)
	}
}

func TestNormalizeAllowedScopes_ContextResolveCanonical(t *testing.T) {
	in := []string{"context:resolve", "context-resolve", ""}
	got := provider.NormalizeAllowedScopes(in)
	if len(got) != 1 {
		t.Fatalf("len=%d want 1: %#v", len(got), got)
	}
	if got[0] != "context:resolve" {
		t.Fatalf("got %#v", got)
	}
	// Input must not be mutated.
	if in[1] != "context-resolve" {
		t.Fatal("input mutated")
	}
}

func TestNormalizeAllowedScopes_Passthrough(t *testing.T) {
	got := provider.NormalizeAllowedScopes([]string{"openid", "actor-type-workload"})
	if len(got) != 2 || got[0] != "openid" {
		t.Fatalf("%#v", got)
	}
}

func TestNormalizeAllowedScopes_TrimsWhitespace(t *testing.T) {
	got := provider.NormalizeAllowedScopes([]string{" context-resolve ", " context:resolve ", "", "  ", "openid"})
	want := []string{"context:resolve", "openid"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}
