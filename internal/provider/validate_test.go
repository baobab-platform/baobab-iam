package provider_test

import (
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestExternalSubjectValidate(t *testing.T) {
	if err := (provider.ExternalSubject{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("empty subject: %v", err)
	}
	if err := (provider.ExternalSubject{Issuer: "https://id.example", Subject: "sub"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadProvisioningSpecValidate(t *testing.T) {
	if err := (provider.WorkloadProvisioningSpec{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("empty: %v", err)
	}
	ok := provider.WorkloadProvisioningSpec{
		LogicalClientID: "baobab-trade-workload",
		AuthMethod:      provider.WorkloadAuthClientSecret,
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.AuthMethod = "not-a-method"
	if err := bad.Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("bad auth: %v", err)
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
