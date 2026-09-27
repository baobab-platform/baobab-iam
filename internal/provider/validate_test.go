package provider_test

import (
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestExternalSubjectValidate(t *testing.T) {
	if err := (provider.ExternalSubject{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("expected invalid argument, got %v", err)
	}
	if err := (provider.ExternalSubject{Issuer: "https://id.example", Subject: "sub"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadProvisioningSpecValidate(t *testing.T) {
	if err := (provider.WorkloadProvisioningSpec{}).Validate(); !provider.IsInvalidArgument(err) {
		t.Fatalf("expected invalid argument, got %v", err)
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
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestIdentityProvisioningSpecRejectsBusinessTraits(t *testing.T) {
	err := (provider.IdentityProvisioningSpec{
		Traits: map[string]any{"email": "a@b.c", "tenant": "t1"},
	}).Validate()
	if !provider.IsInvalidArgument(err) {
		t.Fatalf("expected invalid argument for tenant trait, got %v", err)
	}
	if err := (provider.IdentityProvisioningSpec{
		Traits: map[string]any{"email": "a@b.c"},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}
