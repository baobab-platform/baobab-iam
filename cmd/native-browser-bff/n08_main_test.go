package main

import (
	"context"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/assurance"
)

func TestN08NativeExecutableRequiresExactReviewedScopeToAssurance(t *testing.T) {
	allowed, err := n08NativeScopePolicy("openid trade:buy")
	if err != nil || len(allowed) != 1 || allowed["trade:buy"] != assurance.OrdinaryBuyer {
		t.Fatal("reviewed identity-only scope must retain an explicit assurance operation")
	}
	for _, input := range []string{
		"", "openid", "trade:buy", "openid  trade:buy", "openid trade:buy ",
		"openid trade:buy profile", "openid identity:admin", "openid trade:buy trade:buy",
	} {
		if _, err := n08NativeScopePolicy(input); err == nil {
			t.Fatalf("unreviewed native scope unexpectedly admitted")
		}
	}
}

func TestN08NoInventedCurrentRiskOrPrivilegedWitness(t *testing.T) {
	risk, err := (unavailableN08Risk{}).CurrentRisk(
		context.Background(), assurance.CurrentSessionKey{Issuer: "synthetic"},
		assurance.CommitBuyer)
	if err == nil || !risk.ObservedAt.IsZero() || risk.PrivilegedContextVerified {
		t.Fatal("unavailable high-risk proof must not become a low-risk assertion")
	}
}
