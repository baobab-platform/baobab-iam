package ory

import (
	"context"
	"crypto/tls"

	"github.com/baobab-platform/baobab-iam/internal/federation"
	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// CheckComposedNativeWorkloadReadiness uses the production C4-02 factories.
// Both paths make authenticated, current CP reads using separately reviewed
// service-credential files, and the native path additionally verifies the
// Hydra OAuth authorization-server runtime alongside the workload issuer.
// There is no identity allocation, fallback provider selection or registration
// from these configuration files.
//
// This is a single observation for operations, not an authenticated endpoint,
// capability grant, production-readiness certificate or durable health record.
// Every actual token issue and human login still uses its own per-operation
// current CP dispatch. A live receipt must additionally cover real consumption.
func CheckComposedNativeWorkloadReadiness(
	ctx context.Context,
	human, issuer federation.RuntimeComposition,
	tlsConfig *tls.Config,
	health NativeWorkloadHealth,
) (NativeWorkloadReadiness, error) {
	denied := func() (NativeWorkloadReadiness, error) {
		return NativeWorkloadReadiness{}, federation.ErrDenied
	}
	if ctx == nil || ctx.Err() != nil || absentHealth(health) {
		return denied()
	}
	service, cancel := context.WithCancel(ctx)
	defer cancel()

	// This factory enforces one CP tenant/organisation/market/security-domain
	// context for Kratos human and its companion Hydra OAuth/issuer proofs.
	native, nativeContexts, err := federation.StartNativeRuntimeComposition(service, human, issuer, tlsConfig)
	if err != nil {
		return denied()
	}
	defer func() {
		cancel()
		<-nativeContexts.Done()
	}()

	// Workload issuance must resolve independently of human login. Never
	// interpret native readiness as a workload client's canonical grant.
	workload, workloadContexts, err := federation.StartRuntimeComposition(
		service, issuer, provider.CapabilityWorkloadTokenIssue, tlsConfig,
	)
	if err != nil {
		return denied()
	}
	defer func() {
		cancel()
		<-workloadContexts.Done()
	}()

	// Provider health lies between CP checks, and each check includes fresh
	// support/binding/artifact/current caller resolution. Any drift denies.
	return CheckGovernedNativeWorkloadReadiness(service, native, workload, health)
}
