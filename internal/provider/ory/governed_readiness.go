package ory

import (
	"context"
	"errors"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// NativeWorkloadReadiness is an observational diagnostic, never a CP binding,
// grant, provider-support registration or production release certificate.
// The zero value deliberately signals denial, not a degraded operational mode.
type NativeWorkloadReadiness struct {
	HumanCurrent    bool
	WorkloadCurrent bool
	KratosReady     bool
	HydraReady      bool
}

// NativeWorkloadHealth is the existing Ory adapter's two-admin-plane probe.
// It does not select providers or establish capability entitlement.
type NativeWorkloadHealth interface {
	CheckReady(context.Context) (ReadyStatus, error)
}

// CheckGovernedNativeWorkloadReadiness combines the existing C4-02 native
// Kratos+Hydra authority composition, independently resolved workload issuer,
// and both provider health planes. All authority checks are current CP reads,
// not a cached declaration of provider support or an invitation to fail over
// from Ory to Keycloak.
//
// This is a non-authorising readiness observation: each *actual* login,
// consent, issuance and resource operation MUST repeat its own CP checks.
// There is no cross-service atomic guarantee between these reads.
func CheckGovernedNativeWorkloadReadiness(
	ctx context.Context,
	native, workload DispatchAuthority,
	health NativeWorkloadHealth,
) (NativeWorkloadReadiness, error) {
	deny := func() (NativeWorkloadReadiness, error) {
		return NativeWorkloadReadiness{}, errors.New("governed native/workload readiness denied")
	}
	if ctx == nil || ctx.Err() != nil ||
		absentDispatchAuthority(native) || absentDispatchAuthority(workload) ||
		absentHealth(health) {
		return deny()
	}
	// Native CP authority includes Kratos HUMAN_AUTHENTICATION and the
	// companion Hydra WORKLOAD_TOKEN_ISSUANCE + OAUTH_AUTHORIZATION_SERVER
	// runtime facets; an unrelated workload context cannot substitute.
	if native.CheckCapability(ctx, provider.CapabilityHumanAuthentication) != nil {
		return deny()
	}
	if workload.CheckCapability(ctx, provider.CapabilityWorkloadTokenIssue) != nil {
		return deny()
	}
	ready, err := health.CheckReady(ctx)
	if err != nil || !ready.OK() || ctx.Err() != nil {
		return deny()
	}
	// A provider health probe can race a release, binding or grant withdrawal.
	// Re-resolve both native and workload authority after checking health.
	if native.CheckCapability(ctx, provider.CapabilityHumanAuthentication) != nil ||
		workload.CheckCapability(ctx, provider.CapabilityWorkloadTokenIssue) != nil ||
		ctx.Err() != nil {
		return deny()
	}
	return NativeWorkloadReadiness{
		HumanCurrent: true, WorkloadCurrent: true,
		KratosReady: ready.KratosAdminOK, HydraReady: ready.HydraAdminOK,
	}, nil
}

func absentHealth(h NativeWorkloadHealth) bool {
	// A typed nil must not turn a missing deployment probe into readiness.
	if h == nil {
		return true
	}
	return nilHealth(h)
}
