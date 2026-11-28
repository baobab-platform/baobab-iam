package admin

import (
	"context"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type workloadExecutionFixture struct {
	target        WorkloadTarget
	now           time.Time
	reserved      bool
	disabled      int
	verified      bool
	changedTarget bool
	missingDenial bool
}

func (f *workloadExecutionFixture) ResolveWorkloadTarget(context.Context, Request) (WorkloadTarget, error) {
	target := f.target
	if f.reserved && f.changedTarget {
		target.Client.ProviderClientID = "different-client"
	}
	return target, nil
}

func (f *workloadExecutionFixture) DisableWorkload(_ context.Context, client provider.ProviderWorkloadReference) error {
	if client != f.target.Client {
		return ErrBreakGlassDenied
	}
	f.disabled++
	return nil
}

func (f *workloadExecutionFixture) VerifyWorkloadDenial(context.Context, Request, WorkloadTarget) (WorkloadDenial, error) {
	if f.missingDenial {
		return WorkloadDenial{}, ErrBreakGlassDenied
	}
	return WorkloadDenial{Target: f.target, ObservedAt: f.now, Reference: "ref_denial_original"}, nil
}

func (f *workloadExecutionFixture) ReserveWorkloadExecution(context.Context, Request, WorkloadTarget) error {
	if f.reserved {
		return ErrBreakGlassDenied
	}
	f.reserved = true
	return nil
}

func (f *workloadExecutionFixture) VerifyWorkloadExecution(context.Context, Request, WorkloadDenial) error {
	f.verified = true
	return nil
}

func TestEmergencyWorkloadRevocationScopesAndFencesExecution(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		change, missing, withdraw bool
		wantDisable               int
		wantVerified              bool
	}{
		{name: "verified", wantDisable: 1, wantVerified: true},
		{name: "target changed", change: true},
		{name: "lease withdrawn", withdraw: true},
		{name: "provider changed but existing token denial unavailable", missing: true, wantDisable: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			lease, journal, verifier, _, _, request := setup(now)
			request.Action, request.ScopeType = revokeOAuthClient, "OAUTH_CLIENT"
			if err := lease.Activate(ctx, request); err != nil {
				t.Fatal(err)
			}
			f := &workloadExecutionFixture{now: now, target: WorkloadTarget{ScopeID: request.ScopeID, Revision: 1,
				Client:     provider.ProviderWorkloadReference{LogicalClientID: "worker", ProviderClientID: "native-worker"},
				ValidUntil: now.Add(time.Minute)}, changedTarget: tc.change, missingDenial: tc.missing}
			if tc.withdraw {
				verifier.onVerify = func() {
					if f.reserved {
						_ = journal.Terminate(ctx, request.LeaseID)
					}
				}
			}
			executor := WorkloadRevoker{Lease: lease, Targets: f, Hydra: f, Denial: f, Journal: f}
			if err := executor.Execute(ctx, request); (err == nil) != tc.wantVerified ||
				f.disabled != tc.wantDisable || f.verified != tc.wantVerified {
				t.Fatalf("unexpected execution result: %v, mutations %d, verified %t", err, f.disabled, f.verified)
			}
			if err := executor.Execute(ctx, request); err == nil || f.disabled != tc.wantDisable {
				t.Fatal("reserved execution replayed")
			}
		})
	}
}
