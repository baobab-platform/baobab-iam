package ory

import (
	"context"
	"errors"
	"testing"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

// The test authority is deliberately NOT a CP fixture. It proves the
// readiness function invokes the two different facets and rejects drift.
// Live CP and provider registration acceptance remains a separate gate.
type c404Authority struct {
	want   string
	calls  int
	denyAt int
	probe  func()
}

func (a *c404Authority) CheckCapability(ctx context.Context, key string) error {
	a.calls++
	if a.probe != nil {
		a.probe()
	}
	if ctx.Err() != nil || key != a.want || (a.denyAt != 0 && a.calls >= a.denyAt) {
		return errors.New("current CP authority unavailable or withdrawn")
	}
	return nil
}

type c404HealthProbe struct {
	status ReadyStatus
	err    error
	onRead func()
	calls  int
}

func (p *c404HealthProbe) CheckReady(ctx context.Context) (ReadyStatus, error) {
	p.calls++
	if p.onRead != nil {
		p.onRead()
	}
	if ctx.Err() != nil {
		return ReadyStatus{}, ctx.Err()
	}
	return p.status, p.err
}

func c404Inputs() (*c404Authority, *c404Authority, *c404HealthProbe) {
	return &c404Authority{want: provider.CapabilityHumanAuthentication},
		&c404Authority{want: provider.CapabilityWorkloadTokenIssue},
		&c404HealthProbe{status: ReadyStatus{KratosAdminOK: true, HydraAdminOK: true}}
}

func TestC404ReadinessRechecksIndependentCPFacetsAfterProviderHealth(t *testing.T) {
	human, workload, health := c404Inputs()
	result, err := CheckGovernedNativeWorkloadReadiness(context.Background(), human, workload, health)
	if err != nil || !result.HumanCurrent || !result.WorkloadCurrent || !result.KratosReady || !result.HydraReady {
		t.Fatal("valid observed dual-authority readiness denied", err)
	}
	if human.calls != 2 || workload.calls != 2 || health.calls != 1 {
		t.Fatal("CP authorities or native health were skipped or cached")
	}
	// Repeated observations cannot reuse the last verdict.
	_, err = CheckGovernedNativeWorkloadReadiness(context.Background(), human, workload, health)
	if err != nil || human.calls != 4 || workload.calls != 4 || health.calls != 2 {
		t.Fatal("stale readiness reused")
	}
}

func TestC404ReadinessFailsClosedForEachAuthorityAndProviderFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*c404Authority, *c404Authority, *c404HealthProbe)
	}{
		{"human unregistered", func(h, w *c404Authority, p *c404HealthProbe) { h.denyAt = 1 }},
		{"workload unregistered", func(h, w *c404Authority, p *c404HealthProbe) { w.denyAt = 1 }},
		{"human withdrawn during health", func(h, w *c404Authority, p *c404HealthProbe) {
			p.onRead = func() { h.denyAt = 2 }
		}},
		{"issuer withdrawn during health", func(h, w *c404Authority, p *c404HealthProbe) {
			p.onRead = func() { w.denyAt = 2 }
		}},
		{"Kratos outage", func(h, w *c404Authority, p *c404HealthProbe) { p.status.KratosAdminOK = false }},
		{"Hydra outage", func(h, w *c404Authority, p *c404HealthProbe) { p.status.HydraAdminOK = false }},
		{"provider observation error", func(h, w *c404Authority, p *c404HealthProbe) {
			p.err = errors.New("health unavailable")
		}},
		{"wrong human facet", func(h, w *c404Authority, p *c404HealthProbe) {
			h.want = provider.CapabilityWorkloadTokenIssue
		}},
		{"wrong workload facet", func(h, w *c404Authority, p *c404HealthProbe) {
			w.want = provider.CapabilityHumanAuthentication
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			human, workload, health := c404Inputs()
			tc.mutate(human, workload, health)
			result, err := CheckGovernedNativeWorkloadReadiness(context.Background(), human, workload, health)
			if err == nil || result != (NativeWorkloadReadiness{}) {
				t.Fatal("failed or drifting authority produced a positive readiness")
			}
		})
	}
}

func TestC404ReadinessRejectsMissingOrCancelledAuthority(t *testing.T) {
	human, workload, health := c404Inputs()
	var missingHuman *c404Authority
	var missingHealth *c404HealthProbe
	for _, inputs := range []struct {
		human, workload DispatchAuthority
		health          NativeWorkloadHealth
	}{
		{nil, workload, health},
		{missingHuman, workload, health},
		{human, nil, health},
		{human, workload, nil},
		{human, workload, missingHealth},
	} {
		got, err := CheckGovernedNativeWorkloadReadiness(context.Background(), inputs.human, inputs.workload, inputs.health)
		if err == nil || got != (NativeWorkloadReadiness{}) {
			t.Fatal("missing typed or untyped authority accepted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := CheckGovernedNativeWorkloadReadiness(cancelled, human, workload, health)
	if err == nil || got != (NativeWorkloadReadiness{}) || human.calls != 0 || workload.calls != 0 || health.calls != 0 {
		t.Fatal("cancelled context reached a provider or returned readiness")
	}
}

func TestC404ReadinessCannotTurnCancellationDuringHealthIntoSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	human, workload, health := c404Inputs()
	health.onRead = cancel
	got, err := CheckGovernedNativeWorkloadReadiness(ctx, human, workload, health)
	if err == nil || got != (NativeWorkloadReadiness{}) {
		t.Fatal("cancelled authority operation accepted")
	}
	if human.calls != 1 || workload.calls != 1 || health.calls != 1 {
		t.Fatal("health-read cancellation bypassed expected gate order")
	}
}
