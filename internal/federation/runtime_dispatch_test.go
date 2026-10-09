package federation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type runtimePlatform struct {
	value  PlatformSnapshot
	mutate func(*PlatformSnapshot, int)
	calls  int
	err    error
}

func (p *runtimePlatform) RuntimeBinding(_ context.Context, provider, instance string, scope Scope, facet string) (PlatformSnapshot, error) {
	p.calls++
	if provider != p.value.ProviderID || instance != p.value.EngineInstanceID || scope != p.value.Scope || facet != p.value.RuntimeCapability {
		return PlatformSnapshot{}, ErrDenied
	}
	out := p.value
	if p.mutate != nil {
		p.mutate(&out, p.calls)
	}
	return out, p.err
}
func runtimeSetup(t *testing.T, key string) (*RuntimeDispatch, *dispatchResolver, *runtimePlatform, *dispatchContext) {
	t.Helper()
	_, f := setup(t, "oidc")
	r := &dispatchResolver{f: f}
	h := &dispatchContext{value: ResolutionContext{"ctx_iamowned", f.clock.Add(2 * time.Minute)}}
	p := &runtimePlatform{value: f.platform}
	p.value.RuntimeCapability = runtimeFacet(key)
	d, err := NewRuntimeDispatch(RuntimeDispatchConfig{Resolver: r, Contexts: h, Platform: p, Scope: f.platform.Scope, CapabilityKey: key,
		ProviderID: p.value.ProviderID, EngineInstanceID: p.value.EngineInstanceID, ServiceReference: "service://baobab-iam/enterprise-federation", Now: func() time.Time { return f.clock }})
	if err != nil {
		t.Fatal(err)
	}
	return d, r, p, h
}
func TestRuntimeDispatchFreshSelectionAndProfile(t *testing.T) {
	for _, key := range []string{"identity.authentication.perform", "identity.workload-token.issue"} {
		t.Run(key, func(t *testing.T) {
			d, r, p, _ := runtimeSetup(t, key)
			for n := 0; n < 2; n++ {
				if err := d.Check(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if r.calls != 4 || p.calls != 4 {
				t.Fatal("authority was cached", r.calls, p.calls)
			}
		})
	}
}
func TestRuntimeDispatchDeniesResolutionAndLifecycleDrift(t *testing.T) {
	cases := map[string]func(*RuntimeDispatch, *dispatchResolver, *runtimePlatform, *dispatchContext){
		"denied": func(_ *RuntimeDispatch, r *dispatchResolver, _ *runtimePlatform, _ *dispatchContext) {
			r.mutate = func(v *CapabilityResolution) { v.Decision = "DENIED" }
		},
		"wrong-provider": func(_ *RuntimeDispatch, r *dispatchResolver, _ *runtimePlatform, _ *dispatchContext) {
			r.mutate = func(v *CapabilityResolution) { v.Invocation.ProviderID = "baobab-iam.other" }
		},
		"wrong-context": func(_ *RuntimeDispatch, r *dispatchResolver, _ *runtimePlatform, _ *dispatchContext) {
			r.mutate = func(v *CapabilityResolution) { v.ContextID = "ctx_foreign" }
		},
		"expired": func(d *RuntimeDispatch, r *dispatchResolver, _ *runtimePlatform, _ *dispatchContext) {
			r.mutate = func(v *CapabilityResolution) { now := d.config.Now(); v.ExpiresAt = &now }
		},
		"binding-withdrawn": func(_ *RuntimeDispatch, r *dispatchResolver, _ *runtimePlatform, _ *dispatchContext) {
			r.mutate = func(v *CapabilityResolution) {
				if r.calls > 1 {
					v.BindingID = "bind_changed"
				}
			}
		},
		"inactive": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.value.ProviderStatus = "SUSPENDED"
		},
		"partial": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.value.SupportStatus = "UNVERIFIED"
		},
		"artifact-drift": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.value.DeployedArtifactDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"cross-organisation": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.value.Scope.OrganisationID = "other"
		},
		"profile-drift": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.mutate = func(v *PlatformSnapshot, n int) {
				if n > 1 {
					v.ProfileRevision++
				}
			}
		},
		"stale-profile": func(d *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.value.EvidenceExpiresAt = d.config.Now()
		},
		"expired-context": func(d *RuntimeDispatch, _ *dispatchResolver, _ *runtimePlatform, h *dispatchContext) {
			h.value.ExpiresAt = d.config.Now()
		},
		"unavailable": func(_ *RuntimeDispatch, _ *dispatchResolver, p *runtimePlatform, _ *dispatchContext) {
			p.err = errors.New("offline")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d, r, p, h := runtimeSetup(t, "identity.workload-token.issue")
			change(d, r, p, h)
			if d.Check(context.Background()) == nil {
				t.Fatal("unsafe dispatch accepted")
			}
		})
	}
}

func TestRuntimeDispatchCannotAuthorizeDifferentCapability(t *testing.T) {
	d, _, _, _ := runtimeSetup(t, "identity.workload-token.issue")
	if d.CheckCapability(context.Background(), "identity.authentication.perform") == nil {
		t.Fatal("wrong operation admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.Check(ctx) == nil {
		t.Fatal("cancelled dispatch admitted")
	}
}
