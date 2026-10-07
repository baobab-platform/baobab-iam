package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

type dispatchContext struct {
	value ResolutionContext
	err   error
}

func (c *dispatchContext) Context(context.Context) (ResolutionContext, error) { return c.value, c.err }

type dispatchResolver struct {
	f      *fakeAuthority
	mutate func(*CapabilityResolution)
	err    error
	calls  int
}

func (r *dispatchResolver) ResolveCapability(_ context.Context, request CapabilityRequest) (CapabilityResolution, error) {
	r.calls++
	expires := r.f.clock.Add(time.Minute)
	b := r.f.snapshot.Trust.ProviderBinding
	out := CapabilityResolution{ResolutionID: "res_citest", ContextID: request.ContextID, CapabilityKey: request.CapabilityKey,
		ContractVersion: 1, Decision: "RESOLVED", GrantID: "grant_citest", BindingID: "bind_citest",
		ResolvedAt: r.f.clock, ExpiresAt: &expires, CorrelationID: request.CorrelationID,
		Invocation: &CapabilityInvocation{"service://baobab-iam/enterprise-federation", "http", 1, b.ProviderID, b.EngineInstanceID}}
	if r.mutate != nil {
		r.mutate(&out)
	}
	return out, r.err
}

type dispatchAdapter struct{ begins, completes int }

func (a *dispatchAdapter) BeginFederation(context.Context, provider.EnterpriseLogin) (provider.EnterpriseChallenge, error) {
	a.begins++
	return provider.EnterpriseChallenge{EventID: "approved-event"}, nil
}
func (a *dispatchAdapter) CompleteFederation(context.Context, provider.EnterpriseCallback) (provider.EnterpriseEvent, error) {
	a.completes++
	return provider.EnterpriseEvent{EventID: "approved-event"}, nil
}

func dispatchSetup(t *testing.T, protocol string) (*EnterpriseDispatch, *fakeAuthority, *dispatchResolver, *dispatchContext, *dispatchAdapter) {
	t.Helper()
	_, f := setup(t, protocol)
	r := &dispatchResolver{f: f}
	c := &dispatchContext{value: ResolutionContext{"ctx_iamowned", f.clock.Add(2 * time.Minute)}}
	a := &dispatchAdapter{}
	b := f.snapshot.Trust.ProviderBinding
	d, err := NewEnterpriseDispatch(EnterpriseDispatchConfig{Resolver: r, Contexts: c, Governance: f, Platform: f,
		Scope: f.platform.Scope, Adapters: []EnterpriseAdapterBinding{{b.ProviderID, b.EngineInstanceID, "service://baobab-iam/enterprise-federation", a}},
		Now: func() time.Time { return f.clock }})
	if err != nil {
		t.Fatal(err)
	}
	return d, f, r, c, a
}

func TestEnterpriseDispatchConsumesCPSelectionAndProtocolProjection(t *testing.T) {
	for _, protocol := range []string{"oidc", "saml2"} {
		t.Run(protocol, func(t *testing.T) {
			d, f, r, _, a := dispatchSetup(t, protocol)
			var observations []DispatchObservation
			d.config.Observe = func(o DispatchObservation) { observations = append(observations, o) }
			begin, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID})
			if err != nil || begin.EventID != "approved-event" || a.begins != 1 {
				t.Fatal(begin, err)
			}
			complete, err := d.CompleteFederation(context.Background(), provider.EnterpriseCallback{TrustID: f.snapshot.Trust.ID})
			if err != nil || complete.EventID != "approved-event" || a.completes != 1 || r.calls != 2 {
				t.Fatal(complete, err)
			}
			if len(observations) != 2 || observations[0].Outcome != "SELECTED" || observations[0].CorrelationID == observations[1].CorrelationID {
				t.Fatal("missing decision lineage or reused correlation")
			}
		})
	}
}

func TestEnterpriseDispatchRejectsInvalidCPDecisionsWithoutCallingAdapter(t *testing.T) {
	cases := map[string]func(*CapabilityResolution){
		"denied":                   func(r *CapabilityResolution) { r.Decision = "DENIED" },
		"ambiguous":                func(r *CapabilityResolution) { r.Decision = "AMBIGUOUS" },
		"unavailable":              func(r *CapabilityResolution) { r.Decision = "UNAVAILABLE" },
		"incompatible":             func(r *CapabilityResolution) { r.Decision = "INCOMPATIBLE" },
		"missing invocation":       func(r *CapabilityResolution) { r.Invocation = nil },
		"wrong capability":         func(r *CapabilityResolution) { r.CapabilityKey = "identity.workload-token.issue" },
		"candidate federation key": func(r *CapabilityResolution) { r.CapabilityKey = "identity.federation.enterprise" },
		"wrong context":            func(r *CapabilityResolution) { r.ContextID = "ctx_bffowned" },
		"wrong correlation":        func(r *CapabilityResolution) { r.CorrelationID = "22222222-2222-4222-8222-222222222222" },
		"invalid resolution":       func(r *CapabilityResolution) { r.ResolutionID = "secret callback material" },
		"missing grant":            func(r *CapabilityResolution) { r.GrantID = "" },
		"missing binding":          func(r *CapabilityResolution) { r.BindingID = "" },
		"denial reason in success": func(r *CapabilityResolution) { r.ReasonCode = "DENIED" },
		"wrong major":              func(r *CapabilityResolution) { r.ContractVersion = 2 },
		"wrong invocation major":   func(r *CapabilityResolution) { r.Invocation.ContractVersion = 2 },
		"wrong protocol":           func(r *CapabilityResolution) { r.Invocation.Protocol = "grpc" },
		"other provider":           func(r *CapabilityResolution) { r.Invocation.ProviderID = "provider_other" },
		"other instance":           func(r *CapabilityResolution) { r.Invocation.EngineInstanceID = "ei_other" },
		"raw endpoint":             func(r *CapabilityResolution) { r.Invocation.ServiceReference = "https://keycloak.attacker.test" },
		"other service":            func(r *CapabilityResolution) { r.Invocation.ServiceReference = "service://baobab-iam/native-login" },
		"missing expiry":           func(r *CapabilityResolution) { r.ExpiresAt = nil },
		"expired":                  func(r *CapabilityResolution) { at := r.ResolvedAt; r.ExpiresAt = &at },
		"extends context":          func(r *CapabilityResolution) { at := r.ResolvedAt.Add(time.Hour); r.ExpiresAt = &at },
		"future decision":          func(r *CapabilityResolution) { r.ResolvedAt = r.ResolvedAt.Add(time.Second) },
		"missing decision time":    func(r *CapabilityResolution) { r.ResolvedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d, f, r, _, a := dispatchSetup(t, "oidc")
			r.mutate = mutate
			var observed DispatchObservation
			d.config.Observe = func(o DispatchObservation) { observed = o }
			if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); err == nil || a.begins != 0 || a.completes != 0 {
				t.Fatal("unsafe selection reached adapter", err)
			}
			if observed.Outcome != "DENIED" || strings.Contains(observed.ResolutionID, "secret") {
				t.Fatal("unsafe observation")
			}
		})
	}
}

func TestEnterpriseDispatchRevalidatesTrustProfileAndCallback(t *testing.T) {
	cases := map[string]func(*fakeAuthority, *dispatchResolver, *dispatchContext){
		"revoked trust": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.snapshot.Trust.Status = "REVOKED" },
		"trust changed during selection": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.changeOnRecheck = true
			f.trustCalls = 0
		},
		"trust contained during selection": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.revokeOnRecheck = true
			f.trustCalls = 0
		},
		"expired trust":       func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.snapshot.ValidUntil = f.clock },
		"unapproved revision": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.snapshot.ApprovedRevision = 0 },
		"wrong scope": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.snapshot.Trust.EstateIDs = []string{"estate_other"}
		},
		"unsupported protocol": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.snapshot.Trust.Protocol = "SCIM" },
		"profile unsupported": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.platform.SupportStatus = "UNSUPPORTED"
		},
		"profile expired": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.platform.EvidenceExpiresAt = f.clock
		},
		"wrong artifact": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.platform.DeployedArtifactDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"instance draining": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.platform.InstanceStatus = "DRAINING"
		},
		"provider suspended": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) {
			f.platform.ProviderStatus = "SUSPENDED"
		},
		"binding revoked":  func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.platform.BindingStatus = "REVOKED" },
		"authority outage": func(f *fakeAuthority, _ *dispatchResolver, _ *dispatchContext) { f.err = ErrUnavailable },
		"resolver outage":  func(_ *fakeAuthority, r *dispatchResolver, _ *dispatchContext) { r.err = ErrUnavailable },
		"context outage":   func(_ *fakeAuthority, _ *dispatchResolver, c *dispatchContext) { c.err = ErrUnavailable },
		"context expired":  func(f *fakeAuthority, _ *dispatchResolver, c *dispatchContext) { c.value.ExpiresAt = f.clock },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d, f, r, c, a := dispatchSetup(t, "oidc")
			if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); err != nil {
				t.Fatal(err)
			}
			mutate(f, r, c)
			if _, err := d.CompleteFederation(context.Background(), provider.EnterpriseCallback{TrustID: f.snapshot.Trust.ID}); err == nil || a.completes != 0 {
				t.Fatal("callback reused stale begin authority", err)
			}
		})
	}
}

func TestEnterpriseDispatchAdapterInventoryCannotChooseProvider(t *testing.T) {
	d, f, _, _, a := dispatchSetup(t, "oidc")
	c := d.config
	c.Adapters = append(c.Adapters, c.Adapters[0])
	if _, err := NewEnterpriseDispatch(c); err == nil {
		t.Fatal("duplicate adapter accepted")
	}
	c = d.config
	c.Adapters = []EnterpriseAdapterBinding{{"provider_other", "ei_other", "service://baobab-iam/enterprise-federation", a}}
	d, err := NewEnterpriseDispatch(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); !errors.Is(err, ErrUnsupported) || a.begins != 0 {
		t.Fatal("unavailable selected adapter fell back", err)
	}
}

func TestEnterpriseDispatchComposesAuthenticatedCPWireAndLiveProjection(t *testing.T) {
	d, f, resolver, _, a := dispatchSetup(t, "oidc")
	var paths []string
	authority, _ := tlsAuthority(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer service-token" {
			t.Fatal("unauthenticated resolution")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/capabilities/resolve":
			var req CapabilityRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.CapabilityKey != "identity.authentication.perform" || req.ContextID != "ctx_iamowned" || req.RequiredContractVersion != 1 || !uuidPattern.MatchString(req.CorrelationID) {
				t.Error("incorrect canonical request")
			}
			out, _ := resolver.ResolveCapability(r.Context(), req)
			json.NewEncoder(w).Encode(out)
		case "/internal/federation/v1/binding":
			var req platformBindingWire
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Binding != f.snapshot.Trust.ProviderBinding || req.RuntimeCapability != RuntimeOIDCFederation || req.platformScope() != f.platform.Scope {
				t.Error("incorrect runtime projection request")
			}
			json.NewEncoder(w).Encode(f.platform)
		default:
			t.Error("unreviewed source path")
			w.WriteHeader(404)
		}
	})
	d.config.Resolver, d.config.Platform = authority, authority
	if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); err != nil || a.begins != 1 || len(paths) != 2 {
		t.Fatal("composed CP dispatch failed", err, paths)
	}
}

func TestProtectedResolutionContextReloadsAndRejectsUnsafeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "context.json")
	write := func(value string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	source := FileResolutionContexts{path}
	write(`{"context_id":"ctx_first","expires_at":"2026-10-05T17:00:00Z"}`, 0600)
	first, err := source.Context(context.Background())
	if err != nil || first.ContextID != "ctx_first" {
		t.Fatal(first, err)
	}
	write(`{"context_id":"ctx_renewed","expires_at":"2026-10-05T17:01:00Z"}`, 0600)
	second, err := source.Context(context.Background())
	if err != nil || second.ContextID != "ctx_renewed" {
		t.Fatal("context cached", second, err)
	}
	for _, value := range []string{`{"context_id":"x","context_id":"y"}`, `{"provider":"keycloak"}`, `{} {}`, `{"context_id":null}`} {
		write(value, 0600)
		if _, err := source.Context(context.Background()); err == nil {
			t.Fatal("unsafe document admitted")
		}
	}
	write(`{}`, 0644)
	if _, err := source.Context(context.Background()); err == nil {
		t.Fatal("public file accepted")
	}
}

type recheckUnavailableGovernance struct {
	*fakeAuthority
	calls int
}

func (g *recheckUnavailableGovernance) Trust(ctx context.Context, id string) (TrustSnapshot, error) {
	g.calls++
	if g.calls > 1 {
		return TrustSnapshot{}, ErrUnavailable
	}
	return g.fakeAuthority.Trust(ctx, id)
}
func TestEnterpriseDispatchPreservesUnavailableOnFinalAuthorityRead(t *testing.T) {
	d, f, _, _, a := dispatchSetup(t, "oidc")
	d.config.Governance = &recheckUnavailableGovernance{fakeAuthority: f}
	if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); !errors.Is(err, ErrUnavailable) || a.begins != 0 {
		t.Fatal(err, a.begins)
	}
}
func TestEnterpriseDispatchRejectsClockRollback(t *testing.T) {
	d, f, _, _, a := dispatchSetup(t, "oidc")
	calls := 0
	d.config.Now = func() time.Time {
		calls++
		if calls > 1 {
			return f.clock.Add(-time.Second)
		}
		return f.clock
	}
	if _, err := d.BeginFederation(context.Background(), provider.EnterpriseLogin{TrustID: f.snapshot.Trust.ID}); err == nil || a.begins != 0 {
		t.Fatal(err, a.begins)
	}
}
