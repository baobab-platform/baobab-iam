package federation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireRuntimeContextUsesCurrentCallerAndExactTarget(t *testing.T) {
	d, _, p, _ := runtimeSetup(t, "identity.workload-token.issue")
	target := RuntimeContextTarget{"tn_iam", "org_iam", "ZA"}
	now := d.config.Now()
	wire := runtimeContextWire{ContextID: "ctx_owned", TenantID: target.TenantID, OrganisationID: target.OrganisationID, CountryCode: "ZA", ResolvedAt: now, ExpiresAt: now.Add(time.Minute)}
	for _, scenario := range []string{"valid", "foreign tenant", "foreign organisation", "foreign market", "unbounded", "expired", "future", "excess lifetime", "unknown wire", "outage"} {
		t.Run(scenario, func(t *testing.T) {
			out := wire
			switch scenario {
			case "foreign tenant":
				out.TenantID = "tn_other"
			case "foreign organisation":
				out.OrganisationID = "org_other"
			case "foreign market":
				out.CountryCode = "UG"
			case "unbounded":
				out.ExpiresAt = time.Time{}
			case "expired":
				out.ExpiresAt = now
			case "future":
				out.ResolvedAt = now.Add(time.Second)
			case "excess lifetime":
				out.ExpiresAt = now.Add(time.Hour)
			}
			a, tokens := runtimeHTTP(t, runtimeTarget(p.value), d.config.Now, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/platform-context/resolve" || r.Method != "POST" {
					t.Error("wrong endpoint")
				}
				var got RuntimeContextTarget
				if json.NewDecoder(r.Body).Decode(&got) != nil || got != target {
					t.Error("retargeted context")
				}
				w.Header().Set("Content-Type", "application/json")
				if scenario == "outage" {
					w.WriteHeader(503)
					return
				}
				if scenario == "unknown wire" {
					_, _ = w.Write([]byte(`{"context_id":"ctx_owned","authority":true}`))
					return
				}
				_ = json.NewEncoder(w).Encode(out)
			})
			got, err := a.transport.AcquireRuntimeContext(context.Background(), target, d.config.Now)
			if scenario == "valid" {
				if err != nil || got.ContextID != "ctx_owned" {
					t.Fatal(got, err)
				}
			} else if err == nil || got.ContextID != "" {
				t.Fatal("invalid proof returned", got, err)
			}
			if tokens.calls != 1 {
				t.Fatal("credential missing")
			}
		})
	}
}

func TestSupervisedContextsRenewDenyRecoverAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	var calls atomic.Int64
	var deny atomic.Bool
	acquire := func(context.Context) (ResolutionContext, error) {
		n := calls.Add(1)
		if deny.Load() {
			return ResolutionContext{}, errors.New("unavailable")
		}
		id := "ctx_first"
		if n > 1 {
			id = "ctx_next"
		}
		return ResolutionContext{id, time.Unix(0, clock.Load()).Add(time.Minute)}, nil
	}
	s, err := StartSupervisedContexts(ctx, acquire, func() time.Time { return time.Unix(0, clock.Load()) }, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Context(ctx)
	if err != nil || got.ContextID != "ctx_first" {
		t.Fatal(got, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Context(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("unexpected renewal")
	}
	clock.Store(now.Add(51 * time.Second).UnixNano())
	deny.Store(true)
	if got, err = s.Context(ctx); err == nil || got.ContextID != "" {
		t.Fatal("stale authority reused")
	}
	deny.Store(false)
	if got, err = s.Context(ctx); err != nil || got.ContextID != "ctx_next" {
		t.Fatal("renewal did not recover", err)
	}
	cancel()
	<-s.Done()
	if got, err = s.Context(context.Background()); err == nil || got.ContextID != "" {
		t.Fatal("cancelled supervisor reused")
	}
}

func TestSupervisedContextsRejectUnsafeAcquisitions(t *testing.T) {
	for _, value := range []ResolutionContext{{}, {"ctx_expired", time.Now().Add(-time.Second)}, {"ctx_unbounded", time.Time{}}, {"ctx_too_long", time.Now().Add(time.Hour)}, {"ctx_too_short", time.Now().Add(time.Second)}} {
		if s, err := StartSupervisedContexts(context.Background(), func(context.Context) (ResolutionContext, error) { return value, nil }, time.Now, time.Second, 10*time.Second); err == nil {
			t.Fatal("unsafe acquisition accepted", s)
		}
	}
}

func TestSupervisorRenewsInBackgroundAndCancelsBlockedRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	var calls atomic.Int64
	entered := make(chan struct{})
	s, err := StartSupervisedContexts(ctx, func(call context.Context) (ResolutionContext, error) {
		if calls.Add(1) == 1 {
			return ResolutionContext{"ctx_initial", now.Add(time.Minute)}, nil
		}
		close(entered)
		<-call.Done()
		return ResolutionContext{}, call.Err()
	}, func() time.Time { return time.Unix(0, clock.Load()) }, time.Millisecond, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clock.Store(now.Add(51 * time.Second).UnixNano())
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background renewal did not start")
	}
	cancel()
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("renewal did not stop")
	}
	if _, err := s.Context(context.Background()); err == nil {
		t.Fatal("cancelled renewal retained context")
	}
}

func TestSupervisorRejectsClockRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	s, err := StartSupervisedContexts(ctx, func(context.Context) (ResolutionContext, error) {
		return ResolutionContext{"ctx_clock", now.Add(time.Minute)}, nil
	}, func() time.Time { return time.Unix(0, clock.Load()) }, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-s.Done() }()
	clock.Store(now.Add(-time.Second).UnixNano())
	if got, err := s.Context(ctx); err == nil || got.ContextID != "" {
		t.Fatal("clock rollback reused lease")
	}
}
