package federation

import (
	"context"
	"sync"
	"time"
)

// RuntimeContextTarget is protected deployment input, never browser/token input.
// CP independently attests ownership and current tenant/organisation/market.
type RuntimeContextTarget struct {
	TenantID       string `json:"tenant_id"`
	OrganisationID string `json:"organisation_id"`
	CountryCode    string `json:"country_code"`
}

type runtimeContextWire struct {
	ContextID        string    `json:"context_id"`
	TenantID         string    `json:"tenant_id"`
	ResolvedAt       time.Time `json:"resolved_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	CountryCode      string    `json:"country_code"`
	MarketID         string    `json:"market_id"`
	CurrencyCode     string    `json:"currency_code"`
	OrganisationID   string    `json:"organisation_id"`
	OrganisationType string    `json:"organisation_type"`
}

// AcquireRuntimeContext uses the SAME IAM caller credential source as capability
// resolution. No caller-owned context handle is accepted from an estate. CP's
// returned finite expiry is authoritative; IAM never extends it locally.
func (a *HTTPAuthority) AcquireRuntimeContext(ctx context.Context, target RuntimeContextTarget, now func() time.Time) (ResolutionContext, error) {
	if a == nil || now == nil || !exact(target.TenantID) || !exact(target.OrganisationID) || len(target.CountryCode) != 2 || target.CountryCode[0] < 'A' || target.CountryCode[0] > 'Z' || target.CountryCode[1] < 'A' || target.CountryCode[1] > 'Z' {
		return ResolutionContext{}, ErrInvalid
	}
	started := now().UTC()
	var wire runtimeContextWire
	if err := a.call(ctx, "/v1/platform-context/resolve", target, &wire); err != nil {
		return ResolutionContext{}, err
	}
	finished := now().UTC()
	if ctx.Err() != nil || started.IsZero() || finished.Before(started) || !validResolutionContextID(wire.ContextID) || wire.TenantID != target.TenantID || wire.OrganisationID != target.OrganisationID || wire.CountryCode != target.CountryCode || wire.ResolvedAt.IsZero() || wire.ResolvedAt.After(finished) || !wire.ResolvedAt.Before(wire.ExpiresAt) || !finished.Before(wire.ExpiresAt) || wire.ExpiresAt.Sub(wire.ResolvedAt) > 15*time.Minute {
		return ResolutionContext{}, ErrUnverified
	}
	return ResolutionContext{wire.ContextID, wire.ExpiresAt}, nil
}

// ContextAcquirer creates a new CP-owned handle. It cannot mint local authority.
type ContextAcquirer func(context.Context) (ResolutionContext, error)

// SupervisedContexts owns a bounded handle, not an authorization cache. Every
// protected operation still repeats CP resolution/profile checks. One renewal
// is in flight at a time; any uncertain renewal clears the previous handle.
// Cancellation terminates the supervisor and invalidates all future reads.
type SupervisedContexts struct {
	lastObserved time.Time
	mu           sync.Mutex
	parent       context.Context
	acquire      ContextAcquirer
	now          func() time.Time
	margin       time.Duration
	value        ResolutionContext
	done         chan struct{}
}

func StartSupervisedContexts(ctx context.Context, acquire ContextAcquirer, now func() time.Time, interval, margin time.Duration) (*SupervisedContexts, error) {
	if ctx == nil || ctx.Err() != nil || acquire == nil || now == nil || interval <= 0 || margin < interval || margin > time.Minute {
		return nil, ErrInvalid
	}
	s := &SupervisedContexts{parent: ctx, acquire: acquire, now: now, margin: margin, done: make(chan struct{})}
	if _, err := s.Context(ctx); err != nil {
		return nil, err
	}
	go func() {
		defer close(s.done)
		timer := time.NewTicker(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				s.mu.Lock()
				s.value = ResolutionContext{}
				s.mu.Unlock()
				return
			case <-timer.C:
				_, _ = s.Context(ctx)
			}
		}
	}()
	return s, nil
}

func (s *SupervisedContexts) Context(ctx context.Context) (ResolutionContext, error) {
	if s == nil || ctx == nil || s.parent == nil || s.acquire == nil || s.now == nil {
		return ResolutionContext{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.parent.Err() != nil {
		s.value = ResolutionContext{}
		return ResolutionContext{}, ErrUnavailable
	}
	now := s.now().UTC()
	if now.IsZero() || now.Before(s.lastObserved) {
		s.value = ResolutionContext{}
		return ResolutionContext{}, ErrUnavailable
	}
	s.lastObserved = now
	if !now.IsZero() && validResolutionContextID(s.value.ContextID) && now.Add(s.margin).Before(s.value.ExpiresAt) {
		return s.value, nil
	}
	// Bound the acquisition by BOTH the request and service lifecycle. A cancelled
	// request cannot poison a later successful renewal with stale remote output.
	request, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.parent, cancel)
	defer stop()
	value, err := s.acquire(request)
	finished := s.now().UTC()
	if err != nil || request.Err() != nil || s.parent.Err() != nil || now.IsZero() || finished.Before(now) || !validResolutionContextID(value.ContextID) || !finished.Add(s.margin).Before(value.ExpiresAt) || value.ExpiresAt.Sub(finished) > 15*time.Minute {
		s.value = ResolutionContext{}
		return ResolutionContext{}, ErrUnavailable
	}
	s.lastObserved = finished
	s.value = value
	return value, nil
}

// Done permits executable shutdown to join the renewal worker.
func (s *SupervisedContexts) Done() <-chan struct{} { return s.done }
