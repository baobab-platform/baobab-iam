// Package workloadresource defines the provider-neutral, resource-side
// workload token acceptance boundary (ADR-IAM-0020/0033, EA-DEV DEV-03/14/15).
//
// OAuth/JWKS/introspection remain direct standards. A signed token is never a
// CP Principal, a Tenant grant, a legal mandate or a native business approval.
// A resource consumes its own issuer verifier, current issuer status and CP
// authority adapters. It must not call Baobab IAM as an OAuth proxy.
package workloadresource

import (
	"context"
	"errors"
	"reflect"
	"net/url"
	"slices"
	"strings"
	"time"
)

var ErrDenied = errors.New("workload resource admission denied")

// Claims contains only verified security claims; no Tenant, Organisation,
// Market, external business partner or derived canonical entitlements.
type Claims struct {
	Issuer string
	Subject string
	ClientID string
	Audience []string
	Scopes []string
	ActorType string
	IssuedAt time.Time
	NotBefore time.Time
	ExpiresAt time.Time
}

// LiveStatus is independent RFC 7662/issuer state, not an offline JWT decode.
// Time zero for IssuedAt is allowed: Hydra signs JWT and timestamps its
// introspection requester at different instants.
type LiveStatus struct {
	Active bool
	Issuer string
	Subject string
	ClientID string
	Audience []string
	Scopes []string
	ExpiresAt time.Time
}

// SignedTokenVerifier authenticates a provider-issued signed token (JWKS).
// Neither the caller nor CP may supply a verified Claim object directly.
type SignedTokenVerifier interface {
	VerifySigned(context.Context, string) (Claims, error)
}

// IssuerStatusReader independently reads current issuer state for EXACTLY
// the same original bearer before and after current CP authorization.
type IssuerStatusReader interface {
	ReadCurrent(context.Context, string) (LiveStatus, error)
}

// CurrentAuthority is a current CP-owned decision/consumer integration.
// It MUST verify exact current Principal, context, grant and withdrawal for
// the requested resource operation; implementations cannot use JWT tenant
// fields, a static YAML grant or a local fabricated allowlist as authority.
type CurrentAuthority interface {
	AuthorizeCurrent(context.Context, string, Claims, Operation) error
}

// Operation data must originate from an application-controlled resource
// operation and its canonical CP context, never token content.
type Operation struct {
	ContextID string
	TenantID string
	ResourceOperation string
}

// Profile is immutable, trusted resource configuration. ClientIDs and scopes
// are independently adopted from the reviewed Shared/CP registry. Missing
// or broad/ambiguous trusted profile parameters are refused.
type Profile struct {
	Issuer string
	Audience string
	RequiredScopes []string
	AllowedClients []string
	MaxTokenAge time.Duration
}

type Gate struct {
	p Profile
	verified SignedTokenVerifier
	issuer IssuerStatusReader
	authority CurrentAuthority
}

// No local status cache or fallback token verifier is permitted.
func New(p Profile, verified SignedTokenVerifier, issuer IssuerStatusReader, authority CurrentAuthority) (*Gate, error) {
	return newGate(p, verified, issuer, authority, false)
}

// Internal-only test path accepts the exact disposable issuer. Production
// consumers can only call New, which requires an HTTPS issuer.
func newGate(p Profile, verified SignedTokenVerifier, issuer IssuerStatusReader, authority CurrentAuthority, loopbackFixture bool) (*Gate, error) {
	parsed, parseErr := url.Parse(p.Issuer)
	if parseErr != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" { return nil, ErrDenied }
	if absent(verified) || absent(issuer) || absent(authority) ||
		(!strings.HasPrefix(p.Issuer, "https://") &&
			!(loopbackFixture && p.Issuer == "http://127.0.0.1:4444")) || p.Audience == "" ||
		len(p.RequiredScopes) == 0 || len(p.AllowedClients) == 0 ||
		p.MaxTokenAge <= 0 || p.MaxTokenAge > 15*time.Minute ||
		!distinct(p.RequiredScopes) || !distinct(p.AllowedClients) ||
		strings.TrimSpace(p.Audience) != p.Audience {
		return nil, ErrDenied
	}
	for _, value := range append(slices.Clone(p.RequiredScopes), p.AllowedClients...) {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n*") {
			return nil, ErrDenied
		}
	}
	return &Gate{p: p, verified: verified, issuer: issuer, authority: authority}, nil
}

func absent(v any) bool {
	if v == nil { return true }
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func distinct(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok { return false }
		seen[value] = struct{}{}
	}
	return true
}
func sameSet(a, b []string) bool {
	if !distinct(a) || !distinct(b) || len(a) != len(b) { return false }
	for _, v := range a { if !slices.Contains(b, v) { return false } }
	return true
}
func containsAll(actual, needed []string) bool {
	if !distinct(actual) { return false }
	for _, v := range needed { if !slices.Contains(actual, v) { return false } }
	return true
}

func (g *Gate) current(ctx context.Context, raw string, signed Claims) error {
	status, err := g.issuer.ReadCurrent(ctx, raw)
	if err != nil || ctx.Err() != nil || !status.Active ||
		status.Issuer != signed.Issuer || status.Subject != signed.Subject ||
		status.ClientID != signed.ClientID ||
		!sameSet(status.Audience, signed.Audience) ||
		!sameSet(status.Scopes, signed.Scopes) ||
		!status.ExpiresAt.Equal(signed.ExpiresAt) ||
		!time.Now().Before(status.ExpiresAt) {
		return ErrDenied
	}
	return nil
}

// Authorize checks signed JWT, independent unexpired current issuer status,
// *fresh* CP authority and then issuer status again. A provider outage,
// suspended client, Principal deactivation, changed binding or stale resource
// context is DENY, never a cached allow. It proves no cross-service atomicity;
// the native business commit must repeat relevant owner-native vetoes.
func (g *Gate) Authorize(ctx context.Context, bearer string, operation Operation) error {
	if g == nil || ctx == nil || ctx.Err() != nil || len(bearer) < 20 ||
		len(bearer) > 16384 || strings.TrimSpace(bearer) != bearer ||
		operation.ContextID == "" || operation.TenantID == "" ||
		operation.ResourceOperation == "" {
		return ErrDenied
	}
	signed, err := g.verified.VerifySigned(ctx, bearer)
	now := time.Now()
	if err != nil || ctx.Err() != nil || signed.Issuer != g.p.Issuer ||
		signed.Subject == "" || signed.ClientID == "" ||
		signed.ActorType != "workload" ||
		!slices.Contains(g.p.AllowedClients, signed.ClientID) ||
		!sameSet(signed.Audience, []string{g.p.Audience}) ||
		!containsAll(signed.Scopes, g.p.RequiredScopes) ||
		signed.IssuedAt.IsZero() || signed.ExpiresAt.IsZero() ||
		now.Before(signed.IssuedAt) || now.Before(signed.NotBefore) ||
		!now.Before(signed.ExpiresAt) ||
		signed.ExpiresAt.Sub(signed.IssuedAt) > g.p.MaxTokenAge ||
		signed.ExpiresAt.Sub(signed.IssuedAt) <= 0 {
		return ErrDenied
	}
	if g.current(ctx, bearer, signed) != nil {
		return ErrDenied
	}
	if err := g.authority.AuthorizeCurrent(ctx, bearer, signed, operation); err != nil || ctx.Err() != nil {
		return ErrDenied
	}
	if g.current(ctx, bearer, signed) != nil {
		return ErrDenied
	}
	return nil
}
