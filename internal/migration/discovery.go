// Target path: baobab-iam/internal/migration/discovery.go
//
// FixtureDiscovery is a Phase C DiscoveryPort backed by an in-memory list.
// It enables batch registration tests without a live Keycloak Admin API.
package migration

import (
	"context"
	"fmt"
)

// FixtureDiscovery returns a fixed set of SourceBindings for any batch ID.
// Not for production discovery.
type FixtureDiscovery struct {
	Bindings []SourceBinding
}

// ListSourceBindings implements DiscoveryPort.
func (d FixtureDiscovery) ListSourceBindings(_ context.Context, batchID string) ([]SourceBinding, error) {
	if batchID == "" {
		return nil, fmt.Errorf("migration: batchID is required")
	}
	// Return a copy so callers cannot mutate the fixture slice header
	// in a way that affects the fixture (shallow copy of the slice).
	out := make([]SourceBinding, len(d.Bindings))
	copy(out, d.Bindings)
	return out, nil
}

// MapCanonicalResolver is an in-memory CanonicalResolver for tests and pilots.
// Key format: issuer + "\x00" + subject.
type MapCanonicalResolver struct {
	// Mapping is issuer\x00subject → canonical_identity_id.
	Mapping map[string]string
}

// key builds the lookup key for a source binding.
func (m MapCanonicalResolver) key(source ProviderBinding) string {
	return source.Issuer + "\x00" + source.Subject
}

// ResolveCanonical implements CanonicalResolver.
func (m MapCanonicalResolver) ResolveCanonical(_ context.Context, source ProviderBinding) (string, error) {
	if source.Issuer == "" || source.Subject == "" {
		return "", fmt.Errorf("migration: issuer and subject are required for canonical resolve")
	}
	if m.Mapping == nil {
		return "", ErrNoCanonicalMapping
	}
	id, ok := m.Mapping[m.key(source)]
	if !ok || id == "" {
		return "", ErrNoCanonicalMapping
	}
	return id, nil
}
