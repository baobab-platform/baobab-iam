package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type runtimeTokens struct{ calls int }

func (s *runtimeTokens) Token(context.Context) (string, error) {
	s.calls++
	return fmt.Sprintf("service-%d", s.calls), nil
}

func runtimeTarget(p PlatformSnapshot) RuntimeAuthorityTarget {
	return RuntimeAuthorityTarget{ProviderID: p.ProviderID, EngineInstanceID: p.EngineInstanceID,
		Scope: p.Scope, RuntimeCapability: p.RuntimeCapability,
		ConfigurationReference: "ref_nativeconfig", SecurityDomainReference: "ref_securitydomain"}
}
func runtimeHTTP(t *testing.T, target RuntimeAuthorityTarget, now func() time.Time, h http.HandlerFunc) (*HTTPRuntimeAuthority, *runtimeTokens) {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tokens := &runtimeTokens{}
	a, err := NewHTTPRuntimeAuthority(server.URL, tokens, &tls.Config{RootCAs: roots}, target, now)
	if err != nil {
		t.Fatal(err)
	}
	return a, tokens
}

// Exercise the production HTTP adapter through the existing dispatch gate:
// each operation repeats real TLS reads and obtains fresh service credentials.
// The remote CP server is a wire fixture; PostgreSQL authority is tested in CP.
func TestHTTPRuntimeAuthorityComposesFreshDispatch(t *testing.T) {
	for _, key := range []string{"identity.authentication.perform", "identity.workload-token.issue"} {
		t.Run(key, func(t *testing.T) {
			d, _, p, _ := runtimeSetup(t, key)
			target := runtimeTarget(p.value)
			calls := 0
			revoked := false
			a, tokens := runtimeHTTP(t, target, d.config.Now, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/internal/identity-runtime/v1/binding" || r.Method != "POST" ||
					r.Header.Get("Authorization") != fmt.Sprintf("Bearer service-%d", calls) {
					t.Error("authority destination or current credential mismatch")
				}
				var req runtimeBindingWire
				if json.NewDecoder(r.Body).Decode(&req) != nil ||
					req.ProviderID != target.ProviderID || req.EngineInstanceID != target.EngineInstanceID ||
					req.OrganisationID != target.Scope.OrganisationID || req.EstateID != target.Scope.EstateID ||
					req.ConfigurationReference != target.ConfigurationReference ||
					req.SecurityDomainReference != target.SecurityDomainReference || req.RuntimeCapability != target.RuntimeCapability {
					t.Error("composition references or scope changed on wire")
				}
				w.Header().Set("Content-Type", "application/json")
				if revoked {
					w.WriteHeader(http.StatusConflict)
					return
				}
				_ = json.NewEncoder(w).Encode(p.value)
			})
			d.config.Platform = a
			if err := d.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := d.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls != 4 || tokens.calls != 4 {
				t.Fatal("authority cached", calls, tokens.calls)
			}
			if _, err := a.RuntimeBinding(context.Background(), target.ProviderID, target.EngineInstanceID, Scope{"foreign", target.Scope.EstateID}, target.RuntimeCapability); !errors.Is(err, ErrDenied) || calls != 4 {
				t.Fatal("foreign scope reached authority", err, calls)
			}
			revoked = true
			if d.Check(context.Background()) == nil {
				t.Fatal("withdrawn CP evidence reused")
			}
		})
	}
}
func TestHTTPRuntimeAuthorityRejectsUnsafeEvidence(t *testing.T) {
	d, _, p, _ := runtimeSetup(t, "identity.workload-token.issue")
	cases := map[string]func(*PlatformSnapshot){
		"provider":           func(p *PlatformSnapshot) { p.ProviderID = "provider_foreign" },
		"instance":           func(p *PlatformSnapshot) { p.EngineInstanceID = "ei_foreign" },
		"scope":              func(p *PlatformSnapshot) { p.Scope.EstateID = "estate_foreign" },
		"facet":              func(p *PlatformSnapshot) { p.RuntimeCapability = "OIDC_FEDERATION" },
		"inactive":           func(p *PlatformSnapshot) { p.InstanceStatus = "MAINTENANCE" },
		"unsupported":        func(p *PlatformSnapshot) { p.SupportStatus = "UNSUPPORTED" },
		"binding":            func(p *PlatformSnapshot) { p.BindingStatus = "RETIRED" },
		"provider lifecycle": func(p *PlatformSnapshot) { p.ProviderStatus = "SUSPENDED" },
		"revision":           func(p *PlatformSnapshot) { p.ProfileRevision = 0 },
		"artifact":           func(p *PlatformSnapshot) { p.DeployedArtifactDigest = "sha256:" + strings.Repeat("f", 64) },
		"digest": func(p *PlatformSnapshot) {
			p.ArtifactDigest = "not-a-digest"
			p.DeployedArtifactDigest = p.ArtifactDigest
		},
		"expired": func(p *PlatformSnapshot) { p.EvidenceExpiresAt = d.config.Now() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			out := p.value
			mutate(&out)
			a, _ := runtimeHTTP(t, runtimeTarget(p.value), d.config.Now, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(out)
			})
			got, err := a.RuntimeBinding(context.Background(), p.value.ProviderID, p.value.EngineInstanceID, p.value.Scope, p.value.RuntimeCapability)
			if !errors.Is(err, ErrUnverified) || got.ProviderID != "" {
				t.Fatal("unsafe response accepted", got, err)
			}
		})
	}
}
func TestHTTPRuntimeAuthorityStrictTransportAndConfiguration(t *testing.T) {
	d, _, p, _ := runtimeSetup(t, "identity.authentication.perform")
	target := runtimeTarget(p.value)
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"unauthorized", 401, "private", ErrDenied},
		{"unavailable", 503, "private", ErrUnavailable},
		{"redirect", 302, "private", ErrUnavailable},
		{"missing", 404, "private", ErrDenied},
		{"conflict", 409, "private", ErrUnverified},
		{"unknown", 200, `{"secret":true}`, ErrInvalid},
		{"duplicate", 200, `{"ProviderID":"a","ProviderID":"b"}`, ErrInvalid},
		{"null", 200, `{"ProviderID":null}`, ErrInvalid},
		{"trailing", 200, `{}{}`, ErrInvalid},
		{"missing fields", 200, `{}`, ErrUnverified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := runtimeHTTP(t, target, d.config.Now, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "https://foreign.invalid")
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			})
			got, err := a.RuntimeBinding(context.Background(), target.ProviderID, target.EngineInstanceID, target.Scope, target.RuntimeCapability)
			if !errors.Is(err, tc.want) || got.ProviderID != "" || strings.Contains(err.Error(), "private") {
				t.Fatal(got, err)
			}
		})
	}
	for _, mutate := range []func(*RuntimeAuthorityTarget){
		func(t *RuntimeAuthorityTarget) { t.RuntimeCapability = "OIDC_FEDERATION" },
		func(t *RuntimeAuthorityTarget) { t.ConfigurationReference = "" },
		func(t *RuntimeAuthorityTarget) { t.SecurityDomainReference = "" },
		func(t *RuntimeAuthorityTarget) { t.ProviderID = "../provider" },
		func(t *RuntimeAuthorityTarget) { t.Scope.OrganisationID = "x" },
	} {
		bad := target
		mutate(&bad)
		if _, err := NewHTTPRuntimeAuthority("https://cp.invalid", &runtimeTokens{}, nil, bad, d.config.Now); err == nil {
			t.Fatal("unsafe target accepted")
		}
	}
	if _, err := NewHTTPRuntimeAuthority("http://cp.invalid", &runtimeTokens{}, nil, target, d.config.Now); err == nil {
		t.Fatal("plaintext CP accepted")
	}
	if _, err := NewHTTPRuntimeAuthority("https://cp.invalid", &runtimeTokens{}, &tls.Config{InsecureSkipVerify: true}, target, d.config.Now); err == nil {
		t.Fatal("unverified TLS accepted")
	}
}
