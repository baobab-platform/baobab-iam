package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// This test exercises the production factory, adapters, renewal and dispatch over
// verified TLS. Responses are wire fixtures, not live CP qualification evidence.
func TestRuntimeCompositionCurrentCallerAndIndependentAuthority(t *testing.T) {
	d, _, p, _ := runtimeSetup(t, "identity.workload-token.issue")
	root := t.TempDir()
	resolutionPath, runtimePath := filepath.Join(root, "resolution"), filepath.Join(root, "runtime")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(resolutionPath, "resolution-one")
	write(runtimePath, "runtime-one")
	c := RuntimeComposition{ResolutionTokenFile: resolutionPath, RuntimeTokenFile: runtimePath, ContextTarget: RuntimeContextTarget{"tn_iam", p.value.Scope.OrganisationID, "ZA"}, ProviderID: p.value.ProviderID, EngineInstanceID: p.value.EngineInstanceID, EstateID: p.value.Scope.EstateID, ServiceReference: d.config.ServiceReference, ConfigurationReference: "ref_nativeconfig", SecurityDomainReference: "ref_securitydomain"}
	var withdrawn, outage atomic.Bool
	var resolutions, profiles atomic.Int64
	var rotated atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if outage.Load() {
			w.WriteHeader(503)
			return
		}
		now := time.Now().UTC()
		expires := now.Add(2 * time.Minute)
		credential := "resolution-one"
		if rotated.Load() {
			credential = "resolution-two"
		}
		if r.URL.Path == "/internal/identity-runtime/v1/binding" {
			credential = "runtime-one"
			if rotated.Load() {
				credential = "runtime-two"
			}
		}
		if r.Header.Get("Authorization") != "Bearer "+credential {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/platform-context/resolve":
			var got RuntimeContextTarget
			if json.NewDecoder(r.Body).Decode(&got) != nil || got != c.ContextTarget {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(runtimeContextWire{ContextID: "ctx_owned", TenantID: got.TenantID, OrganisationID: got.OrganisationID, CountryCode: got.CountryCode, ResolvedAt: now, ExpiresAt: expires})
		case "/v1/capabilities/resolve":
			resolutions.Add(1)
			var req CapabilityRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.ContextID != "ctx_owned" {
				w.WriteHeader(400)
				return
			}
			out := CapabilityResolution{ResolutionID: "res_current", ContextID: req.ContextID, CapabilityKey: req.CapabilityKey, ContractVersion: 1, Decision: "RESOLVED", GrantID: "grant_current", BindingID: "bind_current", ResolvedAt: now, ExpiresAt: &expires, CorrelationID: req.CorrelationID, Invocation: &CapabilityInvocation{ServiceReference: c.ServiceReference, Protocol: "http", ContractVersion: 1, ProviderID: c.ProviderID, EngineInstanceID: c.EngineInstanceID}}
			// Resolution cannot outlive its context. Leave a conservative minute here.
			shorter := now.Add(time.Minute)
			out.ExpiresAt = &shorter
			if withdrawn.Load() {
				out.Decision = "DENIED"
				out.Invocation = nil
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/internal/identity-runtime/v1/binding":
			profiles.Add(1)
			out := p.value
			out.EvidenceExpiresAt = expires
			// Keep the snapshot stable across an operation's two reads.
			out.EvidenceExpiresAt = time.Now().UTC().Truncate(time.Hour).Add(2 * time.Hour)
			_ = json.NewEncoder(w).Encode(runtimeReply(out, RuntimeAuthorityTarget{ConfigurationReference: c.ConfigurationReference, SecurityDomainReference: c.SecurityDomainReference}))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c.CPOrigin = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatch, supervisor, err := StartRuntimeComposition(ctx, c, d.config.CapabilityKey, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-supervisor.Done() }()
	if err := dispatch.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if resolutions.Load() != 2 || profiles.Load() != 2 {
		t.Fatal("current reads bypassed")
	}
	write(resolutionPath, "resolution-two")
	write(runtimePath, "runtime-two")
	rotated.Store(true)
	if err := dispatch.Check(ctx); err != nil {
		t.Fatal("rotated credentials failed", err)
	}
	withdrawn.Store(true)
	if dispatch.Check(ctx) == nil {
		t.Fatal("withdrawal accepted")
	}
	withdrawn.Store(false)
	outage.Store(true)
	if dispatch.Check(ctx) == nil {
		t.Fatal("CP outage accepted")
	}
	outage.Store(false)
	if err := dispatch.Check(ctx); err != nil {
		t.Fatal("CP recovery denied", err)
	}
	cancel()
	<-supervisor.Done()
	if dispatch.Check(context.Background()) == nil {
		t.Fatal("stopped supervisor accepted")
	}
}
