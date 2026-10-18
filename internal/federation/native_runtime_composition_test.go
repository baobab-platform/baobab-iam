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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

func TestNativeRuntimeCompositionRequiresBothProvidersAndOAuth(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "credential")
	if err := os.WriteFile(token, []byte("iam-owned-caller"), 0600); err != nil {
		t.Fatal(err)
	}
	human := RuntimeComposition{ResolutionTokenFile: token, RuntimeTokenFile: token, ContextTarget: RuntimeContextTarget{"tn_iam", "org_native", "ZA"}, ProviderID: "provider_kratos", EngineInstanceID: "ei_kratos", EstateID: "estate_native", ServiceReference: "service://baobab-iam/native", ConfigurationReference: "ref_kratos", SecurityDomainReference: "ref_domain"}
	issuer := human
	issuer.ProviderID = "provider_hydra"
	issuer.EngineInstanceID = "ei_hydra"
	issuer.ServiceReference = "service://baobab-iam/issuer"
	issuer.ConfigurationReference = "ref_hydra"
	var scenario atomic.Value
	scenario.Store("")
	var oauthCalls atomic.Int64
	stableExpiry := time.Now().Add(3 * time.Minute).UTC()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer iam-owned-caller" {
			w.WriteHeader(401)
			return
		}
		now := time.Now().UTC()
		expires := now.Add(time.Minute)
		switch r.URL.Path {
		case "/v1/platform-context/resolve":
			_ = json.NewEncoder(w).Encode(runtimeContextWire{ContextID: "ctx_native", TenantID: human.ContextTarget.TenantID, OrganisationID: human.ContextTarget.OrganisationID, CountryCode: "ZA", ResolvedAt: now, ExpiresAt: stableExpiry})
		case "/v1/capabilities/resolve":
			var req CapabilityRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil {
				w.WriteHeader(400)
				return
			}
			c := human
			if req.CapabilityKey == provider.CapabilityWorkloadTokenIssue {
				c = issuer
			}
			out := CapabilityResolution{ResolutionID: "res_native", ContextID: req.ContextID, CapabilityKey: req.CapabilityKey, ContractVersion: 1, Decision: "RESOLVED", GrantID: "grant_native", BindingID: "bind_native", ResolvedAt: now, ExpiresAt: &expires, CorrelationID: req.CorrelationID, Invocation: &CapabilityInvocation{ServiceReference: c.ServiceReference, Protocol: "http", ContractVersion: 1, ProviderID: c.ProviderID, EngineInstanceID: c.EngineInstanceID}}
			if scenario.Load() == "issuer grant revoked" && c.ProviderID == issuer.ProviderID {
				out.Decision = "DENIED"
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/internal/identity-runtime/v1/binding":
			var req runtimeBindingWire
			if json.NewDecoder(r.Body).Decode(&req) != nil {
				w.WriteHeader(400)
				return
			}
			p := PlatformSnapshot{ProviderID: req.ProviderID, EngineInstanceID: req.EngineInstanceID, Scope: Scope{req.OrganisationID, req.EstateID}, ProviderStatus: "ACTIVE", InstanceStatus: "ACTIVE", BindingStatus: "ACTIVE", RuntimeCapability: req.RuntimeCapability, SupportStatus: "VERIFIED", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), DeployedArtifactDigest: "sha256:" + strings.Repeat("a", 64), ProfileRevision: 1, EvidenceExpiresAt: stableExpiry}
			mode := scenario.Load().(string)
			if mode == "Kratos revoked" && req.RuntimeCapability == "HUMAN_AUTHENTICATION" {
				w.WriteHeader(409)
				return
			}
			if mode == "Hydra revoked" && req.RuntimeCapability == "WORKLOAD_TOKEN_ISSUANCE" {
				w.WriteHeader(409)
				return
			}
			if req.RuntimeCapability == "OAUTH_AUTHORIZATION_SERVER" {
				n := oauthCalls.Add(1)
				switch mode {
				case "OAuth missing":
					w.WriteHeader(409)
					return
				case "OAuth outage":
					w.WriteHeader(503)
					return
				case "OAuth expired":
					p.EvidenceExpiresAt = now
				case "OAuth artifact":
					p.ArtifactDigest = "sha256:" + strings.Repeat("b", 64)
					p.DeployedArtifactDigest = p.ArtifactDigest
				case "OAuth revision":
					p.ProfileRevision = 2
				case "OAuth withdrawal during check":
					if n%2 == 0 {
						w.WriteHeader(409)
						return
					}
				}
			}
			_ = json.NewEncoder(w).Encode(runtimeReply(p, RuntimeAuthorityTarget{ConfigurationReference: req.ConfigurationReference, SecurityDomainReference: req.SecurityDomainReference}))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	human.CPOrigin = server.URL
	issuer.CPOrigin = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate, supervisor, err := StartNativeRuntimeComposition(ctx, human, issuer, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-supervisor.Done() }()
	for _, mode := range []string{"", "Kratos revoked", "Hydra revoked", "issuer grant revoked", "OAuth missing", "OAuth outage", "OAuth expired", "OAuth artifact", "OAuth revision", "OAuth withdrawal during check", ""} {
		scenario.Store(mode)
		oauthCalls.Store(0)
		err := gate.CheckCapability(ctx, provider.CapabilityHumanAuthentication)
		if mode == "" && err != nil {
			t.Fatal("valid composition denied", err)
		}
		if mode != "" && err == nil {
			t.Fatal("unsafe composition accepted", mode)
		}
	}
	if gate.CheckCapability(ctx, provider.CapabilityWorkloadTokenIssue) == nil {
		t.Fatal("human gate reused for workload")
	}
	for _, field := range []string{"tenant", "organisation", "market", "estate", "domain", "caller", "origin", "instance"} {
		changed := issuer
		switch field {
		case "tenant":
			changed.ContextTarget.TenantID = "tn_other"
		case "organisation":
			changed.ContextTarget.OrganisationID = "org_other"
		case "market":
			changed.ContextTarget.CountryCode = "UG"
		case "estate":
			changed.EstateID = "estate_other"
		case "domain":
			changed.SecurityDomainReference = "ref_other"
		case "caller":
			changed.ResolutionTokenFile = "/other"
		case "origin":
			changed.CPOrigin = "https://other.invalid"
		case "instance":
			changed.EngineInstanceID = human.EngineInstanceID
		}
		if _, s, err := StartNativeRuntimeComposition(ctx, human, changed, tlsConfig); err == nil || s != nil {
			t.Fatal("mixed composition started", field)
		}
	}
}
