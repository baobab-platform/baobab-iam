package workloadresource

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func n04Target() CPBindingTarget {
	return CPBindingTarget{
		ProviderID: "provider_abcdef1234",
		EngineInstanceID: "ei_abcdef1234",
		OrganisationID: "org_own",
		EstateID: "estate_nabhold",
		ConfigurationReference: "ref_config1234",
		SecurityDomainReference: "ref_security1234",
	}
}

func TestN04LiveTLSCPBindingRequiresExactCurrentRegistration(t *testing.T) {
	target := n04Target()
	const credential = "issuer-read-credential-current-and-separately-registered"
	var mode string
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost ||
			r.URL.Path != "/internal/identity-runtime/v1/binding" ||
			r.Header.Get("Authorization") != "Bearer "+credential ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Error("registered CP read was replaced or unauthenticated")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil ||
			request["provider_id"] != target.ProviderID ||
			request["engine_instance_id"] != target.EngineInstanceID ||
			request["organisation_id"] != target.OrganisationID ||
			request["estate_id"] != target.EstateID ||
			request["runtime_capability"] != "WORKLOAD_TOKEN_ISSUANCE" ||
			request["configuration_reference"] != target.ConfigurationReference ||
			request["security_domain_reference"] != target.SecurityDomainReference ||
			len(request) != 7 {
			t.Error("CP registered target/provenance drift")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if mode == "redirect" {
			http.Redirect(w, r, "https://untrusted.invalid/", http.StatusFound)
			return
		}
		if mode == "error" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if mode != "cache" {
			w.Header().Set("Cache-Control", "no-store")
		}
		if mode == "duplicate" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"provider_id":"provider_abcdef1234","provider_id":"provider_abcdef1234"}`))
			return
		}
		data := map[string]any{
			"provider_id": target.ProviderID,
			"engine_instance_id": target.EngineInstanceID,
			"scope": map[string]string{
				"organisation_id": target.OrganisationID, "estate_id": target.EstateID,
			},
			"provider_status": "ACTIVE",
			"instance_status": "ACTIVE",
			"binding_status": "ACTIVE",
			"runtime_capability": "WORKLOAD_TOKEN_ISSUANCE",
			"support_status": "VERIFIED",
			"artifact_digest": "sha256:" + strings.Repeat("a", 64),
			"deployed_artifact_digest": "sha256:" + strings.Repeat("a", 64),
			"profile_revision": 5,
			"evidence_expires_at": time.Now().Add(time.Minute),
			"configuration_reference": target.ConfigurationReference,
			"security_domain_reference": target.SecurityDomainReference,
		}
		switch mode {
		case "inactive":
			data["provider_status"] = "SUSPENDED"
		case "partial":
			data["support_status"] = "UNVERIFIED"
		case "binding-withdrawn":
			data["binding_status"] = "REVOKED"
		case "wrong-tenant":
			data["scope"] = map[string]string{"organisation_id": "org_other", "estate_id": target.EstateID}
		case "wrong-instance":
			data["engine_instance_id"] = "ei_unauthorized"
		case "wrong-facet":
			data["runtime_capability"] = "HUMAN_AUTHENTICATION"
		case "artifact-drift":
			data["deployed_artifact_digest"] = "sha256:" + strings.Repeat("b", 64)
		case "stale":
			data["evidence_expires_at"] = time.Now().Add(-time.Second)
		case "revision-zero":
			data["profile_revision"] = 0
		case "unapproved-configuration":
			data["configuration_reference"] = "ref_other123"
		case "extra":
			data["self_certified"] = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	read, err := NewCPRegisteredBinding(srv.URL, roots, target,
		func(context.Context) (string, error) { return credential, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := read.CheckCapability(context.Background(), WorkloadIssueCapability); err != nil {
		t.Fatal("current CP registered issuer refused", err)
	}
	for _, name := range []string{
		"redirect", "error", "cache", "duplicate", "inactive",
		"partial", "binding-withdrawn", "wrong-tenant", "wrong-instance",
		"wrong-facet", "artifact-drift", "stale", "revision-zero",
		"unapproved-configuration", "extra",
	} {
		mode = name
		if err := read.CheckCapability(context.Background(), WorkloadIssueCapability); err == nil {
			t.Fatal("invalid CP registered binding accepted", name)
		}
	}
	if calls != 16 {
		t.Fatalf("CP current authority was cached, calls=%d", calls)
	}
	if err := read.CheckCapability(context.Background(), "identity.authentication.perform"); err == nil {
		t.Fatal("native human capability reused for workload issuer")
	}
	if calls != 16 {
		t.Fatal("different capability reached CP")
	}
}

func TestN04CPBindingRejectsUntrustedOriginAndReferences(t *testing.T) {
	tgt := n04Target()
	token := func(context.Context) (string, error) { return strings.Repeat("v", 40), nil }
	for _, origin := range []string{
		"http://localhost:8080", "https://bad.invalid/path",
		"https://bad.invalid/?q=1", "https://user@bad.invalid", "",
	} {
		if _, err := NewCPRegisteredBinding(origin, nil, tgt, token); err == nil {
			t.Fatal("untrusted CP address accepted")
		}
	}
	bad := tgt
	bad.ConfigurationReference = "user_supplied"
	if _, err := NewCPRegisteredBinding("https://cp.invalid", nil, bad, token); err == nil {
		t.Fatal("noncanonical CP reference admitted")
	}
	bad = tgt
	bad.ProviderID = "provider_"
	if _, err := NewCPRegisteredBinding("https://cp.invalid", nil, bad, token); err == nil {
		t.Fatal("unregistered provider id admitted")
	}
	if _, err := NewCPRegisteredBinding("https://cp.invalid", nil, tgt, nil); err == nil {
		t.Fatal("missing separately registered CP caller accepted")
	}
}

func TestN04CPBindingDoesNotReuseExpiredOrRevokedCPCaller(t *testing.T) {
	calls := 0
	tgt := n04Target()
	read, err := NewCPRegisteredBinding("https://cp.invalid", nil, tgt,
		func(context.Context) (string, error) {
			calls++
			return "bad", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := read.CheckCapability(context.Background(), WorkloadIssueCapability); err == nil || calls != 1 {
		t.Fatal("unapproved CP credential was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if read.CheckCapability(ctx, WorkloadIssueCapability) == nil || calls != 1 {
		t.Fatal("cancelled CP operation contacted token source")
	}
}
