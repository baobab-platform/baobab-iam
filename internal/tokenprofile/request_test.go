package tokenprofile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func canonicalFixture() (Config, WorkloadTokenRequest, Evidence) {
	c := Config{SharedCommit: strings.Repeat("a", 40), Environment: "staging", Workloads: map[string]Workload{"worker": {Environment: "staging", CredentialType: "federated_workload_token", Status: "ACTIVE", Scopes: []string{"context:resolve", "billing:read"}, Audiences: []string{"baobab-cp", "baobab-billing"}}}, Bindings: map[string]Binding{"worker": {Issuer: "https://projected.example", Subject: "service-account-worker"}}}
	r := WorkloadTokenRequest{WorkloadID: "worker", Audience: "baobab-cp", Scopes: []string{"context:resolve"}}
	e := Evidence{ClientID: "worker", Subject: "service-account-worker", Grant: FederatedGrant, AssertionIssuer: "https://projected.example", AssertionSubject: "service-account-worker", RequestedScopes: []string{"context:resolve"}, GrantedScopes: []string{"context:resolve"}, GrantedAudiences: []string{"baobab-cp"}}
	return c, r, e
}

func TestCanonicalWorkloadAdmissionUsesAuthenticatedHookBinding(t *testing.T) {
	c, r, e := canonicalFixture()
	out, err := c.AdmitRequest(r, nil, e)
	if err != nil {
		t.Fatal(err)
	}
	out.Scopes[0] = "billing:read"
	if r.Scopes[0] != "context:resolve" {
		t.Fatal("caller mutation changed admitted input")
	}
}

func TestCanonicalWorkloadDefaultsAreExplicitAndAudienceScoped(t *testing.T) {
	c, r, e := canonicalFixture()
	r.Scopes = nil
	defaults := WorkloadDefaults{"worker": {"baobab-cp": {"context:resolve"}}}
	if _, err := c.AdmitRequest(r, defaults, e); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdmitRequest(r, nil, e); err == nil {
		t.Fatal("absent default acquired scopes")
	}
	r.Scopes = []string{}
	if _, err := c.AdmitRequest(r, defaults, e); err == nil {
		t.Fatal("empty scopes became defaults")
	}
}

func TestCanonicalWorkloadAdmissionNegativeMatrix(t *testing.T) {
	for _, scenario := range []string{"unregistered", "provisioned", "revoked", "environment", "wrong-client", "wrong-subject", "wrong-issuer", "wrong-assertion", "wrong-grant", "wrong-audience", "extra-audience", "wrong-scope", "duplicate-scope", "unexpected-granted-scope"} {
		t.Run(scenario, func(t *testing.T) {
			c, r, e := canonicalFixture()
			p := c.Workloads["worker"]
			switch scenario {
			case "unregistered":
				r.WorkloadID = "unknown"
			case "provisioned":
				p.Status = "PROVISIONED"
			case "revoked":
				p.Status = "REVOKED"
			case "environment":
				p.Environment = "production"
			case "wrong-client":
				e.ClientID = "other"
			case "wrong-subject":
				e.Subject = "other"
			case "wrong-issuer":
				e.AssertionIssuer = "https://other.example"
			case "wrong-assertion":
				e.AssertionSubject = "other"
			case "wrong-grant":
				e.Grant = "client_credentials"
			case "wrong-audience":
				r.Audience = "unregistered"
			case "extra-audience":
				e.GrantedAudiences = append(e.GrantedAudiences, "baobab-billing")
			case "wrong-scope":
				r.Scopes = []string{"billing:read"}
			case "duplicate-scope":
				r.Scopes = append(r.Scopes, r.Scopes[0])
			case "unexpected-granted-scope":
				e.GrantedScopes = append(e.GrantedScopes, "billing:read")
			}
			c.Workloads["worker"] = p
			if _, err := c.AdmitRequest(r, nil, e); err == nil {
				t.Fatal("invalid canonical admission accepted")
			}
		})
	}
}

func TestCanonicalWorkloadRequestSharedWireExamples(t *testing.T) {
	for _, fixture := range []struct {
		raw   string
		valid bool
	}{
		{`{"workload_id":"worker","audience":"baobab-cp","scopes":["context:resolve"]}`, true},
		{`{"workload_id":"worker","audience":"baobab-cp"}`, true},
		{`{"workload_id":"Worker","audience":"baobab-cp"}`, false},
		{`{"workload_id":"worker","audience":"https://cp.example"}`, false},
		{`{"workload_id":"worker","audience":"baobab-cp","scopes":["*"]}`, false},
	} {
		var request WorkloadTokenRequest
		if err := json.Unmarshal([]byte(fixture.raw), &request); err != nil {
			if fixture.valid {
				t.Fatal(err)
			}
			continue
		}
		if (request.Validate() == nil) != fixture.valid {
			t.Fatal("Shared wire validation mismatch")
		}
	}
}

func TestCanonicalWorkloadWireRejectsSubstitutionAndMalformedInput(t *testing.T) {
	for _, raw := range []string{
		`{"workload_id":"worker","workload_id":"other","audience":"baobab-cp"}`,
		`{"workload_id":"worker","audience":"baobab-cp","scopes":null}`,
		`{"workload_id":"worker","audience":"baobab-cp","grant_type":"client_credentials"}`,
		`{"workload_id":"worker","audience":"baobab-cp","credential":"secret"}`,
		`{"workload_id":"worker","audience":"baobab-cp"} {}`,
		`{"audience":"baobab-cp"}`,
	} {
		var request WorkloadTokenRequest
		if json.Unmarshal([]byte(raw), &request) == nil {
			t.Fatal("noncanonical wire accepted")
		}
	}
	for _, scopes := range [][]string{nil, {}} {
		request := WorkloadTokenRequest{WorkloadID: "worker", Audience: "baobab-cp", Scopes: scopes}
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip WorkloadTokenRequest
		if err := json.Unmarshal(raw, &roundtrip); err != nil {
			t.Fatal(err)
		}
		if (roundtrip.Scopes == nil) != (scopes == nil) {
			t.Fatal("scope omission changed in roundtrip")
		}
	}
}

func TestPinnedSharedWorkloadRequestCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/canonical-workload-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Valid   bool            `json:"valid"`
		Request json.RawMessage `json:"request"`
	}
	if json.Unmarshal(raw, &cases) != nil || len(cases) == 0 {
		t.Fatal("invalid contract corpus")
	}
	for _, fixture := range cases {
		var request WorkloadTokenRequest
		if (json.Unmarshal(fixture.Request, &request) == nil) != fixture.Valid {
			t.Fatal("pinned Shared corpus mismatch")
		}
	}
}

func TestCanonicalClientCredentialsAndConcurrentAdmission(t *testing.T) {
	c, r, e := canonicalFixture()
	p := c.Workloads["worker"]
	p.CredentialType = "client_credentials"
	delete(c.Bindings, "worker")
	c.Workloads["worker"] = p
	e.Grant = "client_credentials"
	e.Subject = "worker"
	e.AssertionIssuer, e.AssertionSubject = "", ""
	for i := 0; i < 16; i++ {
		t.Run("parallel", func(t *testing.T) {
			t.Parallel()
			if _, err := c.AdmitRequest(r, nil, e); err != nil {
				t.Fatal(err)
			}
		})
	}
}
