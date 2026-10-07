package tokenprofile

import "testing"

func TestWorkloadClaimsFailClosed(t *testing.T) {
	config := Config{Environment: "production", SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd", Workloads: map[string]Workload{"trade": {Environment: "production", CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-control-plane"}}, "cp": {Environment: "production", CredentialType: "federated_workload_token", Status: "PROVISIONED", Scopes: []string{"billing:read"}, Audiences: []string{"baobab-subscriptions"}}}, Bindings: map[string]Binding{"cp": {Issuer: "https://projected.invalid", Subject: "service-account-cp"}}}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	valid := Evidence{ClientID: "trade", Subject: "trade", Grant: "client_credentials", RequestedScopes: []string{"context:resolve"}, GrantedScopes: []string{"context:resolve"}, GrantedAudiences: []string{"baobab-control-plane"}}
	claims, err := config.Claims(valid)
	if err != nil || claims["actor_type"] != "workload" || claims["azp"] != "trade" || claims["scope"] != "context:resolve" || len(claims) != 3 {
		t.Fatal("governed workload claims missing or inflated")
	}
	for _, name := range []string{"unknown-client", "wrong-subject", "wrong-grant", "unrequested-scope", "forbidden-scope", "missing-audience", "wrong-audience", "extra-audience", "duplicate-scope"} {
		t.Run(name, func(t *testing.T) {
			e := valid
			switch name {
			case "unknown-client":
				e.ClientID = "unknown"
			case "wrong-subject":
				e.Subject = "other"
			case "wrong-grant":
				e.Grant = "authorization_code"
			case "unrequested-scope":
				e.GrantedScopes = []string{"context:resolve", "billing:read"}
			case "forbidden-scope":
				e.RequestedScopes = []string{"billing:read"}
				e.GrantedScopes = e.RequestedScopes
			case "missing-audience":
				e.GrantedAudiences = nil
			case "wrong-audience":
				e.GrantedAudiences = []string{"baobab-payments"}
			case "extra-audience":
				e.GrantedAudiences = []string{"baobab-control-plane", "https://issuer.invalid/oauth2/token"}
			case "duplicate-scope":
				e.RequestedScopes = []string{"context:resolve", "context:resolve"}
				e.GrantedScopes = e.RequestedScopes
			}
			if _, err := config.Claims(e); err == nil {
				t.Fatal("invalid provider evidence accepted")
			}
		})
	}
	for _, status := range []string{"SUSPENDED", "REVOKED", "RETIRED"} {
		t.Run(status, func(t *testing.T) {
			p := config.Workloads["trade"]
			p.Status = status
			config.Workloads["trade"] = p
			if _, err := config.Claims(valid); err == nil {
				t.Fatal("nonissuing lifecycle accepted")
			}
		})
	}
	federated := Evidence{ClientID: "cp", Subject: "service-account-cp", Grant: FederatedGrant, AssertionIssuer: "https://projected.invalid", AssertionSubject: "service-account-cp", RequestedScopes: []string{"billing:read"}, GrantedScopes: []string{"billing:read"}, GrantedAudiences: []string{"baobab-subscriptions"}}
	if _, err := config.Claims(federated); err != nil {
		t.Fatal("exact governed federation binding denied")
	}
	for _, name := range []string{"wrong-issuer", "wrong-subject", "downgrade", "assertion-audience-leak"} {
		t.Run(name, func(t *testing.T) {
			e := federated
			switch name {
			case "wrong-issuer":
				e.AssertionIssuer = "https://another.invalid"
			case "wrong-subject":
				e.AssertionSubject = "other"
			case "downgrade":
				e.Grant = "client_credentials"
			case "assertion-audience-leak":
				e.GrantedAudiences = []string{"baobab-subscriptions", "https://issuer.invalid/oauth2/token"}
			}
			if _, err := config.Claims(e); err == nil {
				t.Fatal("invalid federation evidence accepted")
			}
		})
	}
}

func TestDistinctWorkloadsCannotShareProjectedIdentity(t *testing.T) {
	profile := Workload{Environment: "production", CredentialType: "federated_workload_token", Status: "PROVISIONED", Scopes: []string{"billing:read"}, Audiences: []string{"baobab-subscriptions"}}
	binding := Binding{Issuer: "https://projected.invalid", Subject: "shared-service-account"}
	config := Config{
		Environment:  "production",
		SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd",
		Workloads:    map[string]Workload{"cp": profile, "other": profile},
		Bindings:     map[string]Binding{"cp": binding, "other": binding},
	}
	if config.Validate() == nil {
		t.Fatal("distinct workloads may not share a projected issuer/subject identity")
	}
}

// The FB-05 staging evidence provisioner: a federated workload of the staging environment, holding exactly erp:provision for baobab-erp.
func evidenceConfig(environment string) Config {
	return Config{
		Environment:  environment,
		SharedCommit: "70f92ee179888e9fd38e31ae9225060d76833944",
		Workloads: map[string]Workload{"baobab-cp-provisioning-evidence-workload": {Environment: "staging", CredentialType: "federated_workload_token",
			Status: "ACTIVE", Scopes: []string{"erp:provision"}, Audiences: []string{"baobab-erp"}}},
		Bindings: map[string]Binding{"baobab-cp-provisioning-evidence-workload": {Issuer: "https://issuer.staging.invalid", Subject: "provisioner-evidence"}},
	}
}

func evidenceEvidence() Evidence {
	return Evidence{ClientID: "baobab-cp-provisioning-evidence-workload", Subject: "provisioner-evidence", Grant: FederatedGrant,
		AssertionIssuer: "https://issuer.staging.invalid", AssertionSubject: "provisioner-evidence",
		RequestedScopes: []string{"erp:provision"}, GrantedScopes: []string{"erp:provision"}, GrantedAudiences: []string{"baobab-erp"}}
}

func TestEvidenceProvisionerIsIssuedOnlyInItsOwnEnvironment(t *testing.T) {
	staging := evidenceConfig("staging")
	if err := staging.Validate(); err != nil {
		t.Fatal(err)
	}
	claims, err := staging.Claims(evidenceEvidence())
	if err != nil || claims["scope"] != "erp:provision" || claims["actor_type"] != "workload" || len(claims) != 3 {
		t.Fatalf("exact governed evidence issuance denied or inflated: %v %v", claims, err)
	}
	// An issuer of another environment refuses the projection outright, and a hand-built mismatch still issues nothing.
	for _, other := range []string{"production", "development"} {
		if evidenceConfig(other).Validate() == nil {
			t.Fatalf("a %s issuer accepted a staging workload", other)
		}
		cfg := evidenceConfig(other)
		if _, err := cfg.Claims(evidenceEvidence()); err == nil {
			t.Fatalf("a %s issuer issued for a staging workload", other)
		}
	}
	for _, bad := range []string{"", "Staging", "prod", "evidence"} {
		if evidenceConfig(bad).Validate() == nil {
			t.Fatalf("issuer environment %q accepted", bad)
		}
	}
	// Wrong audience, an extra scope, the assertion's token-endpoint audience, and a downgrade to a static secret are all denied.
	for name, mutate := range map[string]func(*Evidence){
		"wrong-audience": func(e *Evidence) { e.GrantedAudiences = []string{"baobab-control-plane"} },
		"extra-audience": func(e *Evidence) {
			e.GrantedAudiences = []string{"baobab-erp", "https://issuer.staging.invalid/oauth2/token"}
		},
		"token-endpoint": func(e *Evidence) { e.GrantedAudiences = []string{"https://issuer.staging.invalid/oauth2/token"} },
		"extra-scope": func(e *Evidence) {
			e.RequestedScopes, e.GrantedScopes = []string{"erp:provision", "erp:read"}, []string{"erp:provision", "erp:read"}
		},
		"static-secret":   func(e *Evidence) { e.Grant = "client_credentials"; e.Subject = e.ClientID },
		"other-assertion": func(e *Evidence) { e.AssertionIssuer = "https://issuer.production.invalid" },
	} {
		e := evidenceEvidence()
		mutate(&e)
		if _, err := staging.Claims(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
