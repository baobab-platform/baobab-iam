package tokenprofile

import "testing"

func TestWorkloadClaimsFailClosed(t *testing.T) {
	config := Config{SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd", Workloads: map[string]Workload{"trade": {CredentialType: "client_credentials", Status: "ACTIVE", Scopes: []string{"context:resolve"}, Audiences: []string{"baobab-control-plane"}}, "cp": {CredentialType: "federated_workload_token", Status: "PROVISIONED", Scopes: []string{"billing:read"}, Audiences: []string{"baobab-subscriptions"}}}, Bindings: map[string]Binding{"cp": {Issuer: "https://projected.invalid", Subject: "service-account-cp"}}}
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
	profile := Workload{CredentialType: "federated_workload_token", Status: "PROVISIONED", Scopes: []string{"billing:read"}, Audiences: []string{"baobab-subscriptions"}}
	binding := Binding{Issuer: "https://projected.invalid", Subject: "shared-service-account"}
	config := Config{
		SharedCommit: "10810e20473709d4626da310fc9a84680f8efddd",
		Workloads:    map[string]Workload{"cp": profile, "other": profile},
		Bindings:     map[string]Binding{"cp": binding, "other": binding},
	}
	if config.Validate() == nil {
		t.Fatal("distinct workloads may not share a projected issuer/subject identity")
	}
}
