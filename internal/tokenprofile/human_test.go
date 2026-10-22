package tokenprofile

import (
	"slices"
	"strings"
	"testing"
)

// ADR-SHARED-042 section 14: synthetic estate BFF only. This proves the
// issuance boundary, not connected IAM acceptance.
func humanConfig(change func(*Workload)) Config {
	bff := Workload{Environment: "staging", CredentialType: "client_credentials", Status: "ACTIVE",
		Scopes: []string{"trade:buyer-handoff"}, Audiences: []string{"baobab-trade"},
		HumanTokenProfile: &HumanTokenProfile{Purpose: "ESTATE_BFF_BUYER", Audiences: []string{"baobab-trade"}, Scopes: []string{"trade:buy"}}}
	if change != nil {
		change(&bff)
	}
	return Config{SharedCommit: strings.Repeat("a", 40), Environment: "staging", Workloads: map[string]Workload{"estate-bff": bff}}
}

func humanEvidence(change func(*HumanEvidence)) HumanEvidence {
	e := HumanEvidence{ClientID: "estate-bff", Subject: "kratos-identity-0001", Grant: "authorization_code",
		GrantedScopes: []string{"openid", "trade:buy"}, GrantedAudiences: []string{"baobab-trade"},
		ACR: "aal2", AMR: []string{"pwd", "otp", "mfa"}, AuthTime: 1792670400}
	if change != nil {
		change(&e)
	}
	return e
}

func TestHumanClaimsCarryVerifiedAssuranceForAnActiveEstateBFF(t *testing.T) {
	config := humanConfig(nil)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	claims, err := config.HumanClaims(humanEvidence(nil))
	if err != nil {
		t.Fatal(err)
	}
	if claims["actor_type"] != "human" || claims["azp"] != "estate-bff" || claims["scope"] != "openid trade:buy" ||
		claims["acr"] != "aal2" || claims["auth_time"] != int64(1792670400) || !slices.Equal(claims["amr"].([]string), []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("claims = %#v", claims)
	}
	// A refresh keeps the same boundary; amr is omitted when none was emitted.
	refreshed, err := config.HumanClaims(humanEvidence(func(e *HumanEvidence) { e.Grant, e.AMR = "refresh_token", nil }))
	if err != nil || refreshed["amr"] != nil {
		t.Fatalf("refresh = %#v, %v", refreshed, err)
	}
}

func TestHumanClaimsRefuseEverythingOutsideTheProfile(t *testing.T) {
	cases := map[string]func(*HumanEvidence){
		"unknown client":           func(e *HumanEvidence) { e.ClientID = "other" },
		"client credentials grant": func(e *HumanEvidence) { e.Grant = "client_credentials" },
		"workload subject":         func(e *HumanEvidence) { e.Subject = "estate-bff" },
		"no subject":               func(e *HumanEvidence) { e.Subject = "" },
		"control plane audience":   func(e *HumanEvidence) { e.GrantedAudiences = []string{"baobab-control-plane"} },
		"extra audience":           func(e *HumanEvidence) { e.GrantedAudiences = []string{"baobab-trade", "baobab-erp"} },
		"no audience":              func(e *HumanEvidence) { e.GrantedAudiences = nil },
		"workload scope":           func(e *HumanEvidence) { e.GrantedScopes = []string{"trade:buy", "context:resolve"} },
		"handoff scope to a human": func(e *HumanEvidence) { e.GrantedScopes = []string{"trade:buy", "trade:buyer-handoff"} },
		"oidc scopes only":         func(e *HumanEvidence) { e.GrantedScopes = []string{"openid", "email"} },
		"duplicate scope":          func(e *HumanEvidence) { e.GrantedScopes = []string{"trade:buy", "trade:buy"} },
		"no acr":                   func(e *HumanEvidence) { e.ACR = "" },
		"provider acr not issued":  func(e *HumanEvidence) { e.ACR = "urn:baobab:acr:gold" },
		"no auth time":             func(e *HumanEvidence) { e.AuthTime = 0 },
		"amr IAM never emits":      func(e *HumanEvidence) { e.AMR = []string{"pwd", "face"} },
		"duplicate amr":            func(e *HumanEvidence) { e.AMR = []string{"pwd", "pwd"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := humanConfig(nil).HumanClaims(humanEvidence(change)); err == nil {
				t.Fatal("issued")
			}
		})
	}
	for name, change := range map[string]func(*Workload){
		"provisioned only": func(w *Workload) { w.Status = "PROVISIONED" },
		"suspended":        func(w *Workload) { w.Status = "SUSPENDED" },
		"no profile":       func(w *Workload) { w.HumanTokenProfile, w.Scopes = nil, []string{"context:resolve"} },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := humanConfig(change).HumanClaims(humanEvidence(nil)); err == nil {
				t.Fatal("issued")
			}
		})
	}
}

func TestHumanTokenProfileValidation(t *testing.T) {
	for name, change := range map[string]func(*Workload){
		"wrong purpose":    func(w *Workload) { w.HumanTokenProfile.Purpose = "ANY" },
		"federated client": func(w *Workload) { w.CredentialType = "federated_workload_token" },
		"no handoff scope": func(w *Workload) {
			w.Scopes, w.Audiences = []string{"context:resolve"}, []string{"baobab-control-plane"}
		},
		"control plane":           func(w *Workload) { w.HumanTokenProfile.Audiences = []string{"baobab-control-plane"} },
		"oidc scope in profile":   func(w *Workload) { w.HumanTokenProfile.Scopes = []string{"openid"} },
		"handoff in profile":      func(w *Workload) { w.HumanTokenProfile.Scopes = []string{"trade:buyer-handoff"} },
		"wildcard":                func(w *Workload) { w.HumanTokenProfile.Scopes = []string{"trade:*"} },
		"empty audiences":         func(w *Workload) { w.HumanTokenProfile.Audiences = nil },
		"handoff without profile": func(w *Workload) { w.HumanTokenProfile = nil },
	} {
		t.Run(name, func(t *testing.T) {
			if err := humanConfig(change).Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
