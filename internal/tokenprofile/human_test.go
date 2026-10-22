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
		HumanTokenProfile:   &HumanTokenProfile{Purpose: "ESTATE_BFF_BUYER", Audiences: []string{"baobab-trade"}, Scopes: []string{"trade:buy"}},
		HumanScopeAudiences: map[string][]string{"trade:buy": {"baobab-trade"}}}
	if change != nil {
		change(&bff)
	}
	return Config{SharedCommit: strings.Repeat("a", 40), Environment: "staging", Workloads: map[string]Workload{"estate-bff": bff}}
}

var testSealKey = []byte(strings.Repeat("s", MinConsentSealKeyBytes))

// humanEvidence is a governed grant: unless change sets Consent itself or
// clears the challenge, it carries the seal governed consent would have
// attached for the evidence's scopes and audience.
func humanEvidence(change func(*HumanEvidence)) HumanEvidence {
	e := HumanEvidence{ClientID: "estate-bff", Subject: "kratos-identity-0001", Grant: "authorization_code",
		ConsentRequestID: "consent-challenge-0001", GrantedScopes: []string{"openid", "trade:buy"}, GrantedAudiences: []string{"baobab-trade"},
		ACR: "aal2", AMR: []string{"pwd", "otp", "mfa"}, AuthTime: 1792670400}
	if change != nil {
		change(&e)
	}
	if e.Consent == nil && e.ConsentRequestID != "" {
		scopes, audience := e.GrantedScopes, e.GrantedAudiences
		if len(scopes) == 0 {
			scopes = e.RequestedScopes
		}
		if len(audience) == 0 {
			audience = []string{"baobab-trade"}
		}
		if seal, err := SealHumanConsent(testSealKey, e.ConsentRequestID, e.ClientID, e.Subject, scopes, audience); err == nil {
			e.Consent = &seal
		}
	}
	return e
}

func TestHumanClaimsCarryVerifiedAssuranceForAnActiveEstateBFF(t *testing.T) {
	config := humanConfig(nil)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	claims, err := config.HumanClaims(humanEvidence(nil), testSealKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims["actor_type"] != "human" || claims["azp"] != "estate-bff" || claims["scope"] != nil ||
		claims["acr"] != "aal2" || claims["auth_time"] != int64(1792670400) || !slices.Equal(claims["amr"].([]string), []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("claims = %#v", claims)
	}
	// A refresh keeps the same boundary; amr is omitted when none was emitted.
	refreshed, err := config.HumanClaims(humanEvidence(func(e *HumanEvidence) { e.Grant, e.AMR = "refresh_token", nil }), testSealKey)
	if err != nil || refreshed["amr"] != nil {
		t.Fatalf("refresh = %#v, %v", refreshed, err)
	}
}

// Real Hydra calls the hook on a code exchange before copying the consent
// grant: only the requested scopes are known. They bound the grant; the
// audience was fixed by governed consent. On refresh the grant is present
// and must be exact.
func TestHumanClaimsOnTheEvidenceHydraSupplies(t *testing.T) {
	config := humanConfig(nil)
	exchange := func(change func(*HumanEvidence)) HumanEvidence {
		return humanEvidence(func(e *HumanEvidence) {
			e.RequestedScopes, e.GrantedScopes, e.GrantedAudiences = []string{"openid", "trade:buy"}, nil, nil
			if change != nil {
				change(e)
			}
		})
	}
	if _, err := config.HumanClaims(exchange(nil), testSealKey); err != nil {
		t.Fatal("code exchange before the grant copy refused:", err)
	}
	for name, change := range map[string]func(*HumanEvidence){
		"requested outside profile":  func(e *HumanEvidence) { e.RequestedScopes = []string{"openid", "trade:buy", "context:resolve"} },
		"requested no profile scope": func(e *HumanEvidence) { e.RequestedScopes = []string{"openid"} },
		"requested nothing":          func(e *HumanEvidence) { e.RequestedScopes = nil },
		"audience without scopes":    func(e *HumanEvidence) { e.GrantedAudiences = []string{"baobab-trade"} },
		"refresh without grant":      func(e *HumanEvidence) { e.Grant = "refresh_token" },
		"refresh without audience":   func(e *HumanEvidence) { e.Grant, e.GrantedScopes = "refresh_token", []string{"openid", "trade:buy"} },
		"granted beats requested": func(e *HumanEvidence) {
			e.GrantedScopes, e.GrantedAudiences = []string{"openid", "context:resolve"}, []string{"baobab-trade"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.HumanClaims(exchange(change), testSealKey); err == nil {
				t.Fatal("issued")
			}
		})
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
			if _, err := humanConfig(nil).HumanClaims(humanEvidence(change), testSealKey); err == nil {
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
			if _, err := humanConfig(change).HumanClaims(humanEvidence(nil), testSealKey); err == nil {
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
		"no scope audiences":      func(w *Workload) { w.HumanScopeAudiences = nil },
		"empty scope audience":    func(w *Workload) { w.HumanScopeAudiences["trade:buy"] = nil },
		"scope audience outside":  func(w *Workload) { w.HumanScopeAudiences["trade:buy"] = []string{"baobab-erp"} },
		"audience for other scope": func(w *Workload) {
			w.HumanScopeAudiences["trade:quote"] = []string{"baobab-trade"}
		},
		"unreached profile audience": func(w *Workload) {
			w.HumanTokenProfile.Audiences = []string{"baobab-trade", "baobab-erp"}
		},
		"scope audiences without profile": func(w *Workload) {
			w.HumanTokenProfile, w.Scopes, w.Audiences = nil, []string{"context:resolve"}, []string{"baobab-control-plane"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := humanConfig(change).Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestHumanConsentDerivesTheRegistryAudienceAndNothingElse(t *testing.T) {
	config := humanConfig(nil)
	audience, err := config.HumanConsent("estate-bff", []string{"openid", "email", "trade:buy"})
	if err != nil || !slices.Equal(audience, []string{"baobab-trade"}) {
		t.Fatalf("audience = %v, %v", audience, err)
	}
	// The derived audience is exactly what the token hook later accepts.
	if _, err := config.HumanClaims(humanEvidence(nil), testSealKey); err != nil {
		t.Fatal(err)
	}
	for name, scopes := range map[string][]string{
		"no openid":          {"trade:buy"},
		"oidc only":          {"openid", "profile"},
		"offline access":     {"openid", "trade:buy", "offline_access"},
		"workload scope":     {"openid", "trade:buy", "context:resolve"},
		"handoff scope":      {"openid", "trade:buy", "trade:buyer-handoff"},
		"unregistered scope": {"openid", "trade:sell"},
		"duplicate":          {"openid", "trade:buy", "trade:buy"},
	} {
		t.Run(name, func(t *testing.T) {
			if audience, err := config.HumanConsent("estate-bff", scopes); err == nil {
				t.Fatalf("consented to %v for %v", scopes, audience)
			}
		})
	}
	for name, change := range map[string]func(*Workload){
		"provisioned":       func(w *Workload) { w.Status = "PROVISIONED" },
		"suspended":         func(w *Workload) { w.Status = "SUSPENDED" },
		"no profile":        func(w *Workload) { w.HumanTokenProfile = nil },
		"other environment": func(w *Workload) { w.Environment = "production" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := humanConfig(change).HumanConsent("estate-bff", []string{"openid", "trade:buy"}); err == nil {
				t.Fatal("consented")
			}
		})
	}
	if _, err := config.HumanConsent("unregistered", []string{"openid", "trade:buy"}); err == nil {
		t.Fatal("consented for an unregistered client")
	}
}

// Synthetic two-audience profile: the audience follows the granted scopes, so
// a scope issued for one resource never yields a token for the other.
func TestHumanAudienceFollowsTheGrantedScopes(t *testing.T) {
	config := humanConfig(func(w *Workload) {
		w.HumanTokenProfile.Audiences = []string{"synthetic-resource-a", "synthetic-resource-b"}
		w.HumanTokenProfile.Scopes = []string{"synthetic-a:use", "synthetic-b:use"}
		w.HumanScopeAudiences = map[string][]string{"synthetic-a:use": {"synthetic-resource-a"}, "synthetic-b:use": {"synthetic-resource-b"}}
	})
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	for scopes, want := range map[string][]string{
		"synthetic-a:use":                 {"synthetic-resource-a"},
		"synthetic-b:use":                 {"synthetic-resource-b"},
		"synthetic-b:use synthetic-a:use": {"synthetic-resource-a", "synthetic-resource-b"},
	} {
		requested := append([]string{"openid"}, strings.Fields(scopes)...)
		got, err := config.HumanConsent("estate-bff", requested)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("%s: audience = %v, %v", scopes, got, err)
		}
		evidence := humanEvidence(func(e *HumanEvidence) { e.GrantedScopes, e.GrantedAudiences = requested, got })
		if _, err := config.HumanClaims(evidence, testSealKey); err != nil {
			t.Fatalf("%s: hook refused the consented audience: %v", scopes, err)
		}
	}
	// The hook refuses a profile audience no granted scope is issued for.
	widened := humanEvidence(func(e *HumanEvidence) {
		e.GrantedScopes = []string{"openid", "synthetic-a:use"}
		e.GrantedAudiences = []string{"synthetic-resource-a", "synthetic-resource-b"}
	})
	if _, err := config.HumanClaims(widened, testSealKey); err == nil {
		t.Fatal("hook accepted an audience beyond the granted scopes")
	}
}

// Only a grant governed consent sealed is issued: the code exchange gives the
// hook no audience, so the seal is the only evidence of what consent decided.
func TestHumanClaimsRequireTheGovernedConsentSeal(t *testing.T) {
	config := humanConfig(nil)
	sealed := func(challenge, client, subject string, audience []string, key []byte) *HumanConsentSeal {
		seal, err := SealHumanConsent(key, challenge, client, subject, []string{"trade:buy", "openid"}, audience)
		if err != nil {
			t.Fatal(err)
		}
		return &seal
	}
	if _, err := config.HumanClaims(humanEvidence(func(e *HumanEvidence) {
		e.Consent = sealed("consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"baobab-trade"}, testSealKey)
	}), testSealKey); err != nil {
		t.Fatal("scope order changed the sealed decision:", err)
	}
	other := []byte(strings.Repeat("o", MinConsentSealKeyBytes))
	for name, change := range map[string]func(*HumanEvidence){
		"no seal":    func(e *HumanEvidence) { e.ConsentRequestID = "" },
		"empty seal": func(e *HumanEvidence) { e.Consent = &HumanConsentSeal{} },
		"forged seal": func(e *HumanEvidence) {
			e.Consent = &HumanConsentSeal{Audience: []string{"baobab-trade"}, Seal: "forged"}
		},
		"other key": func(e *HumanEvidence) {
			e.Consent = sealed("consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"baobab-trade"}, other)
		},
		"other challenge": func(e *HumanEvidence) {
			e.Consent = sealed("consent-challenge-0002", "estate-bff", "kratos-identity-0001", []string{"baobab-trade"}, testSealKey)
		},
		"other client": func(e *HumanEvidence) {
			e.Consent = sealed("consent-challenge-0001", "other-bff", "kratos-identity-0001", []string{"baobab-trade"}, testSealKey)
		},
		"other subject": func(e *HumanEvidence) {
			e.Consent = sealed("consent-challenge-0001", "estate-bff", "kratos-identity-0002", []string{"baobab-trade"}, testSealKey)
		},
		"widened audience": func(e *HumanEvidence) {
			e.Consent = sealed("consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"baobab-trade", "baobab-control-plane"}, testSealKey)
		},
		"relabelled audience": func(e *HumanEvidence) {
			seal := sealed("consent-challenge-0001", "estate-bff", "kratos-identity-0001", []string{"baobab-trade"}, testSealKey)
			seal.Audience = []string{"baobab-control-plane"}
			e.Consent = seal
		},
		"code exchange unsealed": func(e *HumanEvidence) {
			e.RequestedScopes, e.GrantedScopes, e.GrantedAudiences, e.ConsentRequestID = []string{"openid", "trade:buy"}, nil, nil, ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.HumanClaims(humanEvidence(change), testSealKey); err == nil {
				t.Fatal("issued without a governed seal")
			}
		})
	}
	for name, key := range map[string][]byte{"no key": nil, "short key": []byte("short")} {
		t.Run(name, func(t *testing.T) {
			if _, err := config.HumanClaims(humanEvidence(nil), key); err == nil {
				t.Fatal("issued without the consent seal key")
			}
		})
	}
	for name, values := range map[string][4]string{
		"no challenge": {"", "estate-bff", "kratos-identity-0001", "openid"},
		"space":        {"challenge 1", "estate-bff", "kratos-identity-0001", "openid"},
		"nul":          {"challenge", "estate-bff", "kratos\x00identity", "openid"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SealHumanConsent(testSealKey, values[0], values[1], values[2], []string{values[3]}, []string{"baobab-trade"}); err == nil {
				t.Fatal("sealed a noncanonical decision")
			}
		})
	}
	if _, err := SealHumanConsent([]byte("short"), "c", "estate-bff", "s", []string{"openid"}, []string{"baobab-trade"}); err == nil {
		t.Fatal("sealed with a short key")
	}
}
