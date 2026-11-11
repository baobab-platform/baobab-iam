package tokenprofile

import (
	"testing"
)

// ADR-0010/ADR-SHARED-042: a directly invoked consent or token hook must
// enforce the Shared buyer-profile ceiling itself. A valid consent seal does
// not repair a malformed BFF registration. These are synthetic source tests.
func TestBuyerConsentAndHumanHookRefuseUnvalidatedBFFProfiles(t *testing.T) {
	cases := map[string]func(*Workload){
		"no confidential client": func(w *Workload) {
			w.CredentialType = "federated_workload_token"
		},
		"no handoff capability": func(w *Workload) {
			w.Scopes = []string{"context:resolve"}
		},
		"wrong profile purpose": func(w *Workload) {
			w.HumanTokenProfile.Purpose = "UNREVIEWED"
		},
		"wrong scope audience": func(w *Workload) {
			w.HumanScopeAudiences["trade:buy"] = []string{"baobab-erp"}
		},
		"unregistered extra scope mapping": func(w *Workload) {
			w.HumanScopeAudiences["trade:quote"] = []string{"baobab-trade"}
		},
		"unbound profile audience": func(w *Workload) {
			w.HumanTokenProfile.Audiences = []string{"baobab-trade", "baobab-erp"}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			config := humanConfig(change)
			if _, err := config.HumanConsent("estate-bff", []string{"openid", "trade:buy"}); err == nil {
				t.Fatal("malformed BFF profile received governed buyer consent")
			}
			if _, err := config.HumanClaims(humanEvidence(nil), testSealKey); err == nil {
				t.Fatal("malformed BFF profile received human claims from direct token hook")
			}
		})
	}
	config := humanConfig(nil)
	if _, err := config.HumanConsent("estate-bff", []string{"openid", "trade:buy"}); err != nil {
		t.Fatalf("valid, registered buyer BFF refused consent: %v", err)
	}
	if _, err := config.HumanClaims(humanEvidence(nil), testSealKey); err != nil {
		t.Fatalf("valid, governed buyer human issuance refused: %v", err)
	}
}
