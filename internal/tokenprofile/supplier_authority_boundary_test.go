package tokenprofile

import (
	"slices"
	"testing"
)

// ADR-0012: supplier representation, procurement eligibility, bank changes
// and source-approval are domain-owned. A governed B2B buyer token is evidence
// of an authenticated person only; it is never a supplier approval, grant or
// invitation. These fixtures are not connected supplier-domain acceptance.
func TestBuyerTokenCannotGrantSupplierRepresentation(t *testing.T) {
	config := humanConfig(nil)

	// A buyer BFF may not request supplier administration or sourcing scopes
	// that were never registered in its exact Shared human token profile.
	for name, scope := range map[string]string{
		"supplier admin":       "supplier:admin",
		"supplier approval":    "supplier:approve",
		"procurement approval": "procurement:approve",
		"supplier bank update": "supplier:bank-update",
	} {
		t.Run(name, func(t *testing.T) {
			if audiences, err := config.HumanConsent("estate-bff", []string{"openid", "trade:buy", scope}); err == nil || len(audiences) != 0 {
				t.Fatalf("buyer BFF consented to unrelated supplier authority: %v", audiences)
			}
			// Hydra's token hook sees the actual granted scopes on refresh
			// and sometimes only requested scopes before consent grant copying
			// on an authorization-code exchange. Both must fail closed.
			for _, grant := range []string{"authorization_code", "refresh_token"} {
				t.Run(grant+" granted", func(t *testing.T) {
					evidence := humanEvidence(func(e *HumanEvidence) {
						e.Grant = grant
						e.GrantedScopes = []string{"openid", "trade:buy", scope}
					})
					if claims, err := config.HumanClaims(evidence, testSealKey); err == nil || len(claims) != 0 {
						t.Fatalf("buyer %s token hook issued supplier/approval scope: %v", grant, claims)
					}
				})
			}
			t.Run("authorization_code requested before grant copy", func(t *testing.T) {
				evidence := humanEvidence(func(e *HumanEvidence) {
					e.Grant = "authorization_code"
					e.RequestedScopes = []string{"openid", "trade:buy", scope}
					e.GrantedScopes, e.GrantedAudiences = nil, nil
				})
				if claims, err := config.HumanClaims(evidence, testSealKey); err == nil || len(claims) != 0 {
					t.Fatalf("pre-grant buyer token hook issued supplier/approval scope: %v", claims)
				}
			})
		})
	}
	claims, err := config.HumanClaims(humanEvidence(nil), testSealKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"tenant_id", "organisation_id", "supplier_id", "supplier_role",
		"supplier_approved", "supplier_eligibility", "supplier_admin",
		"buyer_membership", "market_id", "purchase_limit",
		"bank_details", "procurement_approval",
	} {
		if _, ok := claims[forbidden]; ok {
			t.Fatalf("human token became authoritative for domain data %q", forbidden)
		}
	}
	// Explicit allowlist proves that human identity/assurance claims never
	// silently become business, company, bank-change or market privileges.
	allowed := map[string]bool{"actor_type": true, "azp": true, "acr": true, "auth_time": true, "amr": true}
	for name := range claims {
		if !allowed[name] {
			t.Fatalf("unreviewed authority or domain claim emitted: %q", name)
		}
	}
	if len(claims) != len(allowed) {
		t.Fatalf("missing approved identity/assurance claims: %#v", claims)
	}
	if slices.Contains(config.Workloads["estate-bff"].HumanTokenProfile.Scopes, "supplier:approve") {
		t.Fatal("fixture unintentionally grants supplier approval")
	}
}
