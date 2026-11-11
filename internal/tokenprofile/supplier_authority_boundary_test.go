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
			evidence := humanEvidence(func(e *HumanEvidence) {
				e.GrantedScopes = []string{"openid", "trade:buy", scope}
			})
			if claims, err := config.HumanClaims(evidence, testSealKey); err == nil || len(claims) != 0 {
				t.Fatalf("buyer token hook issued supplier/approval scope: %v", claims)
			}
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
	if slices.Contains(config.Workloads["estate-bff"].HumanTokenProfile.Scopes, "supplier:approve") {
		t.Fatal("fixture unintentionally grants supplier approval")
	}
}
