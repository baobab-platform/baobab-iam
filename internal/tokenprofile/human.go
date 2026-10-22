package tokenprofile

import (
	"fmt"
	"slices"
	"strings"
)

// ADR-SHARED-042 section 14 (CAA-03/CAA-04; Shared identity/v1
// workload-registry.yaml human_token_profile): a confidential estate BFF may
// obtain human buyer tokens only for the human resource audiences and
// human-only scopes its Shared registry entry declares, and holds
// trade:buyer-handoff so it can authenticate to Trade as itself when it
// presents them. IAM never widens either list.

// HumanTokenProfile mirrors the pinned Shared human_token_profile.
type HumanTokenProfile struct {
	Purpose   string   `json:"purpose"`
	Audiences []string `json:"audiences"`
	Scopes    []string `json:"scopes"`
}

const (
	estateBFFBuyerPurpose = "ESTATE_BFF_BUYER"
	buyerHandoffScope     = "trade:buyer-handoff"
)

// oidcScopes may accompany the profile's human scopes; they carry no
// resource authority.
var oidcScopes = []string{"openid", "profile", "email", "offline_access"}

// The only acr values IAM's native login emits: Kratos authenticator
// assurance levels, set from a verified current session (human_handoff.go).
var issuedACR = []string{"aal1", "aal2"}

// The only amr values IAM's native login emits (RFC 8176 names).
var issuedAMR = []string{"pwd", "otp", "hwk", "mfa"}

func (p HumanTokenProfile) validate(workload Workload) error {
	if p.Purpose != estateBFFBuyerPurpose {
		return fmt.Errorf("human token profile purpose must be %s", estateBFFBuyerPurpose)
	}
	if workload.CredentialType != "client_credentials" {
		return fmt.Errorf("a human token profile requires a confidential client")
	}
	if !slices.Contains(workload.Scopes, buyerHandoffScope) {
		return fmt.Errorf("a human token profile requires %s", buyerHandoffScope)
	}
	for _, values := range [][]string{p.Audiences, p.Scopes} {
		if len(values) == 0 {
			return fmt.Errorf("human token profile audiences and scopes are required")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n*") || seen[value] {
				return fmt.Errorf("noncanonical or duplicate human token profile value")
			}
			seen[value] = true
		}
	}
	if slices.Contains(p.Audiences, "baobab-control-plane") {
		return fmt.Errorf("a human token profile never names the Control Plane audience")
	}
	for _, scope := range p.Scopes {
		if slices.Contains(oidcScopes, scope) || scope == buyerHandoffScope {
			return fmt.Errorf("a human token profile names resource scopes only")
		}
	}
	return nil
}

// HumanEvidence is Hydra's authenticated description of one human token
// grant: the client it authenticated, the grant, the scopes and audiences it
// granted after consent, and the assurance the login accepted from a verified
// Kratos session (the ID token claims). None of it comes from the requester.
type HumanEvidence struct {
	ClientID         string
	Subject          string
	Grant            string
	GrantedScopes    []string
	GrantedAudiences []string
	ACR              string
	AMR              []string
	AuthTime         int64
}

// HumanClaims evaluates a human authorization-code or refresh grant for an
// estate BFF. Only an ACTIVE registration in this issuer's environment
// qualifies: PROVISIONED mechanics never issue human tokens. Every granted
// audience must be in the profile, every granted scope in the profile or an
// OIDC scope, at least one profile scope must be granted, and the assurance
// must be evidence IAM's own login emits. The claims carry that evidence to
// the resource server, which still decides what it is worth.
func (c Config) HumanClaims(e HumanEvidence) (map[string]any, error) {
	p, ok := c.Workloads[e.ClientID]
	if !ok || p.Status != "ACTIVE" || p.HumanTokenProfile == nil || p.Environment == "" || p.Environment != c.Environment {
		return nil, fmt.Errorf("human issuance denied")
	}
	if e.Grant != "authorization_code" && e.Grant != "refresh_token" {
		return nil, fmt.Errorf("human grant profile mismatch")
	}
	if e.Subject == "" || strings.TrimSpace(e.Subject) != e.Subject || e.Subject == e.ClientID {
		return nil, fmt.Errorf("human subject required")
	}
	profile := *p.HumanTokenProfile
	if len(e.GrantedAudiences) == 0 || !subset(e.GrantedAudiences, profile.Audiences) {
		return nil, fmt.Errorf("human audience mismatch")
	}
	resource := 0
	seen := map[string]bool{}
	for _, scope := range e.GrantedScopes {
		if seen[scope] {
			return nil, fmt.Errorf("human scope mismatch")
		}
		seen[scope] = true
		switch {
		case slices.Contains(profile.Scopes, scope):
			resource++
		case slices.Contains(oidcScopes, scope):
		default:
			return nil, fmt.Errorf("human scope mismatch")
		}
	}
	if resource == 0 {
		return nil, fmt.Errorf("human scope mismatch")
	}
	if !slices.Contains(issuedACR, e.ACR) || e.AuthTime <= 0 {
		return nil, fmt.Errorf("human assurance evidence missing")
	}
	amrSeen := map[string]bool{}
	for _, method := range e.AMR {
		if !slices.Contains(issuedAMR, method) || amrSeen[method] {
			return nil, fmt.Errorf("human assurance evidence malformed")
		}
		amrSeen[method] = true
	}
	claims := map[string]any{"actor_type": "human", "azp": e.ClientID, "scope": strings.Join(e.GrantedScopes, " "),
		"acr": e.ACR, "auth_time": e.AuthTime}
	if len(e.AMR) > 0 {
		claims["amr"] = slices.Clone(e.AMR)
	}
	return claims, nil
}
