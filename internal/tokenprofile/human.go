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
	// The projected scope audiences are the Shared scope registry's own: each
	// profile scope has a nonempty audience inside the profile, there is no
	// entry for any other scope, and every profile audience is reached by some
	// scope (the Shared validator's rule, rechecked so a hand-built projection
	// cannot widen it).
	if len(workload.HumanScopeAudiences) != len(p.Scopes) {
		return fmt.Errorf("every human token profile scope needs its registry audience")
	}
	reached := map[string]bool{}
	for _, scope := range p.Scopes {
		audiences, ok := workload.HumanScopeAudiences[scope]
		if !ok || len(audiences) == 0 || !subset(audiences, p.Audiences) {
			return fmt.Errorf("human scope %q audience must be a nonempty subset of the profile", scope)
		}
		for _, audience := range audiences {
			reached[audience] = true
		}
	}
	if len(reached) != len(p.Audiences) {
		return fmt.Errorf("every human token profile audience needs a profile scope")
	}
	return nil
}

// consentScopes are the OIDC scopes the native handoff may grant alongside
// profile scopes. offline_access is deliberately absent: native consent has
// never granted it and buyer consent does not widen that.
var consentScopes = []string{"openid", "profile", "email"}

// HumanConsent decides governed buyer consent for an estate BFF
// (ADR-SHARED-042 section 14, CAA-03). The canonical human authentication
// request carries no audience, so IAM never takes one from the requester:
// it returns the audience the pinned Shared scope registry issues the granted
// profile scopes for, in profile order. Only an ACTIVE registration in this
// issuer's environment qualifies, openid is required, at least one profile
// scope must be requested, and anything outside the profile and the OIDC
// scopes refuses the whole consent. It grants no tenant, organisation,
// membership or purchasing authority: Trade decides that per operation.
func (c Config) HumanConsent(clientID string, requestedScopes []string) ([]string, error) {
	p, ok := c.Workloads[clientID]
	if err := tmsProposalHold(clientID, p); err != nil {
		return nil, err
	}
	if !ok || p.Status != "ACTIVE" || p.HumanTokenProfile == nil || p.Environment == "" || p.Environment != c.Environment {
		return nil, fmt.Errorf("buyer consent denied")
	}
	if !slices.Contains(requestedScopes, "openid") {
		return nil, fmt.Errorf("buyer consent requires openid")
	}
	granted := []string{}
	seen := map[string]bool{}
	for _, scope := range requestedScopes {
		if seen[scope] {
			return nil, fmt.Errorf("buyer consent scope mismatch")
		}
		seen[scope] = true
		switch {
		case slices.Contains(p.HumanTokenProfile.Scopes, scope):
			granted = append(granted, scope)
		case slices.Contains(consentScopes, scope):
		default:
			return nil, fmt.Errorf("buyer consent scope mismatch")
		}
	}
	if len(granted) == 0 {
		return nil, fmt.Errorf("buyer consent requires a profile scope")
	}
	return p.humanAudience(granted), nil
}

// humanAudience is the profile-ordered union of the registry audiences of the
// granted profile scopes.
func (p Workload) humanAudience(profileScopes []string) []string {
	audiences := []string{}
	for _, audience := range p.HumanTokenProfile.Audiences {
		for _, scope := range profileScopes {
			if slices.Contains(p.HumanScopeAudiences[scope], audience) {
				audiences = append(audiences, audience)
				break
			}
		}
	}
	return audiences
}

// HumanEvidence is Hydra's authenticated description of one human token
// grant: the client it authenticated, the grant, the scopes requested and
// granted, the audience granted, and the assurance the login accepted from a
// verified Kratos session (the ID token claims). None of it comes from the
// requester.
//
// Hydra (v26.2.0, observed live) calls the token hook for an authorization
// code exchange before it copies the consent grant onto the request:
// granted_scopes and granted_audience are then empty, and only the requested
// scopes are known. On a refresh they are populated. The consent request ID
// Hydra records on the session and the seal governed consent attached to it
// (HumanConsentSeal) carry the audience that consent decided.
type HumanEvidence struct {
	ClientID         string
	Subject          string
	Grant            string
	ConsentRequestID string
	Consent          *HumanConsentSeal
	RequestedScopes  []string
	GrantedScopes    []string
	GrantedAudiences []string
	ACR              string
	AMR              []string
	AuthTime         int64
}

// HumanClaims evaluates a human authorization-code or refresh grant for an
// estate BFF. Only an ACTIVE registration in this issuer's environment
// qualifies: PROVISIONED mechanics never issue human tokens. Every scope must
// be a profile or OIDC scope with at least one profile scope, and the
// assurance must be evidence IAM's own login emits. The claims carry that
// evidence to the resource server, which still decides what it is worth.
//
// Scope is checked on the strongest evidence Hydra supplies: on a code
// exchange the requested scopes, a ceiling for what consent can grant; on a
// refresh the grant itself. The audience must be the registry audience of the
// profile scopes, as governed consent sealed it (HumanConsentSeal) under
// sealKey: a grant accepted any other way is refused. Wherever Hydra does
// supply the granted audience it must match too. The hook never states scope
// itself: Hydra's own scope claim is the actual grant.
func (c Config) HumanClaims(e HumanEvidence, sealKey []byte) (map[string]any, error) {
	if len(sealKey) < MinConsentSealKeyBytes {
		return nil, fmt.Errorf("human issuance requires the consent seal key")
	}
	p, ok := c.Workloads[e.ClientID]
	if err := tmsProposalHold(e.ClientID, p); err != nil {
		return nil, err
	}
	if err := tmsGrantHold(Evidence{ClientID: e.ClientID, RequestedScopes: e.RequestedScopes, GrantedScopes: e.GrantedScopes, GrantedAudiences: e.GrantedAudiences}); err != nil {
		return nil, err
	}
	if !ok || p.Status != "ACTIVE" || p.HumanTokenProfile == nil || p.Environment == "" || p.Environment != c.Environment {
		return nil, fmt.Errorf("human issuance denied")
	}
	if e.Grant != "authorization_code" && e.Grant != "refresh_token" {
		return nil, fmt.Errorf("human grant profile mismatch")
	}
	if e.Subject == "" || strings.TrimSpace(e.Subject) != e.Subject || e.Subject == e.ClientID {
		return nil, fmt.Errorf("human subject required")
	}
	scopes, codeExchange := e.GrantedScopes, false
	if len(scopes) == 0 && e.Grant == "authorization_code" {
		scopes, codeExchange = e.RequestedScopes, true
		if len(e.GrantedAudiences) != 0 {
			return nil, fmt.Errorf("human audience without granted scopes")
		}
	}
	profile := *p.HumanTokenProfile
	resource := []string{}
	seen := map[string]bool{}
	for _, scope := range scopes {
		if seen[scope] {
			return nil, fmt.Errorf("human scope mismatch")
		}
		seen[scope] = true
		switch {
		case slices.Contains(profile.Scopes, scope):
			resource = append(resource, scope)
		case slices.Contains(oidcScopes, scope):
		default:
			return nil, fmt.Errorf("human scope mismatch")
		}
	}
	if len(resource) == 0 {
		return nil, fmt.Errorf("human scope mismatch")
	}
	// The audience is exactly what governed consent derives from the scopes,
	// never a profile audience no granted scope is issued for, and only a
	// sealed governed decision establishes it.
	audience := p.humanAudience(resource)
	if !verifyHumanConsent(sealKey, e.Consent, e.ConsentRequestID, e.ClientID, e.Subject, scopes, audience) {
		return nil, fmt.Errorf("human consent not governed")
	}
	if !codeExchange && !sameSet(e.GrantedAudiences, audience) {
		return nil, fmt.Errorf("human audience mismatch")
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
	claims := map[string]any{"actor_type": "human", "azp": e.ClientID, "acr": e.ACR, "auth_time": e.AuthTime}
	if len(e.AMR) > 0 {
		claims["amr"] = slices.Clone(e.AMR)
	}
	return claims, nil
}
