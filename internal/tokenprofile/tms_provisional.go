package tokenprofile

import (
	"fmt"
	"strings"
)

// Shared #409 accepts a development authority design, not active registry
// adoption. TMS native-execution and validator issuance therefore remain HELD. Neither an independently supplied workload profile nor
// synthetic provider evidence may create scope, issuer or client approval.
// This guard applies to Validate and Claims (including hand-built Configs);
// no production credential is provisioned or minted by this package.
func tmsProposalHold(id string, p Workload) error {
	// Direct hooks can bypass Config.Validate. Each value must still be one
	// canonical token before OAuth scope serialization joins the list.
	for _, values := range [][]string{p.Scopes, p.Audiences} {
		for _, value := range values {
			if !singleIssuanceToken(value) {
				return fmt.Errorf("noncanonical scope or audience in issuance profile")
			}
		}
	}
	if reservedTMSClient(id) {
		return fmt.Errorf("TMS workload is not registered for issuance: %s", id)
	}
	for _, audience := range p.Audiences {
		if reservedTMSAudience(audience) {
			return fmt.Errorf("TMS resource audience is not registered for issuance")
		}
	}
	for _, scope := range p.Scopes {
		if strings.HasPrefix(scope, "tms:") {
			return fmt.Errorf("TMS native operation scope is not accepted")
		}
	}
	for scope, audiences := range p.HumanScopeAudiences {
		if !singleIssuanceToken(scope) {
			return fmt.Errorf("noncanonical human scope mapping")
		}
		for _, audience := range audiences {
			if !singleIssuanceToken(audience) {
				return fmt.Errorf("noncanonical human audience mapping")
			}
			if reservedTMSAudience(audience) {
				return fmt.Errorf("TMS human resource audience is not registered for issuance")
			}
		}
		if strings.HasPrefix(scope, "tms:") {
			return fmt.Errorf("TMS native operation scope cannot be a human token scope")
		}
	}
	if p.HumanTokenProfile != nil {
		for _, audience := range p.HumanTokenProfile.Audiences {
			if !singleIssuanceToken(audience) {
				return fmt.Errorf("noncanonical human audience")
			}
			if reservedTMSAudience(audience) {
				return fmt.Errorf("TMS human resource audience is not registered for issuance")
			}
		}
		for _, scope := range p.HumanTokenProfile.Scopes {
			if !singleIssuanceToken(scope) {
				return fmt.Errorf("noncanonical human scope")
			}
			if strings.HasPrefix(scope, "tms:") {
				return fmt.Errorf("TMS native operation scope cannot be a human token scope")
			}
		}
	}
	return nil
}

func reservedTMSClient(id string) bool {
	return id == "baobab-tms" || strings.HasPrefix(id, "baobab-tms-") ||
		strings.HasPrefix(id, "baobab-dev-tms-")
}

func reservedTMSAudience(audience string) bool {
	return audience == "baobab-tms" || strings.HasPrefix(audience, "baobab-tms-")
}

// Check authenticated evidence as well as the configured ceiling: direct
// provider hooks cannot smuggle unregistered audiences or native scopes.
func tmsGrantHold(e Evidence) error {
	if reservedTMSClient(e.ClientID) {
		return fmt.Errorf("TMS workload is not registered for issuance")
	}
	for _, audience := range e.GrantedAudiences {
		if !singleIssuanceToken(audience) {
			return fmt.Errorf("noncanonical granted audience")
		}
		if reservedTMSAudience(audience) {
			return fmt.Errorf("TMS resource audience is not registered for issuance")
		}
	}
	for _, scopes := range [][]string{e.RequestedScopes, e.GrantedScopes} {
		for _, scope := range scopes {
			if !singleIssuanceToken(scope) {
				return fmt.Errorf("noncanonical requested or granted scope")
			}
			if strings.HasPrefix(scope, "tms:") {
				return fmt.Errorf("TMS native operation scope is not registered for issuance")
			}
		}
	}
	return nil
}

// Scope/audience entries cannot contain separators, controls or wildcard and
// quote escapes. Otherwise strings.Join can grant multiple scopes from one
// array element in an unvalidated profile or authenticated provider payload.
func singleIssuanceToken(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if c <= 0x20 || c >= 0x7f || c == '*' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
