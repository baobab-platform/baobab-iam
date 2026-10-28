package tokenprofile

import (
	"fmt"
	"strings"
)

// TMS native-execution and validator issuance remain HELD while Shared #409
// is only PROPOSED. Neither an independently supplied workload profile nor
// synthetic provider evidence may create scope, issuer or client approval.
// This guard applies to Validate and Claims (including hand-built Configs);
// no production credential is provisioned or minted by this package.
func tmsProposalHold(id string, p Workload) error {
	if id == "baobab-tms" || strings.HasPrefix(id, "baobab-tms-") {
		return fmt.Errorf("TMS workload proposal is not accepted: %s", id)
	}
	for _, audience := range p.Audiences {
		if audience == "baobab-tms" {
			return fmt.Errorf("TMS resource audience is not registered for issuance")
		}
	}
	for _, scope := range p.Scopes {
		if strings.HasPrefix(scope, "tms:") {
			return fmt.Errorf("TMS native operation scope is not accepted")
		}
	}
	for scope := range p.HumanScopeAudiences {
		if strings.HasPrefix(scope, "tms:") {
			return fmt.Errorf("TMS native operation scope cannot be a human token scope")
		}
	}
	if p.HumanTokenProfile != nil {
		for _, scope := range p.HumanTokenProfile.Scopes {
			if strings.HasPrefix(scope, "tms:") {
				return fmt.Errorf("TMS native operation scope cannot be a human token scope")
			}
		}
	}
	return nil
}
