package tokenprofile

import (
    "fmt"
    "strings"
)

// TMS native execution authority remains PROPOSED in Shared #409.
// Both normal Config.Validate and direct provider-hook Config.Claims must
// reject any TMS authority projected without a later accepted Shared contract.
func reservedTMSWorkloadID(id string) bool {
    return id == "baobab-tms" || strings.HasPrefix(id,"baobab-tms-") ||
        strings.HasPrefix(id,"baobab-dev-tms-")
}

func reservedTMSAudience(audience string) bool {
    return audience=="baobab-tms" || strings.HasPrefix(audience,"baobab-tms-")
}

func reservedTMSNativeScope(scope string) bool {
    return strings.HasPrefix(scope,"tms:")
}

func rejectUnacceptedTMSProfile(id string,p Workload) error {
    if reservedTMSWorkloadID(id) {
        return fmt.Errorf("TMS workload registration is not accepted in pinned Shared")
    }
    for _,audience:=range p.Audiences {
        if reservedTMSAudience(audience){
            return fmt.Errorf("TMS audience is not accepted in pinned Shared")
        }
    }
    for _,scope:=range p.Scopes {
        if reservedTMSNativeScope(scope){
            return fmt.Errorf("TMS native operation scope is not accepted in pinned Shared")
        }
    }
    if p.HumanTokenProfile!=nil {
        for _,audience:=range p.HumanTokenProfile.Audiences {
            if reservedTMSAudience(audience) {
                return fmt.Errorf("TMS human audience is not accepted in pinned Shared")
            }
        }
        for _,scope:=range p.HumanTokenProfile.Scopes {
            if reservedTMSNativeScope(scope) {
                return fmt.Errorf("TMS human native scope is not accepted in pinned Shared")
            }
        }
    }
    return nil
}

func rejectUnacceptedTMSGrant(e Evidence) bool {
    if reservedTMSWorkloadID(e.ClientID) {
        return true
    }
    for _,audience:=range e.GrantedAudiences {
        if reservedTMSAudience(audience) {return true}
    }
    for _,scope:=range e.RequestedScopes {
        if reservedTMSNativeScope(scope) {return true}
    }
    for _,scope:=range e.GrantedScopes {
        if reservedTMSNativeScope(scope) {return true}
    }
    return false
}
