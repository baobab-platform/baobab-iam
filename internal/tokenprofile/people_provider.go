package tokenprofile

import (
    "fmt"
    "slices"
)

// ADR-SHARED-045/Shared #436. This is solely an IAM token-issuance fence:
// even an accepted OAuth scope is never an employer permission or selected
// provider binding. CP rechecks authoritative tenancy and choice every time.
const peopleProviderReadScope = "people:provider:read"
const peopleContextResolveScope = "context:resolve"
const peopleControlPlaneAudience = "baobab-control-plane"

func validatePeopleProviderReaderProfile(id string, profile Workload) error {
    if !slices.Contains(profile.Scopes, peopleProviderReadScope) {
        return nil
    }
    // Only an independently registered workload for CP can receive this
    // scope. No human, consent, unrelated API audience or default migration.
    if profile.HumanTokenProfile != nil ||
        len(profile.Audiences) != 1 || profile.Audiences[0] != peopleControlPlaneAudience ||
        !slices.Contains(profile.Scopes, peopleContextResolveScope) {
        return fmt.Errorf("People provider reader profile denied for %q", id)
    }
    // The first BYOP acceptance slice is development-only. Production or
    // staging require a separately qualified issuer/policy revision.
    if profile.Environment != "development" {
        return fmt.Errorf("People provider reader not qualified for protected environment")
    }
    return nil
}

func validatePeopleProviderReaderToken(profile Workload, evidence Evidence) error {
    if !slices.Contains(evidence.GrantedScopes, peopleProviderReadScope) &&
        !slices.Contains(evidence.RequestedScopes, peopleProviderReadScope) {
        return nil
    }
    if profile.Status != "ACTIVE" || profile.Environment != "development" ||
        len(evidence.GrantedAudiences) != 1 ||
        evidence.GrantedAudiences[0] != peopleControlPlaneAudience ||
        !slices.Contains(evidence.GrantedScopes, peopleProviderReadScope) ||
        !slices.Contains(evidence.GrantedScopes, peopleContextResolveScope) ||
        !slices.Contains(evidence.RequestedScopes, peopleProviderReadScope) ||
        !slices.Contains(evidence.RequestedScopes, peopleContextResolveScope) {
        return fmt.Errorf("People provider read token scope/audience/lifecycle denied")
    }
    return nil
}
