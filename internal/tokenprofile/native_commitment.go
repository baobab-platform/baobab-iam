package tokenprofile

import (
	"fmt"
	"regexp"
	"slices"
)

// ADR-SHARED-042 section 14, Decision 9 (ADR-IAM-0034): a server application
// that submits native commitments to Trade outside a governed BFF
// authenticates as its own IAM workload, holding trade:native-commitment:submit.
// CP verifies that token and attests the application's governed estate
// assignment; Trade never accepts a Medusa publishable key, a sales channel or
// a self-asserted estate in its place. IAM's part is only that the identity is
// distinct and narrow:
//   - it is a confidential workload (client_credentials or a federated
//     workload token), never a human or a key;
//   - its client id has the Shared workloadClientId grammar the assignment
//     names, so a publishable key (pk_...) can never be one;
//   - it is never an estate BFF: a BFF proves its estate through the
//     estate-client binding, and one identity holding both would make the
//     provenance of its commitments ambiguous;
//   - a token carrying the scope is for Trade alone, so it cannot be replayed
//     against any other resource.
//
// The scope is registered and allocated to no workload; nothing here
// allocates it.

const (
	nativeCommitmentSubmitScope = "trade:native-commitment:submit"
	nativeCommitmentAudience    = "baobab-trade"
)

// The Shared estate-resource-assignment workloadClientId grammar.
var workloadClientID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,62}$`)

func validateNativeCommitmentSubmitter(id string, p Workload) error {
	if !slices.Contains(p.Scopes, nativeCommitmentSubmitScope) {
		return nil
	}
	if !workloadClientID.MatchString(id) {
		return fmt.Errorf("workload %q holds %s but is not a canonical workload client id", id, nativeCommitmentSubmitScope)
	}
	if p.HumanTokenProfile != nil || slices.Contains(p.Scopes, buyerHandoffScope) {
		return fmt.Errorf("workload %q holds %s and is an estate BFF; the two provenances never share an identity",
			id, nativeCommitmentSubmitScope)
	}
	if !slices.Contains(p.Audiences, nativeCommitmentAudience) {
		return fmt.Errorf("workload %q holds %s without the %s audience", id, nativeCommitmentSubmitScope, nativeCommitmentAudience)
	}
	return nil
}

// nativeCommitmentTokenScoped reports whether a token granting the submit
// scope is issued for Trade alone.
func nativeCommitmentTokenScoped(e Evidence) bool {
	return !slices.Contains(e.GrantedScopes, nativeCommitmentSubmitScope) ||
		(len(e.GrantedAudiences) == 1 && e.GrantedAudiences[0] == nativeCommitmentAudience)
}
