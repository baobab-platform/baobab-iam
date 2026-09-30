// Target path: baobab-iam/internal/migration/policy.go
//
// Phase C policy: the state machine may *know* CUTOVER edges, but production
// cutover is not authorized until M18 + explicit operator approval.
package migration

import (
	"context"
	"fmt"
)

// PhaseCPolicyGate denies transitions into production cutover states.
// It allows the rest of the happy path through VERIFIED and control states
// so greenfield unit tests and non-prod pilots can exercise the ledger.
//
// CUTOVER and LEGACY_RETIRED require a later PolicyGate (M18) that checks
// IssuerTrust, cohort authorization, and rollback baseline Scenario D.
type PhaseCPolicyGate struct{}

// AllowTransition implements PolicyGate.
func (PhaseCPolicyGate) AllowTransition(_ context.Context, migrationID string, from, to MigrationState) error {
	switch to {
	case StateCutover, StateLegacyRetired:
		return fmt.Errorf(
			"migration: transition %s → %s denied by Phase C policy for %q (production cutover not authorized; see ADR-IAM-0022 / M18)",
			from, to, migrationID,
		)
	default:
		return nil
	}
}

// AllowAllPolicyGate permits any state-machine-legal transition. Intended for
// synthetic tests of the full graph only — do not use in shared or production
// services.
type AllowAllPolicyGate struct{}

// AllowTransition implements PolicyGate.
func (AllowAllPolicyGate) AllowTransition(_ context.Context, _ string, _, _ MigrationState) error {
	return nil
}
