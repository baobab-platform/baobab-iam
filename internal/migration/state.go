package migration

import "fmt"

// allowedTransitions enumerates legal MigrationState edges (happy path + control).
// Failure states may be entered from any mutation stage per ADR-0022 §10–11;
// recovery edges back onto the happy path are listed explicitly where safe.
var allowedTransitions = map[MigrationState][]MigrationState{
	StateDiscovered: {
		StateValidated, StateBlocked, StateFailedManualReview, StateQuarantined,
	},
	StateValidated: {
		StateReady, StateBlocked, StateFailedManualReview, StateQuarantined,
	},
	StateReady: {
		StateProvisioning, StateBlocked, StateFailedRetryable, StateFailedManualReview, StateQuarantined,
	},
	StateProvisioning: {
		StateProvisioned, StateFailedRetryable, StateFailedManualReview, StateRolledBack, StateQuarantined,
	},
	StateProvisioned: {
		StateCredentialPending, StateCredentialReady, // workload may skip credential pending
		StateFailedRetryable, StateFailedManualReview, StateRolledBack, StateQuarantined,
	},
	StateCredentialPending: {
		StateCredentialReady, StateFailedRetryable, StateFailedManualReview, StateQuarantined,
	},
	StateCredentialReady: {
		StateVerificationPending, StateFailedRetryable, StateFailedManualReview, StateQuarantined,
	},
	StateVerificationPending: {
		StateVerified, StateFailedRetryable, StateFailedManualReview, StateQuarantined,
	},
	StateVerified: {
		StateCutoverReady, StateFailedManualReview, StateQuarantined,
	},
	StateCutoverReady: {
		StateCutover, StateFailedManualReview, StateRolledBack, StateQuarantined,
	},
	StateCutover: {
		StateLegacyRetired, StateRolledBack, StateQuarantined,
	},
	StateLegacyRetired: {}, // terminal happy path
	// Control / failure recoveries (narrow)
	StateBlocked: {
		StateValidated, StateReady, StateFailedManualReview, StateQuarantined,
	},
	StateFailedRetryable: {
		StateReady, StateProvisioning, StateCredentialPending, StateVerificationPending,
		StateFailedManualReview, StateQuarantined, StateRolledBack,
	},
	StateFailedManualReview: {
		StateReady, StateQuarantined, StateRolledBack,
	},
	StateRolledBack: {
		StateReady, StateQuarantined, // may re-enter after remediation
	},
	StateQuarantined: {
		StateFailedManualReview, // only after explicit review
	},
}

// CanTransition reports whether from → to is an allowed edge.
func CanTransition(from, to MigrationState) bool {
	next, ok := allowedTransitions[from]
	if !ok {
		return false
	}
	for _, s := range next {
		if s == to {
			return true
		}
	}
	return false
}

// Transition moves r to to if the edge is allowed and structural validation passes.
// It increments AttemptCount on transitions into mutation stages.
func (r *Record) Transition(to MigrationState) error {
	if r == nil {
		return fmt.Errorf("migration: record is nil")
	}
	if !CanTransition(r.MigrationState, to) {
		return fmt.Errorf("migration: illegal transition %s → %s", r.MigrationState, to)
	}
	if r.IdentityClass == ClassOrphanCandidate || r.CanonicalIdentityID == "" {
		switch to {
		case StateBlocked, StateFailedManualReview, StateQuarantined:
		default:
			return fmt.Errorf("migration: unresolved orphan cannot advance into execution")
		}
	}
	previous := r.MigrationState
	r.MigrationState = to
	if err := r.ValidateStructural(); err != nil {
		r.MigrationState = previous
		return err
	}
	switch to {
	case StateProvisioning, StateCredentialPending, StateVerificationPending, StateCutover:
		r.AttemptCount++
	}
	return r.ValidateStructural()
}

// ResolveCanonicalByEmailAlone is intentionally unimplemented.
// ADR-0022 §7 prohibits using email equality as the sole canonical key.
// Callers must resolve CanonicalIdentity via CP issuer+subject mapping.
func ResolveCanonicalByEmailAlone(email string) (canonicalID string, err error) {
	_ = email
	return "", fmt.Errorf("migration: canonical identity must not be resolved by email alone (ADR-0022 §7)")
}
