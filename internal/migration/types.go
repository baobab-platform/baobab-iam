package migration

import (
	"fmt"
	"time"
)

// IdentityClass classifies a migration row (ADR-IAM-0022 §12).
type IdentityClass string

const (
	ClassHuman              IdentityClass = "HUMAN"
	ClassWorkload           IdentityClass = "WORKLOAD"
	ClassPrivilegedHuman    IdentityClass = "PRIVILEGED_HUMAN"
	ClassBreakGlass         IdentityClass = "BREAK_GLASS"
	ClassFederatedHuman     IdentityClass = "FEDERATED_HUMAN"
	ClassServiceIntegration IdentityClass = "SERVICE_INTEGRATION"
	ClassTestOrNonProd      IdentityClass = "TEST_OR_NONPRODUCTION"
	ClassOrphanCandidate    IdentityClass = "ORPHAN_CANDIDATE"
)

// Valid reports whether c is a known identity class.
func (c IdentityClass) Valid() bool {
	switch c {
	case ClassHuman, ClassWorkload, ClassPrivilegedHuman, ClassBreakGlass,
		ClassFederatedHuman, ClassServiceIntegration, ClassTestOrNonProd, ClassOrphanCandidate:
		return true
	default:
		return false
	}
}

// CredentialStrategy is the explicit human credential path (ADR-IAM-0022 §16).
// WORKLOAD rows typically use NO_CREDENTIAL_REQUIRED (Hydra client secrets
// are handled by WorkloadProvisioner, not stored on the ledger).
type CredentialStrategy string

const (
	StrategyDirectImport          CredentialStrategy = "DIRECT_IMPORT"
	StrategyFirstLoginMigration   CredentialStrategy = "FIRST_LOGIN_MIGRATION"
	StrategyControlledReEnrolment CredentialStrategy = "CONTROLLED_RE_ENROLMENT"
	StrategyFederatedRebind       CredentialStrategy = "FEDERATED_REBIND"
	StrategyPasskeyReEnrolment    CredentialStrategy = "PASSKEY_RE_ENROLMENT"
	StrategyMFAReEnrolment        CredentialStrategy = "MFA_RE_ENROLMENT"
	StrategyNoCredentialRequired  CredentialStrategy = "NO_CREDENTIAL_REQUIRED"
)

// Valid reports whether s is a known credential strategy.
func (s CredentialStrategy) Valid() bool {
	switch s {
	case StrategyDirectImport, StrategyFirstLoginMigration, StrategyControlledReEnrolment,
		StrategyFederatedRebind, StrategyPasskeyReEnrolment, StrategyMFAReEnrolment,
		StrategyNoCredentialRequired:
		return true
	default:
		return false
	}
}

// MigrationState is the ledger row state (ADR-IAM-0022 §10–11).
type MigrationState string

const (
	StateDiscovered          MigrationState = "DISCOVERED"
	StateValidated           MigrationState = "VALIDATED"
	StateReady               MigrationState = "READY"
	StateProvisioning        MigrationState = "PROVISIONING"
	StateProvisioned         MigrationState = "PROVISIONED"
	StateCredentialPending   MigrationState = "CREDENTIAL_PENDING"
	StateCredentialReady     MigrationState = "CREDENTIAL_READY"
	StateVerificationPending MigrationState = "VERIFICATION_PENDING"
	StateVerified            MigrationState = "VERIFIED"
	StateCutoverReady        MigrationState = "CUTOVER_READY"
	StateCutover             MigrationState = "CUTOVER"
	StateLegacyRetired       MigrationState = "LEGACY_RETIRED"
	// Failure / control states
	StateBlocked            MigrationState = "BLOCKED"
	StateFailedRetryable    MigrationState = "FAILED_RETRYABLE"
	StateFailedManualReview MigrationState = "FAILED_MANUAL_REVIEW"
	StateRolledBack         MigrationState = "ROLLED_BACK"
	StateQuarantined        MigrationState = "QUARANTINED"
)

// Valid reports whether s is one of the migration states defined by
// ADR-IAM-0022. Persisted rows fail closed on unknown values so a typo
// cannot create a ledger record that has no legal transition path.
func (s MigrationState) Valid() bool {
	switch s {
	case StateDiscovered, StateValidated, StateReady, StateProvisioning,
		StateProvisioned, StateCredentialPending, StateCredentialReady,
		StateVerificationPending, StateVerified, StateCutoverReady,
		StateCutover, StateLegacyRetired, StateBlocked, StateFailedRetryable,
		StateFailedManualReview, StateRolledBack, StateQuarantined:
		return true
	default:
		return false
	}
}

// ProviderBinding is one side of the migration mapping (issuer + subject).
// Sensitive credential material MUST NOT appear here.
type ProviderBinding struct {
	Provider string `json:"provider"` // "keycloak" | "ory"
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
}

// Record is one auditable migration ledger row (ADR-IAM-0022 §9).
//
// Explicitly excluded (never add fields for these):
// password hashes, TOTP secrets, WebAuthn payloads, OAuth client secrets,
// recovery codes, session tokens.
type Record struct {
	MigrationID      string `json:"migration_id"`
	MigrationBatchID string `json:"migration_batch_id,omitempty"`
	// CanonicalIdentityID is the CP Principal / canonical id. It MUST come from
	// an authoritative mapping, never from email equality alone.
	CanonicalIdentityID string `json:"canonical_identity_id"`

	Source ProviderBinding `json:"source"`
	Target ProviderBinding `json:"target"`

	IdentityClass      IdentityClass      `json:"identity_class"`
	CredentialStrategy CredentialStrategy `json:"credential_strategy"`
	MigrationState     MigrationState     `json:"migration_state"`
	VerificationState  string             `json:"verification_state,omitempty"`
	CutoverState       string             `json:"cutover_state,omitempty"`

	// SourceSnapshotReference points at a redacted export or batch artifact ID.
	SourceSnapshotReference string `json:"source_snapshot_reference,omitempty"`
	AttemptCount            int    `json:"attempt_count"`
	LastErrorCode           string `json:"last_error_code,omitempty"`

	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CutoverAt  *time.Time `json:"cutover_at,omitempty"`
	RetiredAt  *time.Time `json:"retired_at,omitempty"`
}

// targetOptional reports states where target issuer/subject may still be empty.
// PROVISIONING is the stage that creates the target binding.
func targetOptional(s MigrationState) bool {
	switch s {
	case StateDiscovered, StateValidated, StateReady, StateProvisioning,
		StateBlocked, StateFailedRetryable, StateFailedManualReview,
		StateRolledBack, StateQuarantined:
		return true
	default:
		return false
	}
}

// ValidateStructural checks required fields and enum validity.
// It does not perform network I/O or CP lookups.
func (r *Record) ValidateStructural() error {
	if r == nil {
		return fmt.Errorf("migration: record is nil")
	}
	if r.MigrationID == "" {
		return fmt.Errorf("migration: migration_id is required")
	}
	if r.CanonicalIdentityID == "" {
		return fmt.Errorf("migration: canonical_identity_id is required (do not invent from email)")
	}
	if r.Source.Issuer == "" || r.Source.Subject == "" {
		return fmt.Errorf("migration: source issuer and subject are required")
	}
	if r.Source.Provider == "" {
		return fmt.Errorf("migration: source provider is required")
	}
	if !targetOptional(r.MigrationState) {
		if r.Target.Issuer == "" || r.Target.Subject == "" {
			return fmt.Errorf("migration: target issuer and subject required in state %s", r.MigrationState)
		}
	}
	if !r.IdentityClass.Valid() {
		return fmt.Errorf("migration: invalid identity_class %q", r.IdentityClass)
	}
	if !r.CredentialStrategy.Valid() {
		return fmt.Errorf("migration: invalid credential_strategy %q", r.CredentialStrategy)
	}
	if !r.MigrationState.Valid() {
		return fmt.Errorf("migration: invalid migration_state %q", r.MigrationState)
	}
	// ADR-0022 §9: ledger is not a secret store — reject sensitive markers if
	// callers embed secret material in snapshot references or error codes.
	if err := checkForbiddenLedgerStrings(r.SourceSnapshotReference, r.LastErrorCode, r.MigrationID); err != nil {
		return err
	}
	return nil
}

// checkForbiddenLedgerStrings scans selected string fields for substrings that
// indicate secret material was placed on the ledger. This is a safety net for
// pilot/memory stores; durable schemas must also omit secret columns.
func checkForbiddenLedgerStrings(values ...string) error {
	for _, v := range values {
		lower := toLowerASCII(v)
		for _, bad := range forbiddenLedgerSubstrings {
			if containsASCII(lower, bad) {
				return fmt.Errorf("migration: field must not contain sensitive material marker %q (ADR-0022 §9)", bad)
			}
		}
	}
	return nil
}

// forbiddenLedgerSubstrings are case-insensitive markers. Prefer structured
// columns over embedding secrets in snapshot references or error codes.
var forbiddenLedgerSubstrings = []string{
	"password=",
	"client_secret=",
	"totp_secret",
	"private_key",
	"-----begin",
}

func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsASCII(hay, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
