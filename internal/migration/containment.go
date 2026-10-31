package migration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/jackc/pgx/v5"
)

var n05OperationID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{15,159}$`)

// NativeContainmentProvider is the existing REAL Kratos/Ory IAM admin adapter
// with the additional independent session GET readback. A mock is usable
// only in source tests; a real N05 runtime must connect through a trusted
// private admin transport and original IAM/CP witnesses.
type NativeContainmentProvider interface {
	provider.IdentityLifecycleManager
	provider.SessionRevoker
	provider.IdentityReader
	ActiveSessionCount(ctx context.Context, subject provider.ExternalSubject) (int, error)
}

// CurrentVetoEvidence comes ONLY from the independent resource/CP authority
// verifier. Neither ledger status, an IdP HTTP response, nor the caller's
// claimed JWT contents can prove current-token denial at the resource.
type CurrentVetoEvidence struct {
	SourceIssuerDenied bool
	TargetIssuerDenied bool
	CanonicalUnchanged bool
	ObservedAt time.Time
	OriginalReference string
}
type CurrentVetoReader interface {
	VerifyCurrentDenial(ctx context.Context,
		source, target provider.ExternalSubject,
		canonicalPrincipalID string) (CurrentVetoEvidence, error)
}

// NativeContainment seals an immutable durable deny fence BEFORE any
// nontransactional provider side effects. The source (retained Keycloak
// enterprise federation) is NOT globally disabled/retired by this action;
// the CP current-veto witness MUST deny it for the affected exact principal.
type NativeContainment struct {
	Store *PostgresStore
	Provider NativeContainmentProvider
	Current CurrentVetoReader
}

type ContainmentReceipt struct {
	OperationID string
	MigrationID string
	Phase string
	Classification string
	Source provider.ExternalSubject
	Target provider.ExternalSubject
	CanonicalPrincipalID string
}

func (c *NativeContainment) begin(ctx context.Context, migrationID, operationID string) (*ContainmentReceipt, error) {
	if c == nil || c.Store == nil || c.Store.pool == nil || ctx == nil ||
		!n05OperationID.MatchString(operationID) || migrationID == "" {
		return nil, errors.New("migration: bounded N05 containment input required")
	}
	tx, err := c.Store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil { return nil, n05WriteError(err) }
	defer tx.Rollback(ctx)
	var state MigrationState
	var category IdentityClass
	var source, target provider.ExternalSubject
	var canonicalID string
	err = tx.QueryRow(ctx, `SELECT migration_state, identity_class, canonical_identity_id,
source_issuer, source_subject, target_issuer, target_subject
FROM iam_migration.record WHERE migration_id=$1 FOR UPDATE`, migrationID).Scan(
		&state, &category, &canonicalID,
		&source.Issuer, &source.Subject, &target.Issuer, &target.Subject)
	if errors.Is(err, pgx.ErrNoRows) { return nil, ErrNotFound }
	if err != nil { return nil, n05WriteError(err) }
	if category != ClassHuman && category != ClassPrivilegedHuman &&
		category != ClassFederatedHuman && category != ClassTestOrNonProd {
		return nil, errors.New("migration: N05 human containment cannot impersonate workload lifecycle")
	}
	if target.Issuer == "" || target.Subject == "" || canonicalID == "" ||
		state == StateLegacyRetired || state == StateDiscovered {
		return nil, errors.New("migration: no verified, reversible target human binding")
	}
	if state != StateQuarantined && !CanTransition(state, StateQuarantined) {
		return nil, errors.New("migration: quarantine transition not permitted")
	}
	// One operation per migration. Idempotent replay requires the exact same
	// operator-supplied id, not a second operation that races with a prior
	// provider side effect (including one in UNKNOWN outcome).
	var prior string
	err = tx.QueryRow(ctx, `SELECT operation_id FROM iam_migration.containment
WHERE migration_id=$1 LIMIT 1 FOR UPDATE`, migrationID).Scan(&prior)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) { return nil, n05WriteError(err) }
	if err == nil && prior != operationID {
		return nil, ErrMigrationConflict
	}
	if err != nil {
		if _, err = tx.Exec(ctx, `INSERT INTO iam_migration.containment
(operation_id,migration_id,target_issuer,target_subject,phase)
VALUES ($1,$2,$3,$4,'PENDING')`,
			operationID, migrationID, target.Issuer, target.Subject); err != nil {
			return nil, n05WriteError(err)
		}
	}
	// Persist the deny fence before the external call. A stale backup or
	// a later ROLLED_BACK transition may not erase it.
	if _, err = tx.Exec(ctx, `INSERT INTO iam_migration.deny_fence
(migration_id,source_issuer,source_subject,target_issuer,target_subject)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT (migration_id) DO NOTHING`,
		migrationID, source.Issuer, source.Subject,
		target.Issuer, target.Subject); err != nil {
		return nil, n05WriteError(err)
	}
	var observedSource, observedSubject, observedTarget, observedTargetSubject string
	err = tx.QueryRow(ctx, `SELECT source_issuer,source_subject,target_issuer,target_subject
FROM iam_migration.deny_fence WHERE migration_id=$1`, migrationID).Scan(
		&observedSource, &observedSubject, &observedTarget, &observedTargetSubject)
	if err != nil || observedSource != source.Issuer || observedSubject != source.Subject ||
		observedTarget != target.Issuer || observedTargetSubject != target.Subject {
		return nil, ErrMigrationConflict
	}
	if state != StateQuarantined {
		if _, err = tx.Exec(ctx, `UPDATE iam_migration.record
SET migration_state='QUARANTINED', revision=revision+1
WHERE migration_id=$1`, migrationID); err != nil { return nil, n05WriteError(err) }
	}
	var phase string
	if err = tx.QueryRow(ctx, `SELECT phase FROM iam_migration.containment
WHERE operation_id=$1`, operationID).Scan(&phase); err != nil {
		return nil, n05WriteError(err)
	}
	if err = tx.Commit(ctx); err != nil { return nil, n05WriteError(err) }
	return &ContainmentReceipt{
		OperationID: operationID, MigrationID: migrationID, Phase: phase,
		Classification: "DURABLE_IAM_DENY_FENCE_NOT_RESOURCE_ATTESTATION",
		Source: source, Target: target, CanonicalPrincipalID: canonicalID,
	}, nil
}

func (c *NativeContainment) markPhase(ctx context.Context, id, phase string) error {
	if ctx == nil || c == nil || c.Store == nil {
		return errors.New("migration: containment journal unavailable")
	}
	if phase != "IDENTITY_DISABLED" && phase != "SESSIONS_REVOKED" &&
		phase != "CURRENT_TOKENS_DENIED" && phase != "VERIFIED" &&
		phase != "UNKNOWN" {
		return errors.New("migration: unrecognized containment phase")
	}
	_, err := c.Store.pool.Exec(ctx, `UPDATE iam_migration.containment
SET phase=$2, updated_at=statement_timestamp()
WHERE operation_id=$1 AND (phase <> 'VERIFIED' OR $2='UNKNOWN')`, id, phase)
	return n05PhaseError(err)
}
func n05PhaseError(err error) error {
	if err == nil { return nil }
	return fmt.Errorf("migration: containment journal unavailable: %w", err)
}

// Contain performs the real provider kill-switch, independent current
// provider readback, and CP/resource token-denial readback. Every failure
// leaves the persistent fence and an UNKNOWN journal phase (unless the
// database is unavailable). No success is inferred from HTTP 2xx alone.
func (c *NativeContainment) Contain(ctx context.Context, migrationID, operationID string) (*ContainmentReceipt, error) {
	receipt, err := c.begin(ctx, migrationID, operationID)
	if err != nil { return nil, err }
	if receipt.Phase == "VERIFIED" {
		// A restored provider snapshot can resurrect a previously revoked
		// session. A historical VERIFIED row is NOT a current authority
		// observation: recheck all three independent boundaries on replay,
		// without issuing any enable/delete or new provider mutation.
		if c.Provider == nil || c.Current == nil {
			return nil, errors.New("migration: current verified-containment readback unavailable")
		}
		identity, readErr := c.Provider.GetIdentity(ctx, receipt.Target)
		count, countErr := c.Provider.ActiveSessionCount(ctx, receipt.Target)
		proof, proofErr := c.Current.VerifyCurrentDenial(
			ctx, receipt.Source, receipt.Target, receipt.CanonicalPrincipalID)
		now := time.Now().UTC()
		if readErr != nil || identity == nil ||
			identity.Issuer != receipt.Target.Issuer ||
			identity.Subject != receipt.Target.Subject ||
			identity.Status != provider.IdentityStatusDisabled ||
			countErr != nil || count != 0 || proofErr != nil ||
			!proof.SourceIssuerDenied || !proof.TargetIssuerDenied ||
			!proof.CanonicalUnchanged || proof.OriginalReference == "" ||
			proof.ObservedAt.IsZero() || proof.ObservedAt.After(now) ||
			now.Sub(proof.ObservedAt) > time.Minute {
			// An old VERIFIED event remains immutable history. The *current*
			// state becomes UNKNOWN, never a resurrected trusted session.
			recovery, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = c.markPhase(recovery, operationID, "UNKNOWN")
			return nil, errors.New("migration: current containment drift after restore/replay")
		}
		return receipt, nil
	}
	defer func() {
		if err != nil {
			// Context may have expired mid-provider call. Preserve UNKNOWN
			// using an independent small recovery lease, without logging
			// provider payloads, credentials, or subject identifiers.
			recovery, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = c.markPhase(recovery, operationID, "UNKNOWN")
		}
	}()
	if c.Provider == nil || c.Current == nil {
		err = errors.New("migration: real issuer and CP/resource revocation witnesses required")
		return nil, err
	}
	if err = c.Provider.DisableIdentity(ctx, receipt.Target); err != nil {
		return nil, errors.New("migration: target identity disable unconfirmed")
	}
	currentIdentity, readErr := c.Provider.GetIdentity(ctx, receipt.Target)
	if readErr != nil || currentIdentity == nil ||
		currentIdentity.Issuer != receipt.Target.Issuer ||
		currentIdentity.Subject != receipt.Target.Subject ||
		currentIdentity.Status != provider.IdentityStatusDisabled {
		err = errors.New("migration: target disable readback failed")
		return nil, err
	}
	if err = c.markPhase(ctx, operationID, "IDENTITY_DISABLED"); err != nil {
		return nil, err
	}
	if err = c.Provider.RevokeSessions(ctx, receipt.Target); err != nil {
		return nil, errors.New("migration: target session revocation unconfirmed")
	}
	count, countErr := c.Provider.ActiveSessionCount(ctx, receipt.Target)
	if countErr != nil || count != 0 {
		err = errors.New("migration: active native sessions remain or readback unavailable")
		return nil, err
	}
	if err = c.markPhase(ctx, operationID, "SESSIONS_REVOKED"); err != nil {
		return nil, err
	}
	proof, proofErr := c.Current.VerifyCurrentDenial(
		ctx, receipt.Source, receipt.Target, receipt.CanonicalPrincipalID)
	now := time.Now().UTC()
	if proofErr != nil || !proof.SourceIssuerDenied ||
		!proof.TargetIssuerDenied || !proof.CanonicalUnchanged ||
		proof.OriginalReference == "" ||
		proof.ObservedAt.IsZero() || proof.ObservedAt.After(now) ||
		now.Sub(proof.ObservedAt) > time.Minute {
		err = errors.New("migration: current source/target CP token denial not proven")
		return nil, err
	}
	if err = c.markPhase(ctx, operationID, "CURRENT_TOKENS_DENIED"); err != nil {
		return nil, err
	}
	if err = c.markPhase(ctx, operationID, "VERIFIED"); err != nil { return nil, err }
	receipt.Phase = "VERIFIED"
	receipt.Classification = "IAM_PROVIDER_CP_WITNESSES_REPORTED_NOT_INDEPENDENTLY_ATTESTED"
	return receipt, nil
}

// DeniedByFence is an IAM owner-side durable write-down. CP and resource
// verifiers must separately enforce their own current trust/revocation
// policy; they cannot treat this function alone as proof of bearer denial.
func (s *PostgresStore) DeniedByFence(ctx context.Context, migrationID string) (bool, error) {
	var found bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (
SELECT 1 FROM iam_migration.deny_fence WHERE migration_id=$1)`, migrationID).Scan(&found)
	return found, err
}

// RollbackWitness is supplied only after independent per-actor CP authority,
// original provider and unchanged-Principal verification. It does not
// authorize reenabling credentials or deleting a deny tombstone.
type RollbackWitness struct {
	SourceFallbackConfirmed bool
	TargetActorDenied bool
	CanonicalUnchanged bool
	LegacyRevocationsPreserved bool
	OriginalReference string
}
type RollbackVerifier interface {
	VerifyPreCutoverRollback(ctx context.Context, r *Record) (RollbackWitness, error)
}

// RollbackPreCutover never retires Keycloak federation or restores revoked
// authentication. Cutover is excluded by the default Phase C policy, and a
// prior N05 deny fence prevents any rollback from resurrecting the actor.
func (s *PostgresStore) RollbackPreCutover(
	ctx context.Context, id string, verifier RollbackVerifier,
) (*Record, error) {
	if s == nil || verifier == nil || ctx == nil { return nil, errors.New("migration: rollback verifier required") }
	fenced, err := s.DeniedByFence(ctx, id)
	if err != nil { return nil, err }
	if fenced { return nil, errors.New("migration: rollback cannot restore revoked authority") }
	current, err := s.Get(ctx, id)
	if err != nil { return nil, err }
	if current.MigrationState == StateCutover ||
		current.MigrationState == StateLegacyRetired ||
		!CanTransition(current.MigrationState, StateRolledBack) {
		return nil, ErrCutoverNotApproved
	}
	witness, err := verifier.VerifyPreCutoverRollback(ctx, current)
	if err != nil || !witness.SourceFallbackConfirmed ||
		!witness.TargetActorDenied ||
		!witness.CanonicalUnchanged || !witness.LegacyRevocationsPreserved ||
		witness.OriginalReference == "" {
		return nil, errors.New("migration: independent rollback/trust readback missing")
	}
	svc := &Service{Store: s}
	return svc.ApplyTransition(ctx, id, StateRolledBack)
}
