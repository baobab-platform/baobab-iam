package securityops

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresJournal is a real durable deny-intent/phase journal. DDL lives in
// migrations/001_incident_containment.sql and must be applied by operations.
type PostgresJournal struct{ Pool *pgxpool.Pool }

func (j PostgresJournal) Reserve(ctx context.Context, intent Intent) (Phase, error) {
	if j.Pool == nil || ctx == nil || ctx.Err() != nil ||
		!operationID.MatchString(intent.OperationID) ||
		!operationID.MatchString(intent.IncidentID) ||
		intent.Subject.Validate() != nil {
		return "", errors.New("securityops: invalid journal reservation")
	}
	tx, err := j.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return "", errors.New("securityops: durable journal unavailable")
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO iam_security.incident_containment
(operation_id, incident_id, issuer, subject, phase)
VALUES ($1,$2,$3,$4,'FENCED') ON CONFLICT DO NOTHING`,
		intent.OperationID, intent.IncidentID, intent.Subject.Issuer, intent.Subject.Subject)
	if err != nil {
		return "", errors.New("securityops: durable journal insertion failed")
	}
	var incident, issuer, subject, phase string
	err = tx.QueryRow(ctx, `SELECT incident_id, issuer, subject, phase
FROM iam_security.incident_containment WHERE operation_id=$1 FOR UPDATE`,
		intent.OperationID).Scan(&incident, &issuer, &subject, &phase)
	if err != nil || incident != intent.IncidentID ||
		issuer != intent.Subject.Issuer || subject != intent.Subject.Subject {
		return "", errors.New("securityops: conflicting incident containment intent")
	}
	switch Phase(phase) {
	case PhaseFenced, PhaseDisabled, PhaseRevoked, PhaseVerified, PhaseUnknown:
	default:
		return "", errors.New("securityops: unknown journal phase")
	}
	if err := tx.Commit(ctx); err != nil {
		return "", errors.New("securityops: incident reservation commit unconfirmed")
	}
	return Phase(phase), nil
}

func (j PostgresJournal) Mark(ctx context.Context, id string, phase Phase) error {
	if j.Pool == nil || ctx == nil || !operationID.MatchString(id) {
		return errors.New("securityops: journal unavailable")
	}
	switch phase {
	case PhaseDisabled, PhaseRevoked, PhaseVerified, PhaseUnknown:
	default:
		return errors.New("securityops: unsupported journal phase")
	}
	tag, err := j.Pool.Exec(ctx, `UPDATE iam_security.incident_containment
SET phase=$2, updated_at=statement_timestamp()
WHERE operation_id=$1 AND (phase <> 'VERIFIED' OR $2='UNKNOWN')`, id, string(phase))
	if err != nil || tag.RowsAffected() != 1 {
		return errors.New("securityops: journal transition unconfirmed")
	}
	return nil
}

var _ Journal = PostgresJournal{}
