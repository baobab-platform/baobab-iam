package privacy

import (
	"context"
	"errors"

	"github.com/baobab-platform/baobab-iam/internal/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository must be connected to independent privacy-state custody,
// not to the historical Kratos/Hydra database selected for restore.
type PostgresRepository struct{ Pool *pgxpool.Pool }

func (r PostgresRepository) PutRestricted(ctx context.Context, record Restriction) error {
	if r.Pool == nil || ctx == nil || ctx.Err() != nil ||
		record.Subject.Validate() != nil ||
		!receiptIDPattern.MatchString(record.DecisionID) {
		return ErrPrivacyHold
	}
	// Deliberately insert-only. A changed decision cannot silently erase or
	// overwrite an existing restrictive state. Conflicting receipt is denied.
	_, err := r.Pool.Exec(ctx, `INSERT INTO iam_privacy.restriction_tombstone
(issuer, subject, decision_id)
VALUES ($1,$2,$3) ON CONFLICT (issuer,subject) DO NOTHING`,
		record.Subject.Issuer, record.Subject.Subject, record.DecisionID)
	if err != nil {
		return ErrPrivacyHold
	}
	var persisted string
	err = r.Pool.QueryRow(ctx, `SELECT decision_id FROM iam_privacy.restriction_tombstone
WHERE issuer=$1 AND subject=$2`,
		record.Subject.Issuer, record.Subject.Subject).Scan(&persisted)
	if err != nil || persisted != record.DecisionID {
		return ErrPrivacyHold
	}
	return nil
}

func (r PostgresRepository) IsRestricted(ctx context.Context, subject provider.ExternalSubject) (bool, error) {
	if r.Pool == nil || ctx == nil || ctx.Err() != nil ||
		subject.Validate() != nil {
		return false, ErrPrivacyHold
	}
	var restricted bool
	err := r.Pool.QueryRow(ctx, `SELECT EXISTS(
SELECT 1 FROM iam_privacy.restriction_tombstone WHERE issuer=$1 AND subject=$2)`,
		subject.Issuer, subject.Subject).Scan(&restricted)
	if err != nil {
		return false, ErrPrivacyHold
	}
	return restricted, nil
}

func (r PostgresRepository) ListRestricted(ctx context.Context) ([]provider.ExternalSubject, error) {
	if r.Pool == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrPrivacyHold
	}
	tx, err := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrPrivacyHold
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT issuer, subject FROM iam_privacy.restriction_tombstone
ORDER BY issuer, subject`)
	if err != nil {
		return nil, ErrPrivacyHold
	}
	var subjects []provider.ExternalSubject
	for rows.Next() {
		var subject provider.ExternalSubject
		if err := rows.Scan(&subject.Issuer, &subject.Subject); err != nil ||
			subject.Validate() != nil {
			rows.Close()
			return nil, ErrPrivacyHold
		}
		subjects = append(subjects, subject)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, ErrPrivacyHold
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("privacy: independent journal snapshot unconfirmed")
	}
	return subjects, nil
}

var _ Repository = PostgresRepository{}
