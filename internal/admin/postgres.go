package admin

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresLeaseJournal persists accountable emergency evidence; it MUST be
// isolated from the unavailable IAM provider and use a restricted DB identity.
type PostgresLeaseJournal struct{ Pool *pgxpool.Pool }

func (p PostgresLeaseJournal) Reserve(ctx context.Context, lease Lease) error {
	if p.Pool == nil || ctx == nil || ctx.Err() != nil ||
		!lease.Request.Valid() || lease.Status != StatePending {
		return ErrBreakGlassDenied
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ErrBreakGlassDenied
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO iam_admin.breakglass_lease
(lease_id,incident_id,action,scope_type,scope_id,reason,actor_id,approver_id,
independent_auth_ref,review_ref,approved_at,expires_at,status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'PENDING')
ON CONFLICT (lease_id) DO NOTHING`,
		lease.Request.LeaseID, lease.Request.IncidentID, lease.Request.Action,
		lease.Request.ScopeType, lease.Request.ScopeID, lease.Request.Reason,
		lease.Witness.ActorID, lease.Witness.ApproverID,
		lease.Witness.IndependentAuthRef, lease.Witness.IndependentReviewRef,
		lease.Witness.ApprovedAt, lease.Witness.ExpiresAt)
	if err != nil {
		return ErrBreakGlassDenied
	}
	var observed Lease
	err = tx.QueryRow(ctx, `SELECT incident_id,action,scope_type,scope_id,reason,
actor_id,approver_id,independent_auth_ref,review_ref,approved_at,expires_at,status
FROM iam_admin.breakglass_lease WHERE lease_id=$1 FOR UPDATE`,
		lease.Request.LeaseID).Scan(
		&observed.Request.IncidentID, &observed.Request.Action, &observed.Request.ScopeType,
		&observed.Request.ScopeID, &observed.Request.Reason,
		&observed.Witness.ActorID, &observed.Witness.ApproverID,
		&observed.Witness.IndependentAuthRef, &observed.Witness.IndependentReviewRef,
		&observed.Witness.ApprovedAt, &observed.Witness.ExpiresAt,
		&observed.Status)
	observed.Request.LeaseID = lease.Request.LeaseID
	if err != nil || observed.Request != lease.Request ||
		observed.Status != StatePending ||
		observed.Witness.ActorID != lease.Witness.ActorID ||
		observed.Witness.ApproverID != lease.Witness.ApproverID ||
		observed.Witness.IndependentAuthRef != lease.Witness.IndependentAuthRef ||
		observed.Witness.IndependentReviewRef != lease.Witness.IndependentReviewRef ||
		!observed.Witness.ApprovedAt.Equal(lease.Witness.ApprovedAt) ||
		!observed.Witness.ExpiresAt.Equal(lease.Witness.ExpiresAt) {
		return ErrBreakGlassDenied
	}
	if tx.Commit(ctx) != nil {
		return ErrBreakGlassDenied
	}
	return nil
}

func (p PostgresLeaseJournal) Activate(ctx context.Context, id string) error {
	if p.Pool == nil || ctx == nil || ctx.Err() != nil || !uuid.MatchString(id) {
		return ErrBreakGlassDenied
	}
	tag, err := p.Pool.Exec(ctx, `UPDATE iam_admin.breakglass_lease
SET status='ACTIVE' WHERE lease_id=$1 AND status='PENDING' AND expires_at>statement_timestamp()`, id)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrBreakGlassDenied
	}
	return nil
}

func (p PostgresLeaseJournal) Read(ctx context.Context, id string) (Lease, error) {
	if p.Pool == nil || ctx == nil || ctx.Err() != nil || !uuid.MatchString(id) {
		return Lease{}, ErrBreakGlassDenied
	}
	var out Lease
	err := p.Pool.QueryRow(ctx, `SELECT incident_id,action,scope_type,scope_id,reason,
actor_id,approver_id,independent_auth_ref,review_ref,approved_at,expires_at,status
FROM iam_admin.breakglass_lease WHERE lease_id=$1`, id).Scan(
		&out.Request.IncidentID, &out.Request.Action, &out.Request.ScopeType,
		&out.Request.ScopeID, &out.Request.Reason, &out.Witness.ActorID,
		&out.Witness.ApproverID, &out.Witness.IndependentAuthRef,
		&out.Witness.IndependentReviewRef, &out.Witness.ApprovedAt,
		&out.Witness.ExpiresAt, &out.Status)
	if err != nil {
		return Lease{}, ErrBreakGlassDenied
	}
	out.Request.LeaseID = id
	return out, nil
}

func (p PostgresLeaseJournal) Terminate(ctx context.Context, id string) error {
	if p.Pool == nil || ctx == nil || ctx.Err() != nil || !uuid.MatchString(id) {
		return ErrBreakGlassDenied
	}
	tag, err := p.Pool.Exec(ctx, `UPDATE iam_admin.breakglass_lease
SET status='TERMINATED' WHERE lease_id=$1 AND status='ACTIVE'`, id)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrBreakGlassDenied
	}
	return nil
}

var _ LeaseJournal = PostgresLeaseJournal{}
