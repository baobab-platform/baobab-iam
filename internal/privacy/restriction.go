// Package privacy owns minimal restrictive identity-state records, not
// legal erasure decisions or CP/domain identity and business authority.
// ADR-IAM-0030: do not recreate active access after a backup or event replay.
package privacy

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/baobab-platform/baobab-iam/internal/provider"
)

var receiptIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{15,159}$`)

var ErrPrivacyHold = errors.New("privacy: identity restriction or journal uncertainty denies reactivation")

// Restriction must not contain email, traits, proofing records or secret
// material. Issuer+subject are purpose-limited personal data and still need
// protected storage and bounded retention.
type Restriction struct {
	Subject    provider.ExternalSubject
	DecisionID string
}

type Decision struct {
	DecisionID string
	Subject    provider.ExternalSubject
	ActorID    string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type PrivacyAuthority interface {
	AuthorizeRestriction(context.Context, Restriction) (Decision, error)
}

// Repository must live in an independently recoverable restricted journal.
// A table stored only in the same backup being restored is insufficient.
type Repository interface {
	PutRestricted(context.Context, Restriction) error
	IsRestricted(context.Context, provider.ExternalSubject) (bool, error)
	ListRestricted(context.Context) ([]provider.ExternalSubject, error)
}

type Service struct {
	Authority PrivacyAuthority
	Journal   Repository
	Now       func() time.Time
}

func (s *Service) RecordRestriction(ctx context.Context, record Restriction) error {
	if s == nil || s.Authority == nil || s.Journal == nil || s.Now == nil ||
		ctx == nil || ctx.Err() != nil ||
		record.Subject.Validate() != nil || !receiptIDPattern.MatchString(record.DecisionID) {
		return ErrPrivacyHold
	}
	current := s.Now().UTC()
	auth, err := s.Authority.AuthorizeRestriction(ctx, record)
	if err != nil || auth.Subject != record.Subject ||
		auth.DecisionID != record.DecisionID ||
		!receiptIDPattern.MatchString(auth.ActorID) ||
		auth.VerifiedAt.IsZero() || auth.VerifiedAt.After(current) ||
		current.Sub(auth.VerifiedAt) > time.Minute ||
		!current.Before(auth.ExpiresAt) {
		return ErrPrivacyHold
	}
	// A durable restrictive tombstone is written before any future provider
	// reactivation or restoration is allowed.
	if err := s.Journal.PutRestricted(ctx, record); err != nil {
		return ErrPrivacyHold
	}
	restricted, err := s.Journal.IsRestricted(ctx, record.Subject)
	if err != nil || !restricted {
		return ErrPrivacyHold
	}
	return nil
}

// CheckReactivation is an additional veto, not an authorization to activate.
// A missing row cannot override provider/CP/domain current authority.
func (s *Service) CheckReactivation(ctx context.Context, subject provider.ExternalSubject) error {
	if s == nil || s.Journal == nil || ctx == nil || ctx.Err() != nil ||
		subject.Validate() != nil {
		return ErrPrivacyHold
	}
	restricted, err := s.Journal.IsRestricted(ctx, subject)
	if err != nil || restricted {
		return ErrPrivacyHold
	}
	return nil
}

type NativeRevocationProvider interface {
	provider.IdentityLifecycleManager
	provider.SessionRevoker
	provider.IdentityReader
	ActiveSessionCount(context.Context, provider.ExternalSubject) (int, error)
}

// CPReadback must be an original, current denial by a CP/resource authority,
// not a provider response or an unverified bearer-token payload.
type CPReadback struct {
	Subject         provider.ExternalSubject
	CurrentDenied   bool
	ObservedAt      time.Time
	EvidenceRef     string
}
type CPDenialWitness interface {
	VerifyRestrictedPrincipal(context.Context, provider.ExternalSubject) (CPReadback, error)
}

// CheckpointVerifier is an independent privacy-custody witness. It must
// attest that the list snapshot is complete, not merely that SQL succeeded.
type CheckpointProof struct {
	Revision    string
	EvidenceRef string
	ObservedAt  time.Time
}

type CheckpointVerifier interface {
	VerifyComplete(context.Context) (CheckpointProof, error)
}

type RestoreReconciler struct {
	Journal    Repository
	Provider   NativeRevocationProvider
	CP         CPDenialWitness
	Checkpoint CheckpointVerifier
	Now        func() time.Time
}

func (r *RestoreReconciler) ReassertRestriction(ctx context.Context, subject provider.ExternalSubject) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.Journal == nil ||
		r.Provider == nil || r.CP == nil || r.Now == nil ||
		subject.Validate() != nil {
		return ErrPrivacyHold
	}
	restricted, err := r.Journal.IsRestricted(ctx, subject)
	if err != nil || !restricted {
		return ErrPrivacyHold
	}
	if err := r.Provider.DisableIdentity(ctx, subject); err != nil {
		return ErrPrivacyHold
	}
	identity, err := r.Provider.GetIdentity(ctx, subject)
	if err != nil || identity == nil || identity.Issuer != subject.Issuer ||
		identity.Subject != subject.Subject ||
		identity.Status != provider.IdentityStatusDisabled {
		return ErrPrivacyHold
	}
	if err := r.Provider.RevokeSessions(ctx, subject); err != nil {
		return ErrPrivacyHold
	}
	active, err := r.Provider.ActiveSessionCount(ctx, subject)
	if err != nil || active != 0 {
		return ErrPrivacyHold
	}
	witness, err := r.CP.VerifyRestrictedPrincipal(ctx, subject)
	now := r.Now().UTC()
	if err != nil || witness.Subject != subject || !witness.CurrentDenied ||
		witness.EvidenceRef == "" || witness.ObservedAt.IsZero() ||
		witness.ObservedAt.After(now) || now.Sub(witness.ObservedAt) > time.Minute {
		return ErrPrivacyHold
	}
	// A concurrent restriction journal outage invalidates the replay proof.
	restricted, err = r.Journal.IsRestricted(ctx, subject)
	if err != nil || !restricted {
		return ErrPrivacyHold
	}
	return nil
}

// ReassertAll does not authorize new traffic. An independent Security/Privacy
// checkpoint witness must establish that the journal is COMPLETE before a DR
// promotion controller may consider this replay among its other gates.
func (r *RestoreReconciler) ReassertAll(ctx context.Context) (int, error) {
	if r == nil || r.Journal == nil || r.Checkpoint == nil || r.Now == nil ||
		ctx == nil || ctx.Err() != nil {
		return 0, ErrPrivacyHold
	}
	first, err := r.Checkpoint.VerifyComplete(ctx)
	if err != nil || !r.validCheckpoint(first) {
		return 0, ErrPrivacyHold
	}
	subjects, err := r.Journal.ListRestricted(ctx)
	if err != nil {
		return 0, ErrPrivacyHold
	}
	for i, subject := range subjects {
		if err := r.ReassertRestriction(ctx, subject); err != nil {
			return i, ErrPrivacyHold
		}
	}
	last, err := r.Checkpoint.VerifyComplete(ctx)
	if err != nil || !r.validCheckpoint(last) || first.Revision != last.Revision {
		return len(subjects), ErrPrivacyHold
	}
	return len(subjects), nil
}

func (r *RestoreReconciler) validCheckpoint(proof CheckpointProof) bool {
	now := r.Now().UTC()
	return receiptIDPattern.MatchString(proof.Revision) &&
		proof.EvidenceRef != "" && !proof.ObservedAt.IsZero() &&
		!proof.ObservedAt.After(now) && now.Sub(proof.ObservedAt) <= time.Minute
}
