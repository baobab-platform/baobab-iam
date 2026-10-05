package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// ApprovalAuthority evaluates CURRENT administrative authority at the target
// scope. It returns a canonical CP principal; an IAM role, email or caller ID
// is never accepted as an approval actor. Effective-authority display is not
// an implementation of this port. No default authorizer is provided.
type ApprovalAuthority interface {
	AuthorizeApproval(context.Context, string, ReferenceExpectation) (ApprovalActor, error)
}
type ApprovalActor struct {
	PrincipalID string
	ValidUntil  time.Time
}

// ApprovalProposal is an immutable non-secret receipt target. Resolution of
// the referenced CP ExternalReference and target bytes happens independently
// at approval AND use; existence alone never confers approval.
type ApprovalProposal struct {
	ID                    string
	Receipt               ApprovedReference
	TargetDigest          string
	Maker, Checker        string
	Status                string
	ProposedAt, DecidedAt time.Time
	Revoker               string     `json:",omitempty"`
	RevokedAt             *time.Time `json:",omitempty"`
}
type ApprovalTargets interface {
	// ResolveApprovedTarget verifies the CP reference's current namespace,
	// native target purpose, trust/binding/scope/revision and immutable digest.
	// It must refuse secret-bearing targets and unresolved/manual-import refs.
	ResolveApprovedTarget(context.Context, ReferenceExpectation) (string, error)
}

// ApprovalLedger is a durable local IAM approval ledger. It is not CP's
// principal, platform registry or generic business CanonicalMapping store.
// Open requires an explicit authority, target resolver and clock. Single writer
// file locking and atomic transactions prevent simultaneous checker decisions.
type ApprovalLedger struct {
	db        ledgerDB
	authority ApprovalAuthority
	targets   ApprovalTargets
	now       func() time.Time
}

var approvalBucket = []byte("federation-approvals-v1")

func OpenApprovalLedger(path string, authority ApprovalAuthority, targets ApprovalTargets, now func() time.Time) (*ApprovalLedger, error) {
	return openApprovalLedger(nil, path, authority, targets, now)
}

func OpenApprovalLedgerWithStorage(storage *PostgresStorage, authority ApprovalAuthority, targets ApprovalTargets, now func() time.Time) (*ApprovalLedger, error) {
	return openApprovalLedger(storage, "", authority, targets, now)
}

func openApprovalLedger(storage *PostgresStorage, path string, authority ApprovalAuthority, targets ApprovalTargets, now func() time.Time) (*ApprovalLedger, error) {
	if (path == "" && storage == nil) || absent(authority) || absent(targets) || now == nil {
		return nil, ErrInvalid
	}
	db, err := openLedger(path, storage, "approvals")
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = db.Update(func(tx ledgerTx) error { _, e := tx.CreateBucketIfNotExists(approvalBucket); return e }); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	return &ApprovalLedger{db, authority, targets, now}, nil
}
func (l *ApprovalLedger) Close() error {
	if l == nil || l.db == nil {
		return ErrUnavailable
	}
	return l.db.Close()
}
func approvalKey(id string) []byte { return []byte("proposal:" + id) }
func receiptKey(want ReferenceExpectation) []byte {
	b, _ := json.Marshal(want)
	d := sha256.Sum256(b)
	return []byte("current:" + hex.EncodeToString(d[:]))
}
func validExpectation(w ReferenceExpectation) bool {
	if !validRef(w.ID) ||
		!uuidPattern.MatchString(w.TrustID) ||
		w.SnapshotID == "" || len(w.SnapshotID) > 128 || strings.TrimSpace(w.SnapshotID) != w.SnapshotID ||
		w.TrustRevision < 1 ||
		!validScope(w.Scope) ||
		len(w.ProviderID) < 10 || len(w.ProviderID) > 63 || !providerPattern.MatchString(w.ProviderID) ||
		len(w.EngineInstanceID) < 6 || len(w.EngineInstanceID) > 63 || !instancePattern.MatchString(w.EngineInstanceID) {
		return false
	}
	switch w.Kind {
	case "federation_configuration", "federation_trust_material", "assurance_policy", "attribute_mapping", "provisioning_policy", "federation_activation", "identity_runtime_profile", "identity_runtime_support", "identity_security_domain":
		return w.EventID == "" && w.Issuer == "" && w.Subject == "" && w.Level == "" && w.EvidenceDigest == "" && w.PrincipalID == "" && w.ExternalIdentityID == ""
	case "assurance_mapping_decision":
		return w.Issuer != "" && len(w.Issuer) <= 2048 &&
			uuidPattern.MatchString(w.EventID) && exact(w.Subject) &&
			(w.Level == "BAOBAB-A1" || w.Level == "BAOBAB-A2" || w.Level == "BAOBAB-A3") &&
			digestPattern.MatchString(w.EvidenceDigest) &&
			w.PrincipalID == "" && w.ExternalIdentityID == ""
	case "canonical_identity_mapping":
		return w.Issuer != "" && len(w.Issuer) <= 2048 && exact(w.Subject) &&
			uuidPattern.MatchString(w.PrincipalID) && uuidPattern.MatchString(w.ExternalIdentityID) &&
			w.EventID == "" && w.Level == "" && w.EvidenceDigest == ""
	}
	return false
}
func (l *ApprovalLedger) actor(ctx context.Context, action string, want ReferenceExpectation) (ApprovalActor, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil {
		return ApprovalActor{}, ErrUnavailable
	}
	a, err := l.authority.AuthorizeApproval(ctx, action, want)
	if err != nil {
		return ApprovalActor{}, authorityError(err)
	}
	if !uuidPattern.MatchString(a.PrincipalID) || !l.now().Before(a.ValidUntil) {
		return ApprovalActor{}, ErrDenied
	}
	return a, nil
}
func (l *ApprovalLedger) target(ctx context.Context, w ReferenceExpectation) (string, error) {
	d, err := l.targets.ResolveApprovedTarget(ctx, w)
	if err != nil {
		return "", authorityError(err)
	}
	if !digestPattern.MatchString(d) {
		return "", ErrUnverified
	}
	return d, nil
}
func (l *ApprovalLedger) Propose(ctx context.Context, id string, receipt ApprovedReference) (ApprovalProposal, error) {
	if !uuidPattern.MatchString(id) || !validExpectation(receipt.Expectation) || receipt.Status != "APPROVED" || !receipt.NonSecret {
		return ApprovalProposal{}, ErrInvalid
	}
	a, err := l.actor(ctx, "PROPOSE", receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	d, err := l.target(ctx, receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	currentActor, err := l.actor(ctx, "PROPOSE", receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	if currentActor.PrincipalID != a.PrincipalID {
		return ApprovalProposal{}, ErrDenied
	}
	a = currentActor
	now := l.now()
	if !fresh(receipt.ValidFrom, receipt.ExpiresAt, now) || !now.Before(a.ValidUntil) {
		return ApprovalProposal{}, ErrDenied
	}
	p := ApprovalProposal{ID: id, Receipt: receipt, TargetDigest: d, Maker: a.PrincipalID, Status: "PENDING", ProposedAt: now}
	data, _ := json.Marshal(p)
	err = l.db.Update(func(tx ledgerTx) error {
		if ctx.Err() != nil || !l.now().Before(a.ValidUntil) || !l.now().Before(receipt.ExpiresAt) {
			return ErrDenied
		}
		b := tx.Bucket(approvalBucket)
		if b.Get(approvalKey(id)) != nil {
			return ErrDenied
		}
		return b.Put(approvalKey(id), data)
	})
	if err != nil {
		return ApprovalProposal{}, authorityError(err)
	}
	return p, nil
}
func (l *ApprovalLedger) proposal(ctx context.Context, id string) (ApprovalProposal, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) {
		return ApprovalProposal{}, ErrInvalid
	}
	var p ApprovalProposal
	err := l.db.View(func(tx ledgerTx) error {
		b := tx.Bucket(approvalBucket).Get(approvalKey(id))
		if b == nil {
			return ErrDenied
		}
		return decodeAuthority(b, &p)
	})
	if err != nil {
		return ApprovalProposal{}, authorityError(err)
	}
	return p, nil
}

// Decide is compare-and-swap against the immutable proposal and target digest.
// An expired, changed, already-decided or self-authored target cannot be approved.
func (l *ApprovalLedger) Decide(ctx context.Context, id, digest string, approve bool) (ApprovalProposal, error) {
	p, err := l.proposal(ctx, id)
	if err != nil {
		return ApprovalProposal{}, err
	}
	if p.Status != "PENDING" || digest != p.TargetDigest {
		return ApprovalProposal{}, ErrDenied
	}
	a, err := l.actor(ctx, "DECIDE", p.Receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	if a.PrincipalID == p.Maker {
		return ApprovalProposal{}, ErrDenied
	}
	d, err := l.target(ctx, p.Receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	if d != digest {
		return ApprovalProposal{}, ErrUnverified
	}
	currentActor, err := l.actor(ctx, "DECIDE", p.Receipt.Expectation)
	if err != nil {
		return ApprovalProposal{}, err
	}
	if currentActor.PrincipalID != a.PrincipalID {
		return ApprovalProposal{}, ErrDenied
	}
	a = currentActor
	p.Checker = a.PrincipalID
	p.DecidedAt = l.now()
	p.Status = "REJECTED"
	if approve {
		p.Status = "APPROVED"
	}
	data, _ := json.Marshal(p)
	err = l.db.Update(func(tx ledgerTx) error {
		if ctx.Err() != nil || !l.now().Before(a.ValidUntil) || !fresh(p.Receipt.ValidFrom, p.Receipt.ExpiresAt, l.now()) {
			return ErrDenied
		}
		b := tx.Bucket(approvalBucket)
		var current ApprovalProposal
		if decodeAuthority(b.Get(approvalKey(id)), &current) != nil || current.Status != "PENDING" || current.TargetDigest != digest {
			return ErrDenied
		}
		if approve {
			// Replacing a receipt is explicit: revoke the previous one first.
			if b.Get(receiptKey(p.Receipt.Expectation)) != nil {
				return ErrDenied
			}
			if e := b.Put(receiptKey(p.Receipt.Expectation), []byte(id)); e != nil {
				return e
			}
		}
		return b.Put(approvalKey(id), data)
	})
	if err != nil {
		return ApprovalProposal{}, authorityError(err)
	}
	return p, nil
}

// Revoke is terminal and may be invoked by the maker in an emergency, subject
// to CURRENT explicit revocation authority. Receipt entries are retained so a
// revoked snapshot cannot be replaced or resurrected by a second proposal.
func (l *ApprovalLedger) Revoke(ctx context.Context, id string) error {
	p, err := l.proposal(ctx, id)
	if err != nil {
		return err
	}
	a, err := l.actor(ctx, "REVOKE", p.Receipt.Expectation)
	if err != nil {
		return err
	}
	return authorityErrorUnlessNil(l.db.Update(func(tx ledgerTx) error {
		if ctx.Err() != nil || !l.now().Before(a.ValidUntil) {
			return ErrDenied
		}
		b := tx.Bucket(approvalBucket)
		var current ApprovalProposal
		if decodeAuthority(b.Get(approvalKey(id)), &current) != nil || current.Status != "APPROVED" {
			return ErrDenied
		}
		current.Status = "REVOKED"
		revokedAt := l.now()
		current.RevokedAt = &revokedAt
		current.Revoker = a.PrincipalID
		data, _ := json.Marshal(current)
		return b.Put(approvalKey(id), data)
	}))
}
func authorityErrorUnlessNil(err error) error {
	if err == nil {
		return nil
	}
	return authorityError(err)
}

func (l *ApprovalLedger) Reference(ctx context.Context, want ReferenceExpectation) (ApprovedReference, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !validExpectation(want) {
		return ApprovedReference{}, ErrInvalid
	}
	var id string
	err := l.db.View(func(tx ledgerTx) error {
		v := tx.Bucket(approvalBucket).Get(receiptKey(want))
		if v == nil {
			return ErrUnverified
		}
		id = string(v)
		return nil
	})
	if err != nil {
		return ApprovedReference{}, authorityError(err)
	}
	p, err := l.proposal(ctx, id)
	if err != nil {
		return ApprovedReference{}, err
	}
	if p.Status != "APPROVED" || p.Maker == p.Checker || p.Receipt.Expectation != want || !fresh(p.Receipt.ValidFrom, p.Receipt.ExpiresAt, l.now()) {
		return ApprovedReference{}, ErrUnverified
	}
	d, err := l.target(ctx, want)
	if err != nil {
		return ApprovedReference{}, err
	}
	if d != p.TargetDigest {
		return ApprovedReference{}, ErrUnverified
	}
	// Re-read after the live target lookup so concurrent revocation wins.
	current, err := l.proposal(ctx, id)
	if err != nil {
		return ApprovedReference{}, err
	}
	if current.Status != "APPROVED" || ctx.Err() != nil || !fresh(p.Receipt.ValidFrom, p.Receipt.ExpiresAt, l.now()) {
		return ApprovedReference{}, ErrUnverified
	}
	return p.Receipt, nil
}
