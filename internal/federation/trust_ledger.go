package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TrustLedger persists IAM-owned desired trust revisions and native approval
// history. CP still owns reference registration, principals, platform bindings
// and scope. All authority/target/receipt ports are mandatory, without defaults.
// It shares the local single-writer limitation of the existing approval ledger.
type TrustLedger struct {
	db         *bolt.DB
	actors     ApprovalAuthority
	targets    ApprovalTargets
	references interface {
		Reference(context.Context, ReferenceExpectation) (ApprovedReference, error)
	}
	now func() time.Time
}

type TrustProposal struct {
	ID                     string
	Snapshot               TrustSnapshot
	Target                 ReferenceExpectation
	TargetDigest           string
	PreviousRevision       uint64
	PreviousSnapshotID     string
	Maker, Checker, Status string
	ProposedAt, DecidedAt  time.Time
}

type committedTrust struct {
	Snapshot         TrustSnapshot
	Scope            Scope
	ProposalID       string
	Maker, Checker   string
	DecidedAt        time.Time
	ContainmentActor string     `json:",omitempty"`
	ContainedAt      *time.Time `json:",omitempty"`
}

var trustsBucket = []byte("federation-trusts-v1")
var trustProposalsBucket = []byte("federation-trust-proposals-v1")
var trustClockBucket = []byte("federation-trust-clock-v1")

func OpenTrustLedger(path string, actors ApprovalAuthority, targets ApprovalTargets, references interface {
	Reference(context.Context, ReferenceExpectation) (ApprovedReference, error)
}, now func() time.Time) (*TrustLedger, error) {
	if path == "" || absent(actors) || absent(targets) || absent(references) || now == nil {
		return nil, ErrInvalid
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: privateLedgerFile})
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{trustsBucket, trustProposalsBucket, trustClockBucket} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	return &TrustLedger{db, actors, targets, references, now}, nil
}

func (l *TrustLedger) Close() error {
	if l == nil || l.db == nil {
		return ErrUnavailable
	}
	return l.db.Close()
}

// TrustSnapshotDigest binds approval to all immutable revision and policy facts,
// including allowed scope and lifetime. Go's time metadata has no authority.
func TrustSnapshotDigest(s TrustSnapshot) string {
	s.Trust = canonicalTrust(s.Trust)
	s.ValidUntil = s.ValidUntil.UTC()
	data, _ := json.Marshal(s)
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (l *TrustLedger) actor(ctx context.Context, action string, want ReferenceExpectation) (ApprovalActor, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil {
		return ApprovalActor{}, ErrUnavailable
	}
	if err := l.fence(); err != nil {
		return ApprovalActor{}, err
	}
	actor, err := l.actors.AuthorizeApproval(ctx, action, want)
	if err != nil {
		return ApprovalActor{}, authorityError(err)
	}
	if !uuidPattern.MatchString(actor.PrincipalID) || !l.now().Before(actor.ValidUntil) {
		return ApprovalActor{}, ErrDenied
	}
	return actor, nil
}

func trustTransition(previous, current Trust) bool {
	if !slices.Equal(current.OrganisationIDs, previous.OrganisationIDs) || !slices.Equal(current.EstateIDs, previous.EstateIDs) || current.ProviderBinding.ProviderID != previous.ProviderBinding.ProviderID || current.ProviderBinding.EngineInstanceID != previous.ProviderBinding.EngineInstanceID || current.ID != previous.ID || previous.Revision == ^uint64(0) || current.Revision != previous.Revision+1 || current.Protocol != previous.Protocol || current.UpstreamIssuer != previous.UpstreamIssuer || !current.CreatedAt.Equal(previous.CreatedAt) || current.UpdatedAt.Before(previous.UpdatedAt) || previous.Status == "REVOKED" {
		return false
	}
	if previous.Status == current.Status {
		return previous.Status != "ACTIVE"
	}
	allowed := map[string][]string{"REQUESTED": {"CONFIGURING", "REVOKED"}, "CONFIGURING": {"VERIFYING", "REVOKED"}, "VERIFYING": {"CONFIGURING", "ACTIVE", "REVOKED"}, "ACTIVE": {"SUSPENDED", "ROTATING", "REVOKED"}, "SUSPENDED": {"VERIFYING", "REVOKED"}, "ROTATING": {"VERIFYING", "REVOKED"}}
	return member(allowed[previous.Status], current.Status)
}

func (l *TrustLedger) read(ctx context.Context, id string) (committedTrust, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) {
		return committedTrust{}, ErrInvalid
	}
	var value committedTrust
	err := l.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(trustsBucket).Get([]byte(id))
		if raw == nil {
			return ErrUnverified
		}
		return decodeAuthority(raw, &value)
	})
	if err != nil {
		return committedTrust{}, authorityError(err)
	}
	if value.Snapshot.Trust.ID != id || value.Snapshot.ApprovedRevision != value.Snapshot.Trust.Revision || !exact(value.Snapshot.SnapshotID) || ValidateTrust(value.Snapshot.Trust) != nil || !validScope(value.Scope) || !uuidPattern.MatchString(value.Maker) || !uuidPattern.MatchString(value.Checker) || value.Maker == value.Checker {
		return committedTrust{}, ErrInvalid
	}
	return value, nil
}

func (l *TrustLedger) Propose(ctx context.Context, id string, candidate TrustSnapshot, want ReferenceExpectation) (TrustProposal, error) {
	if !uuidPattern.MatchString(id) || ValidateTrust(candidate.Trust) != nil || !validExpectation(want) || want.Kind != "federation_activation" || want.TrustID != candidate.Trust.ID || want.TrustRevision != candidate.Trust.Revision || want.SnapshotID != candidate.SnapshotID || want.ProviderID != candidate.Trust.ProviderBinding.ProviderID || want.EngineInstanceID != candidate.Trust.ProviderBinding.EngineInstanceID || !exact(candidate.SnapshotID) || candidate.ApprovedRevision != candidate.Trust.Revision || len(candidate.Trust.OrganisationIDs) != 1 || len(candidate.Trust.EstateIDs) != 1 || candidate.Trust.OrganisationIDs[0] != want.Scope.OrganisationID || candidate.Trust.EstateIDs[0] != want.Scope.EstateID {
		return TrustProposal{}, ErrInvalid
	}
	actor, err := l.actor(ctx, "PROPOSE", want)
	if err != nil {
		return TrustProposal{}, err
	}
	now := l.now()
	if candidate.Trust.UpdatedAt.After(now) || !now.Before(candidate.ValidUntil) {
		return TrustProposal{}, ErrDenied
	}
	previous, err := l.read(ctx, candidate.Trust.ID)
	if err != nil && !errors.Is(err, ErrUnverified) {
		return TrustProposal{}, err
	}
	if errors.Is(err, ErrUnverified) {
		if candidate.Trust.Status != "REQUESTED" || candidate.Trust.Revision != 1 {
			return TrustProposal{}, ErrDenied
		}
	} else if !trustTransition(previous.Snapshot.Trust, candidate.Trust) {
		return TrustProposal{}, ErrDenied
	}
	digest, err := l.targets.ResolveApprovedTarget(ctx, want)
	if err != nil {
		return TrustProposal{}, authorityError(err)
	}
	if digest != TrustSnapshotDigest(candidate) {
		return TrustProposal{}, ErrUnverified
	}
	currentActor, err := l.actor(ctx, "PROPOSE", want)
	if err != nil || currentActor.PrincipalID != actor.PrincipalID {
		return TrustProposal{}, ErrDenied
	}
	p := TrustProposal{ID: id, Snapshot: candidate, Target: want, TargetDigest: digest, PreviousRevision: previous.Snapshot.ApprovedRevision, PreviousSnapshotID: previous.Snapshot.SnapshotID, Maker: actor.PrincipalID, Status: "PENDING", ProposedAt: now}
	data, _ := json.Marshal(p)
	err = l.db.Update(func(tx *bolt.Tx) error {
		if err := l.observeClock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil || !l.now().Before(currentActor.ValidUntil) || !l.now().Before(candidate.ValidUntil) {
			return ErrDenied
		}
		if tx.Bucket(trustProposalsBucket).Get([]byte(id)) != nil {
			return ErrDenied
		}
		var current committedTrust
		raw := tx.Bucket(trustsBucket).Get([]byte(candidate.Trust.ID))
		if raw != nil && decodeAuthority(raw, &current) != nil {
			return ErrInvalid
		}
		if current.Snapshot.ApprovedRevision != p.PreviousRevision || current.Snapshot.SnapshotID != p.PreviousSnapshotID {
			return ErrDenied
		}
		return tx.Bucket(trustProposalsBucket).Put([]byte(id), data)
	})
	if err != nil {
		return TrustProposal{}, authorityError(err)
	}
	return p, nil
}

func (l *TrustLedger) proposal(ctx context.Context, id string) (TrustProposal, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !uuidPattern.MatchString(id) {
		return TrustProposal{}, ErrInvalid
	}
	var p TrustProposal
	err := l.db.View(func(tx *bolt.Tx) error { return decodeAuthority(tx.Bucket(trustProposalsBucket).Get([]byte(id)), &p) })
	if err != nil {
		return TrustProposal{}, authorityError(err)
	}
	return p, nil
}

func (l *TrustLedger) activation(ctx context.Context, s TrustSnapshot, scope Scope) error {
	if s.Trust.Status != "ACTIVE" {
		return nil
	}
	for _, item := range []struct{ id, kind string }{{s.Trust.ProviderBinding.ConfigurationReference, "federation_configuration"}, {s.Trust.ProviderBinding.TrustMaterialReference, "federation_trust_material"}, {s.Trust.AssurancePolicyReference, "assurance_policy"}, {s.Trust.AttributeMappingReference, "attribute_mapping"}, {s.Trust.ProvisioningPolicyReference, "provisioning_policy"}, {s.Trust.ActivationEvidenceReference, "federation_activation"}} {
		want := ReferenceExpectation{ID: item.id, Kind: item.kind, TrustID: s.Trust.ID, SnapshotID: s.SnapshotID, TrustRevision: s.ApprovedRevision, ProviderID: s.Trust.ProviderBinding.ProviderID, EngineInstanceID: s.Trust.ProviderBinding.EngineInstanceID, Scope: scope}
		receipt, err := l.references.Reference(ctx, want)
		if err != nil {
			return authorityError(err)
		}
		if receipt.Expectation != want || receipt.Status != "APPROVED" || !receipt.NonSecret || !fresh(receipt.ValidFrom, receipt.ExpiresAt, l.now()) || receipt.ExpiresAt.Before(s.ValidUntil) {
			return ErrUnverified
		}
	}
	return nil
}

func (l *TrustLedger) Decide(ctx context.Context, id, digest string, approve bool) (TrustProposal, error) {
	p, err := l.proposal(ctx, id)
	if err != nil {
		return TrustProposal{}, err
	}
	if p.Status != "PENDING" || p.TargetDigest != digest {
		return TrustProposal{}, ErrDenied
	}
	actor, err := l.actor(ctx, "DECIDE", p.Target)
	if err != nil {
		return TrustProposal{}, err
	}
	if actor.PrincipalID == p.Maker {
		return TrustProposal{}, ErrDenied
	}
	actual, err := l.targets.ResolveApprovedTarget(ctx, p.Target)
	if err != nil {
		return TrustProposal{}, authorityError(err)
	}
	if actual != digest || actual != TrustSnapshotDigest(p.Snapshot) {
		return TrustProposal{}, ErrUnverified
	}
	if approve {
		if err := l.activation(ctx, p.Snapshot, p.Target.Scope); err != nil {
			return TrustProposal{}, err
		}
	}
	currentActor, err := l.actor(ctx, "DECIDE", p.Target)
	if err != nil || currentActor.PrincipalID != actor.PrincipalID {
		return TrustProposal{}, ErrDenied
	}
	p.Checker = actor.PrincipalID
	p.DecidedAt = l.now()
	p.Status = "REJECTED"
	if approve {
		p.Status = "APPROVED"
	}
	data, _ := json.Marshal(p)
	err = l.db.Update(func(tx *bolt.Tx) error {
		if err := l.observeClock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil || !l.now().Before(currentActor.ValidUntil) || !l.now().Before(p.Snapshot.ValidUntil) {
			return ErrDenied
		}
		var pending TrustProposal
		if decodeAuthority(tx.Bucket(trustProposalsBucket).Get([]byte(id)), &pending) != nil || pending.Status != "PENDING" {
			return ErrDenied
		}
		if approve {
			var current committedTrust
			raw := tx.Bucket(trustsBucket).Get([]byte(p.Snapshot.Trust.ID))
			if raw != nil && decodeAuthority(raw, &current) != nil {
				return ErrInvalid
			}
			if current.Snapshot.ApprovedRevision != p.PreviousRevision || current.Snapshot.SnapshotID != p.PreviousSnapshotID {
				return ErrDenied
			}
			if raw != nil && !trustTransition(current.Snapshot.Trust, p.Snapshot.Trust) {
				return ErrDenied
			}
			value := committedTrust{Snapshot: p.Snapshot, Scope: p.Target.Scope, ProposalID: p.ID, Maker: p.Maker, Checker: p.Checker, DecidedAt: p.DecidedAt}
			encoded, _ := json.Marshal(value)
			if err := tx.Bucket(trustsBucket).Put([]byte(p.Snapshot.Trust.ID), encoded); err != nil {
				return err
			}
		}
		return tx.Bucket(trustProposalsBucket).Put([]byte(id), data)
	})
	if err != nil {
		return TrustProposal{}, authorityError(err)
	}
	return p, nil
}

func (l *TrustLedger) Trust(ctx context.Context, id string) (TrustSnapshot, error) {
	value, err := l.read(ctx, id)
	if err != nil {
		return TrustSnapshot{}, err
	}
	if err := l.fence(); err != nil {
		return TrustSnapshot{}, err
	}
	if !l.now().Before(value.Snapshot.ValidUntil) || ValidateTrust(value.Snapshot.Trust) != nil {
		return TrustSnapshot{}, ErrUnverified
	}
	if err := l.activation(ctx, value.Snapshot, value.Scope); err != nil {
		return TrustSnapshot{}, err
	}
	if err := l.fence(); err != nil {
		return TrustSnapshot{}, err
	}
	current, err := l.read(ctx, id)
	if err != nil {
		return TrustSnapshot{}, err
	}
	if !l.now().Before(value.Snapshot.ValidUntil) || !sameSnapshot(value.Snapshot, current.Snapshot) {
		return TrustSnapshot{}, ErrUnverified
	}
	return value.Snapshot, nil
}

func (l *TrustLedger) Reference(ctx context.Context, want ReferenceExpectation) (ApprovedReference, error) {
	if l == nil || absent(l.references) {
		return ApprovedReference{}, ErrUnavailable
	}
	return l.references.Reference(ctx, want)
}

// Contain allows an explicitly authorised emergency suspension or terminal
// revocation without a checker/target-service round trip. No outage can reactivate
// a trust; re-entry must pass through VERIFYING and independent approval.
func (l *TrustLedger) Contain(ctx context.Context, id string, revision uint64, status string) error {
	if status != "SUSPENDED" && status != "REVOKED" {
		return ErrInvalid
	}
	current, err := l.read(ctx, id)
	if err != nil {
		return err
	}
	s := current.Snapshot
	if s.ApprovedRevision != revision || s.Trust.Status == "REVOKED" || status == "SUSPENDED" && s.Trust.Status != "ACTIVE" {
		return ErrDenied
	}
	want := ReferenceExpectation{ID: s.Trust.ProviderBinding.ConfigurationReference, Kind: "federation_configuration", TrustID: id, SnapshotID: s.SnapshotID, TrustRevision: revision, ProviderID: s.Trust.ProviderBinding.ProviderID, EngineInstanceID: s.Trust.ProviderBinding.EngineInstanceID, Scope: current.Scope}
	actor, err := l.actor(ctx, "REVOKE", want)
	if err != nil {
		return err
	}
	now := l.now()
	snapshotID, err := randomUUID()
	if err != nil {
		return err
	}
	s.Trust.Revision++
	s.ApprovedRevision = s.Trust.Revision
	s.SnapshotID = snapshotID
	s.Trust.Status = status
	s.Trust.UpdatedAt = now
	if status == "REVOKED" {
		s.Trust.RevokedAt = &now
	}
	if !trustTransition(current.Snapshot.Trust, s.Trust) || ValidateTrust(s.Trust) != nil {
		return ErrDenied
	}
	current.Snapshot = s
	current.ContainmentActor = actor.PrincipalID
	current.ContainedAt = &now
	encoded, _ := json.Marshal(current)
	return authorityErrorUnlessNil(l.db.Update(func(tx *bolt.Tx) error {
		if err := l.observeClock(tx); err != nil {
			return err
		}
		if ctx.Err() != nil || !l.now().Before(actor.ValidUntil) {
			return ErrDenied
		}
		var live committedTrust
		if decodeAuthority(tx.Bucket(trustsBucket).Get([]byte(id)), &live) != nil || live.Snapshot.ApprovedRevision != revision || live.Snapshot.SnapshotID != want.SnapshotID {
			return ErrDenied
		}
		return tx.Bucket(trustsBucket).Put([]byte(id), encoded)
	}))
}

var _ GovernanceAuthority = (*TrustLedger)(nil)

// Reads also advance the durable watermark: expiry cannot reopen after restart.
func (l *TrustLedger) observeClock(tx *bolt.Tx) error {
	b := tx.Bucket(trustClockBucket)
	now := l.now().UTC()
	if raw := b.Get(clockKey); raw != nil {
		previous, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil || now.Before(previous) {
			return ErrDenied
		}
	}
	return b.Put(clockKey, []byte(now.Format(time.RFC3339Nano)))
}
func (l *TrustLedger) fence() error {
	if l == nil || l.db == nil {
		return ErrUnavailable
	}
	return authorityErrorUnlessNil(l.db.Update(l.observeClock))
}
