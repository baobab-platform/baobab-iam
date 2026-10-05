package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

const nativeTargetClassification = "NON_SECRET"

var (
	nativeTargetContentBucket = []byte("federation-native-target-content-v1")
	nativeTargetBindingBucket = []byte("federation-native-target-bindings-v1")
)

type nativeTargetRecord struct {
	ReferenceID    string          `json:"reference_id"`
	Kind           string          `json:"kind"`
	Classification string          `json:"classification"`
	Digest         string          `json:"digest"`
	Content        json.RawMessage `json:"content"`
}

type nativeTargetBinding struct {
	Expectation ReferenceExpectation `json:"expectation"`
	Digest      string               `json:"digest"`
}

// NativeTargetLedger owns IAM's immutable, non-secret governance target bytes.
// It has no update/delete operation. A ref_ can acquire additional exact
// trust-revision/snapshot bindings only when its original bytes and kind are
// unchanged. Secrets must never be supplied to this ledger; production
// composition must source secret material from the secret boundary instead.
type NativeTargetLedger struct {
	db *bolt.DB
}

func OpenNativeTargetLedger(path string) (*NativeTargetLedger, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: privateLedgerFile})
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{nativeTargetContentBucket, nativeTargetBindingBucket} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, ErrUnavailable
	}
	return &NativeTargetLedger{db: db}, nil
}

func (l *NativeTargetLedger) Close() error {
	if l == nil || l.db == nil {
		return ErrUnavailable
	}
	return l.db.Close()
}

func iamOwnedNativeTargetKind(kind string) bool {
	switch kind {
	case "federation_configuration",
		"federation_trust_material",
		"assurance_policy",
		"attribute_mapping",
		"provisioning_policy",
		"federation_activation",
		"assurance_mapping_decision",
		"identity_security_domain":
		return true
	default:
		return false
	}
}

func validateNativeTargetJSON(content []byte) bool {
	if len(content) == 0 || len(content) > 65536 || !utf8.Valid(content) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(content))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	// Restart from the beginning because uniqueJSON expects the opening token.
	d = json.NewDecoder(bytes.NewReader(content))
	if uniqueJSON(d) != nil {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	return true
}

func nativeTargetDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func nativeTargetBindingKey(w ReferenceExpectation) []byte {
	data, _ := json.Marshal(w)
	sum := sha256.Sum256(data)
	return []byte("binding:" + hex.EncodeToString(sum[:]))
}

// RegisterNonSecretTarget persists exact native JSON bytes and binds them to an
// exact ReferenceExpectation. It is deliberately not exposed as a public or
// private HTTP mutation route in this increment: only the trusted IAM
// composition root may load reviewed non-secret target bytes.
func (l *NativeTargetLedger) RegisterNonSecretTarget(ctx context.Context, w ReferenceExpectation, content []byte) (string, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !validExpectation(w) ||
		!iamOwnedNativeTargetKind(w.Kind) || !validateNativeTargetJSON(content) {
		return "", ErrInvalid
	}
	digest := nativeTargetDigest(content)
	record := nativeTargetRecord{
		ReferenceID:    w.ID,
		Kind:           w.Kind,
		Classification: nativeTargetClassification,
		Digest:         digest,
		Content:        append(json.RawMessage(nil), content...),
	}
	recordBytes, _ := json.Marshal(record)
	binding := nativeTargetBinding{Expectation: w, Digest: digest}
	bindingBytes, _ := json.Marshal(binding)

	err := l.db.Update(func(tx *bolt.Tx) error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		contents := tx.Bucket(nativeTargetContentBucket)
		if raw := contents.Get([]byte(w.ID)); raw != nil {
			var existing nativeTargetRecord
			if decodeAuthority(raw, &existing) != nil ||
				existing.ReferenceID != record.ReferenceID ||
				existing.Kind != record.Kind ||
				existing.Classification != nativeTargetClassification ||
				existing.Digest != digest ||
				!bytes.Equal(existing.Content, content) {
				return ErrDenied
			}
		} else if err := contents.Put([]byte(w.ID), recordBytes); err != nil {
			return err
		}

		bindings := tx.Bucket(nativeTargetBindingBucket)
		key := nativeTargetBindingKey(w)
		if raw := bindings.Get(key); raw != nil {
			var existing nativeTargetBinding
			if decodeAuthority(raw, &existing) != nil || existing.Expectation != w || existing.Digest != digest {
				return ErrDenied
			}
			return nil
		}
		return bindings.Put(key, bindingBytes)
	})
	if err != nil {
		return "", authorityError(err)
	}
	return digest, nil
}

// RegisterTrustSnapshotTarget writes the canonical TrustSnapshot bytes used by
// TrustSnapshotDigest. This is the only supported federation_activation writer
// in this increment, so a trust proposal cannot approve bytes unrelated to the
// exact candidate revision/snapshot.
func (l *NativeTargetLedger) RegisterTrustSnapshotTarget(ctx context.Context, w ReferenceExpectation, snapshot TrustSnapshot) (string, error) {
	if !validExpectation(w) || w.Kind != "federation_activation" ||
		ValidateTrust(snapshot.Trust) != nil ||
		w.TrustID != snapshot.Trust.ID ||
		w.TrustRevision != snapshot.ApprovedRevision ||
		w.TrustRevision != snapshot.Trust.Revision ||
		w.SnapshotID != snapshot.SnapshotID ||
		w.ProviderID != snapshot.Trust.ProviderBinding.ProviderID ||
		w.EngineInstanceID != snapshot.Trust.ProviderBinding.EngineInstanceID ||
		len(snapshot.Trust.OrganisationIDs) != 1 ||
		len(snapshot.Trust.EstateIDs) != 1 ||
		snapshot.Trust.OrganisationIDs[0] != w.Scope.OrganisationID ||
		snapshot.Trust.EstateIDs[0] != w.Scope.EstateID {
		return "", ErrInvalid
	}
	snapshot.Trust = canonicalTrust(snapshot.Trust)
	snapshot.ValidUntil = snapshot.ValidUntil.UTC()
	content, err := json.Marshal(snapshot)
	if err != nil {
		return "", ErrInvalid
	}
	digest, err := l.RegisterNonSecretTarget(ctx, w, content)
	if err != nil {
		return "", err
	}
	if digest != TrustSnapshotDigest(snapshot) {
		return "", ErrUnverified
	}
	return digest, nil
}

func (l *NativeTargetLedger) NativeTargetDigest(ctx context.Context, w ReferenceExpectation) (string, error) {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil || !validExpectation(w) || !iamOwnedNativeTargetKind(w.Kind) {
		return "", ErrInvalid
	}
	var binding nativeTargetBinding
	var record nativeTargetRecord
	err := l.db.View(func(tx *bolt.Tx) error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		rawBinding := tx.Bucket(nativeTargetBindingBucket).Get(nativeTargetBindingKey(w))
		if rawBinding == nil || decodeAuthority(rawBinding, &binding) != nil {
			return ErrUnverified
		}
		rawRecord := tx.Bucket(nativeTargetContentBucket).Get([]byte(w.ID))
		if rawRecord == nil || decodeAuthority(rawRecord, &record) != nil {
			return ErrUnverified
		}
		return nil
	})
	if err != nil {
		return "", authorityError(err)
	}
	if binding.Expectation != w ||
		binding.Digest != record.Digest ||
		record.ReferenceID != w.ID ||
		record.Kind != w.Kind ||
		record.Classification != nativeTargetClassification ||
		!validateNativeTargetJSON(record.Content) ||
		nativeTargetDigest(record.Content) != record.Digest ||
		!digestPattern.MatchString(record.Digest) {
		return "", ErrUnverified
	}
	return record.Digest, nil
}

var _ NativeTargetAuthority = (*NativeTargetLedger)(nil)

// CompositeApprovalTargets is the final IAM ApprovalTargets resolver. CP proves
// current registration/topology/scope; IAM proves the immutable native bytes
// bound to the exact trust revision/snapshot. Neither authority can succeed
// alone. CP is read both before and after the native read so target drift fails
// closed rather than composing evidence from different moments.
type CompositeApprovalTargets struct {
	registration TargetRegistrationAuthority
	native       NativeTargetAuthority
}

func NewCompositeApprovalTargets(registration TargetRegistrationAuthority, native NativeTargetAuthority) (*CompositeApprovalTargets, error) {
	if absent(registration) || absent(native) {
		return nil, ErrInvalid
	}
	return &CompositeApprovalTargets{registration: registration, native: native}, nil
}

func (c *CompositeApprovalTargets) ResolveApprovedTarget(ctx context.Context, w ReferenceExpectation) (string, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || absent(c.registration) || absent(c.native) || !validExpectation(w) {
		return "", ErrInvalid
	}
	if !iamOwnedNativeTargetKind(w.Kind) {
		return "", ErrUnsupported
	}
	before, err := c.registration.TargetRegistration(ctx, w)
	if err != nil {
		return "", authorityError(err)
	}
	if !digestPattern.MatchString(before.Digest) {
		return "", ErrUnverified
	}
	digest, err := c.native.NativeTargetDigest(ctx, w)
	if err != nil {
		return "", authorityError(err)
	}
	if digest != before.Digest {
		return "", ErrUnverified
	}
	after, err := c.registration.TargetRegistration(ctx, w)
	if err != nil {
		return "", authorityError(err)
	}
	if after != before || after.Digest != digest || ctx.Err() != nil {
		return "", ErrUnverified
	}
	return digest, nil
}

var _ ApprovalTargets = (*CompositeApprovalTargets)(nil)
