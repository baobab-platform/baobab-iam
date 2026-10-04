package federation

import (
	"bytes"
	"encoding/json"
	"time"
)

func canonicalTrust(t Trust) Trust {
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	copyTime := func(value *time.Time) *time.Time {
		if value == nil {
			return nil
		}
		utc := value.UTC()
		return &utc
	}
	t.ActivatedAt = copyTime(t.ActivatedAt)
	t.RevokedAt = copyTime(t.RevokedAt)
	return t
}

// Time location and monotonic-clock metadata are not authority facts. All
// other immutable fields must still match exactly, including reference scope.
func sameTrust(a, b Trust) bool {
	left, e1 := json.Marshal(canonicalTrust(a))
	right, e2 := json.Marshal(canonicalTrust(b))
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}

func sameSnapshot(a, b TrustSnapshot) bool {
	return a.ApprovedRevision == b.ApprovedRevision && a.SnapshotID == b.SnapshotID && a.ValidUntil.Equal(b.ValidUntil) && sameTrust(a.Trust, b.Trust)
}
