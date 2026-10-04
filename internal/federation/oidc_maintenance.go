package federation

import (
	"bytes"
	"context"
	"time"

	bolt "go.etcd.io/bbolt"
)

var maintenanceBucket = []byte("oidc-maintenance-v1")
var clockKey = []byte("clock-high-water")

// Pruning a replay fence is safe only after its acceptance window closes and
// that window cannot reopen through clock rollback. The durable watermark is
// checked in every event transaction, including after a process restart.
func (e *OIDCEvents) observeClock(tx *bolt.Tx) error {
	return e.observeClockAt(tx, e.now().UTC())
}

func (e *OIDCEvents) observeClockAt(tx *bolt.Tx, now time.Time) error {
	b := tx.Bucket(maintenanceBucket)
	if raw := b.Get(clockKey); raw != nil {
		previous, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil || now.Before(previous) {
			return ErrDenied
		}
	}
	return b.Put(clockKey, []byte(now.Format(time.RFC3339Nano)))
}

// Prune scans at most limit records per bucket. Persistent cursors ensure an
// active record at the start cannot starve expired records later in the bucket.
// Expired records release pages for bbolt reuse; live or merely consumed but
// unexpired records and token replay fences remain. No background goroutine or
// unbounded transaction is needed: Begin runs one small maintenance batch.
func (e *OIDCEvents) Prune(ctx context.Context, limit int) (int, error) {
	if e == nil || e.db == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > 4096 {
		return 0, ErrInvalid
	}
	deleted := 0
	err := e.db.Update(func(tx *bolt.Tx) error {
		now := e.now().UTC()
		if err := e.observeClockAt(tx, now); err != nil {
			return err
		}
		for _, name := range [][]byte{requestsBucket, eventsBucket, replayBucket} {
			cursorKey := append([]byte("cursor:"), name...)
			meta := tx.Bucket(maintenanceBucket)
			resume := bytes.Clone(meta.Get(cursorKey))
			cursor := tx.Bucket(name).Cursor()
			key, value := cursor.First()
			if resume != nil {
				key, value = cursor.Seek(resume)
				if bytes.Equal(key, resume) {
					key, value = cursor.Next()
				}
			}
			var last []byte
			for scanned := 0; key != nil && scanned < limit; scanned++ {
				if ctx.Err() != nil {
					return ErrUnavailable
				}
				last = bytes.Clone(key)
				var expiry time.Time
				switch {
				case bytes.Equal(name, requestsBucket):
					var request storedRequest
					if decodeAuthority(value, &request) != nil {
						return ErrInvalid
					}
					expiry = request.ExpiresAt
				case bytes.Equal(name, eventsBucket):
					var event storedEvent
					if decodeAuthority(value, &event) != nil {
						return ErrInvalid
					}
					expiry = minimum(event.Bundle.ExternalPrincipal.ExpiresAt, event.Bundle.Assurance.ExpiresAt)
				default:
					var err error
					expiry, err = time.Parse(time.RFC3339Nano, string(value))
					if err != nil {
						return ErrInvalid
					}
				}
				if expiry.IsZero() {
					return ErrInvalid
				}
				if !now.Before(expiry) {
					if err := cursor.Delete(); err != nil {
						return err
					}
					deleted++
				}
				key, value = cursor.Next()
			}
			if key == nil {
				if err := meta.Delete(cursorKey); err != nil {
					return err
				}
			} else if last != nil {
				if err := meta.Put(cursorKey, last); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, authorityError(err)
	}
	return deleted, nil
}
