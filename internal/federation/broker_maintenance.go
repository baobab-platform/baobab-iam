package federation

import (
	"context"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Prune bounds staging state while retaining replay fences through the maximum
// accepted upstream lifetime. It shares the durable monotonic-clock fence.
func (e *BrokerEvents) Prune(ctx context.Context, limit int) (int, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > 1024 {
		return 0, ErrInvalid
	}
	removed := 0
	err := e.db.Update(func(tx *bolt.Tx) error {
		if err := e.clock(tx); err != nil {
			return err
		}
		now := e.cfg.Now()
		for _, name := range [][]byte{brokerRequests, brokerCaptures, brokerVerified, brokerReplay} {
			cursor := tx.Bucket(name).Cursor()
			for key, raw := cursor.First(); key != nil && removed < limit; key, raw = cursor.Next() {
				if ctx.Err() != nil {
					return ErrUnavailable
				}
				var expiry time.Time
				switch string(name) {
				case string(brokerRequests):
					var r brokerRequest
					if decodeAuthority(raw, &r) != nil {
						return ErrUnverified
					}
					expiry = r.Request.ExpiresAt
				case string(brokerCaptures):
					var c brokerCapture
					if decodeAuthority(raw, &c) != nil {
						return ErrUnverified
					}
					expiry = c.Assurance.ExpiresAt
				case string(brokerVerified):
					var event storedEvent
					if decodeAuthority(raw, &event) != nil {
						return ErrUnverified
					}
					expiry = event.Bundle.Assurance.ExpiresAt
				case string(brokerReplay):
					var err error
					expiry, err = time.Parse(time.RFC3339Nano, string(raw))
					if err != nil {
						return ErrUnverified
					}
				}
				if !now.Before(expiry) {
					if string(name) == string(brokerRequests) {
						var r brokerRequest
						decodeAuthority(raw, &r)
						if err := tx.Bucket(brokerNonces).Delete([]byte(r.Request.NonceDigest)); err != nil {
							return err
						}
					}
					if err := cursor.Delete(); err != nil {
						return err
					}
					removed++
				}
			}
		}
		return nil
	})
	return removed, authorityErrorUnlessNil(err)
}
