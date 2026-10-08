package federation

import (
	"context"
	"encoding/hex"
)

// NativeChallengeLedger is IAM-owned consumption state, never CP authority.
// Production replicas use the existing TLS/namespace/recovery-epoch fenced
// PostgresStorage. Local storage is for isolated development and CI only.
// There is deliberately no retry, delete or reset operation.
type NativeChallengeLedger struct{ db ledgerDB }

func OpenNativeChallengeLedger(path string) (*NativeChallengeLedger, error) {
	if path == "" {
		return nil, ErrInvalid
	}
	return openNativeChallengeLedger(path, nil)
}

func OpenNativeChallengeLedgerWithStorage(storage *PostgresStorage) (*NativeChallengeLedger, error) {
	if storage == nil {
		return nil, ErrInvalid
	}
	return openNativeChallengeLedger("", storage)
}

func openNativeChallengeLedger(path string, storage *PostgresStorage) (*NativeChallengeLedger, error) {
	db, err := openLedger(path, storage, "native-human-challenges")
	if err != nil {
		return nil, ErrUnavailable
	}
	return &NativeChallengeLedger{db}, nil
}

func (l *NativeChallengeLedger) Close() error {
	if l == nil || l.db == nil {
		return ErrUnavailable
	}
	return l.db.Close()
}

func (l *NativeChallengeLedger) ConsumeNativeChallenge(ctx context.Context, key string) error {
	if l == nil || l.db == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != key {
		return ErrInvalid
	}
	return l.db.Update(func(tx ledgerTx) error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		bucket, err := tx.CreateBucketIfNotExists([]byte("consumed-native-challenges-v1"))
		if err != nil {
			return ErrUnavailable
		}
		if bucket.Get(raw) != nil {
			return ErrDenied
		}
		return bucket.Put(raw, []byte{1})
	})
}
