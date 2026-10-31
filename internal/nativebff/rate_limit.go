package nativebff

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrRateLimited is deliberately independent of identity or token validity.
// It does not disclose whether the requested account or challenge exists.
var ErrRateLimited = errors.New("native browser authentication rate limit reached")

// AdmissionLimiter is required for the public authentication routes.
// Its production implementation uses PostgreSQL: local counters are not
// suitable because another BFF replica would independently admit attempts.
type AdmissionLimiter interface {
	Admit(context.Context, string, string) error
}

var limits = map[string]int32{
	"POST /auth/start":    20,
	"GET /auth/login":     60,
	"GET /auth/consent":   60,
	"POST /auth/consent":  30,
	"GET /auth/callback":  60,
	"GET /auth/session":   120,
	"POST /auth/logout":   30,
}

// PostgresAdmissionLimiter uses a private HMAC digest of the observed TCP
// peer and operation, avoiding plaintext IP persistence. The BFF must receive
// a trusted client-peer address, or a separately governed ingress limiter must
// be qualified before deployment. Never trust caller-supplied X-Forwarded-For.
type PostgresAdmissionLimiter struct {
	pool *pgxpool.Pool
	key  []byte
}

func NewPostgresAdmissionLimiter(pool *pgxpool.Pool, key []byte) (*PostgresAdmissionLimiter, error) {
	if pool == nil || len(key) != 32 {
		return nil, errors.New("private PostgreSQL admission ledger and key required")
	}
	return &PostgresAdmissionLimiter{pool: pool, key: append([]byte(nil), key...)}, nil
}

func (l *PostgresAdmissionLimiter) Admit(ctx context.Context, operation, remote string) error {
	ceiling, ok := limits[operation]
	if l == nil || l.pool == nil || ctx == nil || ctx.Err() != nil || !ok {
		return errors.New("authentication admission boundary unavailable")
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return errors.New("trusted TCP peer address required")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("trusted TCP peer IP required")
	}
	// The database only sees a keyed, fixed-width pseudonymous digest.
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte("baobab-native-bff-rate-v1:" + operation + ":" + ip.String()))
	key := mac.Sum(nil)
	var attempts int32
	err = l.pool.QueryRow(ctx, `INSERT INTO native_bff_rate_limits (id_hash, window_start, attempts)
VALUES ($1, date_trunc('minute', clock_timestamp()), 1)
ON CONFLICT (id_hash) DO UPDATE
SET attempts = CASE WHEN native_bff_rate_limits.window_start = EXCLUDED.window_start
  THEN LEAST(native_bff_rate_limits.attempts + 1, 1000000) ELSE 1 END,
    window_start = EXCLUDED.window_start
RETURNING attempts`, key).Scan(&attempts)
	if err != nil {
		return errors.New("authentication admission ledger unavailable")
	}
	if attempts > ceiling {
		return ErrRateLimited
	}
	return nil
}

var _ AdmissionLimiter = (*PostgresAdmissionLimiter)(nil)
