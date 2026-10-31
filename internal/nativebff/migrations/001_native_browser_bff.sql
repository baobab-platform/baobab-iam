-- IAM-N02: standalone PostgreSQL 17 browser BFF transaction/session ledger.
-- Apply under a dedicated IAM runtime/migration role. No CP-owned state here.
-- All plaintext verifiers, OAuth tokens and canonical references are encrypted
-- by nativebff.PostgresStore before leaving the IAM process.
-- Do not expose these tables to the estate frontend, Hydra, or Kratos.
CREATE TABLE IF NOT EXISTS native_bff_transactions (
    id_hash BYTEA PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    sealed BYTEA NOT NULL CHECK (octet_length(sealed) BETWEEN 29 AND 65564),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS native_bff_transactions_expires ON native_bff_transactions(expires_at);
CREATE TABLE IF NOT EXISTS native_bff_sessions (
    id_hash BYTEA PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    sealed BYTEA NOT NULL CHECK (octet_length(sealed) BETWEEN 29 AND 65564),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS native_bff_sessions_expires ON native_bff_sessions(expires_at);
-- HMAC-pseudonymised, per-peer/operation fixed-minute admission ledger.
-- A single row per key is atomically updated across all native BFF replicas.
CREATE TABLE IF NOT EXISTS native_bff_rate_limits (
    id_hash BYTEA PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    window_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 1000000)
);
CREATE INDEX IF NOT EXISTS native_bff_rate_limits_window ON native_bff_rate_limits(window_start);
-- Purge old windows in the IAM-owned bounded maintenance task. Never retain
-- pseudonymous source data beyond the approved abuse-prevention purpose.
-- Maintenance: purge expired rows in a bounded scheduled IAM-owned job.
-- Do not TRUNCATE during a running OAuth transaction or before retention review.
-- Key material must be supplied by the approved secret store and rotated only
-- through a controlled drain/rekey migration (old ciphertext is not recoverable
-- with a new key). Database backup/restore follows IAM-MP16 resilience gates.
