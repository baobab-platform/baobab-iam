-- IAM-N06: private disposable/approved PG17 source of truth for WebAuthn.
-- Session/subject/issuer and unpredictable challenge are encrypted by IAM
-- AES-256-GCM. Only opaque random challenge ID and times are queryable.
CREATE SCHEMA IF NOT EXISTS iam_security;
CREATE TABLE IF NOT EXISTS iam_security.webauthn_challenge (
 challenge_id text PRIMARY KEY CHECK (length(challenge_id) BETWEEN 12 AND 160),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 32 AND 8240),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(expires_at>created_at),
 CHECK(expires_at<=created_at+interval '2 minutes')
);
CREATE INDEX IF NOT EXISTS n06_webauthn_challenge_expiry
 ON iam_security.webauthn_challenge (expires_at);
