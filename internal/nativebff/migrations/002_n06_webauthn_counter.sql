-- IAM keeps a separate high-water mark for assertions it verifies itself.
-- Kratos remains the source of identity, credential and key status.
CREATE TABLE IF NOT EXISTS iam_security.webauthn_counter (
 credential_ref bytea PRIMARY KEY CHECK (octet_length(credential_ref)=32),
 key_ref bytea NOT NULL CHECK (octet_length(key_ref)=32),
 sign_count bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295)
);
-- Prevent an accidental configuration change from opening a fresh namespace
-- and discarding all prior observations.
CREATE TABLE IF NOT EXISTS iam_security.webauthn_counter_key (
 singleton boolean PRIMARY KEY CHECK (singleton),
 key_commitment bytea NOT NULL CHECK (octet_length(key_commitment)=32)
);
