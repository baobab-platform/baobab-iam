-- ADR-IAM-0030: minimal, independently recoverable restrictive journal.
-- Store in a distinct protected security/privacy custody database. This SQL
-- must never be executed against a historical provider backup as sole source.
CREATE SCHEMA IF NOT EXISTS iam_privacy;
CREATE TABLE IF NOT EXISTS iam_privacy.restriction_tombstone (
    issuer text NOT NULL,
    subject text NOT NULL,
    decision_id text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (issuer, subject)
);
-- Deliberately no email, traits, documents, arbitrary metadata, DELETE path,
-- automatic expiry or plaintext proofing/credential material. Access is by
-- dedicated privilege; no PUBLIC grants. Governance decides lawful release.
