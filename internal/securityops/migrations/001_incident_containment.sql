-- ADR-IAM-0029: durable identity-scoped containment intent, separate
-- from generic migration authority and from CP canonical grants.
-- Protect table with owner-only writes, private network, backup + DR replay.
CREATE SCHEMA IF NOT EXISTS iam_security;
CREATE TABLE IF NOT EXISTS iam_security.incident_containment (
    operation_id text PRIMARY KEY,
    incident_id text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    phase text NOT NULL DEFAULT 'FENCED',
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT incident_containment_phase_check
        CHECK (phase IN ('FENCED','IDENTITY_DISABLED','SESSIONS_REVOKED','VERIFIED','UNKNOWN')),
    CONSTRAINT incident_containment_incident_subject_unique
        UNIQUE (incident_id, issuer, subject)
);
-- Deliberately no DELETE/re-enable/reset operation; retain restrictive
-- incident state through replay. No direct application or public grants.
