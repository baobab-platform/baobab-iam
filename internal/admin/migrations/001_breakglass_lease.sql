-- ADR-IAM-0031: separate, limited emergency-evidence lease.
-- No issuer signing key, credential, raw token, business capability, or
-- private identity data is stored. No PUBLIC roles or cross-tenant access.
CREATE SCHEMA IF NOT EXISTS iam_admin;
CREATE TABLE IF NOT EXISTS iam_admin.breakglass_lease (
    lease_id uuid PRIMARY KEY,
    incident_id uuid NOT NULL,
    action text NOT NULL,
    scope_type text NOT NULL,
    scope_id uuid NOT NULL,
    reason text NOT NULL,
    actor_id uuid NOT NULL,
    approver_id uuid NOT NULL,
    independent_auth_ref text NOT NULL,
    review_ref text NOT NULL,
    approved_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING','ACTIVE','TERMINATED')),
    recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (actor_id <> approver_id),
    CHECK (expires_at > approved_at),
    CHECK (expires_at <= approved_at + interval '15 minutes'),
    CHECK ((action='RESTORE_IAM_ADMIN_PLANE' AND scope_type='IAM_ADMIN_PLANE') OR
           (action='SUSPEND_FEDERATION' AND scope_type='FEDERATION') OR
           (action='SUSPEND_ISSUER' AND scope_type='ISSUER') OR
           (action='REVOKE_OAUTH_CLIENT' AND scope_type='OAUTH_CLIENT')),
    UNIQUE (incident_id, actor_id, action, scope_type, scope_id)
);
