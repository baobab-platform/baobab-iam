-- IAM-N05 v1: PostgreSQL 17 native-identity migration ledger.
-- Separate authority from CP Principal. Keycloak remains ENTERPRISE_SSO
-- under ADR-IAM-0033; this migration does not retire its federation service.
CREATE SCHEMA IF NOT EXISTS iam_migration;

CREATE TABLE IF NOT EXISTS iam_migration.record (
    migration_id text PRIMARY KEY CHECK (length(migration_id) BETWEEN 1 AND 160),
    migration_batch_id text NOT NULL DEFAULT '' CHECK (length(migration_batch_id) <= 160),
    canonical_identity_id text NOT NULL DEFAULT '' CHECK (length(canonical_identity_id) <= 160),
    source_provider text NOT NULL CHECK (length(source_provider) BETWEEN 1 AND 40),
    source_issuer text NOT NULL CHECK (length(source_issuer) BETWEEN 1 AND 2048),
    source_subject text NOT NULL CHECK (length(source_subject) BETWEEN 1 AND 512),
    target_provider text NOT NULL DEFAULT '' CHECK (length(target_provider) <= 40),
    target_issuer text NOT NULL DEFAULT '' CHECK (length(target_issuer) <= 2048),
    target_subject text NOT NULL DEFAULT '' CHECK (length(target_subject) <= 512),
    identity_class text NOT NULL CHECK (identity_class IN (
        'HUMAN', 'WORKLOAD', 'PRIVILEGED_HUMAN', 'BREAK_GLASS',
        'FEDERATED_HUMAN', 'SERVICE_INTEGRATION',
        'TEST_OR_NONPRODUCTION', 'ORPHAN_CANDIDATE')),
    credential_strategy text NOT NULL CHECK (credential_strategy IN (
        'DIRECT_IMPORT', 'FIRST_LOGIN_MIGRATION', 'CONTROLLED_RE_ENROLMENT',
        'FEDERATED_REBIND', 'PASSKEY_RE_ENROLMENT', 'MFA_RE_ENROLMENT',
        'NO_CREDENTIAL_REQUIRED')),
    migration_state text NOT NULL CHECK (migration_state IN (
        'DISCOVERED', 'VALIDATED', 'READY', 'PROVISIONING', 'PROVISIONED',
        'CREDENTIAL_PENDING', 'CREDENTIAL_READY', 'VERIFICATION_PENDING',
        'VERIFIED', 'CUTOVER_READY', 'CUTOVER', 'LEGACY_RETIRED', 'BLOCKED',
        'FAILED_RETRYABLE', 'FAILED_MANUAL_REVIEW', 'ROLLED_BACK', 'QUARANTINED')),
    verification_state text NOT NULL DEFAULT '' CHECK (length(verification_state) <= 80),
    cutover_state text NOT NULL DEFAULT '' CHECK (length(cutover_state) <= 80),
    source_snapshot_reference text NOT NULL DEFAULT ''
        CHECK (length(source_snapshot_reference) <= 512),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code text NOT NULL DEFAULT '' CHECK (length(last_error_code) <= 80),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    verified_at timestamptz,
    cutover_at timestamptz,
    retired_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    CONSTRAINT migration_source_binding_unique UNIQUE
        (source_provider, source_issuer, source_subject),
    CONSTRAINT migration_orphan_requires_blank_canonical CHECK (
        (identity_class = 'ORPHAN_CANDIDATE' AND canonical_identity_id = '')
        OR (identity_class <> 'ORPHAN_CANDIDATE' AND canonical_identity_id <> '')),
    CONSTRAINT migration_target_complete CHECK (
        (target_provider = '' AND target_issuer = '' AND target_subject = '')
        OR (target_provider <> '' AND target_issuer <> '' AND target_subject <> '')),
    CONSTRAINT migration_provisioned_target_required CHECK (
        migration_state NOT IN ('PROVISIONED', 'CREDENTIAL_PENDING',
        'CREDENTIAL_READY', 'VERIFICATION_PENDING', 'VERIFIED',
        'CUTOVER_READY', 'CUTOVER', 'LEGACY_RETIRED')
        OR target_subject <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS migration_target_binding_unique
    ON iam_migration.record(target_provider, target_issuer, target_subject)
    WHERE target_subject <> '';
CREATE INDEX IF NOT EXISTS migration_batch_idx
    ON iam_migration.record(migration_batch_id, migration_id);
CREATE INDEX IF NOT EXISTS migration_state_idx
    ON iam_migration.record(migration_state, identity_class);

CREATE TABLE IF NOT EXISTS iam_migration.history (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    migration_id text NOT NULL REFERENCES iam_migration.record(migration_id),
    revision bigint NOT NULL CHECK (revision > 0),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    from_state text,
    to_state text NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'DISCOVERED', 'STATE_CHANGED', 'TARGET_BOUND', 'RECONCILED')),
    CONSTRAINT migration_history_revision_unique UNIQUE(migration_id, revision)
);
CREATE OR REPLACE FUNCTION iam_migration.prevent_history_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'IAM-N05 append-only migration history';
END;
$$;
DROP TRIGGER IF EXISTS n05_history_append_only ON iam_migration.history;
CREATE TRIGGER n05_history_append_only
BEFORE UPDATE OR DELETE ON iam_migration.history
FOR EACH ROW EXECUTE FUNCTION iam_migration.prevent_history_change();

CREATE OR REPLACE FUNCTION iam_migration.audit_record_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (OLD.migration_id, OLD.migration_batch_id, OLD.canonical_identity_id,
        OLD.source_provider, OLD.source_issuer, OLD.source_subject,
        OLD.identity_class, OLD.credential_strategy, OLD.created_at)
       IS DISTINCT FROM
       (NEW.migration_id, NEW.migration_batch_id, NEW.canonical_identity_id,
        NEW.source_provider, NEW.source_issuer, NEW.source_subject,
        NEW.identity_class, NEW.credential_strategy, NEW.created_at)
    THEN
      RAISE EXCEPTION 'IAM-N05 immutable identity/canonical migration binding';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
      RAISE EXCEPTION 'IAM-N05 non-monotonic migration revision';
    END IF;
  ELSIF NEW.revision <> 1 THEN
    RAISE EXCEPTION 'IAM-N05 initial migration revision must be one';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS n05_record_immutability ON iam_migration.record;
CREATE TRIGGER n05_record_immutability BEFORE INSERT OR UPDATE
ON iam_migration.record FOR EACH ROW
EXECUTE FUNCTION iam_migration.audit_record_revision();

CREATE OR REPLACE FUNCTION iam_migration.append_record_history()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO iam_migration.history(migration_id, revision, from_state,
      to_state, event_type)
  VALUES (NEW.migration_id, NEW.revision,
      CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.migration_state END,
      NEW.migration_state,
      CASE
        WHEN TG_OP = 'INSERT' THEN 'DISCOVERED'
        WHEN NEW.migration_state <> OLD.migration_state THEN 'STATE_CHANGED'
        WHEN (NEW.target_provider,NEW.target_issuer,NEW.target_subject)
             IS DISTINCT FROM
             (OLD.target_provider,OLD.target_issuer,OLD.target_subject)
             THEN 'TARGET_BOUND'
        ELSE 'RECONCILED'
      END);
  RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS n05_record_history ON iam_migration.record;
CREATE TRIGGER n05_record_history AFTER INSERT OR UPDATE
ON iam_migration.record FOR EACH ROW
EXECUTE FUNCTION iam_migration.append_record_history();

CREATE TABLE IF NOT EXISTS iam_migration.containment (
    operation_id text PRIMARY KEY CHECK (length(operation_id) BETWEEN 16 AND 160),
    migration_id text NOT NULL REFERENCES iam_migration.record(migration_id),
    target_issuer text NOT NULL,
    target_subject text NOT NULL,
    phase text NOT NULL DEFAULT 'PENDING' CHECK (phase IN (
        'PENDING', 'IDENTITY_DISABLED', 'SESSIONS_REVOKED',
        'CREDENTIALS_REVOKED', 'VERIFIED', 'UNKNOWN')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (length(target_issuer) BETWEEN 1 AND 2048),
    CHECK (length(target_subject) BETWEEN 1 AND 512)
);
-- Persist a durable DENY until explicitly reviewed and resolved. An
-- attacker cannot clear the tombstone by restoring an old user snapshot.
CREATE TABLE IF NOT EXISTS iam_migration.deny_fence (
    migration_id text PRIMARY KEY REFERENCES iam_migration.record(migration_id),
    source_issuer text NOT NULL,
    source_subject text NOT NULL,
    target_issuer text NOT NULL,
    target_subject text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE OR REPLACE FUNCTION iam_migration.prevent_fence_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'IAM-N05 revocation fence cannot be removed by rollback';
END;
$$;
DROP TRIGGER IF EXISTS n05_fence_immutable ON iam_migration.deny_fence;
CREATE TRIGGER n05_fence_immutable BEFORE UPDATE OR DELETE
ON iam_migration.deny_fence FOR EACH ROW
EXECUTE FUNCTION iam_migration.prevent_fence_delete();
