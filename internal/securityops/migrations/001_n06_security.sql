-- IAM-N06: isolated PostgreSQL 17 IAM security operations (ADR-IAM-0024/25/28/29).
-- No passwords, OTPs, passkey private keys, tokens, user emails or browser data.
CREATE SCHEMA IF NOT EXISTS iam_security;

CREATE TABLE IF NOT EXISTS iam_security.recovery_hold (
  principal_key bytea PRIMARY KEY CHECK (octet_length(principal_key) = 32),
  issuer_key bytea NOT NULL CHECK (octet_length(issuer_key) = 32),
  security_domain_key bytea NOT NULL CHECK (octet_length(security_domain_key) = 32),
  observed_at timestamptz NOT NULL,
  hold_until timestamptz NOT NULL,
  reason text NOT NULL CHECK (reason IN ('RECOVERY_COMPLETE','AUTHENTICATOR_REPLACED','SUSPECTED_TAKEOVER')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  CHECK (hold_until > observed_at)
);
CREATE INDEX IF NOT EXISTS n06_hold_expiry ON iam_security.recovery_hold(hold_until);
-- Holds only extend automatically; they cannot silently shrink under replay.
CREATE OR REPLACE FUNCTION iam_security.hold_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'N06 hold cannot be deleted by online runtime'; END IF;
 IF (OLD.principal_key,OLD.issuer_key,OLD.security_domain_key)
      IS DISTINCT FROM (NEW.principal_key,NEW.issuer_key,NEW.security_domain_key)
    OR NEW.hold_until < OLD.hold_until
    OR NEW.revision <> OLD.revision + 1 THEN
   RAISE EXCEPTION 'N06 holder identity or minimum hold shortened';
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS n06_protect_hold ON iam_security.recovery_hold;
CREATE TRIGGER n06_protect_hold BEFORE UPDATE OR DELETE ON iam_security.recovery_hold
FOR EACH ROW EXECUTE FUNCTION iam_security.hold_immutable();

CREATE TABLE IF NOT EXISTS iam_security.event (
  event_id uuid PRIMARY KEY,
  event_type text NOT NULL CHECK(event_type IN (
    'authentication.failed','authentication.succeeded',
    'mfa.challenge.failed','passkey.registered','passkey.revoked',
    'recovery.started','recovery.completed','identity.disabled',
    'session.revoked','credential.rotated','crypto.key.compromised',
    'oauth_client.revoked','incident.contained','incident.unknown',
    'authorization.denied')),
  occurred_at timestamptz NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  actor_key bytea CHECK (actor_key IS NULL OR octet_length(actor_key)=32),
  subject_key bytea NOT NULL CHECK(octet_length(subject_key)=32),
  correlation_id uuid NOT NULL,
  outcome text NOT NULL CHECK(outcome IN ('ALLOWED','DENIED','UNKNOWN','RECORDED')),
  severity text NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (jsonb_typeof(metadata)='object' AND pg_column_size(metadata)<=2048)
);
CREATE INDEX IF NOT EXISTS n06_security_event_lookup
 ON iam_security.event(subject_key,occurred_at DESC);
CREATE OR REPLACE FUNCTION iam_security.append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'IAM-N06 security evidence is append-only'; END; $$;
DROP TRIGGER IF EXISTS n06_event_immutable ON iam_security.event;
CREATE TRIGGER n06_event_immutable BEFORE UPDATE OR DELETE
ON iam_security.event FOR EACH ROW EXECUTE FUNCTION iam_security.append_only();

CREATE TABLE IF NOT EXISTS iam_security.rotation_plan (
  rotation_id uuid PRIMARY KEY,
  security_domain text NOT NULL CHECK(length(security_domain) BETWEEN 1 AND 80),
  environment text NOT NULL CHECK(environment IN ('development','staging','production')),
  purpose text NOT NULL CHECK(purpose IN ('HYDRA_SIGNING','HYDRA_CLIENT','KRATOS_COOKIE','KRATOS_CIPHER','TLS_CERT','FEDERATION_TRUST')),
  previous_key_ref text NOT NULL CHECK(length(previous_key_ref) BETWEEN 1 AND 160),
  next_key_ref text NOT NULL CHECK(length(next_key_ref) BETWEEN 1 AND 160),
  overlap_until timestamptz NOT NULL,
  phase text NOT NULL DEFAULT 'PREPARED' CHECK(phase IN (
      'PREPARED','DUAL_VALID','CONSUMERS_VERIFIED','OLD_RETIRED','ABORTED','UNKNOWN')),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  CHECK (previous_key_ref <> next_key_ref),
  UNIQUE(security_domain,environment,purpose,next_key_ref)
);
CREATE TABLE IF NOT EXISTS iam_security.rotation_history (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  rotation_id uuid NOT NULL REFERENCES iam_security.rotation_plan(rotation_id),
  revision bigint NOT NULL,
  phase text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(rotation_id,revision)
);
DROP TRIGGER IF EXISTS n06_rotation_history_immutable ON iam_security.rotation_history;
CREATE TRIGGER n06_rotation_history_immutable BEFORE UPDATE OR DELETE ON iam_security.rotation_history
FOR EACH ROW EXECUTE FUNCTION iam_security.append_only();
CREATE OR REPLACE FUNCTION iam_security.record_rotation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
   IF (OLD.rotation_id,OLD.security_domain,OLD.environment,OLD.purpose,
       OLD.previous_key_ref,OLD.next_key_ref,OLD.overlap_until)
       IS DISTINCT FROM
       (NEW.rotation_id,NEW.security_domain,NEW.environment,NEW.purpose,
        NEW.previous_key_ref,NEW.next_key_ref,NEW.overlap_until)
      OR NEW.revision <> OLD.revision+1 THEN
      RAISE EXCEPTION 'N06 rotation owner, trust boundary or revision drift';
   END IF;
   IF OLD.phase='OLD_RETIRED' OR OLD.phase='ABORTED' THEN
      RAISE EXCEPTION 'N06 terminal rotation cannot be reopened';
   END IF;
 END IF;
 INSERT INTO iam_security.rotation_history(rotation_id,revision,phase)
   VALUES(NEW.rotation_id,NEW.revision,NEW.phase);
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS n06_rotation_audit ON iam_security.rotation_plan;
CREATE TRIGGER n06_rotation_audit AFTER INSERT OR UPDATE ON iam_security.rotation_plan
FOR EACH ROW EXECUTE FUNCTION iam_security.record_rotation();

-- A high-risk credential change is a pre-authorised, provider-verified
-- rebinding ceremony, NOT permission to modify CP principal/membership.
CREATE TABLE IF NOT EXISTS iam_security.credential_rebind (
  request_id uuid PRIMARY KEY,
  principal_key bytea NOT NULL CHECK(octet_length(principal_key)=32),
  issuer_key bytea NOT NULL CHECK(octet_length(issuer_key)=32),
  credential_kind text NOT NULL CHECK (credential_kind IN ('PASSKEY','TOTP','RECOVERY_FACTOR')),
  requester_key bytea NOT NULL CHECK(octet_length(requester_key)=32),
  approver_key bytea NOT NULL CHECK(octet_length(approver_key)=32),
  reason text NOT NULL CHECK(reason IN ('LOST_DEVICE','COMPROMISE','PLANNED_REPLACEMENT')),
  phase text NOT NULL DEFAULT 'PENDING' CHECK(phase IN ('PENDING','PROVIDER_VERIFIED','COMMITTED','UNKNOWN')),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  CHECK (requester_key <> approver_key)
);
CREATE TABLE IF NOT EXISTS iam_security.rebind_history (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES iam_security.credential_rebind(request_id),
  phase text NOT NULL,
  revision bigint NOT NULL,
  at timestamptz NOT NULL DEFAULT statement_timestamp(),
  UNIQUE(request_id,revision)
);
DROP TRIGGER IF EXISTS n06_rebind_history_immutable ON iam_security.rebind_history;
CREATE TRIGGER n06_rebind_history_immutable BEFORE UPDATE OR DELETE
ON iam_security.rebind_history FOR EACH ROW EXECUTE FUNCTION iam_security.append_only();
CREATE OR REPLACE FUNCTION iam_security.audit_rebind()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='UPDATE' THEN
    IF (OLD.request_id,OLD.principal_key,OLD.issuer_key,OLD.credential_kind,
        OLD.requester_key,OLD.approver_key,OLD.reason) IS DISTINCT FROM
       (NEW.request_id,NEW.principal_key,NEW.issuer_key,NEW.credential_kind,
        NEW.requester_key,NEW.approver_key,NEW.reason)
       OR NEW.revision <> OLD.revision+1 THEN
       RAISE EXCEPTION 'IAM-N06 credential rebind ownership/revision changed';
    END IF;
    IF OLD.phase='COMMITTED' THEN
       RAISE EXCEPTION 'IAM-N06 completed credential rebind cannot reopen';
    END IF;
  END IF;
  INSERT INTO iam_security.rebind_history(request_id,phase,revision)
  VALUES (NEW.request_id,NEW.phase,NEW.revision);
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS n06_rebind_audit ON iam_security.credential_rebind;
CREATE TRIGGER n06_rebind_audit AFTER INSERT OR UPDATE
ON iam_security.credential_rebind FOR EACH ROW EXECUTE FUNCTION iam_security.audit_rebind();

-- Exact, low-blast-radius incident scope. The CP/resource authority is a
-- separately observed/approved step, not a flag this IAM table can grant.
CREATE TABLE IF NOT EXISTS iam_security.incident_command (
 command_id uuid PRIMARY KEY,
 incident_id uuid NOT NULL,
 target_key bytea NOT NULL CHECK(octet_length(target_key)=32),
 target_type text NOT NULL CHECK(target_type IN ('SESSION','NATIVE_IDENTITY','WORKLOAD_CLIENT')),
 action text NOT NULL CHECK(action IN ('REVOKE_SESSION','DISABLE_NATIVE','DISABLE_WORKLOAD')),
 reason text NOT NULL CHECK(reason IN ('CREDENTIAL_COMPROMISE','SESSION_THEFT','CONFIRMED_TAKEOVER')),
 approved_by_key bytea CHECK(approved_by_key IS NULL OR octet_length(approved_by_key)=32),
 requester_key bytea NOT NULL CHECK(octet_length(requester_key)=32),
 status text NOT NULL CHECK(status IN ('PENDING','PROVIDER_APPLIED','CP_DENIED','VERIFIED','UNKNOWN')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(incident_id,target_key,action),
 CHECK(approved_by_key IS NULL OR approved_by_key<>requester_key)
);
CREATE TABLE IF NOT EXISTS iam_security.incident_history (
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 command_id uuid NOT NULL REFERENCES iam_security.incident_command(command_id),
 revision bigint NOT NULL,
 status text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(command_id,revision)
);
DROP TRIGGER IF EXISTS n06_incident_history_immutable ON iam_security.incident_history;
CREATE TRIGGER n06_incident_history_immutable BEFORE UPDATE OR DELETE
ON iam_security.incident_history FOR EACH ROW EXECUTE FUNCTION iam_security.append_only();
CREATE OR REPLACE FUNCTION iam_security.record_incident()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
   IF (OLD.command_id,OLD.incident_id,OLD.target_key,OLD.target_type,
       OLD.action,OLD.reason,OLD.requester_key,OLD.approved_by_key)
      IS DISTINCT FROM
      (NEW.command_id,NEW.incident_id,NEW.target_key,NEW.target_type,
       NEW.action,NEW.reason,NEW.requester_key,NEW.approved_by_key)
       OR NEW.revision<>OLD.revision+1 THEN
      RAISE EXCEPTION 'N06 incident target/approval mutation refused';
   END IF;
 END IF;
 INSERT INTO iam_security.incident_history(command_id,revision,status)
 VALUES(NEW.command_id,NEW.revision,NEW.status);
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS n06_incident_audit ON iam_security.incident_command;
CREATE TRIGGER n06_incident_audit AFTER INSERT OR UPDATE
ON iam_security.incident_command FOR EACH ROW EXECUTE FUNCTION iam_security.record_incident();
