#!/usr/bin/env bash
# IAM-N08: only an isolated PostgreSQL 17 GitHub Actions service.
# Tests actual pg_dump and pg_restore on synthetic IAM-N06 records; no production data.
set -Eeuo pipefail
umask 077
if [[ "$IAM_N08_DISPOSABLE_PG" != "1" || "$IAM_N08_DATABASE_NAME" != "n06_ci" || ! "$IAM_N08_PG_CONTAINER" =~ ^[0-9a-f]{12,64}$ || "$GITHUB_ACTIONS" != "true" ]]; then
  echo N08_BLOCKED_DISPOSABLE_PG_REQUIRED >&2; exit 2
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
cd "$ROOT"
tmp="$(mktemp -d)"; chmod 700 "$tmp"
container="$IAM_N08_PG_CONTAINER"
restored_owned=0
corrupt_owned=0
# This disposable CI run may delete only databases it actually created.
# Teardown is part of the same execution, including failure and interruptions:
# a dirty DB is not an independent successful recovery receipt.
cleanup() {
  local original_status="$1" cleanup_failed=0
  trap - EXIT
  set +e
  if [[ "$corrupt_owned" == "1" ]]; then
    docker exec "$container" dropdb --if-exists -U n06_ci n08_corrupt > /dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$restored_owned" == "1" ]]; then
    docker exec "$container" dropdb --if-exists -U n06_ci n08_restored > /dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ "$corrupt_owned" == "1" || "$restored_owned" == "1" ]]; then
    remaining="$(docker exec "$container" psql -X -At -U n06_ci -d n06_ci -c       "SELECT count(*) FROM pg_database WHERE datname IN ('n08_restored','n08_corrupt')" 2>/dev/null)"
    if [[ "$remaining" != "0" ]]; then cleanup_failed=1; fi
  fi
  rm -rf -- "$tmp"
  if [[ "$cleanup_failed" != "0" ]]; then
    echo N08_DISPOSABLE_DATABASE_TEARDOWN_NOT_VERIFIED >&2
    exit 2
  fi
  if [[ "$original_status" == "0" ]]; then
    echo N08_PG17_BACKUP_RESTORE_REPLAY_NEGATIVES_OBSERVED_DEVELOPMENT_ONLY
  fi
  exit "$original_status"
}
trap 'cleanup "$?"' EXIT
psql_real() { docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U n06_ci -d "$1"; }
version="$(docker exec "$container" psql -X -At -U n06_ci -d n06_ci -c 'SHOW server_version_num')"
if [[ ! "$version" =~ ^17[0-9]{4}$ ]]; then echo N08_BLOCKED_POSTGRES17_REQUIRED >&2; exit 2; fi
psql_real n06_ci < internal/securityops/migrations/001_n06_security.sql > /dev/null
psql_real n06_ci <<'SQL' > /dev/null
INSERT INTO iam_security.event(event_id,event_type,occurred_at,subject_key,correlation_id,outcome,severity,metadata)
VALUES ('10000000-0000-4000-8000-000000000008','authorization.denied',now(),
        decode(repeat('ab',32),'hex'),'20000000-0000-4000-8000-000000000008',
        'DENIED','MEDIUM','{"synthetic":true}');
INSERT INTO iam_security.recovery_hold
(principal_key,issuer_key,security_domain_key,observed_at,hold_until,reason)
VALUES (decode(repeat('cd',32),'hex'),decode(repeat('ef',32),'hex'),
        decode(repeat('12',32),'hex'),now()-interval '1 minute',
        now()+interval '24 hours','SUSPECTED_TAKEOVER');
SQL
docker exec "$container" pg_dump -Fc --no-owner -U n06_ci -d n06_ci -n iam_security > "$tmp/original.dump"
test -s "$tmp/original.dump"
sha256sum "$tmp/original.dump" > "$tmp/original.sha256"
( cd "$tmp" && sha256sum -c original.sha256 ) > /dev/null
docker exec "$container" createdb -U n06_ci n08_restored
restored_owned=1
docker exec -i "$container" pg_restore --exit-on-error --no-owner --no-acl -U n06_ci -d n08_restored < "$tmp/original.dump"
restored="$(docker exec "$container" psql -X -At -U n06_ci -d n08_restored -c "SELECT count(*) FROM iam_security.event WHERE event_id='10000000-0000-4000-8000-000000000008'")"
hold="$(docker exec "$container" psql -X -At -U n06_ci -d n08_restored -c "SELECT count(*) FROM iam_security.recovery_hold WHERE hold_until>now() AND revision=1")"
if [[ "$restored" != "1" || "$hold" != "1" ]]; then echo N08_RESTORE_ORIGINAL_MISSING >&2; exit 2; fi
if psql_real n08_restored <<'SQL' > /dev/null 2>&1; then
INSERT INTO iam_security.event(event_id,event_type,occurred_at,subject_key,correlation_id,outcome,severity)
VALUES ('10000000-0000-4000-8000-000000000008','authorization.denied',now(),
        decode(repeat('ab',32),'hex'),'20000000-0000-4000-8000-000000000008','DENIED','MEDIUM');
SQL
  echo N08_DUPLICATE_REPLAY_ACCEPTED >&2; exit 2
fi
if psql_real n08_restored <<'SQL' > /dev/null 2>&1; then
UPDATE iam_security.event SET outcome='ALLOWED'
 WHERE event_id='10000000-0000-4000-8000-000000000008';
SQL
  echo N08_RESTORED_EVENT_MUTATION_ACCEPTED >&2; exit 2
fi
if psql_real n08_restored <<'SQL' > /dev/null 2>&1; then
DELETE FROM iam_security.event
 WHERE event_id='10000000-0000-4000-8000-000000000008';
SQL
  echo N08_RESTORED_EVENT_DELETION_ACCEPTED >&2; exit 2
fi
if psql_real n08_restored <<'SQL' > /dev/null 2>&1; then
UPDATE iam_security.recovery_hold SET hold_until=now()+interval '1 hour',
revision=revision+1 WHERE principal_key=decode(repeat('cd',32),'hex');
SQL
  echo N08_RESTORED_HOLD_SHRUNK >&2; exit 2
fi
head -c 24 "$tmp/original.dump" > "$tmp/corrupt.dump"
docker exec "$container" createdb -U n06_ci n08_corrupt
corrupt_owned=1
if docker exec -i "$container" pg_restore --exit-on-error --no-owner --no-acl -U n06_ci -d n08_corrupt < "$tmp/corrupt.dump" > /dev/null 2>&1; then
  echo N08_CORRUPT_RESTORE_ACCEPTED >&2; exit 2
fi
# The EXIT trap, not the body of the script, prints the success marker
# only AFTER both disposable restored databases have been independently
# removed and absence read back.
