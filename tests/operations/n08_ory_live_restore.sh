#!/usr/bin/env bash
# IAM N08: actual Kratos + Hydra state restored into the disposable *same*
# isolated PG17 Foundation, with identity/session and workload denial readback.
# This performs destructive database reconstruction; refuse all other contexts.
set -Eeuo pipefail
umask 077
test "${GITHUB_ACTIONS:-}" = true
test "${ORY_FOUNDATION:-}" = 1
test "${ORY_KRATOS_ADMIN_URL:-}" = "http://127.0.0.1:4434"
test "${ORY_HYDRA_ADMIN_URL:-}" = "http://127.0.0.1:4445"
test "${ORY_KRATOS_PUBLIC_URL:-}" = "http://127.0.0.1:4433"
test "${ORY_PUBLIC_ISSUER:-}" = "http://127.0.0.1:4444"
cd "$(dirname "$0")/../.."
project=ory-foundation-ci
compose=(docker compose -p "$project" -f docker-compose.ory.yml)
tmp="$(mktemp -d)"
chmod 700 "$tmp"
security_owned=0
cleanup_native_restore() {
  local result="$?" failed=0
  trap - EXIT
  set +e
  # Only the DB created by this exact disposable CI run may be deleted.
  if [[ "$security_owned" = "1" && -n "${kratos_db:-}" ]]; then
    docker exec "$kratos_db" dropdb --if-exists -U kratos n08_security_ci >/dev/null 2>&1 || failed=1
    current="$(docker exec "$kratos_db" psql -X -At -U kratos -d postgres -c        "SELECT count(*) FROM pg_database WHERE datname='n08_security_ci'" 2>/dev/null)"
    if [[ "$current" != "0" ]]; then failed=1; fi
  fi
  rm -rf -- "$tmp"
  if [[ "$failed" != "0" ]]; then
    echo N08_SECURITY_DATABASE_TEARDOWN_UNVERIFIED >&2
    exit 2
  fi
  exit "$result"
}
trap cleanup_native_restore EXIT
# Labels prove that only this disposable GitHub CI Compose project is touched.
kratos_db="$("${compose[@]}" ps -q postgres-kratos)"
hydra_db="$("${compose[@]}" ps -q postgres-hydra)"
for id in "$kratos_db" "$hydra_db"; do
  test -n "$id"
  test "$(docker inspect "$id" -f '{{index .Config.Labels "com.docker.compose.project"}}')" = "$project"
  test "$(docker inspect "$id" -f '{{.State.Running}}')" = true
done
test "$(docker exec "$kratos_db" psql -X -At -U kratos -d kratos -c 'SHOW server_version_num')" != ""
test "$(docker exec "$hydra_db" psql -X -At -U hydra -d hydra -c 'SHOW server_version_num')" != ""
[[ "$(docker exec "$kratos_db" psql -X -At -U kratos -d kratos -c 'SHOW server_version_num')" =~ ^17[0-9]{4}$ ]]
[[ "$(docker exec "$hydra_db" psql -X -At -U hydra -d hydra -c 'SHOW server_version_num')" =~ ^17[0-9]{4}$ ]]

# Third source of record: IAM's approved security/recovery journal in the
# SAME isolated multi-provider restore, never a foreign production database.
existing="$(docker exec "$kratos_db" psql -X -At -U kratos -d postgres -c   "SELECT count(*) FROM pg_database WHERE datname='n08_security_ci'")"
test "$existing" = 0
docker exec "$kratos_db" createdb -U kratos n08_security_ci
security_owned=1
docker exec -i "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d n08_security_ci   < internal/securityops/migrations/001_n06_security.sql >/dev/null
docker exec -i "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d n08_security_ci <<'SQL' >/dev/null
INSERT INTO iam_security.event(event_id,event_type,occurred_at,subject_key,correlation_id,outcome,severity,metadata)
VALUES ('10000000-0000-4000-8000-000000000088','authorization.denied',now(),
        decode(repeat('ab',32),'hex'),'20000000-0000-4000-8000-000000000088',
        'DENIED','MEDIUM','{"synthetic":true}');
INSERT INTO iam_security.recovery_hold
(principal_key,issuer_key,security_domain_key,observed_at,hold_until,reason)
VALUES (decode(repeat('cd',32),'hex'),decode(repeat('ef',32),'hex'),
        decode(repeat('12',32),'hex'),now()-interval '1 minute',
        now()+interval '24 hours','SUSPECTED_TAKEOVER');
SQL

export ORY_FOUNDATION=1
python3 tests/operations/n08_ory_restore_state.py prepare "$tmp/native-fixtures.json"
"${compose[@]}" stop kratos hydra
# Snapshot BOTH real source of record DBs; never transmit or upload raw dump.
docker exec "$kratos_db" pg_dump -U kratos -d kratos -Fc --no-owner > "$tmp/kratos.dump"
docker exec "$hydra_db" pg_dump -U hydra -d hydra -Fc --no-owner > "$tmp/hydra.dump"
docker exec "$kratos_db" pg_dump -U kratos -d n08_security_ci -Fc --no-owner > "$tmp/security.dump"
test -s "$tmp/kratos.dump"
test -s "$tmp/hydra.dump"
test -s "$tmp/security.dump"
( cd "$tmp" && sha256sum kratos.dump hydra.dump security.dump > source.sha256 && sha256sum -c source.sha256 ) > /dev/null
# These are exclusively synthetic disposable PostgreSQL 17 volumes. Restore
# into the same service addresses after destroying each original database.
docker exec "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d postgres -c 'DROP DATABASE kratos WITH (FORCE)' >/dev/null
docker exec "$kratos_db" createdb -U kratos kratos
docker exec -i "$kratos_db" pg_restore --exit-on-error --no-owner --no-acl -U kratos -d kratos < "$tmp/kratos.dump"
docker exec "$hydra_db" psql -X -v ON_ERROR_STOP=1 -U hydra -d postgres -c 'DROP DATABASE hydra WITH (FORCE)' >/dev/null
docker exec "$hydra_db" createdb -U hydra hydra
docker exec -i "$hydra_db" pg_restore --exit-on-error --no-owner --no-acl -U hydra -d hydra < "$tmp/hydra.dump"
# Restore IAM security event/hold into the same disposable security DB.
docker exec "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d postgres -c   'DROP DATABASE n08_security_ci WITH (FORCE)' >/dev/null
docker exec "$kratos_db" createdb -U kratos n08_security_ci
docker exec -i "$kratos_db" pg_restore --exit-on-error --no-owner --no-acl -U kratos -d n08_security_ci   < "$tmp/security.dump"
"${compose[@]}" start kratos hydra
for port in 4434 4445; do
  ready=0
  for attempt in $(seq 1 40); do
    if curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$port/admin/health/ready" ||
       curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$port/health/ready"; then
      ready=1; break
    fi
    sleep 2
  done
  test "$ready" = 1
done
python3 tests/operations/n08_ory_restore_state.py verify "$tmp/native-fixtures.json"

# Independently query the third restored owner database while both providers
# are live. The event is immutable and the future-dated security hold survives.
restored_event="$(docker exec "$kratos_db" psql -X -At -U kratos -d n08_security_ci -c   "SELECT count(*) FROM iam_security.event WHERE event_id='10000000-0000-4000-8000-000000000088'")"
restored_hold="$(docker exec "$kratos_db" psql -X -At -U kratos -d n08_security_ci -c   "SELECT count(*) FROM iam_security.recovery_hold WHERE hold_until>now() AND revision=1")"
if [[ "$restored_event" != "1" || "$restored_hold" != "1" ]]; then
  echo N08_IAM_SECURITY_JOURNAL_RESTORE_NOT_PROVEN >&2; exit 2
fi
if docker exec -i "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d n08_security_ci <<'SQL' >/dev/null 2>&1; then
UPDATE iam_security.event SET outcome='ALLOWED' WHERE event_id='10000000-0000-4000-8000-000000000088';
SQL
  echo N08_RESTORED_SECURITY_EVENT_MUTATED >&2; exit 2
fi
if docker exec -i "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d n08_security_ci <<'SQL' >/dev/null 2>&1; then
UPDATE iam_security.recovery_hold SET hold_until=now()+interval '1 hour',
revision=revision+1 WHERE principal_key=decode(repeat('cd',32),'hex');
SQL
  echo N08_RESTORED_RECOVERY_HOLD_DOWNGRADED >&2; exit 2
fi
echo N08_THREE_DATABASE_PROVIDER_AND_SECURITY_RESTORE_OBSERVED_DEVELOPMENT_ONLY

echo N08_REAL_NATIVE_PROVIDER_DATABASE_RESTORE_OBSERVED_DEVELOPMENT_ONLY
# The parent workflow always performs Compose down -v; the traps above also
# delete the *private* original dump/credential material, including failures.
