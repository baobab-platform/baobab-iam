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
trap 'rm -rf -- "$tmp"' EXIT
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
export ORY_FOUNDATION=1
python3 tests/operations/n08_ory_restore_state.py prepare "$tmp/native-fixtures.json"
"${compose[@]}" stop kratos hydra
# Snapshot BOTH real source of record DBs; never transmit or upload raw dump.
docker exec "$kratos_db" pg_dump -U kratos -d kratos -Fc --no-owner > "$tmp/kratos.dump"
docker exec "$hydra_db" pg_dump -U hydra -d hydra -Fc --no-owner > "$tmp/hydra.dump"
test -s "$tmp/kratos.dump"
test -s "$tmp/hydra.dump"
( cd "$tmp" && sha256sum kratos.dump hydra.dump > source.sha256 && sha256sum -c source.sha256 ) > /dev/null
# These are exclusively synthetic disposable PostgreSQL 17 volumes. Restore
# into the same service addresses after destroying each original database.
docker exec "$kratos_db" psql -X -v ON_ERROR_STOP=1 -U kratos -d postgres -c 'DROP DATABASE kratos WITH (FORCE)' >/dev/null
docker exec "$kratos_db" createdb -U kratos kratos
docker exec -i "$kratos_db" pg_restore --exit-on-error --no-owner --no-acl -U kratos -d kratos < "$tmp/kratos.dump"
docker exec "$hydra_db" psql -X -v ON_ERROR_STOP=1 -U hydra -d postgres -c 'DROP DATABASE hydra WITH (FORCE)' >/dev/null
docker exec "$hydra_db" createdb -U hydra hydra
docker exec -i "$hydra_db" pg_restore --exit-on-error --no-owner --no-acl -U hydra -d hydra < "$tmp/hydra.dump"
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
echo N08_REAL_NATIVE_PROVIDER_DATABASE_RESTORE_OBSERVED_DEVELOPMENT_ONLY
# The parent workflow always performs Compose down -v; the traps above also
# delete the *private* original dump/credential material, including failures.
