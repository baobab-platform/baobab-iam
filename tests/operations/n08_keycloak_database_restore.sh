#!/usr/bin/env bash
# This exact disposable test restores the retained enterprise Keycloak
# database, without querying browser credentials, private JWTs or CP grants.
set -Eeuo pipefail
umask 077
test "${GITHUB_ACTIONS:-}" = true
test "${IAM_N08_ENTERPRISE_DISPOSABLE:-}" = 1
cd "$(dirname "$0")/../.."
compose=(docker compose -p iam-n08-enterprise-recovery -f tests/enterprise/docker-compose.yml)
temp="$(mktemp -d)"
chmod 700 "$temp"
trap 'rm -rf -- "$temp"' EXIT
db="$("${compose[@]}" ps -q postgres)"
test -n "$db"
test "$(docker inspect "$db" -f '{{index .Config.Labels "com.docker.compose.project"}}')" = iam-n08-enterprise-recovery
test "$(docker inspect "$db" -f '{{.State.Running}}')" = true
version="$(docker exec "$db" psql -X -At -U enterprise -d enterprise -c 'SHOW server_version_num')"
[[ "$version" =~ ^17[0-9]{4}$ ]]
curl --cacert tests/enterprise/tls/ca.crt -fsS -o /dev/null   --max-time 4 https://localhost:9000/health/ready
# Original Keycloak realm and disabled-trust state are the actual contents
# of provider PostgreSQL. Never place a synthetic positive in a trace.
before="$(docker exec "$db" psql -X -At -v ON_ERROR_STOP=1 -U enterprise -d enterprise   -c 'SELECT count(*) FROM realm WHERE name = '\''master'\''' )"
test "$before" = 1
# Establish and revoke a real disposable broker-local user session before
# the exact provider database is snapshotted. Never persist the password,
# bearer or session identifier into the recovery archive.
python3 tests/operations/n08_keycloak_session_restore.py prepare "$temp/keycloak-session.json"
"${compose[@]}" stop keycloak
docker exec "$db" pg_dump -U enterprise -d enterprise -Fc --no-owner > "$temp/keycloak.dump"
test -s "$temp/keycloak.dump"
( cd "$temp" && sha256sum keycloak.dump > checksum && sha256sum -c checksum ) > /dev/null
docker exec "$db" psql -X -v ON_ERROR_STOP=1 -U enterprise -d postgres   -c 'DROP DATABASE enterprise WITH (FORCE)' >/dev/null
docker exec "$db" createdb -U enterprise enterprise
docker exec -i "$db" pg_restore --exit-on-error --no-owner --no-acl -U enterprise   -d enterprise < "$temp/keycloak.dump"
# Start with a *fresh* provider filesystem. The pinned Keycloak entrypoint
# creates a one-use /tmp truststore on boot; restarting the same container
# would reuse that truststore and incorrectly fail its import. Recreate only
# the Keycloak service, retaining the exact just-restored PostgreSQL state.
"${compose[@]}" up -d --no-deps --force-recreate keycloak
ready=0
for attempt in $(seq 1 45); do
  if curl --cacert tests/enterprise/tls/ca.crt --max-time 4 -fsS     -o /dev/null https://localhost:9000/health/ready; then
    ready=1; break
  fi
  sleep 3
done
test "$ready" = 1
after="$(docker exec "$db" psql -X -At -v ON_ERROR_STOP=1 -U enterprise -d enterprise   -c 'SELECT count(*) FROM realm WHERE name = '\''master'\''' )"
test "$after" = "$before"
python3 tests/operations/n08_keycloak_session_restore.py verify "$temp/keycloak-session.json"
echo N08_ACTUAL_KEYCLOAK_PG17_PROVIDER_RESTORE_OBSERVED
