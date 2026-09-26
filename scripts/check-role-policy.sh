#!/usr/bin/env bash
# check-role-policy.sh -- report workforce role assignments that break
# config/governance/role-policy.json.
#
# Keycloak cannot refuse an assignment by itself, so the separation-of-
# duties rules there (a toxic combination such as onboarding-requester +
# onboarding-authoriser, and a role's required realm role) are checked
# against a running realm instead: by operators after every privileged
# assignment and on a schedule, and by tests/integration/run.sh. Under
# ADR-BCP-020 the same rules become AdministrativeGrant constraints.
#
# A person's roles are their effective roles: assigned directly, through a
# group or subgroup, or through a composite. Policy roles must be assigned
# directly or through a group, so a composite role that contains one is
# itself reported -- it would hand the responsibility to everyone holding
# that composite without anyone deciding so.
#
# Runs from an operator's host or the CI runner (curl, jq, bash), like
# tests/integration/run.sh. Exit status: 0 no violation, 1 violations
# found, 2 the check could not run.
#
#   KC_URL                                   default http://localhost:8080
#   KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD default admin / admin123
#   REALM                                    default baobab
#   ROLE_POLICY_FILE                         default config/governance/role-policy.json
set -euo pipefail

KC_URL=${KC_URL:-http://localhost:8080}
KC_ADMIN=${KEYCLOAK_ADMIN:-admin}
KC_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-admin123}
REALM=${REALM:-baobab}
POLICY=${ROLE_POLICY_FILE:-$(dirname "$0")/../config/governance/role-policy.json}
PAGE=500

die() { echo "check-role-policy: $1" >&2; exit 2; }

[ -f "$POLICY" ] || die "policy file $POLICY not found"
TOKEN=$(curl -sf --max-time 30 -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d "username=$KC_ADMIN" -d "password=$KC_ADMIN_PASSWORD" -d grant_type=password \
  | jq -r '.access_token // empty') || die "could not obtain an admin token from $KC_URL"
[ -n "$TOKEN" ] || die "could not obtain an admin token from $KC_URL"

api() {
  curl -sf --max-time 30 -H "Authorization: Bearer $TOKEN" "$KC_URL/admin/realms/$REALM/$1" || die "GET $1 failed"
}

# paged PATH prints every element of a paged collection, one JSON per line.
paged() {
  local path=$1 first=0 batch count separator
  separator=$([[ "$path" == *\?* ]] && echo "&" || echo "?")
  while :; do
    batch=$(api "${path}${separator}first=$first&max=$PAGE")
    echo "$batch" | jq -c '.[]'
    count=$(echo "$batch" | jq 'length')
    [ "$count" -lt "$PAGE" ] && break
    first=$((first + PAGE))
  done
}

client_uuid() {
  api "clients?clientId=$1" | jq -r '.[0].id // empty'
}

# group_members GROUP_ID prints the ids of the group's members and of every
# subgroup's members, since a subgroup inherits its parent's role mappings.
group_members() {
  local group=$1 child
  paged "groups/$group/members?briefRepresentation=true" | jq -r '.id'
  for child in $(paged "groups/$group/children?briefRepresentation=true" | jq -r '.id'); do
    group_members "$child"
  done
}

VIOLATIONS=0
violation() { echo "VIOLATION: $1"; VIOLATIONS=$((VIOLATIONS + 1)); }

# Every (client, role) the policy names, and the client uuids behind them.
POLICY_ROLES=$(jq -c '[.toxic_combinations[].roles[], .prerequisites[].role] | unique | .[]' "$POLICY")
declare -A CLIENT_UUIDS=()
for entry in $POLICY_ROLES; do
  client=$(echo "$entry" | jq -r '.client')
  if [ -z "${CLIENT_UUIDS[$client]:-}" ]; then
    CLIENT_UUIDS[$client]=$(client_uuid "$client")
    [ -n "${CLIENT_UUIDS[$client]}" ] || die "client '$client' named by the policy does not exist in realm '$REALM'"
  fi
  role=$(echo "$entry" | jq -r '.role')
  api "clients/${CLIENT_UUIDS[$client]}/roles/$role" > /dev/null
done

# 1. No composite role may contain a policy role.
is_policy_role() {
  echo "$POLICY_ROLES" | jq -e --arg c "$1" --arg r "$2" 'select(.client == $c and .role == $r)' > /dev/null
}
for realm_role in $(paged "roles?briefRepresentation=false" | jq -r 'select(.composite) | .name'); do
  for client in "${!CLIENT_UUIDS[@]}"; do
    for contained in $(api "roles/$realm_role/composites/clients/${CLIENT_UUIDS[$client]}" | jq -r '.[].name'); do
      if is_policy_role "$client" "$contained"; then
        violation "realm role '$realm_role' composites '$client/$contained'; assign policy roles directly or through a group"
      fi
    done
  done
done
for client in "${!CLIENT_UUIDS[@]}"; do
  for client_role in $(paged "clients/${CLIENT_UUIDS[$client]}/roles?briefRepresentation=false" | jq -r 'select(.composite) | .name'); do
    for inner in "${!CLIENT_UUIDS[@]}"; do
      for contained in $(api "clients/${CLIENT_UUIDS[$client]}/roles/$client_role/composites/clients/${CLIENT_UUIDS[$inner]}" | jq -r '.[].name'); do
        if is_policy_role "$inner" "$contained"; then
          violation "client role '$client/$client_role' composites '$inner/$contained'; assign policy roles directly or through a group"
        fi
      done
    done
  done
done

# 2. Everyone holding a policy role, directly or through a group.
CANDIDATES=$(
  for entry in $POLICY_ROLES; do
    client=$(echo "$entry" | jq -r '.client')
    role=$(echo "$entry" | jq -r '.role')
    paged "clients/${CLIENT_UUIDS[$client]}/roles/$role/users?briefRepresentation=true" | jq -r '.id'
    for group in $(paged "clients/${CLIENT_UUIDS[$client]}/roles/$role/groups?briefRepresentation=true" | jq -r '.id'); do
      group_members "$group"
    done
  done | sort -u
)

# 3. Each candidate's effective roles against the policy.
for user in $CANDIDATES; do
  username=$(api "users/$user" | jq -r '.username')
  realm_roles=$(api "users/$user/role-mappings/realm/composite" | jq -c '[.[].name]')
  held='[]'
  for client in "${!CLIENT_UUIDS[@]}"; do
    held=$(api "users/$user/role-mappings/clients/${CLIENT_UUIDS[$client]}/composite" \
      | jq -c --arg c "$client" --argjson held "$held" '$held + [.[] | {client: $c, role: .name}]')
  done
  while IFS= read -r combination; do
    [ -n "$combination" ] || continue
    violation "user '$username' ($user) holds the toxic combination $(echo "$combination" | jq -r '.name'): $(echo "$combination" | jq -r '[.roles[] | .client + "/" + .role] | join(" + ")')"
  done < <(jq -c --argjson held "$held" '.toxic_combinations[] | select(all(.roles[]; . as $r | $held | index($r)))' "$POLICY")
  while IFS= read -r prerequisite; do
    [ -n "$prerequisite" ] || continue
    violation "user '$username' ($user) holds $(echo "$prerequisite" | jq -r '.role.client + "/" + .role.role') without the realm role $(echo "$prerequisite" | jq -r '.requires_realm_role')"
  done < <(jq -c --argjson held "$held" --argjson realm "$realm_roles" \
    '.prerequisites[] | select((.role as $r | $held | index($r)) and ((.requires_realm_role as $q | $realm | index($q)) | not))' "$POLICY")
done

if [ "$VIOLATIONS" -gt 0 ]; then
  echo "check-role-policy: $VIOLATIONS violation(s) of $POLICY in realm '$REALM'."
  exit 1
fi
echo "check-role-policy: no violation of $POLICY in realm '$REALM' ($(echo "$CANDIDATES" | grep -c . || true) holder(s) checked)."
