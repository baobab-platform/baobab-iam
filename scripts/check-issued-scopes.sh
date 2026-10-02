#!/usr/bin/env bash
# scripts/check-issued-scopes.sh
#
# Every scope Baobab IAM issues into access tokens must exist in the exact
# baobab-platform/shared scope registry that contracts.lock.yaml pins (EA Plan
# v2.0 EA-01C). Without this, IAM can implement and merge a scope (as it did
# for administrator:read, :write and :approve) while its lock still claims a
# registry that has never heard of it, and the lock stops describing what IAM
# implements.
#
# A "scope IAM issues" is a client scope under config/scopes/ whose
# include.in.token.scope attribute is "true". The few that are not Baobab
# vocabulary (Keycloak's own feature scopes) are listed in NON_BAOBAB_SCOPES
# below, each with the reason; adding to that list is a reviewed decision, not
# a way around the check.
#
#   scripts/check-issued-scopes.sh
#
# Reads the registry at the pinned commit from SHARED_REPO_DIR (a local git
# checkout of baobab-platform/shared, for development) when set, otherwise from
# raw.githubusercontent.com. Needs bash, jq, yq; git when SHARED_REPO_DIR is set.
# Exit 0: every issued scope is registered. Exit 1: at least one is not.
# Exit 2: the registry at the pinned commit could not be read.
set -euo pipefail

cd "$(dirname "$0")/.."

# Scopes issued under Keycloak's own feature, not Baobab vocabulary:
#   organization  Keycloak Organizations membership scope (ADR-0010; the
#                 oidc-organization-membership-mapper), defined by Keycloak.
NON_BAOBAB_SCOPES=("organization")

# yq comes in two implementations: mikefarah/yq (CI; needs -o=json) and the
# Python yq (prints JSON by default). Either works here.
yaml_to_json() {
  if yq --version 2>&1 | grep -qi mikefarah; then yq -o=json '.'; else yq '.'; fi
}

REGISTRY_PATH="contracts/authorization/v1/scope-registry.yaml"
LOCK_SHA=$(yaml_to_json < contracts.lock.yaml | jq -r '.source.commit')

if [ -n "${SHARED_REPO_DIR:-}" ]; then
  REGISTRY_YAML=$(git -C "$SHARED_REPO_DIR" show "$LOCK_SHA:$REGISTRY_PATH" 2>/dev/null || true)
else
  REGISTRY_YAML=$(curl -sf --max-time 30 "https://raw.githubusercontent.com/baobab-platform/shared/$LOCK_SHA/$REGISTRY_PATH" || true)
fi
if [ -z "$REGISTRY_YAML" ]; then
  echo "could not read $REGISTRY_PATH at the pinned Shared commit $LOCK_SHA (contracts.lock.yaml)" >&2
  exit 2
fi
REGISTERED=$(echo "$REGISTRY_YAML" | yaml_to_json | jq -r '.scopes[].name')

FAILED=0
CHECKED=0
for FILE in config/scopes/*.json; do
  [ "$(jq -r '.attributes["include.in.token.scope"] // "false"' "$FILE")" = "true" ] || continue
  NAME=$(jq -r '.name' "$FILE")
  CHECKED=$((CHECKED + 1))
  if echo "$REGISTERED" | grep -qx "$NAME"; then
    continue
  fi
  skip=0
  for OTHER in "${NON_BAOBAB_SCOPES[@]}"; do
    [ "$OTHER" = "$NAME" ] && skip=1
  done
  if [ "$skip" = "1" ]; then
    continue
  fi
  echo "FAIL: IAM issues scope '$NAME' ($FILE) but it is not in $REGISTRY_PATH at the pinned Shared commit $LOCK_SHA" >&2
  FAILED=1
done

if [ "$FAILED" = "1" ]; then
  echo "Re-pin contracts.lock.yaml to a Shared commit whose scope registry contains these scopes (explicit pull request, EA-01)." >&2
  exit 1
fi
echo "OK: all $CHECKED issued scopes exist in the scope registry at $LOCK_SHA"
