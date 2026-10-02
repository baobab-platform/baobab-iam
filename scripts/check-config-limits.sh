#!/usr/bin/env bash
# scripts/check-config-limits.sh
#
# Keycloak stores client and client-scope descriptions in VARCHAR(255) columns. A longer description makes the import fail
# server-side, and bootstrap.sh's create-or-skip fallback swallows the failure, so the client or scope silently never exists
# (it broke iam#55 and, earlier, Gate IAM-4's context:resolve scope). Fail the build before that can reach a realm.
#
#   scripts/check-config-limits.sh
# Needs bash and jq. Exit 0: every description fits. Exit 1: at least one is too long.
set -euo pipefail
cd "$(dirname "$0")/.."

LIMIT=255
FAILED=0
for FILE in config/clients/*.json config/scopes/*.json; do
  LENGTH=$(jq -r '(.description // "") | length' "$FILE")
  if [ "$LENGTH" -gt "$LIMIT" ]; then
    echo "FAIL: $FILE description is $LENGTH characters; Keycloak allows $LIMIT" >&2
    FAILED=1
  fi
done
if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
echo "OK: every client and scope description fits Keycloak's $LIMIT-character limit"
