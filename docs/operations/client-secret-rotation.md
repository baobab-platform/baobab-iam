# Client Secret Rotation

Workload client secrets must be rotated periodically or after any suspected compromise.

## Prerequisites

- Access to Keycloak Admin Console or the `kcadm.sh` CLI.
- The new secret must be generated with high entropy (e.g., `openssl rand -base64 32`).
- An admin access token in `$ADMIN_TOKEN` (see `tests/integration/run.sh`'s `get_admin_token`
  for the exact call) and `$KC_URL` pointing at the Keycloak instance, if using the Admin API
  examples below rather than `kcadm.sh`.

## Rotation steps

Replace `{uuid}` throughout with the client's internal id (`GET
/admin/realms/baobab/clients?clientId={clientId}`), and `{clientId}` with its `clientId` value.

1. **Capture the current (soon-to-be-old) secret first**, so step 5's verification has a real
   value to test against rather than an empty string:
   ```bash
   OLD_SECRET=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
     "$KC_URL/admin/realms/baobab/clients/{uuid}/client-secret" | jq -r '.value')
   ```
2. **Generate a new secret**:
   ```bash
   NEW_SECRET=$(openssl rand -base64 32)
   ```
3. **Update Keycloak** — Keycloak's `client-secret` sub-resource only supports `GET` (read) and
   `POST` (server-generates a random one, ignoring any caller-supplied value); it has no `PUT`
   that accepts a caller-chosen secret. To set our own high-entropy value, fetch the full client
   representation, merge in the new `secret` field, and `PUT` it back — the same pattern
   `scripts/bootstrap.sh` already uses for setting a workload client's secret at creation time:
   ```bash
   CLIENT_JSON=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
     "$KC_URL/admin/realms/baobab/clients/{uuid}")
   curl -sf -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
     "$KC_URL/admin/realms/baobab/clients/{uuid}" \
     -d "$(echo "$CLIENT_JSON" | jq --arg secret "$NEW_SECRET" '. + {secret: $secret}')"
   ```
   (`kcadm.sh update clients/{uuid} -s "secret=$NEW_SECRET" -r baobab` does the equivalent
   fetch-merge-update internally and works equally well from the Keycloak Admin CLI.)
4. **Deploy the new secret to the workload** — via this platform's secret-management boundary
   (ADR-0002 §25), never by hand-editing a running service's config. Exactly how depends on
   which system consumes the client (e.g. `baobab-erp`'s `baobab.iam.workload.client.secret`
   system property, `baobab-platform/baobab-cp`'s own workload configuration) — see that system's own
   deployment docs for its specific mechanism.
5. **Verify the new secret works and the old one is rejected**. This step requires the client
   to be **enabled** — if you arrived here from the incident runbook (`security-incident-runbook.md`
   §3), the client was disabled in that procedure's step 1 and isn't re-enabled until its step
   3; run this verification only *after* that re-enable, not immediately after step 4 above,
   or every check below fails regardless of whether rotation actually worked:
   ```bash
   # New secret succeeds:
   curl -s -o /dev/null -w "%{http_code}\n" -X POST "$KC_URL/realms/baobab/protocol/openid-connect/token" \
     -d "client_id={clientId}" -d "client_secret=$NEW_SECRET" -d "grant_type=client_credentials"
   # Old secret is rejected (401):
   curl -s -o /dev/null -w "%{http_code}\n" -X POST "$KC_URL/realms/baobab/protocol/openid-connect/token" \
     -d "client_id={clientId}" -d "client_secret=$OLD_SECRET" -d "grant_type=client_credentials"
   ```
   Setting a new secret via step 3 immediately invalidates the old one — Keycloak holds only
   one secret value per client, with no overlap window where both work. For a **routine**
   rotation (not an incident, client stays enabled throughout), this means step 4 SHALL be
   ready to run immediately after step 3, or the workload will start failing to authenticate
   the moment step 3 completes — plan for that brief gap (or a coordinated deploy) rather than
   being surprised by it.