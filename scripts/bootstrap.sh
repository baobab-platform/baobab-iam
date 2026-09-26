#!/usr/bin/env bash
# bootstrap.sh – idempotent realm and client provisioning
set -euo pipefail

KC_ADMIN=${KEYCLOAK_ADMIN:-admin}
KC_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-admin123}
KC_URL=${KC_URL:-http://localhost:8080}

# kcadm.sh persists its login session to $HOME/.keycloak/kcadm.config by
# default. The runtime container has no /etc/passwd entry for its non-root
# UID, so $HOME resolves to empty/"/" — which that UID cannot write to
# ("Failed to create config file: /.keycloak/kcadm.config"). Rather than
# depend on which directories under /opt/keycloak happen to be writable by
# that UID, point the config file at a fresh file under /tmp, which is
# writable by any UID regardless of image specifics.
KCADM_CONFIG=$(mktemp)
kcadm() {
  /opt/keycloak/bin/kcadm.sh "$@" --config "$KCADM_CONFIG"
}

# reconcile_step_up_flow adds Gate IAM-5 phase 3's (ADR-0009 §41-45)
# "Baobab - Step-Up" subflow and its acr.loa.map realm attribute to an
# already-existing realm. `kcadm create realms` above only ever applies
# authenticationFlows/attributes from baobab-realm.json on first
# bootstrap -- an already-existing realm otherwise never picks up a flow
# or attribute change committed after that, unlike client-scopes/clients
# below, which are reconciled every run. This is the one such change Gate
# IAM-5 phase 3 makes, so reconcile it specifically here rather than
# leaving every persistent deployment stuck on whatever
# authenticationFlows/attributes existed at first bootstrap.
#
# Idempotent: skips entirely once "Baobab - Step-Up" is present, so
# repeat container restarts never re-run it.
reconcile_step_up_flow() {
  if kcadm get "authentication/flows/Baobab%20-%20Step-Up/executions" -r baobab > /dev/null 2>&1; then
    echo "'Baobab - Step-Up' subflow already present. Skipping step-up reconciliation."
  else
    echo "Reconciling Gate IAM-5 phase 3's 'Baobab - Step-Up' subflow into the existing realm..."
    # executions/flow creates the child flow already wired into its parent
    # in one call. There is no REST operation to attach an already-created,
    # standalone flow as a subflow instead -- and separately creating a
    # top-level flow, then deleting it, leaves the parent's execution list
    # holding a dangling reference to the deleted flow (verified against a
    # real Keycloak 26.7.3 instance while developing this: Keycloak's
    # flow-id delete endpoint does not clean up the parent's now-invalid
    # execution entry, breaking every subsequent read of the parent flow
    # with a 500 NullPointerException). Deleting via the execution's own
    # id instead does cascade correctly, but the fix here is simpler:
    # never create the flow disconnected from its parent to begin with.
    kcadm create "authentication/flows/Baobab%20browser/executions/flow" -r baobab \
      -s alias="Baobab - Step-Up" -s provider=basic-flow -s type=basic-flow \
      -s "description=Gate IAM-5 phase 3 (ADR-0009 41-45): on-demand step-up, independent of iam:mfa-required." \
      > /dev/null

    STEP_UP_EXECUTION_JSON=$(kcadm get "authentication/flows/Baobab%20browser/executions" -r baobab \
      | jq -c '[.[] | select(.displayName == "Baobab - Step-Up")][0]')
    TMP_FILE=$(mktemp)
    echo "$STEP_UP_EXECUTION_JSON" | jq '.requirement = "CONDITIONAL"' > "$TMP_FILE"
    kcadm update "authentication/flows/Baobab%20browser/executions" -r baobab -f "$TMP_FILE"
    rm -f "$TMP_FILE"

    kcadm create "authentication/flows/Baobab%20-%20Step-Up/executions/execution" -r baobab -s provider=conditional-level-of-authentication > /dev/null
    kcadm create "authentication/flows/Baobab%20-%20Step-Up/executions/execution" -r baobab -s provider=auth-otp-form > /dev/null

    STEP_UP_EXECUTIONS_JSON=$(kcadm get "authentication/flows/Baobab%20-%20Step-Up/executions" -r baobab)
    LOA_CONDITION_ID=$(echo "$STEP_UP_EXECUTIONS_JSON" | jq -r '[.[] | select(.providerId == "conditional-level-of-authentication")][0].id')
    OTP_FORM_ID=$(echo "$STEP_UP_EXECUTIONS_JSON" | jq -r '[.[] | select(.providerId == "auth-otp-form")][0].id')

    for EXECUTION_ID in "$LOA_CONDITION_ID" "$OTP_FORM_ID"; do
      TMP_FILE=$(mktemp)
      echo "$STEP_UP_EXECUTIONS_JSON" | jq --arg id "$EXECUTION_ID" '[.[] | select(.id == $id)][0] | .requirement = "REQUIRED"' > "$TMP_FILE"
      kcadm update "authentication/flows/Baobab%20-%20Step-Up/executions" -r baobab -f "$TMP_FILE"
      rm -f "$TMP_FILE"
    done

    # Matches authenticatorConfig "baobab-step-up-loa-gold" in
    # config/realm/baobab-realm.json: loa-condition-level 2 ("gold"),
    # loa-max-age 300 seconds.
    kcadm create "authentication/executions/$LOA_CONDITION_ID/config" -r baobab \
      -s alias=baobab-step-up-loa-gold -s 'config."loa-condition-level"=2' -s 'config."loa-max-age"=300' > /dev/null

    echo "'Baobab - Step-Up' subflow reconciled."
  fi

  # Cheap and idempotent to re-apply every run (a PUT of the same value is
  # a no-op) -- unlike the flow reconciliation above, no existence check
  # is needed first.
  echo "Reconciling realm attribute acr.loa.map..."
  TMP_FILE=$(mktemp)
  kcadm get realms/baobab -r baobab | jq '.attributes["acr.loa.map"] = "{\"silver\":1,\"gold\":2}"' > "$TMP_FILE"
  kcadm update realms/baobab -f "$TMP_FILE"
  rm -f "$TMP_FILE"
}

# Wait for Keycloak to be ready, then log in as admin.
#
# This retries kcadm's own login rather than curl-polling a health
# endpoint: kcadm.sh is a bundled Java CLI with its own HTTP client, so it
# needs no extra runtime dependency, and a successful login both confirms
# readiness and completes the login step in one loop. (An earlier version
# of this script used curl for the wait loop, which required installing
# curl into the image — removed after a vulnerability scan flagged
# multiple HIGH-severity CVEs in the ubi9-provided curl/libcurl package
# with no fixed version yet available upstream; kcadm.sh has no such
# exposure since it ships with Keycloak itself.)
echo "Waiting for Keycloak at $KC_URL ..."
READY=0
for _ in $(seq 1 60); do
  if kcadm config credentials --server "$KC_URL" --realm master --user "$KC_ADMIN" --password "$KC_ADMIN_PASSWORD"; then
    READY=1
    break
  fi
  sleep 5
done
if [ "$READY" -ne 1 ]; then
  echo "Keycloak admin login did not succeed within 5 minutes; giving up." >&2
  exit 1
fi

# Import realm if not exists
REALM_EXISTS=$(kcadm get realms/baobab > /dev/null 2>&1 && echo "yes" || echo "no")
if [ "$REALM_EXISTS" = "no" ]; then
  echo "Creating realm 'baobab'..."
  kcadm create realms -f /opt/keycloak/config/realm/baobab-realm.json
else
  echo "Realm 'baobab' already exists. Skipping creation."
  # kcadm create realms above is the ONLY place authenticationFlows/realm
  # attributes are applied -- an already-existing realm otherwise never
  # picks up flow or attribute changes committed to baobab-realm.json
  # after its first bootstrap (unlike client-scopes/clients below, which
  # are reconciled every run). Gate IAM-5 phase 3 (ADR-0009 §41-45) adds
  # exactly one such change -- the "Baobab - Step-Up" subflow and its
  # acr.loa.map realm attribute -- so reconcile that specific change here,
  # idempotently, rather than leaving every persistent deployment stuck on
  # whatever authenticationFlows/attributes existed at first bootstrap.
  reconcile_step_up_flow
fi

# Import client scopes (custom scopes required by ADR-0006's token profile,
# e.g. actor-type-human, actor-type-workload, context:resolve). These must
# exist before any client references them in defaultClientScopes.
for scope_file in /opt/keycloak/config/scopes/*.json; do
  if [ -f "$scope_file" ]; then
    SCOPE_NAME=$(jq -r '.name' "$scope_file")
    echo "Creating client scope '$SCOPE_NAME' ..."
    kcadm create client-scopes -r baobab -f "$scope_file" || echo "Client scope '$SCOPE_NAME' may already exist; skipping."
  fi
done

# Import workload clients (service accounts).
#
# BOOTSTRAP_WORKLOAD_CLIENT_SECRET, when set, seeds every workload client
# with the same deterministic secret at creation time. This exists ONLY to
# make local development and CI integration testing (tests/integration/)
# reproducible without a Keycloak admin round-trip per client. Production
# secrets SHALL be injected by the platform secret-management boundary per
# ADR-0002 Section 25 and SHALL NOT use this variable.
#
# zuribeans-backend and thamani-backend are the exception to "every
# workload client gets the identical literal secret": unlike the other
# workload clients here (each a platform *service*, all inside the same
# security boundary today), these two represent different *tenants* --
# Gate ZB-03's "Thamani != ZuriBeans" isolation requirement is exactly
# about not letting one impersonate the other. Sharing one literal secret
# string between them would mean anyone holding it could authenticate as
# either estate's backend interchangeably by simply naming the other
# client_id (nabhold/baobab-iam#31 review finding) -- so each gets the
# shared seed suffixed with its own client_id instead. This needs no new
# binary dependency (this image is deliberately minimal ubi9-micro with
# only jq added -- see this repo's Dockerfile), just a different string.
for client_file in /opt/keycloak/config/clients/*-workload.json; do
  if [ -f "$client_file" ]; then
    CLIENT_ID=$(jq -r '.clientId' "$client_file")
    echo "Creating workload client '$CLIENT_ID' ..."
    if [ -n "${BOOTSTRAP_WORKLOAD_CLIENT_SECRET:-}" ]; then
      TMP_FILE=$(mktemp)
      case "$CLIENT_ID" in
        zuribeans-backend | thamani-backend)
          jq --arg secret "${BOOTSTRAP_WORKLOAD_CLIENT_SECRET}-${CLIENT_ID}" '. + {secret: $secret}' "$client_file" > "$TMP_FILE"
          ;;
        *)
          jq --arg secret "$BOOTSTRAP_WORKLOAD_CLIENT_SECRET" '. + {secret: $secret}' "$client_file" > "$TMP_FILE"
          ;;
      esac
      kcadm create clients -r baobab -f "$TMP_FILE" || echo "Client '$CLIENT_ID' may already exist; skipping."
      rm -f "$TMP_FILE"
    else
      kcadm create clients -r baobab -f "$client_file" || echo "Client '$CLIENT_ID' may already exist; skipping."
    fi
  fi
done

# Import remaining (non-workload) clients. Workload files are excluded here
# since the loop above already imports them — matching them again against
# the broad *.json glob previously caused a redundant, silently-swallowed
# second create attempt per workload client.
for client_file in /opt/keycloak/config/clients/*.json; do
  case "$client_file" in
    *-workload.json) continue ;;
  esac
  if [ -f "$client_file" ]; then
    CLIENT_ID=$(jq -r '.clientId' "$client_file")
    echo "Importing client '$CLIENT_ID' ..."
    kcadm create clients -r baobab -f "$client_file" || echo "Client '$CLIENT_ID' may already exist; skipping."
  fi
done

# reconcile_client_scopes_and_roles brings every already-existing client up
# to what config/ declares for two things the create-or-skip imports above
# never revisit: optional client scopes, and client roles. Without it a
# deployment bootstrapped before a scope or role was added never receives
# it (e.g. baobab-control-plane-admin's onboarding:request/authorise scopes
# and onboarding-requester/authoriser roles, ADR-BCP-017 §§22, 39).
# Idempotent: attaching an attached scope, or adding a composite a role
# already has, changes nothing. It only ever adds; removing a scope or role
# stays a deliberate, reviewed operation.
reconcile_client_scopes_and_roles() {
  local client_file client_id client_uuid scope_name scope_uuid roles_file role_name realm_role composite_file
  for client_file in /opt/keycloak/config/clients/*.json; do
    [ -f "$client_file" ] || continue
    client_id=$(jq -r '.clientId' "$client_file")
    client_uuid=$(kcadm get clients -r baobab -q clientId="$client_id" --fields id | jq -r '.[0].id // empty')
    [ -n "$client_uuid" ] || continue
    for scope_name in $(jq -r '.optionalClientScopes // [] | .[]' "$client_file"); do
      scope_uuid=$(kcadm get client-scopes -r baobab --fields id,name | jq -r --arg n "$scope_name" '[.[] | select(.name == $n)][0].id // empty')
      if [ -z "$scope_uuid" ]; then
        echo "Client scope '$scope_name' listed by '$client_id' does not exist; skipping." >&2
        continue
      fi
      kcadm update "clients/$client_uuid/optional-client-scopes/$scope_uuid" -r baobab -n
    done
  done

  for roles_file in /opt/keycloak/config/client-roles/*.json; do
    [ -f "$roles_file" ] || continue
    client_id=$(jq -r '.clientId' "$roles_file")
    client_uuid=$(kcadm get clients -r baobab -q clientId="$client_id" --fields id | jq -r '.[0].id // empty')
    if [ -z "$client_uuid" ]; then
      echo "Client '$client_id' for $roles_file does not exist; skipping its roles." >&2
      continue
    fi
    for role_name in $(jq -r '.roles[].name' "$roles_file"); do
      if ! kcadm get "clients/$client_uuid/roles/$role_name" -r baobab > /dev/null 2>&1; then
        echo "Creating client role '$client_id/$role_name' ..."
        kcadm create "clients/$client_uuid/roles" -r baobab -s name="$role_name" \
          -s "description=$(jq -r --arg n "$role_name" '.roles[] | select(.name == $n) | .description' "$roles_file")"
      fi
      for realm_role in $(jq -r --arg n "$role_name" '.roles[] | select(.name == $n) | .composites.realm // [] | .[]' "$roles_file"); do
        composite_file=$(mktemp)
        kcadm get "roles/$realm_role" -r baobab | jq '[{id: .id, name: .name}]' > "$composite_file"
        kcadm create "clients/$client_uuid/roles/$role_name/composites" -r baobab -f "$composite_file"
        rm -f "$composite_file"
      done
    done
  done
}
reconcile_client_scopes_and_roles

rm -f "$KCADM_CONFIG"
echo "Bootstrap completed."
