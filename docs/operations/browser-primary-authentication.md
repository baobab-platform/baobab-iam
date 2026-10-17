# Browser primary authentication repair — 17 October 2026

Authority: ADR-0009 workforce/step-up, ADR-0015 privileged MFA and
ADR-IAM-0024 assurance policy. This corrects execution hierarchy; it introduces
no authentication exemption, business grant, provider activation or new ACR.

## Failure and cause

Infrastructure #35 run `38985822405` reached the actual IAM authorization page
but found one form/six inputs and no username/password/TOTP fields. The pinned
Keycloak 26.7.5 `DefaultAuthenticationFlow.fillListsOfExecutions` collects
CONDITIONAL as required and immediately clears ALTERNATIVE siblings, before
evaluating whether conditions are disabled. The old root mixed cookie,
identity-provider redirect and forms alternatives with conditional step-up.
Structural import tests alone did not establish a working browser login.

The fresh realm now has:

- REQUIRED `Baobab - Primary Authentication` at priority 5, containing the
  unchanged cookie, federation redirect and forms alternatives;
- CONDITIONAL passkey step-up at 35, then CONDITIONAL OTP step-up at 40;
- unchanged REQUIRED username/password and conditional privileged role/OTP
  inside `Baobab forms`, with all existing role composites and assurance
  configuration retained.

## Persistent-realm reconciliation

`bootstrap.sh` sources `reconcile_browser_primary.sh` after the existing
assurance reconciliation. The repair uses authenticated Admin API operations:

1. Require the known Baobab browser binding and expected active branches.
   Operator custom bindings/disabled identification branches fail for review.
2. Prepare an unattached, discoverable primary flow, copying the existing execution models
   and authenticator-configuration references. Interrupted preparation is
   restartable; a partial flow is never attached to the active browser root.
   Keycloak lists only top-level flows, so the pending candidate uses that
   discovery flag and a reserved description. Existing child IDs come from
   recursive execution references. The migrated candidate remains listed
   (the API does not update this flag); the realm's browser binding stays
   `Baobab browser`, never the primary-only wrapper. Fresh imports can mark
   the already-attached wrapper non-top-level.
3. Verify exactly the three expected alternatives, then attach the complete
   primary as one REQUIRED execution before assurance. This single REST
   transaction is the security cutover.
4. Disable the old root references, preserving them for audit/recovery. Never
   delete a forms execution/flow: Keycloak deletion cascades into the MFA
   graph that the new primary still references.

There is no automatic rollback to the broken mixed-level hierarchy. A failure
after attachment can leave disabled cleanup unfinished, but the complete
required primary is already active and retry completes cleanup. Custom policy
requires an explicit maintainer review, not an automatic re-enable. Normal
protected deployment/backup and session-retest procedures still apply; do not
erase a realm/database to pick up this configuration.

## Evidence and remaining acceptance

Twelve focused tests cover source topology, assurance preservation, actual
shell repair with stateful CLI transport, fresh no-op, interrupted preparation,
retry, idempotence, omitted primitive JSON defaults and rejection of operator customisations. The transport is
a test double, not authentication evidence. CI additionally requests a real
code/S256 authorization page and requires username/password inputs. It does
not log or retain session-bound HTML.

The required `integration-test` aggregate requires two real Keycloak variants:
fresh import and the historical mixed-level hierarchy mounted as synthetic
realm policy before bootstrap. Both run the existing full provider suite and
the credential-HTML regression. The legacy variant changes no image/source
artifact; it validates the actual persistent-realm reconciliation API path.

Complete browser login, actual privileged TOTP enrollment, callback/code/nonce
negatives, current CP acceptance and record isolation still require the
Infrastructure #35 real run. No live acceptance is predeclared by this source
repair or the HTML check.

Primary implementation references:

- https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/authentication/DefaultAuthenticationFlow.java
- https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/AuthenticationManagementResource.java
