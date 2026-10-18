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

- CONDITIONAL `Baobab - Primary Authentication` at priority 5, containing a
  REQUIRED native LoA-1 predicate at priority 0, followed by the unchanged
  cookie, federation redirect and forms alternatives;
- CONDITIONAL OTP step-up at 40, then CONDITIONAL passkey step-up at 45;
- unchanged REQUIRED username/password and conditional privileged role/OTP
  inside `Baobab forms`, with all existing role composites and assurance
  configuration retained.

## Follow-up: baseline assurance before stronger conditions

The first hierarchy correction (#118) restored the credential page, but
Infrastructure run `38988838729` still failed after password submission.
Closed-vocabulary stack fingerprints led to `DefaultAuthenticationFlow` line
489; native Keycloak 26.7.5 reproduction confirmed the passwordless WebAuthn
authenticator was invoked on an ordinary login. `ConditionalLoaAuthenticator`
returns true for any configured level while current-request LoA is zero.
A plain REQUIRED identity wrapper never records baseline assurance, so the
LoA-3 branch was entered before ordinary privileged TOTP enrollment completed.

The primary wrapper is now CONDITIONAL with a native LoA-1 predicate.
Keycloak excludes conditional authenticator predicates from its required vs
alternative classification. This preserves the three identification choices.
Its `onParentFlowSuccess` records level 1 only after successful primary
execution, before the higher-level root branches evaluate. `loa-max-age=0`
limits this baseline to the current request. No password is labelled LoA 2/3;
privileged role-driven TOTP and explicit stronger assurance remain enforced.
Cookie/federation alternatives and existing session policy are unchanged.

An unenrolled user requesting essential LoA 3 previously hit an internal
`CREDENTIAL_SETUP_REQUIRED` error. The passkey branch now adds Keycloak's
native `conditional-user-configured` predicate before REQUIRED WebAuthn.
An enrolled key must still be proved; an unenrolled user cannot complete that
branch. The native top-flow essential-LoA check rejects the unmet request
with `acrNotFulfilled` (HTTP 400). It never enables automatic passkey enrollment
or labels a password/OTP as LoA 3. The regression requires this exact denial;
arbitrary HTTP errors, including 500, cannot count as a passing negative.
Existing passkey policy/configuration is checked before adding the predicate.

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

5. Prepare the native baseline predicate while the wrapper remains REQUIRED,
   create and attach its exact LoA-1/max-age-0 config, and validate it before
   switching the wrapper to CONDITIONAL as the final REST transaction.
   Interrupted configuration leaves identification REQUIRED; retry resumes.
   The previous #118 wrapper and fresh imports use the same checks. Custom
   baseline levels, persistence, duplicates or extra config fail for review.

There is no automatic rollback to the broken mixed-level hierarchy. A failure
after attachment can leave disabled cleanup unfinished, but the complete
required primary is already active and retry completes cleanup. Custom policy
requires an explicit maintainer review, not an automatic re-enable. Normal
protected deployment/backup and session-retest procedures still apply; do not
erase a realm/database to pick up this configuration.

## Evidence and remaining acceptance

Nineteen focused tests cover source topology, baseline assurance limits,
actual shell migration from both historical graphs, fresh no-op, interruption,
retry, idempotence, omitted primitive defaults and rejection of custom policy.
The CLI transport is a test double, not authentication evidence.

The required `integration-test` aggregate requires three actual Keycloak
variants: fresh import, the historical mixed root and the intermediate #118
REQUIRED wrapper. Every variant runs the full existing provider suite plus
`browser_assurance.py`: real HTML form/cookie processing, ordinary password,
privileged TOTP enrollment, S256 code exchange and baseline LoA output;
wrong passwords cannot get codes; an unenrolled essential passkey request
must return the defined HTTP 400 assurance denial, never a generic server error.
Synthetic users/sessions are removed through the Admin API. No direct-grant
workforce shortcut, stored HTML or printed credential/session data is used.

The standard-library HTTP probe models Chromium's localhost Secure-cookie
behavior only for its guarded exact loopback HTTP origin. It refuses external
form actions/redirects; HTTPS still uses normal certificate verification.
Failure diagnostics contain only fixed stage/error kinds and HTTP status.

A private native Keycloak diagnostic additionally completed real privileged
password/TOTP enrollment to the callback. This is diagnostic, not the pinned
Docker/PostgreSQL acceptance receipt. The new CI results must be checked before
merge. Chromium UI behavior, maintained RP signature/nonce/callback/replay
negatives, CP authorization/revocation, provider qualification and record
isolation remain Infrastructure #35 acceptance; no gate is predeclared PASS.

Primary implementation references:

- https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/authentication/DefaultAuthenticationFlow.java
- https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/services/resources/admin/AuthenticationManagementResource.java
- https://github.com/keycloak/keycloak/blob/26.7.5/services/src/main/java/org/keycloak/authentication/authenticators/conditional/ConditionalLoaAuthenticator.java
