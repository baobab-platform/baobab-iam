# Gate IAM-12 — Identity Lifecycle, Revocation and Deprovisioning

**Status:** Phase 1 complete (administrative audit logging enabled and verified; the IAM-side "kill switch" — disable identity + revoke sessions — proven end-to-end against a real Keycloak instance). This ADR has 213 sections and is overwhelmingly cross-repo; baobab-iam's own slice is narrow — see §2.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0016 — Identity Lifecycle, Revocation and Deprovisioning`
**Repositories:** `baobab-platform/baobab-iam` (authentication identity/credential/session lifecycle, this gate's scope), `baobab-platform/shared` (lifecycle event contracts — already substantially built, see §3)
**Depends on:** Gate IAM-4 (workload lifecycle states, partially overlapping §79), Gate IAM-11 (credential/MFA — this gate's session/identity revocation builds on it)

---

## 1. Why this gate's IAM-side scope is narrow

ADR-0016's own ownership table (§203) assigns most of its 213 sections elsewhere:

| Lifecycle domain | Owner |
|---|---|
| Canonical Identity, tenant membership, capability entitlement | `baobab-cp` |
| Buyer membership, customer actor | `baobab-trade` |
| Supplier membership/approval | supplier domain (doesn't exist yet — Gate IAM-8) |
| AD_User/AD_Role | `baobab-erp` |
| CMS actor/roles | `baobab-cms` |
| Pulse domain access | `baobab-pulse` |
| **Authentication identity lifecycle, credentials, IAM sessions** | **`baobab-iam`** |

The reconciliation sagas, orphan detection, cross-engine event propagation, and workforce joiner/mover/leaver orchestration that make up most of this ADR's text are `baobab-cp`'s job (it's the system that actually knows about tenants, entitlements, and cross-engine mappings) — not something this repository can implement unilaterally. This gate targets only what `baobab-iam` itself owns: disabling an identity, revoking its credentials/sessions, and auditing that those actions happened.

## 2. Discovery — a real, concrete audit gap

Reading the realm configuration directly (not assuming) found: `eventsEnabled: true` (so user-facing events like `LOGIN`/`LOGIN_ERROR` are captured), but **`adminEventsEnabled` was entirely absent** (Keycloak defaults this to `false`). This means every administrative lifecycle action this gate cares about — disabling a user, deleting a credential, revoking a role — left **no audit trail at all**. This directly violates ADR-0016 §98 ("Lifecycle events SHALL identify the authoritative producer... correlation ID") and §139 ("At minimum, audit: identity disabled, identity reactivated... credential revoked, sessions revoked...").

## 3. Discovery — `baobab-platform/shared` already has the cross-engine event contracts

Before assuming §90/§186-189's "shared SHOULD define lifecycle events" was unstarted work, `baobab-platform/shared/contracts/identity-events/v1/` was checked directly. It already contains, fully built (schemas, an `asyncapi.yaml`, and example payloads): `identity-created`, `identity-disabled`, `identity-suspended`, `identity-reactivated`, `session-revoked`, `membership-revoked`, `entitlement-revoked`, `credential-compromised`, and `workload-revoked`. This is a real, substantial head start this gate didn't need to duplicate.

What's still missing is a **producer**: nothing in `baobab-iam` actually emits these schemas anywhere. Keycloak has no built-in generic webhook/event-forwarding mechanism (only pluggable `eventsListeners`, of which only `jboss-logging` — writing to the server's own log — is configured); publishing to `baobab-platform/shared`'s schemas from real IAM state changes would require a custom Keycloak Event Listener SPI provider (a Java bundle under `providers/`, which the repo's `providers/README.md` explicitly says to avoid "unless a requirement cannot be met by native Keycloak configuration," per ADR-0002 §26-27). Since Keycloak's native Admin Events API (fixed by phase 1's `adminEventsEnabled`) already exposes every administrative lifecycle change in a structured, queryable form, whether a custom SPI is actually justified — versus `baobab-cp` or an infrastructure component polling that native API — is a design decision this gate defers rather than guesses at (see §5).

## 4. Phase 1 (this PR)

1. **`config/realm/baobab-realm.json`** — added `"adminEventsEnabled": true, "adminEventsDetailsEnabled": true`. This alone closes the §98/§139 audit gap using pure native configuration, with no custom code, matching ADR-0002's stated preference.
2. **`tests/integration/run.sh` §16** — a real, end-to-end "kill switch" (§158-159) proof against a live Keycloak instance, using `admin-cli` (Keycloak's own built-in client, present in every realm with direct grants enabled by default — not a Baobab-created client, since no workforce client allows direct grants after Gate IAM-5):
   - Creates a throwaway test user and confirms it can authenticate.
   - Revokes its sessions via the Admin API and confirms the session count actually drops to zero (not just that the endpoint returns success).
   - Disables the identity and confirms a **new** authentication attempt is rejected — the ADR-0016 §211 required test "`DISABLED identity + valid token = DENY`" from the IAM side specifically (full DENY of an already-issued token is a resource-server responsibility this repo doesn't own; what IAM owns is that no *new* session can be established).
   - Confirms the admin-events log actually recorded these actions (`GET .../admin-events?resourceTypes=USER&resourcePath=users/{id}`), proving phase 1's config change works, not just that the flag is set.
   - Cleans up the test user unconditionally.

## 5. What remains open (deferred, not started)

Given the ADR's size, only the narrow items above were tractable as a bounded, IAM-owned PR. Substantial remaining scope:

1. **Whether IAM needs a custom Event Listener SPI to push lifecycle events to `baobab-platform/shared`'s schemas, or whether `baobab-cp`/infrastructure should poll the native Admin Events API instead** — a real architectural fork (§3 above), not resolved here. Revisit once `baobab-cp`'s own event-consumption design (referenced in Gate IAM-4's scope doc as pending the `ADR-BCP-*` series) is clearer.
2. **Everything CP/Trade/ERP/CMS/Pulse own**: tenant membership, capability entitlement, buyer/supplier membership, AD_User/Role, CMS/Pulse actor lifecycle, the full workforce joiner/mover/leaver saga (§35-48, §206, §209), reconciliation (§112-119), orphan detection (§112-115), the deprovisioning saga/dead-letter handling (§120-127) — none of this is `baobab-iam` code and none of it was touched.
3. **Workload lifecycle states** (§79-85) — explicitly left open by Gate IAM-4's own phase 5 ("fold into phase 2's registry schema... blocked on phase 4"), still not implemented; unrelated to this gate's own scope beyond the overlap in terminology.
4. **Credential-specific lifecycle beyond Gate IAM-11** (§12-14 ENROLLED/ACTIVE/COMPROMISED/REVOKED/REPLACED as an explicit state machine, rather than relying on Keycloak's native credential CRUD) — not modeled explicitly; Keycloak's own credential management already satisfies the underlying requirement (a credential can be individually deleted without affecting others), just not as a named state machine.
5. **Dormant-account review, access certification** (§166-171) — operational/product policy, not started.
6. **DR/backup-restoration reconciliation** (§181-183) — infrastructure-owned, not investigated this session.
