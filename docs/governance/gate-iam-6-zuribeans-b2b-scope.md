# Gate IAM-6 — Zuribeans B2B

**Status:** Phase 1 complete (this PR): Keycloak Organizations feature enabled in `baobab-iam`, verified end-to-end against a real Keycloak instance in CI. Phases 2+ (buyer-organization canonical-entity registration in `baobab-cp`, IAM↔CP↔Trade wiring, cross-buyer isolation tests driven by real tokens) are scoped below but not yet implemented — see §4.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0010 — Zuribeans B2B Identity and Organization Access`
**Repositories:** `baobab-platform/baobab-iam` (IAM Organizations, owner of this phase), `baobab-platform/baobab-cp` (canonical identity/entity, platform context), `baobab-platform/baobab-trade` (buyer organization, membership, procurement roles — authoritative), `baobab-platform/zuribeans` (buyer frontend UX — not attached to this session)
**Depends on:** Gate IAM-3 (canonical identity spine), Gate IAM-5 (workforce SSO — internal Zuribeans operators use workforce identity per ADR-0010 §70, not buyer identity)
**Out of scope (this phase):** purchase authority/approval limits/commercial terms (ADR-0010 §6 explicitly keeps these out of IAM entirely, permanently — not deferred, prohibited), MFA policy specifics (ADR-0015), full invitation-flow implementation (§28-33, requires `baobab-trade`'s existing invitation-token machinery to be wired to real IAM-issued invitations, not just its own local tokens).

The Consolidated Technical Specification's own one-line scope for this gate (§209) is: *"Implement: buyer identity, buyer company, company onboarding, invitation, buyer membership, role separation, purchase authority, multi-company context, cross-buyer tests."* ADR-0010 is 122 sections; this document scopes Gate IAM-6 to what's genuinely IAM-owned per its own §115 ownership table (human authentication, IAM Organizations) plus the cross-repo wiring gaps a discovery pass found, rather than re-litigating what `baobab-trade` already correctly owns and has built.

---

## 1. Current state (verified against source, 2026-09-12)

A discovery pass across the three attached repos, cross-checked directly against code:

**`baobab-iam`** had zero B2B/organization support before this PR: no `organizationsEnabled` realm flag, no organization-related client scope, and `zuribeans-web`'s client config was plain human-login OIDC with no organization claim. ADR-0010 itself is still `Status: Proposed` (a design document, not yet implemented anywhere).

**`baobab-trade`**'s `src/modules/b2b/` is **substantially built and unit-tested already** — this was the biggest surprise of the discovery pass. It's a real Medusa module (`B2B_MODULE`) with 16 registered models: `b2b-organisation.ts` (tenant_id, legal_name, registration_number, status enum `PENDING/ACTIVE/SUSPENDED/CLOSED`, `canonical_organisation_id` field already present), `buyer-membership.ts` (status `INVITED/ACTIVE/SUSPENDED/REVOKED`, `invitation_token_hash`, `invitation_expires_at`, `invitation_accepted_at`), `buyer-role.ts` (`BUYER/SENIOR_BUYER/APPROVER/PROCUREMENT_MANAGER/ACCOUNT_ADMIN/VIEWER`), plus a full purchase-authority model (`spend-limit.ts`, `approval-policy.ts`, `purchase-approval.ts`, `purchase-constraint.ts`, `purchase-order-requirement.ts`) with real DB migrations. `tests/b2b-policy.test.ts` and `tests/b2b-threat-model.test.ts` (explicitly labeled "Gate 15") already cover cross-org rejection, inactive-membership rejection, spend-limit/approval-threshold decisioning, cross-tenant/cross-org IDOR, role escalation, and principal-binding spoofing — matching most of ADR-0010 §100-107's required test categories, at the unit-test level.

**What `baobab-trade`'s module does NOT do**: it has zero integration with `baobab-cp` (`canonical_organisation_id` is an unwired local column, not a live call) and zero integration with any real IAM-issued token or organization claim — its invitation/membership/role logic is fully self-contained and exercised only against locally-constructed test fixtures, not real tokens from `baobab-iam`.

**`baobab-cp`**'s `internal/domain/canonical.go` defines a generic, entity-type-agnostic `CanonicalEntity` (already used for `PRODUCT` and `SUPPLIER_ORGANISATION` per `internal/domain/entity_types.go`) with a full CRUD/lifecycle API (`api/canonical_handler.go`, `POST/GET /v1/canonical-entities`). No `BUYER_ORGANISATION`-equivalent entity type is registered — the infrastructure is ready to host one, but nothing does yet.

**Verdict:** this gate is mostly **cross-repo integration and gap-filling**, not building from scratch — the hard domain-logic and procurement-policy work already exists and is tested in `baobab-trade`. What's missing is specifically the IAM-side organization/invitation layer (this phase) and the wiring between it, `baobab-cp`'s canonical-entity registry, and `baobab-trade`'s already-built `canonical_organisation_id` field.

---

## 2. Gaps against ADR-0010

1. **No Keycloak Organizations feature anywhere** (§6 "IAM Organization Role") — **fixed in this PR** (§3).
2. **No `organization` OIDC claim available to any client** — **fixed in this PR** (§3).
3. **No `BUYER_ORGANISATION` canonical entity type in `baobab-cp`** (§5, §82 "Company Identity Mapping": `Keycloak Organization ID → CanonicalEntity ID → Trade BuyerOrganization ID`) — the middle link of this chain doesn't exist. Deferred to phase 2 (§4).
4. **No wiring between a Keycloak Organization and `baobab-trade`'s existing `canonical_organisation_id` field** — the column exists and is unpopulated by anything live. Deferred to phase 2 (§4).
5. **No invitation flow uses real IAM identity** — `baobab-trade`'s invitation machinery (`invitation_token_hash` etc.) is entirely local; ADR-0010 §28-33 describes a flow where invitation acceptance authenticates through IAM. Deferred to phase 3 (§4) — this is genuinely new integration work, not just wiring existing pieces, since it touches both the invitation UX (owned by `baobab-platform/zuribeans`, not attached to this session) and `baobab-trade`'s acceptance endpoint.
6. **No end-to-end cross-buyer isolation test driven by a real IAM token carrying an `organization` claim** — `baobab-trade`'s existing tests are thorough but self-contained (locally constructed fixtures, not real tokens). Deferred to phase 2/3 once the claim actually carries real organization membership.
7. **No `BUYER_ORGANISATION` verification/lifecycle state machine surfacing in IAM** — correctly, per §15-17, this SHALL NOT live in IAM at all; it's already correctly a `baobab-trade`-owned concern via `b2b-organisation.ts`'s status enum. Not a gap to fix here.

---

## 3. Phase 1 (this PR) — `baobab-iam`

- `config/realm/baobab-realm.json`: `organizationsEnabled: true`. Verified this is Keycloak's real realm-export field (`RealmRepresentation.organizationsEnabled`, `Type.DEFAULT` feature — always available, no server-level `--features` flag needed) by reading Keycloak's own source directly rather than assuming.
- `config/scopes/organization.json`: a new client scope carrying Keycloak's built-in `oidc-organization-membership-mapper` (claim name `organization`) — copied verbatim from a Keycloak-authored test fixture (`tests/base/.../acr-values-import-bug.json` in `keycloak/keycloak`) to avoid guessing at the protocol-mapper config shape.
- `config/clients/zuribeans-web.json`: `organization` added to `optionalClientScopes` (not default — per ADR-0010 §13, identity registration can precede company approval/membership, so the claim must be genuinely optional, and per §35 buyer-context selection is meant to be explicit rather than always-on).
- `tests/integration/run.sh` §13: verifies `organizationsEnabled=true` on the live realm, the `organization` scope exists with the correct mapper, `zuribeans-web` can request it, and — as a real end-to-end smoke test rather than config-shape checking alone — creates an actual Organization via the Admin API (`POST /admin/realms/baobab/organizations`), confirms `201`, then deletes it for idempotent re-runs.

**Deliberately not touched:** no `BUYER_ORGANISATION` canonical entity type in `baobab-cp` (phase 2), no wiring to `baobab-trade`'s `canonical_organisation_id` (phase 2), no invitation-flow changes anywhere (phase 3) — `baobab-trade`'s existing, already-tested invitation/membership/role logic is untouched.

---

## 4. Remaining phases (scoped, not yet implemented)

2. **`baobab-cp` — register `BUYER_ORGANISATION` and wire the mapping chain.** Add a `BUYER_ORGANISATION` entity type alongside the existing `PRODUCT`/`SUPPLIER_ORGANISATION` types in `internal/domain/entity_types.go`; establish the `Keycloak Organization ID → CanonicalEntity ID → Trade BuyerOrganization ID` mapping ADR-0010 §82 describes (reusing the existing `ExternalReference`/`Mapping` constructs per §85's own recommendation, not a bespoke table) so `baobab-trade`'s already-present `canonical_organisation_id` column has something real behind it.
3. **Real cross-buyer isolation tests against live tokens.** Once phase 2's wiring exists, extend `baobab-trade`'s already-thorough `tests/b2b-*.test.ts` suite (or add an integration-level test) to exercise the `organization` claim from a real IAM token rather than only locally-constructed fixtures — closing the gap between "unit-tested against fixtures" (already true today) and "proven against the real IAM→CP→Trade chain" (not yet true).
4. **Invitation flow through real IAM identity.** `baobab-trade`'s invitation acceptance today is fully local. Wiring it to real IAM registration/authentication (ADR-0010 §28-33) is `baobab-platform/zuribeans` frontend work plus a `baobab-trade` acceptance-endpoint change — out of reach without that repo attached; scoped here for whoever picks it up next.
5. **Company federation, JIT buyer provisioning** (§56-58) — explicitly "MAY... later" in the ADR; no current business requirement to build against.

Each phase gets its own PR, full local validation, and a check-in loop to green/merge before the next phase starts, matching the established Gate IAM-3 through IAM-5 discipline.

---

## 5. Required tests not yet covered

ADR-0010 §100-107's full cross-buyer/role/invitation/lifecycle/multi-org/supplier-separation test matrix is **already substantially covered** by `baobab-trade`'s existing `tests/b2b-policy.test.ts` and `tests/b2b-threat-model.test.ts` — this is not a gap this gate needs to fill from scratch, contrary to what the ADR's test section might suggest in isolation. What remains uncovered specifically is the *real-token* end-to-end path (§4 phase 3 above); the domain-logic correctness is not in question.
