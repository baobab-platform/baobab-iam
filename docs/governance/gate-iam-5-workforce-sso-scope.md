# Gate IAM-5 — Workforce SSO

**Status:** Phase 1 complete. Phase 2a (`baobab-trade` OIDC wiring) complete — `nabhold/baobab-trade#70`. Phase 2b (`baobab-cms` OIDC wiring) complete — `nabhold/baobab-cms#9` — see §5.1. Phase 3 (`baobab-cp` workforce membership model + role-aware admin authorization) complete — `nabhold/baobab-cp#104` — see §5.3. Phase 5 (MFA/step-up) complete — see §5.5. Phase 6 (break-glass) complete — see §5.6. Remaining: access review/audit correlation (§96-101) — see §5.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0009 — Workforce SSO and Privileged Access`
**Repositories:** `nabhold/baobab-iam` (workforce SSO clients, owner), `nabhold/baobab-cp` (canonical identity, CP administration), `nabhold/baobab-cms`, `nabhold/baobab-trade`, `nabhold/baobab-erp`, `nabhold/baobab-pulse` (engine admin surfaces)
**Depends on:** Gate IAM-3 (canonical identity spine — complete), Gate IAM-4 (workload identity — complete)
**Out of scope (this phase):** MFA/step-up policy mechanics (ADR-0015, Gate IAM-11), identity lifecycle/deprovisioning automation (ADR-0016, Gate IAM-12), audit/observability wiring (ADR-0017, Gate IAM-13-ish) — ADR-0009 itself defers these ("exact assurance policy will be refined in ADR-0015", §39/§82).

The Consolidated Technical Specification's own one-line scope for this gate (§208) is: *"Integrate: Nabhold digital estate, CP administration, CMS admin, Pulse admin, Trade admin with central workforce authentication."* ADR-0009 is 125 sections covering the full workforce/privileged-access programme (SSO, privilege segregation, joiner/mover/leaver, break-glass, executive access, audit). This document scopes Gate IAM-5 to the SSO integration surface specifically, consistent with how Gate IAM-4 scoped ADR-0007 to workload identity rather than every downstream capability-entitlement concern.

---

## 1. Current state (verified against source, 2026-09-11)

A discovery pass across all five engine repos, cross-checked directly against code (not summaries):

**`baobab-iam`** has no workforce/admin SSO client at all before this PR — only bearer-only engine resource-server clients (`baobab-control-plane`, `baobab-cms`, `baobab-trade`, `baobab-erp`, `baobab-pulse`, all `bearerOnly: true`, `standardFlowEnabled: false`, no redirect URIs), the `*-workload.json` service-account clients (Gate IAM-4), and two B2C browser clients (`thamani-web`, `zuribeans-web`, `standardFlowEnabled: true` + PKCE). No client anywhere is set up for an administrator to actually log in. No realm roles are defined (`config/realm/baobab-realm.json` had no `roles` key at all).

**`baobab-cp`** is API-only (no frontend of its own anywhere in the repo). `internal/auth/oidc.go`'s `Verify()` only ever accepts/produces `actor_type ∈ {human, workload}` (line ~71) — matching `internal/domain.Principal`'s own `validPrincipalActorTypes = {human, workload, external}` (`internal/domain/identity.go`). But `api/router.go` gated every admin route (`/v1/tenants*`, `/v1/entitlements`, `/v1/canonical-entities*`, `/v1/capabilities/explain`) on `principal.ActorType == "admin"` — a literal value `Verify()` can never produce. **This meant every admin-gated route in `baobab-cp` has been unreachable by any real IAM-issued token since it was written**, exactly the same class of defect as Gate IAM-4 phase 4's workload-tenant gap: every existing test hand-constructed a synthetic `auth.Principal{ActorType: "admin", ...}` bypassing the verifier entirely, so the bug was invisible to the test suite. **Fixed in this PR** (§4). No CP admin role/permission model exists otherwise — authorization is flat OAuth2 scopes only (`tenant:write`, `canonical:write`, etc.), no RBAC table.

**`baobab-cms`** (Payload CMS 3.x) uses Payload's built-in local email/password auth with no `auth.strategies` customization. The `Users` collection already isolates authorization from the concrete auth mechanism via a `ContextActor` structural interface (`docs/identity/README.md` explicitly anticipates SSO as a future `auth.strategies` addition, and states this needs no change to `src/baobab/context`/`authorization`). Clean, low-risk integration point once phase 2 wires it up. No OIDC/SSO plugin dependency exists yet.

**`baobab-trade`** (Medusa v2.20.1) runs Medusa's default `emailpass` admin auth with zero customization — confirming Gate IAM-0's original finding still holds. Medusa v2 ships `@medusajs/auth-oidc` (backed by `openid-client`) as a first-party, already-available auth-provider module; it is simply not configured in `medusa-config.ts`. This is the lowest-effort real integration target for phase 2 — no bespoke OIDC client code needs to be written, only the provider needs enabling and pointing at Keycloak.

**`baobab-pulse`** has no admin UI or console of any kind (confirmed: no `admin`/`console` paths, no frontend directory) and no authentication layer at all, human or machine. It is explicitly out of this phase's scope — there is nothing to integrate SSO with yet. Revisit once Pulse grows an operator-facing surface.

**`baobab-erp`** is not part of this gate's explicit scope per the Consolidated Spec's §208 line (ERP SSO is `ADR-0014`/Gate IAM-10's concern) and was not re-investigated here.

---

## 2. Gaps against ADR-0009

1. **No distinct workforce admin client registrations** (§9-10) — fixed in phase 1 for CP/CMS/Trade (§4).
2. **No workforce role namespace** (§102-103) — fixed in phase 1: a starter realm-role catalog (§4).
3. **`baobab-cp`'s admin routes were unreachable by any real human token** (§3, §93 — "IAM login succeeds but application access denied" is expected only when authorization is correctly evaluated, not when the actor-type check itself is unsatisfiable) — fixed in phase 1 (§4).
4. **No actual SSO wiring in any engine's admin UI** (§6) — **closed.** Trade (phase 2a, `nabhold/baobab-trade#70`) and CMS (phase 2b, `nabhold/baobab-cms#9`) are both wired now; `baobab-cp` has no admin console of its own yet to wire, and `baobab-pulse` has no admin surface at all (§1).
5. **No CP admin role model beyond flat scopes** (§14-16) — the new `cp:platform-admin`/`cp:tenant-admin` realm roles (§4) give IAM-side vocabulary, but nothing in `baobab-cp` yet maps a workforce token's roles into scoped authorization decisions beyond the existing flat per-route scopes. Deferred to phase 3 (§5).
6. **MFA is not enforced for any client, privileged or not** (§37-40) — deferred to ADR-0015/Gate IAM-11 per ADR-0009's own text.
7. **No joiner/mover/leaver process, break-glass mechanism, or access-review tooling** (§29-36, §53-67) — joiner/mover/leaver and break-glass are now closed (§5.3, §5.6); access-review tooling remains deferred.
8. **No audit correlation for privileged actions** (§96-101) — deferred to ADR-0017/Gate IAM-13-ish.

---

## 3. Architectural note: "admin" was never a real actor type

The `baobab-cp` defect in §1/§2.3 is worth stating plainly because it's easy to miss: this was not a missing feature, it was a self-inconsistency already present in the codebase. `internal/domain/identity_test.go`'s own `TestPrincipalValidateRejectsUnknownActorType` explicitly asserts `"admin"` is an *invalid* canonical actor_type (only `human`/`workload`/`external` are valid) — the same file that defines the correct vocabulary also (in a different package, `api/router.go`) violated it. ADR-0009 §3's core principle — "one workforce identity does not mean one universal workforce privilege" — is exactly the fix's shape: a workforce user authenticates as `actor_type=human` like anyone else; scope/role claims, not a separate magic actor type, are what admin routes should (and, after this PR, do) gate on.

---

## 4. Phase 1 (this PR)

**`baobab-iam`:**
- Three new distinct workforce SSO clients (ADR-0009 §9's own naming examples): `baobab-control-plane-admin` (public + PKCE S256 — `baobab-cp` has no session/cookie layer of its own, so its eventual admin console authenticates directly against Keycloak the same way `thamani-web`/`zuribeans-web` already do, then presents the access token as a Bearer credential), `baobab-cms-admin` and `baobab-trade-admin` (both confidential — Payload and Medusa's admin auth both run server-side and can hold a client secret). All three: `standardFlowEnabled: true`, `actor-type-human` default scope, distinct from and additional to the pre-existing bearer-only engine clients (§9-10's "no universal admin client" + independent redirect URIs/audiences/revocation).
- A starter workforce realm-role catalog in `config/realm/baobab-realm.json` (§102-103's namespaced naming: `iam:security-admin`, `iam:helpdesk`, `cp:platform-admin`, `cp:tenant-admin`, `trade:operator`, `cms:editor`, `cms:publisher`) — deliberately small and directly traceable to ADR-0009's own named examples rather than attempting to enumerate every conceivable role (§104's role-explosion warning). None are added to `defaultRoles` (§13 least privilege, §87-88 no privileged JIT provisioning).
- `tests/integration/run.sh` §11-12: the new admin clients are provisioned as distinct SSO-capable (not bearer-only) registrations with PKCE and the `actor-type-human` scope, alongside (not replacing) their engine counterparts; the new realm roles exist and none of them leak into `default-roles-baobab`.

**`baobab-cp`:**
- `api/router.go`: every `a.authorize(a.adminVerifier, "admin", ...)` call now requires `"human"` — the actor type real workforce tokens actually carry — instead of the never-producible `"admin"` literal. Scope-per-route gating (`tenant:write`, `canonical:write`, `capabilities:explain`, etc.) is unchanged.
- `api/capability_explain_handler.go`: its own separate inline `principal.ActorType != "admin"` check fixed the same way.
- Test fixtures in `api/router_test.go` and `api/capability_explain_handler_test.go` updated from a synthetic `ActorType: "admin"` to `ActorType: "human"`, matching what `Verify()` can actually produce; `TestCapabilityExplainHandlerRejectsNonAdmin`'s workload-principal negative case is untouched and still passes, confirming actor-type separation still holds.
- `go build`, `go vet`, `gofmt -l`, `go test -race ./...` all green.

**Deliberately not touched:** no OIDC wiring inside `baobab-cms` or `baobab-trade` themselves (phase 2), no CP-side role-to-scope mapping (phase 3), no MFA/step-up configuration (ADR-0015/Gate IAM-11).

---

## 5. Remaining phases (scoped, not yet implemented)

2a. ~~**`baobab-trade` — real OIDC wiring.**~~ **Done — `nabhold/baobab-trade#70`.** Enabled Medusa's bundled `@medusajs/auth-oidc` provider in `medusa-config.ts` pointed at `baobab-trade-admin` — no bespoke client code, only configuration (registering `@medusajs/medusa/auth` explicitly, with `emailpass` kept alongside the new conditional `oidc` entry so nothing regresses when `BAOBAB_IAM_OIDC_ISSUER` is unset). `npm run format:check`/`lint`/`typecheck`/`test`/`build` all green, `build` exercised in both the SSO-enabled and SSO-disabled configurations.

### 5.1 `baobab-cms` — real OIDC wiring — **Done, `nabhold/baobab-cms#9`**

Unlike Trade, Payload CMS has no official or community OIDC auth-provider plugin (checked directly against the npm registry — nothing matching `payload`+`oidc`/`sso`/`keycloak` exists). This phase was originally deferred (2026-09-11 check-in) specifically because it meant writing net-new security-critical authentication code — PKCE/state/nonce handling, token exchange, ID-token verification, session issuance — rather than configuring an already-audited module, and that risk profile deserved its own dedicated pass rather than being rushed alongside phase 1/2a.

That dedicated pass is now complete. Built directly on `openid-client` (the same library Medusa's own official module uses): `/api/oidc/login`/`/api/oidc/callback` as Payload `Endpoint`s, a signed httpOnly transaction cookie carrying PKCE's `code_verifier` (never the `state` param, which would defeat PKCE's interception protection), full `authorizationCodeGrant()` validation (state/PKCE/nonce/ID-token signature via the discovered JWKS), and identity matching by `Users.ssoSubject` (`"{issuer}#{sub}"`, never email alone — the exact rule Gate IAM-10 found iDempiere's own plugin deviating from). Every subsequent request is authenticated by Payload's existing, unmodified JWT strategy — no custom `auth.strategies` implementation was needed after all, since OIDC only runs once at login to mint an ordinary Payload session via the same primitives (`addSessionToUser`/`getFieldsToSign`/`jwtSign`/`generatePayloadCookie`) Payload's own local-auth login handler uses.

Two real, review-caught bugs were fixed before merge, both verified against a real local Postgres instance installed specifically to check rather than guess: (1) auto-provisioning a brand-new SSO user called `payload.create()` with no password, which Payload's local-auth strategy requires unconditionally and would have rejected every first-time SSO login — fixed with a generated, never-disclosed password; (2) the new `ssoSubject` column had no committed migration — generated and applied for real, including finding and fixing a broken import in Payload's own migration-generator output. **Not built this phase** (documented in `baobab-cms`'s `docs/identity/README.md`): a login-page UI link (the URL works when navigated to directly; wiring it into Payload's admin login screen needs an import-map rebuild no live instance here could verify) and Keycloak-side logout integration (a local Payload logout doesn't end the Keycloak session).

3. ~~**`baobab-cp` — role-aware admin authorization.**~~ **Done, together with item 4 — `nabhold/baobab-cp#104`.** See §5.3.
4. ~~**Workforce membership model in `baobab-cp`** (§27-28)~~ **Done — `nabhold/baobab-cp#104`.** See §5.3.
5. ~~**MFA/step-up**~~ **Done.** See §5.5. (ADR-0015/Gate IAM-11 already covers *mandatory* MFA for privileged roles; this closes ADR-0009 §41-45's separate *on-demand* step-up requirement, which applies regardless of role.)
6. ~~**Break-glass**~~ **Done.** See §5.6. Access review and audit correlation (§96-101) remain deferred — ADR-0017/Gate IAM-13-ish territory.
7. **`baobab-pulse` admin surface** — revisit once Pulse has an operator-facing console to integrate; nothing to wire today.
8. **`baobab-erp`** — owned by Gate IAM-10 (`ADR-0014`), not this gate.

Each phase gets its own PR, full local validation, and a check-in loop to green/merge before the next phase starts, matching Gate IAM-3/IAM-4's discipline.

### 5.3 `baobab-cp` — workforce membership model and role-aware admin authorization — **Done, `nabhold/baobab-cp#104`**

Adds `domain.WorkforceMembership` (ADR-0009 §27: `CanonicalIdentity → WorkforceMembership → {LegalEntity, Tenant, status}`), with in-memory and PostgreSQL repository implementations (new migration `000032_workforce_membership.sql`, `identity.workforce_membership` with `UNIQUE(principal_id, tenant_id)` so a mover changes an existing row rather than accumulating privilege per §31-32) — deliberately with **no auto-provisioning path**, matching this gate's phase-1 no-privileged-JIT-provisioning precedent (§29, §87-88): membership is always created via an explicit joiner action, never materialized just because a token happened to resolve.

`auth.Principal` now carries `Roles`, parsed from the Keycloak `realm_access.roles` claim phase 1's `cp:platform-admin`/`cp:tenant-admin` realm roles already populate. A new `requireAdminRole` middleware in `api/router.go` gives those roles actual authorization teeth: `cp:platform-admin` authorizes any tenant unconditionally; `cp:tenant-admin` authorizes a request only if the caller has an **ACTIVE** `WorkforceMembership` for the specific tenant the request targets, resolved read-only from the verified token's issuer+subject (never JIT-provisioned, same principle as above). Routes with no tenant of their own to scope against — tenant creation, canonical entities, capability diagnostics — are platform-admin only, since there is no tenant yet (or ever) for a `cp:tenant-admin` membership to match.

`go build`/`go vet`/`gofmt -l`/`go test -race ./...` all green, including a real-PostgreSQL-backed integration test for the new migration (found and fixed a real bug in the process: the new migration file existed on disk but was not registered in `internal/store/postgres/migrate.go`'s explicit `canonicalMigrationNames` list, so `ApplyMigrations` would have silently never applied it in any environment) and 9 positive/negative authorization test cases for `requireAdminRole`.

### 5.5 MFA/step-up — **Done**

Gate IAM-11 (ADR-0015) already made MFA *mandatory* for every role compositing `iam:mfa-required` — that is a standing property of the account, checked at every login. ADR-0009 §41-45 asks for something additionally: certain **sensitive actions** (grant platform-admin, change IAM policy, reset another administrator's MFA, high-risk financial transactions, etc.) SHALL be able to demand stronger or more recent authentication *on demand*, regardless of the acting account's standing role — a relying party decides a specific request needs elevated assurance, not IAM deciding it up front for an entire account.

Implemented as a new Keycloak authentication subflow, `Baobab - Step-Up`, wired into `Baobab browser` as a `CONDITIONAL` execution alongside (not replacing) Gate IAM-11's existing `Baobab - Privileged MFA` subflow: a `Condition - Level of Authentication` executor (`loa-condition-level: 2`, `loa-max-age: 300`) followed by an OTP re-entry, firing only when a relying party has requested the `gold` ACR (LOA 2, declared via the new realm attribute `acr.loa.map: {"silver":1,"gold":2}`) and the session hasn't satisfied it within the last 5 minutes (ADR-0009 §44's "authentication within N minutes"). Because the condition is independent of `iam:mfa-required`, **any** authenticated user can be challenged, and an existing SSO cookie session does not by itself satisfy it — exactly ADR-0009 §42's flow (`authenticated → requests sensitive action → app detects required assurance → Baobab IAM step-up → higher assurance established → authorization → action`).

A relying party (`baobab-cp`, an engine) requests step-up by redirecting to the authorization endpoint with `acr_values=gold` (or the equivalent `claims` parameter) before performing a sensitive action, and verifies the returned token's `acr` claim equals `gold` (ADR-0009 §43's OIDC assurance information) before authorizing the action — no relying-party-side code exists for this yet in any engine; that is each engine's own future work when it has a sensitive action to gate, matching how this gate has consistently scoped IAM-side plumbing separately from each engine's use of it.

Verified against a real Keycloak 26.7.3 instance (downloaded and run directly via `kc.sh`/`kcadm.sh`, matching `scripts/bootstrap.sh`'s own realm-import command, since this sandbox has no working Docker daemon for the full `docker-compose` stack) rather than assumed: the realm imports cleanly, the flow/condition/config structure round-trips exactly as authored via the Admin API, and a first import attempt caught a real bug — the flow's initial description text exceeded Keycloak's authentication-flow `description` column limit and made realm import fail outright with a generic "Database operation failed" (no exception logged at any level), found only by bisecting the diff against a known-good import, not by reading an error message. `tests/integration/run.sh` §19 adds four structural checks (the same admin-API assertions run during this manual verification): `acr.loa.map` declares `gold` as LOA 2, the `Baobab - Step-Up` subflow is wired into `Baobab browser`, it contains the Level-of-Authentication condition, and that condition demands LOA 2. As with Gate IAM-11's own MFA subflow, an actual browser-driven login being challenged end-to-end cannot be exercised in this repo's CI (no headless-browser tooling, and every workforce admin client has `directAccessGrantsEnabled: false`).

### 5.6 Break-glass — **Done**

ADR-0009 §53-58 asks for a controlled, rarely-used, separately-stored, monitored, audited, rotated-after-use emergency access mechanism for when normal privileged IAM access is itself unavailable (configuration failure, federation outage, administrative lockout). Rather than building a bespoke emergency-token mechanism — which ADR-0009 §56 and ADR-0018 §221 both specifically warn against as an ungoverned bypass — this reuses a separation Keycloak already provides: the **master realm's bootstrap administrator**, entirely distinct from the `baobab` realm's own governed, SSO-authenticated, MFA-enforced administrators.

This is documented, not built — the mechanism already exists (`KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD` in `docker-compose.yml`, used non-interactively by `scripts/bootstrap.sh`), and ADR-0009's own break-glass requirements are almost entirely procedural (approval before use, rotation after use, audit review) rather than application code. New: `docs/operations/break-glass-runbook.md`, a third runbook alongside the existing security-incident and disaster-recovery runbooks, covering exactly the scenario neither of those two assumes possible — that the `baobab` realm's own admin path itself is unusable.

One fact in that runbook was verified empirically against a real Keycloak instance rather than assumed: an action taken against the `baobab` realm by a master-realm-authenticated token (i.e., break-glass use) is captured in `baobab`'s own existing `admin-events` audit trail (Gate IAM-13's mechanism, already enabled in `config/realm/baobab-realm.json`) with no new code needed — distinguishable from a routine governed-admin action by `authDetails.realmId` on the event (master's realm id instead of `baobab`'s own). The runbook documents the exact query this gives an incident reviewer.

---

## 6. Required tests not yet covered

ADR-0009 §108-111's full test list (SSO cross-application, MFA, separation-of-duties, lifecycle, cross-tenant, break-glass, offboarding, access-review) is aspirational for the *whole* gate. Phases 1-3/5-6 (§4, §5.3, §5.5, §5.6) now cover: distinct client registration, PKCE/actor-type-human wiring, least-privilege role provisioning, workforce membership CRUD and tenant-scoped role-aware authorization (with a real-Postgres-backed test), on-demand step-up configuration (verified against a real Keycloak instance), and a documented, mechanism-verified break-glass procedure. Still not covered: end-to-end browser-driven login flows (no headless-browser tooling in this repo's CI, same limitation Gate IAM-11 already documented), access-review tooling, and audit correlation across privileged actions (§96-101, deferred to ADR-0017/Gate IAM-13-ish). This is recorded explicitly rather than silently, per this session's established documentation discipline (see Gate IAM-4's scope doc §6-8 for the same pattern).
