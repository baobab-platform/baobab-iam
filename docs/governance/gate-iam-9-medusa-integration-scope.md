# Gate IAM-9 — Medusa Integration

**Status:** Mostly already satisfied by earlier gates. One real gap found and fixed — `baobab-platform/baobab-trade#71`. Remaining work (customer actor wiring) is blocked on Gate IAM-7's still-unresolved decision, not new to this gate.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0013 — MedusaJS Authentication Integration`
**Repositories:** `baobab-platform/baobab-iam` (OIDC client configuration — already complete for admin), `baobab-platform/baobab-trade` (Medusa OIDC provider, AuthIdentity, actor mapping), `baobab-platform/baobab-cp` (canonical identity, unaffected)
**Depends on:** Gate IAM-5 (workforce SSO — proved the exact integration pattern this ADR specifies), Gate IAM-7 (Thamani B2C — the customer-side blocker this gate shares)

The Consolidated Technical Specification's own one-line scope for this gate (§212) is: *"baobab-oidc provider, AuthIdentity mapping, customer actor, admin user actor, migration, negative tests, legacy credential retirement."* ADR-0013 is 146 sections describing, in detail, exactly the integration pattern Gate IAM-5 phase 2a already built and CI-verified.

---

## 1. Current state — most of this ADR is already satisfied

Reading ADR-0013 closely against what Gate IAM-5 already shipped shows this gate is substantially done already, not greenfield:

- **§2-4 (Medusa Auth Module as integration boundary, no fork)** — satisfied. Gate IAM-5 registered `@medusajs/auth-oidc`, Medusa's own official Auth Module provider, exactly as prescribed. No fork, no core modification.
- **§5 ("provider identifier such as `baobab-oidc`")** — the registered id is `"oidc"`, not literally `baobab-oidc`. The ADR itself allows "another explicitly versioned name"; `oidc` is descriptive and already proven in CI. Not worth renaming for its own sake — cosmetic, not a correctness gap.
- **§9-10 (customer actor / admin `user` actor)** — admin (`user`) actor is wired and CI-verified (Gate IAM-5). Customer actor is not — see §3 below.
- **§17, §24-27 (Authorization Code + PKCE, state, issuer/subject as the identity key)** — all handled by `@medusajs/auth-oidc` itself (verified directly against its source in Gate IAM-5's research): builds the authorization URL with PKCE S256 and a random `state`, validates `state`/`nonce` on callback, keys the `AuthIdentity` by `entity_id` derived from claims (`sub` by default), not email.
- **§29-31 (AuthIdentity ≠ CanonicalIdentity, actor binding via `app_metadata`)** — this is exactly how Medusa's own `generateJwtTokenForAuthIdentity` works (`entityId = authIdentity.app_metadata[actor_type + "_id"]`), confirmed by reading Medusa core's source directly.
- **§33-36 (admin JIT provisioning SHALL require explicit authorization, no login-equals-admin)** — **already safe, verified this session**: `OidcAuthService.validateCallback` never sets `app_metadata.user_id` — it only creates/updates the bare `AuthIdentity`. The resulting JWT's `actor_id` is empty unless a separate, already-governed Medusa mechanism (invite acceptance) has bound `app_metadata.user_id` first. A successful Keycloak login alone cannot make anyone a Medusa admin. `OidcAuthService.register()` even explicitly throws ("OIDC does not support registration") rather than offering a shortcut.
- **§12-13 (`authMethodsPerActor` configured explicitly)** — **was NOT satisfied until this gate**: Gate IAM-5 registered the `oidc` provider globally with no actor restriction. Confirmed directly against Medusa's own `auth-methods-per-actor.js`: *"Not having the config defined would allow for all auth providers for the particular actor."* This meant `oidc` was also implicitly reachable via `/auth/customer/oidc/*` despite no customer integration existing. **Fixed — `baobab-platform/baobab-trade#71`.**

---

## 2. What this gate actually needed to do

Given how much §1 was already correct, this gate's real, bounded contribution is `baobab-platform/baobab-trade#71`: adding `http.authMethodsPerActor` with `customer: ["emailpass"]` and `user: ["emailpass", "oidc"]` (derived from the already-registered provider list, not hand-duplicated). This is a small, precise, defense-in-depth fix — not a new integration.

---

## 3. What remains blocked (not new to this gate)

**Customer actor wiring (§9, §18, §64, §143)** is the one piece of ADR-0013 not yet implemented, and it's blocked on exactly the same open decision Gate IAM-7 already surfaced and deferred: does the customer OIDC redirect terminate at Medusa directly (mirroring the admin pattern) or at a Thamani-owned BFF (per ADR-0011 §9/§61 and ADR-0013 §18/§48's own "Thamani/BFF" step)? This gate doesn't add a new fork — it's the same one, now confirmed to matter for two ADRs (0011 and 0013), not just one. See `docs/governance/gate-iam-7-thamani-b2c-scope.md` §3.1 for the full reasoning; nothing here changes that analysis.

**Migration (§74-81, §119, §125)** — not applicable yet: there are no existing Medusa `emailpass` customers or admins with real production history to migrate in this codebase today (this is a greenfield build, not a system with legacy users). This section of the ADR is aspirational for a future point when real users exist under the old scheme; revisit if/when that's true.

**Negative/actor-confusion tests (§99, §127)** — largely inherent to Medusa's own route/actor-type separation (distinct `/admin/*` vs `/store/*` route trees, `actor_type` embedded in the JWT itself) rather than something this integration needs to add. Not independently verified end-to-end in this session (no live Keycloak+Medusa integration test environment available), but no gap was found either.

---

## 4. Remaining phases (scoped, not yet implemented)

1. **Resolve the shared Gate IAM-7/IAM-9 customer-OIDC-termination fork** — once decided, wire the `customer` actor the same way `user` already is (or build the BFF, per whichever option is chosen), and update `authMethodsPerActor.customer` accordingly.
2. **Migration tooling** — deferred until real legacy Medusa credentials exist to migrate.
3. **Live negative-test verification** — once a real Keycloak+Medusa integration test environment exists (this session has neither Docker nor a live IAM+Trade stack together), add the §120-127 test categories against real tokens rather than relying on source-level verification.

---

## 5. Why this gate is mostly a documentation exercise

Gate IAM-5 already built the substance of this ADR without knowing this ADR number existed — the two describe the same underlying integration pattern from different angles (workforce SSO vs. Medusa-specific mechanics). Re-verifying that overlap against ADR-0013's specific claims, rather than re-implementing what already works, is the correct use of this gate's effort; the one genuine gap found (`authMethodsPerActor`) is fixed.
