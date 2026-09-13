# Gate IAM-7 — Thamani B2C

**Status:** The full customer-identity gate remains scoped, not implemented — the two genuine architectural decisions in §3 still block it. However, `nabhold/zuribeans`'s **"ZuriBeans Go-Live Implementation Plan"** (its master cross-repo implementation plan) names a narrower, unblocked deliverable that touches this gate: Gate ZB-03 ("IAM and Isolation") lists **"Thamani ≠ ZuriBeans"** as a mandatory isolation test, provable today without resolving §3.1/§3.2. That structural isolation proof is now done — see §6.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0011 — Thamani B2C Customer Identity`
**Repositories:** `nabhold/baobab-iam` (customer OIDC client, owner), `nabhold/baobab-cp` (canonical identity mapping), `nabhold/baobab-trade` (Medusa customer actor, order/cart ownership), `nabhold/thamani` (customer frontend UX)
**Depends on:** Gate IAM-3 (canonical identity spine), Gate IAM-5 phase 2a (proved the `@medusajs/auth-oidc` module pattern this gate would reuse for the `customer` actor type)

The Consolidated Technical Specification's own one-line scope for this gate (§210) is: *"customer OIDC, guest flow, Medusa customer mapping, social login readiness, guest-to-account conversion, recovery, customer isolation."* ADR-0011 is 132 sections; this document scopes discovery and phase 1 planning only, since the two genuinely open design questions found below (§3) block a confident implementation.

---

## 1. Current state (verified against source, 2026-09-12)

**`baobab-iam`** already has `thamani-web` (public, PKCE S256, `standardFlowEnabled`, `actor-type-human` scope, redirect to `localhost:3001`) and `thamani-backend-workload` (confidential client-credentials workload client) from earlier scaffolding — neither was touched or added in this gate. No customer-specific scope/claim exists yet (nothing analogous to Gate IAM-6's `organization` scope is needed here per ADR-0011 — customer identity doesn't need an equivalent claim).

**`baobab-trade`** has real, tested order/resource-isolation logic already: `src/baobab/thamani/customer/authorization.ts` implements `assertOwnCustomerResource` (session-ownership check, rejects cross-customer access and unowned/guest resources) and `verifyGuestOrderLookup` (guest order lookup by `displayId`+email, both-mismatches-collapse-to-one-error to resist order-number enumeration, citing ADR-0017 §102). `tests/thamani-customer-authorization.test.ts` and `tests/thamani-customer-anonymisation.test.ts` cover ownership/IDOR/enumeration-resistance and GDPR-style anonymisation respectively. `medusa-config.ts` registers `@medusajs/auth-oidc` for the workforce/admin (`user`) actor type only (Gate IAM-5 phase 2a) — **nothing is registered for the `customer` actor type.** No guest-to-account conversion or order-claiming logic exists anywhere (`policy.ts`'s `resolveCheckoutMode`/`assertConsumerCustomer` handle checkout-mode selection and B2B-membership guarding, not claiming).

**`baobab-cp`** needs no new construct: `internal/domain/identity.go` already documents that a Medusa customer maps via the same generic `Mapping`/`ExternalReference` machinery Gate IAM-3 built for `CanonicalIdentity`/`ExternalIdentity` — it explicitly names "Medusa customer" as a future example actor. This is ready to use as-is.

**`nabhold/thamani`** (newly attached to this session to resolve §3's question) is a real, actively-scaffolded Next.js 16 app (catalogue/cart/checkout-gate vertical slice, its own ADRs, CI, tests) but has **zero** authentication code: no login/account/callback routes, no session-cookie handling, no PKCE/token logic, and no reference anywhere to `thamani-web`, OIDC, or Keycloak. Its own docs (`SECURITY.md`, `docs/medusa-integration.md`, `docs/adr/0002-supplier-onboarding-portal.md`) consistently describe authentication as something "governed by their owning engines" that Thamani will consume once those engines "publish contracts" — not something it plans to implement itself.

---

## 2. Gaps against ADR-0011

1. **No customer-actor OIDC wiring in `baobab-trade`** (§7-9) — blocked on §3.1 below.
2. **No guest-to-account conversion / order-claiming logic** (§23-24, §110, §131) — blocked on §3.2 below.
3. **No social login configured** (§41-44) — reasonably deferred until customer OIDC itself (gap 1) is wired, since social providers broker through the same Keycloak OIDC boundary.
4. **No customer MFA/passkey policy** (§54-57) — explicitly ADR-0015/Gate IAM-11 territory per the ADR's own text, not this gate.
5. **Order/resource isolation, anonymisation:** **not a gap** — already correctly implemented and tested in `baobab-trade` (§1).

---

## 3. Two decisions blocking implementation

### 3.1 Where does the customer OIDC redirect terminate?

ADR-0011 §9's own flow diagram shows the authorization code landing at **"Thamani / BFF"** as a distinct step *before* a separate "Medusa customer mapping" step, and §61 explicitly recommends a BFF for higher-value deployments "where it materially reduces browser token exposure." That points toward Thamani's own Next.js app owning the redirect.

But `nabhold/thamani`'s current state points the other way: it has no BFF/callback scaffolding at all, and its own docs consistently treat authentication as belonging to "owning engines" (`baobab-iam`/`baobab-trade`), not something it builds itself. Mirroring Gate IAM-5 phase 2a's proven pattern (Medusa's own `@medusajs/auth-oidc` module handling the full browser redirect for the `user` actor) would extend cleanly to a `customer` actor registration too — but doing so would require **changing `thamani-web`'s already-registered redirect URI** from Thamani's own frontend origin (`localhost:3001`) to Medusa's backend origin (`localhost:9000`), a change with real consequences if wrong.

**Decision (2026-09-12, explicit check-in): deferred.** Neither option was implemented. This needs either a `nabhold/thamani` architecture decision (does it become a BFF?) or explicit confirmation that Medusa should own the redirect, before `thamani-web`'s client config or `baobab-trade`'s `medusa-config.ts` should change.

### 3.2 How is a guest order's claim proof delivered and verified?

ADR-0011 §24 requires additional proof beyond email match before attaching a historical guest order to a new account — e.g. "possession of a secure order claim secret." Implementing this well requires deciding: where a claim token is generated and persisted (a new field/table, analogous to the B2B module's `invitation_token_hash`, which itself has no generation/hashing service code yet — only a schema column), and how the guest receives it (presumably at checkout, via a notification mechanism this session doesn't own). This is real design work, not a pure function to add alongside the existing `verifyGuestOrderLookup` — building it without those decisions risks inventing a persistence/delivery mechanism that doesn't match how checkout notifications actually work in this platform.

**Decision (2026-09-12): deferred**, for the same reason phase 2b's custom Payload OIDC strategy was deferred in Gate IAM-5 — this is net-new design and persistence work, not configuration of something already proven, and deserves its own focused pass rather than being rushed alongside a scoping session.

---

## 4. Remaining phases (scoped, not yet implemented)

1. **Resolve §3.1** — likely needs a `nabhold/thamani` design decision, then either wire `@medusajs/auth-oidc` for the `customer` actor (if Medusa owns the redirect) or build BFF callback/session code in `nabhold/thamani` (if it does) — mirroring whichever of Gate IAM-5's two patterns (official-module configuration vs. custom `openid-client` build) applies.
2. **Resolve §3.2** — design a guest-order-claim token mechanism (generation, storage, expiry, single-use, delivery), then implement claim verification in `src/baobab/thamani/customer/authorization.ts` alongside the existing `verifyGuestOrderLookup`.
3. **Social login** (§41-44) — once phase 1 lands, add Keycloak identity-provider brokering (Google/Apple/etc.) — a Keycloak IdP-broker config task, not a code change, matching this repo's existing `config/` conventions.
4. **Canonical identity mapping wiring** — no new construct needed in `baobab-cp` (§1), but the actual `Mapping`/`ExternalReference` row creation for a real Thamani customer needs the JIT-provisioning flow ADR-0011 §30-32 describes, which depends on phase 1 existing first.

Each phase gets its own PR, full local validation, and a check-in loop to green/merge before the next phase starts, matching the established Gate IAM-3 through IAM-6 discipline.

---

## 5. Why this gate has no code changes (beyond §6)

Gate IAM-4 (workload identity) and Gate IAM-6 (Zuribeans B2B) both found concrete, unambiguous gaps fixable within a single bounded PR. Gate IAM-7's remaining gaps both turn on genuine architectural decisions this session correctly identified rather than guessed past — matching Gate IAM-5's phase 2b precedent (the CMS custom-OIDC-strategy deferral). Scoping and documenting the fork, rather than picking an answer and building on it, is the correct phase-1 outcome here.

---

## 6. "Thamani ≠ ZuriBeans" structural isolation — **Done**

`nabhold/zuribeans`'s master implementation plan (4,437-line ADR, "ZuriBeans Go-Live Implementation Plan — Multi-Market B2B Cross-Border Trading") sequences the whole cross-repo programme into 30 numbered gates (ZB-00 through ZB-29). Its **Gate ZB-03 ("IAM and Isolation")** requires several capabilities (workforce SSO, buyer organisations, supplier identities, Control Plane context, etc. — most blocked on Control Plane completion, ZB-02, which is not done) and lists seven mandatory tests, one of which is exactly: `Thamani ≠ ZuriBeans`.

This is provable today, independent of every other ZB-03 blocker, because it doesn't need a Control-Plane-issued canonical tenant id for either estate (neither exists yet) — it needs only what's already true structurally: `thamani-web`/`thamani-backend` and `zuribeans-web`/`zuribeans-backend` are fully independent registered Keycloak clients. This also deliberately does **not** touch §3.1/§3.2 above — no customer-facing login flow for either estate was built or assumed.

Two things worth noting from what verification against a real Keycloak 26.7.3 instance found:

- **No `tenant_id` claim exists on any token today** (workload or human) — confirmed by decoding real client-credentials tokens for both `zuribeans-backend` and `thamani-backend`. This isn't a gap to rush shut here: ADR-0006 §33-34 ("Platform Context Claims", "Tenant Claim Policy") deliberately discourages relying on a JWT tenant claim as the authorization boundary at all ("the default architecture SHALL not depend on such claims for mutable authorization"), and minting a placeholder-but-plausible-looking `tn_zuribeans`/`tn_thamani` value now would risk being mistaken for a real Control-Plane-issued canonical id later (`baobab-cp`'s actual tenant ids are opaque, e.g. `tn_01k4...`, not human-readable slugs) — the same "don't invent a parallel authority" discipline this session has applied everywhere else (CMS's `isProjection: true`, ADR-0015's "never invent Medusa IDs").
- **`zuribeans-backend` and `thamani-backend` now get distinct secrets.** All other workload clients still share one literal `BOOTSTRAP_WORKLOAD_CLIENT_SECRET` value (`scripts/bootstrap.sh`, for CI/local reproducibility — unchanged, since they're all platform services inside one security boundary today). These two are the exception: since they represent different *tenants*, `bootstrap.sh` seeds each with the shared seed suffixed by its own `client_id` instead of the identical literal string. This was itself a review finding on this gate's PR — the first version of this proof relied on `azp`/`sub` alone, which only describes a token that was already successfully issued and doesn't rule out one estate's secret authenticating as the other's `client_id`. With distinct secrets, that cross-credential rejection is now a real, meaningful assertion rather than one testing a false premise.

`tests/integration/run.sh` §20-21 add eight checks, all verified passing against a real instance (including sanity checks that deliberately broke `thamani-web`'s redirect URI registration and `thamani-backend`'s secret-distinctness, and confirmed each test would have caught the regression):

1. ZuriBeans' and Thamani's workload tokens each carry their own `azp` (the actual discriminator, since both share the same `aud`).
2. The two workload clients resolve to distinct `sub` values.
3. `zuribeans-backend`'s `client_id` paired with `thamani-backend`'s secret is rejected (401), and the reverse — proving one estate's workload credential cannot authenticate as the other's client.
4. `thamani-web` requesting `zuribeans-web`'s registered redirect URI is rejected by Keycloak itself (400); `thamani-web` requesting its own redirect URI is accepted (302).
5. The mirror of (4): `zuribeans-web` requesting `thamani-web`'s registered redirect URI is rejected (400); `zuribeans-web` requesting its own redirect URI is accepted (302).

**What this does not prove**: real customer login for either estate, or resource-level isolation inside `baobab-trade`/`baobab-cp` (a Thamani-authenticated actor being rejected from a Zuribeans-tenant-scoped resource) — that depends on Control Plane's canonical tenant/organisation model (ZB-02) and is that gate's, not this one's, responsibility.
