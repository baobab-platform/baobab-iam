# Gate IAM-3 (remainder) — CanonicalIdentity / ExternalIdentity Layer, Scope

**Status:** Complete — all 6 phases implemented and merged (see §3)
**Date:** 2026-09-10 (scoped, decided, and implemented in the same session)
**Governing ADR:** `ADR-0004 — Canonical Identity and External Identity Mapping`
**Repositories:** `baobab-platform/baobab-cp` (runtime owner), `baobab-platform/shared` (contract owner), `baobab-platform/baobab-iam` (authentication subject)
**Depends on:** Gate IAM-0 discovery (R-3, now fixed in `baobab-platform/baobab-cp#63`); ADR-0003, ADR-0005

This document scopes the second half of Gate IAM-3: introducing a real `CanonicalIdentity`/`ExternalIdentity(issuer, subject)` layer. It records what already exists, what's missing, and two decisions that needed to be made before implementation could start, per ADR-0004 §75 ("do not implement duplicate concepts if existing CP entities already fulfil these roles"). Both decisions were made (§2), and all 6 phases of the resulting plan (§3) have since been implemented and merged into `baobab-platform/baobab-cp` across PRs #64-#71 — see each phase's row in §3 for its PR and what it delivered.

---

## 1. What already exists (verified against source)

**Wire contracts already match the ADR almost exactly** — `baobab-platform/shared` doesn't need new schemas, just Go implementations of what's already there:

| ADR-0004 concept (§3, §6, §75) | Existing contract | Match |
|---|---|---|
| `CanonicalIdentity{id, actor_type, status, created_at, updated_at}` | `contracts/identity/v1/principal.schema.json` | Field-for-field identical (named `Principal`, not `CanonicalIdentity` — kept as `Principal`, see Decision 1) |
| `ExternalIdentity{id, canonical_identity_id, issuer, subject, provider_type, status, created_at, last_seen_at}` | `contracts/identity/v1/external-identity.schema.json` | Field-for-field identical (`principal_id` instead of `canonical_identity_id`) |
| Human-specific attributes | `contracts/identity/v1/human-identity.schema.json` | Already exists (`display_name`, `email`, `verified`) |
| Workload-specific attributes | `contracts/identity/v1/workload-identity.schema.json` | Already exists (`client_id`, `owner`, `environment`) |

**The verified `(issuer, subject)` extraction point already exists** — `internal/auth/oidc.go`'s `OIDCVerifier.Verify` returns `Principal{Subject: c.Subject, Issuer: token.Issuer, ...}` per request, and its own comment already anticipates this ADR: *"per ADR-0004 a stable canonical identity is ultimately keyed by (issuer, subject), not subject alone."* This `Principal` is baobab-cp's own ephemeral, per-request auth type — unrelated to the shared `Principal` contract above despite the name collision (Decision 1 below). Nothing today turns this per-request `(issuer, subject)` into a durable, persisted identity. ADR-0004 §11's flow (`Extract iss+sub → Find ExternalIdentity → CanonicalIdentity`) has no implementation past "extract."

**A generic entity-mapping infrastructure exists, but for a different domain concept:**
- `registry.canonical_entity` (`entity_type text NOT NULL`, `tenant_id text` nullable, no CHECK constraint on `entity_type`'s values) — used today with `entity_type = 'PRODUCT'` by the Mapping/resolution domain (Gate 1/2 work).
- `registry.external_reference` (`canonical_entity_id uuid NOT NULL REFERENCES registry.canonical_entity ... ON DELETE CASCADE`, `provider`, `provider_key`, `external_url`) — the Postgres table backing engine-mapping records.
- `domain.ExternalReference` (`internal/domain/resolution.go`) — the matching Go struct (`CanonicalEntityID`, `EngineID`, `EngineInstanceID`, `NativeType`, `NativeID`, `ExternalURL`, `Status`, `Metadata`). **Has no repository implementation at all yet** — grep confirms no Postgres or in-memory CRUD exists for it, only a foreign-key reference from `Mapping.ExternalReferenceID`.

ADR-0004 §24 directs reusing this infrastructure "where appropriate" for `CanonicalIdentity → engine-native actor` mappings (Medusa customer, `AD_User`, Payload user) — but `registry.canonical_entity` today represents *business entities* (products, in the one entity_type used so far), not *actors*, and its `external_reference` table's FK is hard-wired to `canonical_entity_id`. Reusing it for identities either means identity rows physically living in `registry.canonical_entity` (Decision 2), or a parallel identity-scoped reference table.

---

## 2. Decisions (made 2026-09-10)

### Decision 1 — Naming: `Principal` vs `CanonicalIdentity` → **keep `Principal`**

`baobab-platform/shared`'s existing contract is called `Principal`; ADR-0004 calls the same concept `CanonicalIdentity` throughout. `internal/auth.Principal` in `baobab-cp` is a *third*, unrelated thing (the ephemeral per-request auth struct) that already uses the name `Principal`.

**Resolved:** keep `Principal` everywhere in `shared` and `baobab-cp`'s new domain code; no contract rename. ADR-0004's "CanonicalIdentity" remains the conceptual name only, not a required identifier.

Residual friction this leaves, to handle at implementation time rather than resolve here: `internal/auth.Principal` (ephemeral, per-request) and the new durable `domain.Principal` (persisted, resolved from `(issuer, subject)`) will coexist as two distinct types with the same name in different packages. They compile and import fine as `auth.Principal`/`domain.Principal`, but every call site touching both needs a doc comment or local variable naming that makes which one is meant unambiguous — this should be an explicit review item on phase 2/4's PRs (below), not left implicit.

### Decision 2 — Where identity rows live → **new parallel tables**

- **(a) Reuse `registry.canonical_entity`** with a new `entity_type = 'IDENTITY'` value, leaving `tenant_id` NULL for those rows. Identity-to-engine mappings then reuse `registry.external_reference` and `domain.ExternalReference` exactly as ADR-0004 §24 suggests, with zero new mapping infrastructure.
- **(b) New parallel tables** (`identity.canonical_identity`, `identity.external_identity`, `identity.identity_reference`), keeping the Mapping/resolution domain's entity registry (products) and the identity domain (people/workloads) in separate schemas even though their shapes rhyme.

**Resolved: (b).** `registry.canonical_entity`'s `status` column already defaults to lowercase `'active'` while ADR-0004 wants uppercase `ACTIVE`/`SUSPENDED`/`DISABLED`/`ARCHIVED` (matching every other lifecycle status in this codebase), and "one table holds both SKUs and people" is a stretch of "where appropriate." `domain.ExternalReference` having zero existing persistence either way means the effort delta between (a) and (b) was smaller than it looked, so the cleaner separation won out.

---

## 3. Phased plan — all phases complete

Sized against this session's established PR pattern (bounded, one concern per PR, real Postgres tests, ADR citations). Every phase below shipped in its own PR against `baobab-platform/baobab-cp`, in order, each merged with green CI before the next started:

1. **Domain types + migration** — `baobab-platform/baobab-cp#64`. `domain.Principal` (Decision 1), `domain.ExternalIdentity`, matching the shared contracts; `identity.principal`/`identity.external_identity` migration (000026, Decision 2 — table named `identity.principal`, not `identity.canonical_identity`, per Decision 1's naming resolution); `UNIQUE(issuer, subject)` constraint (ADR-0004 §7, §54).
2. **Repository layer** — `baobab-platform/baobab-cp#65`. `ResolveIdentity(ctx, issuer, subject) (Principal, error)` and `CreateIdentity`/`LinkExternalIdentity` on `IdentityRepository`, in-memory + Postgres implementations — mirrors the `MappingScopeWriter` pattern from Gate 2 exactly.
3. **First-authentication provisioning** — `baobab-platform/baobab-cp#66`. `IdentityService.Resolve` implements the resolve-or-create flow (ADR-0004 §12, §56 — re-read on uniqueness conflict for concurrent first-logins). Built as a pluggable `ProvisioningPolicy` hook rather than hardcoding which actor types get auto-provisioned, per §13; a nil policy denies provisioning for every actor type (fail closed).
4. **Wire into the request path** — `baobab-platform/baobab-cp#67`. `auth.NewOperationContext` now takes a resolved canonical `principalID` instead of deriving `domain.Context.PrincipalID` from the raw OIDC subject; `api.ResolverHandler.Resolve` (`/v1/resolve`) calls `IdentityService.Resolve` between token verification and context construction. `service.WorkloadOnlyProvisioningPolicy` auto-provisions workload actors at this one call site specifically (a user-confirmed decision — see the PR for the reasoning: every workload calling `/v1/resolve` already has a valid OIDC token but zero rows in the new `identity.*` schema, so fail-closed would have broken existing traffic with no provisioning API yet built to fix it).
5. **Engine-reference mapping** (Medusa/ERP/CMS actors) — `baobab-platform/baobab-cp#68`. `domain.IdentityReference` + `identity.identity_reference` migration (000027), matching `contracts/identity/v1/external-reference.schema.json` field-for-field — a shared contract that already existed and already matched ADR-0004 §23-27 before this phase's Go type did. Deliberately a new, identity-scoped table rather than a reuse of `registry.external_reference` (Decision 2's reasoning extended to the reference table).
6. **Linking/unlinking/merge** (ADR-0004 §15-22) — shipped as three sub-slices, as anticipated below:
   - **6a — audited linking** — `baobab-platform/baobab-cp#69`. `IdentityLinkingRepository.LinkExternalIdentityAudited` adds a second `ExternalIdentity` to an existing `Principal`, writing the link and an `audit_events` row (ADR-0004 §16) in one transaction.
   - **6b — audited unlinking** — `baobab-platform/baobab-cp#70`. `IdentityUnlinkingRepository.UnlinkExternalIdentityAudited` marks an `ExternalIdentity` `UNLINKED` (never deleted), denying the operation (`ErrLastCredentialDenied`) if it would leave the `Principal` with zero `ACTIVE` credentials unless the caller marks it administrative (ADR-0004 §18). Its own tests caught and fixed a real pre-existing gap: `ResolveIdentity` (since phase 2) never filtered by `external_identity.status`, so an unlinked/revoked credential would have kept authenticating successfully.
   - **6c — audited merge** — `baobab-platform/baobab-cp#71`. `IdentityMergeRepository.MergePrincipalsAudited` transfers every `ExternalIdentity`/`IdentityReference` from a source `Principal` to a target, archives the source (`status = ARCHIVED`, never deleted — ADR-0004 §20), and writes two linked `audit_events` rows (one per `Principal`) capturing what §21 requires. Identity split (§22, the reverse operation) remains out of scope, as anticipated below.

Phases 1-4 made Gate IAM-3 substantively "real identity, not just a verified token." Phases 5-6 were sizable enough to warrant separate check-ins, consistent with this session's bounded-slice practice — phase 6 in particular needed the three-PR split anticipated when this plan was first scoped.

## 4. Explicitly not in this scope (still true after completion)

- Identity split (§22) — the reverse of merge; deferred to its own pass given the same auditability/security requirements merge (§19-21, phase 6c) needed, per §22's own text ("SHALL require security/administrative handling rather than ordinary self-service").
- Merging business relationships this repository doesn't model yet (tenant memberships, buyer/supplier relationships) — those live in `baobab-cp`'s tenant/membership domain (`internal/store`), not the identity tables phases 1-6 built.
- Actor-type-specific provisioning policy (§13) — belongs to domain-specific ADRs that don't exist yet (Zuribeans/Thamani/Supplier); phase 3's `ProvisioningPolicy` hook is the mechanism those ADRs will eventually configure.
- HTTP endpoints for linking/unlinking/merge, and the `identity.external-linked.v1`/`external-unlinked.v1`/`merged.v1` event envelopes ADR-0004 §50 lists — `baobab-cp` has no human-facing authentication surface yet for such endpoints to sit behind, and `baobab-platform/shared`'s `contracts/identity-events/v1/` doesn't define those payload schemas yet. `audit_events` rows satisfy §16/§21/§52's auditability requirement in the meantime.
- The `/v1/resolve` response-shape gap flagged in `baobab-platform/baobab-cp#63` — unrelated to identity, tracked separately.
