# Gate IAM-8 — Supplier Identity

**Status:** Scoped, not yet implemented. No repository anywhere in this ecosystem currently owns "supplier domain" logic — this is a bigger blocker than Gate IAM-7's two forks and needs a decision above this gate's IAM-scoped level. Discovery is complete across `baobab-iam`/`baobab-cp`/`baobab-trade`/`baobab-erp`/`baobab-platform/thamani`.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0012 — Supplier Identity and Representative Access`
**Repositories:** `baobab-platform/baobab-iam` (supplier representative authentication, owner), `baobab-platform/baobab-cp` (canonical identity/entity, platform context), supplier onboarding/domain service (**does not yet exist** — see §3), `baobab-platform/baobab-trade` (Trade supplier mapping), `baobab-platform/baobab-erp` (ERP Business Partner mapping)
**Depends on:** Gate IAM-3 (canonical identity spine), Gate IAM-6 (the Keycloak Organizations feature this gate would reuse, not re-enable — already realm-wide)

The Consolidated Technical Specification's own one-line scope for this gate (§211) is: *"supplier representative, supplier organization, registration, vetting, approval, product capability, market eligibility, estate sourcing relationships, supplier roles, supplier lifecycle."* ADR-0012 is 141 sections and — unlike every gate so far — names an owning repository ("supplier onboarding/domain services") that doesn't exist anywhere in this session's attached repos, or apparently anywhere yet at all.

---

## 1. Current state (verified against source, 2026-09-12)

**`baobab-cp`** has exactly one relevant artifact: `internal/domain/entity_types.go` registers `EntityTypeSupplierOrganisation = "SUPPLIER_ORGANISATION"` alongside `PRODUCT`, with its own doc comment explicitly stating *"It is registered here as a name only: this package does not create, resolve, or map any SUPPLIER_ORGANISATION entity, and no other control-plane code branches on this constant. Registration happens exclusively through the existing entity-type-agnostic `CanonicalEntityService.Create` API once a hosting estate is ready to call it."* Nothing else — no representative membership, vetting state, approval workflow, or sourcing-relationship code exists anywhere in the repo.

**`baobab-platform/thamani`** has `docs/adr/0002-supplier-onboarding-portal.md` — Status **Accepted**, but purely a design document: no live database yet ("later, scoped work, this program's Phase 2" per its own text), no auth system, no event publishing, no canonical Organisation identity. It names the domain model as living in `@baobab-platform/supplier-domain`, a package from `baobab-platform/shared` "extracted from `baobab-platform/zuribeans`'s ADR-0006" — **not yet published** (unpinned in `contracts.lock.yaml`). `grep -rni supplier src/` in `baobab-platform/thamani` returns zero matches; no code exists.

**`baobab-trade`** has a *synthetic supplier catalogue* model (`src/modules/thamani/models/supplier.ts`, table `thamani_supplier`, `synthetic: true` by default) used for simulated/seed commerce data, with an unpopulated `erp_business_partner_reference` placeholder field anticipating the eventual ERP mapping — but no real supplier identity, vetting, representative-membership, or purchase-order domain logic, and no supplier-specific module registered in `medusa-config.ts` (only the buyer-side `b2b` module exists).

**`baobab-erp`** has zero supplier/vendor/Business-Partner implementation anywhere in `modules/`, `idempiere/extensions/`, or `db/` — its own `docs/supplier-onboarding.md` states this explicitly. `ADR-ERP-007` specifies the target canonical mapping shape (`Party → C_BPartner`) at the design level only, with checklist items unchecked. The repo's own README self-describes as "Foundation stage."

**`baobab-iam`** has zero supplier-related config anywhere — no client, scope, or realm entry (confirmed by direct search, not assumed).

**Verdict:** unlike Zuribeans B2B (substantially pre-built in `baobab-trade`) or Thamani B2C (mostly greenfield but with real, tested domain logic already in place), Gate IAM-8 has **no owning implementation anywhere**: one unused enum value, an Accepted-but-empty design ADR, a synthetic catalogue placeholder, and a Foundation-stage ERP repo with design-only mapping docs. `@baobab-platform/supplier-domain`, the package every downstream document defers to, doesn't exist yet as a published artifact.

---

## 2. What IS reusable without new work

Two pieces Gate IAM-8 depends on are already correctly built by earlier gates and need no changes:

1. **Keycloak Organizations** (Gate IAM-6) — ADR-0012 §7 asks for exactly the same feature Gate IAM-6 already enabled realm-wide (`organizationsEnabled: true`, the `organization` client scope/claim). This is not a per-estate or per-domain feature; supplier representative organizations can use it as-is once a client requests the scope.
2. **`baobab-cp`'s generic `CanonicalEntity`/`Mapping`/`ExternalReference` machinery** (Gate IAM-3) — already documented as ready to host `SUPPLIER_ORGANISATION` the same way it's ready to host a Medusa customer actor (Gate IAM-7's finding). No new construct needed in `baobab-cp` either.

---

## 3. The blocking gap: no supplier-domain owner

ADR-0012 §132's ownership table assigns supplier onboarding, vetting, approval, product/category eligibility, and sourcing relationships to "supplier domain" — a service this ecosystem does not yet have. This is a materially bigger blocker than Gate IAM-7's two architectural forks (which were about *how* an existing repo does something): here, *no repo does anything yet*, and deciding where this logic should live is itself a significant infrastructure decision:

- **Option A** — a new dedicated repository/service (matching how `baobab-trade`, `baobab-erp` etc. are each their own service).
- **Option B** — folded into an existing repo (`baobab-cp`, given it already owns canonical entities and cross-estate context; or `baobab-trade`, given it already has the closest thing to supplier-adjacent code today).
- **Option C** — wait for `@baobab-platform/supplier-domain` to be published from `baobab-platform/shared`/`baobab-platform/zuribeans`'s own ADR-0006 work, which may already be in progress outside this session's visibility, and integrate against that once it exists.

This session has no basis to choose between these — it's a genuine cross-team architecture decision, not a pattern question resolvable by reading existing code (unlike Gate IAM-7's forks, where reading `baobab-platform/thamani`'s actual code settled part of the question). Implementing IAM-side supplier authentication ahead of this decision would mean guessing at a client/registration shape with nothing real to integrate against.

**Decision: deferred**, pending either an explicit repo/ownership decision or `@baobab-platform/supplier-domain`'s publication.

---

## 4. Remaining phases (scoped, not yet implemented)

1. **Resolve §3** — a repo/ownership decision for the supplier domain, or confirmation that `@baobab-platform/supplier-domain` is the intended integration point once published.
2. **`baobab-iam`** — once phase 1 exists to integrate against: a supplier representative client (or reuse of `zuribeans-web`/`thamani-web`, per ADR-0012 §73's "frontend location SHALL not determine supplier authority" — supplier portals may live inside existing Digital Estate frontends rather than needing a dedicated client).
3. **`baobab-cp`** — register `SUPPLIER_ORGANISATION` for real via `CanonicalEntityService.Create` once a hosting estate/domain is ready to call it (the doc comment's own stated precondition).
4. **`baobab-trade`/`baobab-erp` mappings** — Trade supplier/vendor representation and ERP Business Partner mapping, both explicitly downstream of supplier approval existing first.

---

## 5. Why this gate has no code changes

Matching Gate IAM-5 phase 2b and Gate IAM-7's precedent: this session documents genuine blockers rather than guessing past them. Gate IAM-8's blocker is larger in kind — no owning service exists at all, not just an unresolved pattern choice — so the correct phase-1 outcome is thorough discovery and an explicit statement of what needs to be decided before any code is written, not a partial implementation against a domain layer that doesn't exist.
