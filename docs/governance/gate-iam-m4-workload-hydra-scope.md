# Gate IAM-M4 — Workload identity on Hydra

**Status:** In progress — inventory + CLI + offline adapter tests; live Hydra evidence residual  
**Date:** 2026-09-30  
**Gate:** IAM-M4 (ADR-IAM-0019; ADR-0007 workload identity; ADR-0020 WorkloadProvisioner)  
**Depends on:** M2/M3 Ory foundation (Hydra admin reachable); M1 provider contracts  
**Primary repos:** `baobab-platform/baobab-iam`, consuming services under CP/Trade/etc.  
**Does not:** Bulk human migration, dual-issuer production browser traffic, Keycloak retirement  

---

## 1. Goal

Provision **machine / workload** OAuth clients on **Hydra** using the provider-neutral
`WorkloadProvisioner` surface, while preserving Baobab **logical client IDs** and
scope names from the Phase 0 freeze list.

Rationale (ADR-IAM-0019): workload cutover is lower user risk than human login
migration and proves admin-plane automation before M5 human migration tooling.

---

## 2. Non-goals

| Non-goal | Gate |
|----------|------|
| Human identity bulk import | M5 |
| Browser dual-issuer | M18 |
| Keycloak decommission | M19 |
| Changing scope **meanings** | Forbidden without ADR |
| Putting Tenant/Capability into Hydra client metadata as authz source of truth | Forbidden (ADR-0020 Category C) |

---

## 3. Inputs (preserve)

| Asset | Location | M4 action |
|-------|----------|-----------|
| Logical client IDs | `config/clients/*` | PRESERVE IDs; provision Hydra client_id = logical id where possible |
| Scope names | `config/scopes/*` + M0 §5 | PRESERVE names; attach only scopes the workload is allowed |
| `WorkloadProvisioner` | `internal/provider` | Use Ory adapter against foundation / non-prod Hydra |
| Client classification | `docs/governance/gate-iam-m4-client-inventory.md` | M4-PRIMARY first |

---

## 4. Deliverables

1. [x] Inventory of workload clients classified as M4 candidates — **`gate-iam-m4-client-inventory.md`**.
2. [x] Bootstrap path: `cmd/provision-workload` + `Adapter.ProvisionWorkload` (`LogicalClientID`, `AllowedScopes`, `AuthMethod`).
3. [ ] Evidence: client exists on Hydra admin; client_credentials token obtainable against local/public Hydra **in non-prod only** (requires live foundation).
4. [x] Rollback path: `DisableWorkload` clears `grant_types` (soft-disable); Keycloak client untouched — covered by offline test.
5. [x] No change to production IssuerTrust or estate redirect URIs under this gate alone.
6. [x] Scope TRANSLATE: `context:resolve` → `context-resolve` via `provider.NormalizeAllowedScopes` (applied in Ory adapter + CLI).

**Preferred first client:** `baobab-trade-workload`.

---

## 5. Exit criteria

1. [ ] At least one non-prod workload client provisioned via adapter on Hydra — **offline create path tested; live residual**.
2. [x] Logical client ID stability demonstrated offline (`client_id` = `LogicalClientID`).
3. [x] Scope TRANSLATE covered (`context:resolve` → `context-resolve`); freeze names preserved otherwise.
4. [x] Disable path covered offline (clears grants); rotate remains live residual.
5. [ ] Live evidence linked from this document.
6. [x] Keycloak workload JSON under `config/clients/*` preserved (no production dual-run).

---

## 6. Risks

| Risk | Mitigation |
|------|------------|
| Divergent client_id vs Keycloak | Prefer LogicalClientID as Hydra client_id (adapter already does) |
| Secrets in Git | Client secrets only from provision response / secret store |
| Over-scoping | Explicit AllowedScopes from inventory §3; deny-by-default |
| `context:resolve` vs `context-resolve` spelling | Normalize at TRANSLATE; prefer `context-resolve` (see inventory) |

---

## 7. Next after M4

**IAM-M5** — migration ledger + human identity path (ADR-0022).

---

## 8. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M4 scope (design only) |
| 0.2 | 2026-09-27 | Link full client inventory; preferred first client |
| 0.3 | 2026-09-30 | **M4 residual hygiene:** NormalizeAllowedScopes, httptest provision/disable tests, CLI CheckReady |
