# Gate IAM-M4 — Workload identity on Hydra

**Status:** Ready to start after M2/M3 foundation is healthy  
**Date:** 2026-09-27  
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
| Scope names | `config/scopes/*` | PRESERVE names; attach only scopes the workload is allowed |
| `WorkloadProvisioner` | `internal/provider` | Use Ory adapter against foundation / non-prod Hydra |

---

## 4. Deliverables

1. Inventory of workload clients in `config/clients` classified as M4 candidates (non-browser).
2. Bootstrap path: call `ProvisionWorkload` with `LogicalClientID`, `AllowedScopes`, `AuthMethod`.
3. Evidence: client exists on Hydra admin; client_credentials token obtainable against local/public Hydra **in non-prod only**.
4. Document rollback: disable Hydra client (clear grants) without deleting Keycloak client during dual-run.
5. No change to production IssuerTrust or estate redirect URIs under this gate alone.

---

## 5. Exit criteria

1. [ ] At least one non-prod workload client provisioned via adapter on Hydra.
2. [ ] Logical client ID stability demonstrated (same id as config).
3. [ ] Scope list matches freeze list subset — no renamed scopes.
4. [ ] Disable / rotate credentials exercised via adapter in non-prod.
5. [ ] Evidence linked from this document.
6. [ ] Keycloak workload clients (if any) still available until explicit dual-run decision.

---

## 6. Risks

| Risk | Mitigation |
|------|------------|
| Divergent client_id vs Keycloak | Prefer LogicalClientID as Hydra client_id (adapter already does) |
| Secrets in Git | Client secrets only from provision response / secret store |
| Over-scoping | Explicit AllowedScopes from config; deny-by-default |

---

## 7. Next after M4

**IAM-M5** — migration ledger + human identity path (ADR-0022).

---

## 8. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M4 scope (design only) |
