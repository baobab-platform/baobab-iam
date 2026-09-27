# Gate IAM-M1 — Provider-Neutral Contracts

**Status:** In progress (M1-A code on `feat/adr-iam-ory-migration`; M1-B/C in shared/cp still open)  
**Date:** 2026-09-27  
**Gate:** IAM-M1 (ADR-IAM-0019 §57 / §91; ADR-IAM-0020)  
**Depends on:** Gate IAM-M0 baseline (docs may be completed in parallel; **no production dual-run** until M0 rollback preconditions are met)  
**Primary repos:** `baobab-platform/baobab-iam`, `baobab-platform/shared`, `baobab-platform/baobab-cp`  
**Does not:** Deploy Ory, migrate identities, or change production IssuerTrust  

---

## 1. Goal

Make **provider neutrality enforceable** in contracts and code:

> Baobab depends on identity **standards** and Baobab identity contracts, not on Keycloak (or Ory) business semantics.

After M1:

- Canonical types and shared schemas do not require Keycloak-specific fields for correctness.
- `baobab-iam` has a checked-in **provider adapter contract** (interfaces + errors + capability discovery).
- CP identity resolution continues to key on **issuer + subject** only.
- CI fails if forbidden provider-coupled fields appear in canonical contract surfaces.

**No Ory runtime is required to close this gate.**

---

## 2. What already exists (do not redesign)

| Asset | Location | M1 action |
|-------|----------|-----------|
| `Principal` (canonical actor) | `baobab-cp/internal/domain/identity.go`; `contracts/identity/v1/principal.schema.json` | PRESERVE; confirm no KC-only required fields |
| `ExternalIdentity` (issuer, subject, optional `provider_type`) | CP domain + `external-identity.schema.json` | PRESERVE key; treat `provider_type` as **operational metadata** only |
| `IdentityReference` (engine mapping) | CP domain | PRESERVE |
| Resolve by `(issuer, subject)` | CP repository | PRESERVE |
| Scope names (`actor-type-*`, `context-resolve`, …) | `baobab-iam/config/scopes/*` | PRESERVE names (Phase 0 freeze) |
| Logical client IDs | `config/clients/*` | PRESERVE names |
| Provider Go package | `baobab-iam/internal/provider` | **On feature branch** (M1-A) |

CP already names the canonical type `Principal` (not `CanonicalIdentity`) to match shared contracts — keep that.

---

## 3. Non-goals

- Deploying Kratos/Hydra (→ **M2/M3**)
- Provisioning or migrating identities (→ **M5**)
- Dual-issuer production traffic (→ **M18**; needs CP IssuerTrust)
- Rewriting Trade/CMS/ERP OIDC clients (→ **M6+**)
- Finishing Phase 0 LIVE-VERIFY (can proceed in parallel; does not block M1 code)

---

## 4. Deliverables

### 4.1 `baobab-iam` — provider package on main

```text
internal/provider/
  provider.go      # ExternalSubject, ProviderIdentity, workload types, capability interfaces
  errors.go        # ProviderError, kinds, helpers
  factory.go       # ParseProviderName (ory | keycloak)
  ory/             # Kratos + Hydra admin adapter
  keycloak/        # dual-run stub; methods may return ErrUnsupported
```

**Must compile** with module path consistent with the repo.  
**Must** include compile-time assertions that adapters implement the interfaces they claim.

### 4.2–4.4

Unchanged: contract rules, shared schema widening, CP hygiene (M1-B / M1-C in other repos).

### 4.5 Gate evidence

- This scope doc (status → Complete when exit criteria met)
- PR links for iam / shared / cp when opened

### 4.6 CI

| Check | Repo |
|-------|------|
| `go build ./internal/provider/...` | baobab-iam |
| Unit tests for `ProviderError` helpers / interface satisfaction | baobab-iam |
| Contract compatibility tests still pass | baobab-cp |

---

## 5. Work breakdown

| PR | Repo | Content | Status |
|----|------|---------|--------|
| **M1-A** | `baobab-iam` | `internal/provider` + tests + factory | **On `feat/adr-iam-ory-migration`** |
| **M1-B** | `shared` | Schema tweak for `provider_type` if needed | Open |
| **M1-C** | `baobab-cp` | Ory-shaped fixture; no authz on provider_type | Open |
| **M1-D** | `baobab-iam` | Mark this doc Complete + evidence | After PR merge |

---

## 6. Exit criteria

1. [ ] `internal/provider` on `baobab-iam` main (or agreed release branch) and builds in CI.
2. [x] Capability-oriented interfaces match ADR-0020 (package comments + compile asserts).
3. [ ] Shared identity schemas do not require Keycloak-only enums/fields.
4. [ ] CP resolves by issuer+subject; no authz branch on `provider_type == keycloak`.
5. [ ] At least one CP fixture with non-Keycloak provider_type/issuer.
6. [ ] Forbidden canonical field names checked.
7. [x] Phase 0 freeze list acknowledged — M1 did not rename scopes or logical client IDs.
8. [ ] This document marked Complete with PR links.

---

## 7. Next gate

**Gate IAM-M2 / M3 — Ory foundation** — see `gate-iam-m2-m3-ory-foundation-scope.md`.

---

## 8. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M1 scope |
| 0.2 | 2026-09-27 | M1-A on feature branch; factory; status In progress |
