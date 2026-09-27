# Gate IAM-M1 — Provider-Neutral Contracts

**Status:** Ready to start (Phase 1)  
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
| Provider Go scaffold | artifacts / to land in `baobab-iam/internal/provider` | **Land on main** under this gate |

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

Land (from scaffold or equivalent):

```text
internal/provider/
  provider.go      # ExternalSubject, ProviderIdentity, workload types, capability interfaces
  errors.go        # ProviderError, kinds, helpers
  ory/             # optional stub OK if compile-only; full HTTP client can wait for M2/M3
  keycloak/        # optional dual-run stub; methods may return ErrUnsupported
```

**Must compile** with module path consistent with the repo.  
**Must** include compile-time assertions that adapters implement the interfaces they claim.

Minimum interfaces to expose (ADR-0020):

- `ProviderInfoSource`
- `IdentityReader`
- `IdentityProvisioner`
- `IdentityLifecycleManager`
- `SessionRevoker`
- `WorkloadProvisioner`
- `IdentityReconciler`
- Optional union: `IdentityProvider`

### 4.2 Contract rules (documented + tested)

| Rule | Enforcement |
|------|-------------|
| Canonical key is `issuer` + `subject` | Existing CP tests; add IAM contract test doc |
| `provider_type` / `provider` is optional metadata (`keycloak`, `ory`, …) | Must not gate business authorization |
| No required field `keycloak_user_id` / `ory_identity_id` on Principal or domain models | Grep/CI check in CP + shared |
| No Baobab proprietary OAuth endpoints | Doc assertion only in M1 |
| Scopes and logical client IDs unchanged in meaning | Freeze list from M0 baseline §13 |

### 4.3 `shared` (if schemas live there)

- Confirm `principal.schema.json` and `external-identity.schema.json` allow multiple `provider_type` values (string, not enum locked to `keycloak`).
- If `provider_type` is an enum containing only `keycloak`, widen to include `ory` (and optionally `unknown`) **without** making it required.
- Do **not** add Tenant, LegalEntity, or Capability fields to identity provider contracts.

### 4.4 `baobab-cp` hygiene

- Audit for hard-coded issuer hostnames or `provider_type == "keycloak"` branches that **change authorization outcomes**.
- Test fixtures may still use `provider_type: "keycloak"` and a Keycloak-shaped issuer URL; add at least one fixture with `provider_type: "ory"` and a distinct issuer string to prove resolution is issuer+subject based.
- Document (short note in gate evidence) that dual ExternalIdentity per Principal is allowed for migration (ADR-0022) — schema/status values already include UNLINKED/DISABLED/REVOKED; no code required in M1 beyond not forbidding two ACTIVE rows from different issuers in comments/docs (implementation of dual-active policy may be M5/M18).

### 4.5 Gate evidence doc

Update or add:

- This scope doc (status → Complete when exit criteria met)
- PR links for iam / shared / cp
- Output of forbidden-field grep / CI job

### 4.6 CI

| Check | Repo |
|-------|------|
| `go build ./internal/provider/...` | baobab-iam |
| Unit tests for `ProviderError` helpers / interface satisfaction | baobab-iam |
| Contract compatibility tests still pass | baobab-cp |
| Optional: script fails if `keycloak_user_id` appears under `contracts/identity` | shared or iam |

---

## 5. Work breakdown (suggested PRs)

| PR | Repo | Content |
|----|------|---------|
| **M1-A** | `baobab-iam` | Add `internal/provider` (types, errors, ory/keycloak stubs); `go build`; minimal tests |
| **M1-B** | `shared` | Schema tweak for `provider_type` if needed; contract test update |
| **M1-C** | `baobab-cp` | Ory-shaped fixture; remove any authz branch on provider_type; evidence note |
| **M1-D** | `baobab-iam` | Gate scope status Complete + evidence appendix |

Order: **M1-A** can start immediately. **M1-B/C** parallel once schema/fixture needs are confirmed.

---

## 6. Exit criteria

Gate IAM-M1 is **complete** when:

1. [ ] `internal/provider` is on `baobab-iam` main (or release branch agreed for migration) and builds in CI.
2. [ ] Capability-oriented interfaces match ADR-0020 intent (documented in package comment).
3. [ ] Shared identity schemas do not require Keycloak-only enums/fields for validity.
4. [ ] CP resolves identity by issuer+subject; no authorization decision requires `provider_type == keycloak`.
5. [ ] At least one CP test fixture uses a non-Keycloak `provider_type` / issuer pair.
6. [ ] Forbidden canonical field names checked (manual or CI).
7. [ ] Phase 0 freeze list (§13 baseline) acknowledged — M1 did not rename scopes or logical client IDs.
8. [ ] This document marked Complete with PR links.

**Explicitly not required for M1 exit:** running Kratos/Hydra, migration ledger, IssuerTrust dual-run, LIVE-VERIFY completion.

---

## 7. Risks specific to M1

| Risk | Mitigation |
|------|------------|
| Over-abstracting standards (wrapping OIDC in Baobab APIs) | Package comments + ADR-0020 Category A; no token proxy in interfaces |
| Giant monolithic `IdentityProvider` only | Prefer small interfaces; union is optional |
| Changing Principal/ExternalIdentity field names “for Ory” | Forbidden; breaks CP and engines |
| Blocking M1 on Phase 0 LIVE-VERIFY | Do not; parallel tracks |

---

## 8. Next gate after M1

**Gate IAM-M2 / M3 — Ory foundation**  
Pin Kratos + Hydra images, separate DBs, admin vs public plane, local Compose, CI ephemeral stack. Implement real `ory` adapter HTTP calls against that stack.

---

## 9. Reference artifacts

| Artifact | Path |
|----------|------|
| M0 baseline | `docs/governance/gate-iam-m0-migration-baseline.md` |
| M0 ADR matrix | `docs/governance/gate-iam-m0-adr-matrix.md` |
| Rollback runbook | `docs/operations/migration-rollback-baseline.md` |
| Provider scaffold | `internal/provider/*` (land via M1-A) |
| ADR-0020 | Provider-neutral contract and adapter architecture |
| CP identity domain | `baobab-cp/internal/domain/identity.go` |

---

## 10. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M1 scope; ready to start from existing CP Principal/ExternalIdentity + provider scaffold |
