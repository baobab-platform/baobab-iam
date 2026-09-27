# Gate IAM-M1 — Evidence checklist (M1-D)

**Status:** Checklist for PR review — **M1 not closed** until items below are satisfied on an agreed branch/main and cross-repo work lands  
**Date:** 2026-09-27  
**Gate:** IAM-M1 (ADR-IAM-0019; ADR-IAM-0020)  
**Branch evidence:** `feat/adr-iam-ory-migration`  
**Does not:** Deploy Ory, migrate identities, or change production IssuerTrust  

---

## 1. Purpose

Provide a single place for reviewers to verify Gate IAM-M1 exit criteria against
committed evidence. This document is **M1-D** from the M1 work breakdown; it does
not replace the scope doc.

Primary scope: `docs/governance/gate-iam-m1-provider-neutral-contracts-scope.md`.

---

## 2. Exit criteria matrix

| # | Criterion (from M1 scope §6) | Evidence on this branch | Status |
|---|------------------------------|-------------------------|--------|
| 1 | `internal/provider` on agreed branch and builds | Package under `internal/provider/` (types, errors, factory, ory/, keycloak/); unit tests present | **On feature branch** — complete when PR merges and CI runs `go build` / `go test` |
| 2 | Capability-oriented interfaces match ADR-0020 | `provider.go` interfaces; package comments; `var _ IdentityProvider` asserts in ory/keycloak adapters | **Done on branch** |
| 3 | Shared identity schemas do not require Keycloak-only enums | **Out of repo** — M1-B in `baobab-platform/shared` | **Open** |
| 4 | CP resolves by issuer+subject; no authz on `provider_type == keycloak` | **Out of repo** — M1-C in `baobab-platform/baobab-cp` | **Open** |
| 5 | At least one CP fixture with non-Keycloak provider_type/issuer | **Out of repo** — M1-C | **Open** |
| 6 | Forbidden canonical field names checked | Manual: no `keycloak_user_id` / `ory_identity_id` added under this branch’s contracts surface (none introduced in iam) | **Pass for baobab-iam**; shared/cp greps still required |
| 7 | Phase 0 freeze list acknowledged; no scope/client ID renames in M1 | M0 §13 freeze; this branch did not rename `config/clients/*` or `config/scopes/*` | **Done on branch** |
| 8 | Scope doc Complete with PR links | Update after PR number known | **Pending PR** |

---

## 3. baobab-iam file inventory (M1-A)

| Path | Role |
|------|------|
| `internal/provider/provider.go` | ExternalSubject, ProviderIdentity, capability interfaces, IdentityProvider union |
| `internal/provider/errors.go` | ProviderError kinds + helpers |
| `internal/provider/factory.go` | ParseProviderName (`ory` \| `keycloak`) |
| `internal/provider/errors_test.go` | Error helper tests |
| `internal/provider/factory_test.go` | Provider name parsing tests |
| `internal/provider/ory/*` | Kratos + Hydra admin adapter (compile-time IdentityProvider) |
| `internal/provider/keycloak/*` | Dual-run stub; unsupported methods return ErrUnsupported |
| `internal/provider/README.md` | Contract vs SPI boundary |

**Suggested CI checks (when workflow is updated):**

```text
go build ./internal/provider/...
go test  ./internal/provider/...
```

Smoke against live Ory (`ORY_SMOKE=1`) is **M2/M3-C**, not required for M1 exit.

---

## 4. Explicit non-claims

Per ADR-0020 and M1 scope §3:

- This gate does **not** require running Kratos/Hydra.
- This gate does **not** provision or migrate identities.
- This gate does **not** enable dual-issuer production traffic.
- Adapter HTTP paths exist for later gates; M1 only requires the **contract** surface.

---

## 5. Cross-repo follow-ups (block full M1 close)

| ID | Repo | Work |
|----|------|------|
| M1-B | `shared` | Confirm `provider_type` not locked to `keycloak` only; widen if needed without making it required |
| M1-C | `baobab-cp` | Ory-shaped fixture; audit authz branches on `provider_type` |
| M1-D close | `baobab-iam` | Mark M1 scope **Complete** + fill PR links in this checklist after merge |

---

## 6. Reviewer sign-off (fill at PR)

| Role | Name | Date | Notes |
|------|------|------|-------|
| IAM / Platform | | | |
| CP owner (for M1-C awareness) | | | |
| Shared contracts (for M1-B awareness) | | | |

---

## 7. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M1-D checklist from branch state |
