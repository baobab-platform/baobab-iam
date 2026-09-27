# Gate IAM-M2 / M3 — Ory Foundation (Kratos + Hydra)

**Status:** In progress (M2-A/B, M3-B, **M2/M3-C smoke scaffold**; live evidence + digests open)  
**Date:** 2026-09-27  
**Gate:** IAM-M2 (Kratos) / IAM-M3 (Hydra) — ADR-IAM-0019 §58 / §92; ADR-IAM-0021  
**Depends on:** Gate IAM-M1 provider contracts on branch (may merge in parallel); **M0 rollback baseline** before any shared non-prod dual-run  
**Primary repos:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`  
**Does not:** Migrate production identities, dual-issuer production traffic, or retire Keycloak  

---

## 1. Goal

Stand up **isolated, non-production** Ory runtimes that match ADR-0021 topology so the existing `internal/provider/ory` adapter can be exercised against real admin APIs.

After M2/M3:

- Kratos and Hydra run as **separate processes** with **separate logical databases**.
- Public vs administrative planes are distinct; admin APIs are not internet-facing.
- Versions and (eventually) image digests are pinned in `provider.lock.yaml`.
- Local Compose overlay coexists with the existing Keycloak `docker-compose.yml`.
- CI can optionally boot the Ory stack for adapter integration tests (follow-up).

**Keycloak remains the production path until M18/M19.**

---

## 2. Non-goals

| Non-goal | Belongs to |
|----------|------------|
| Production dual-issuer | M18 + CP IssuerTrust |
| Identity / credential bulk migration | M5 |
| Workload cutover | M4 |
| Estate login UI | M7 / ADR-0023 |
| Adopting Keto or Oathkeeper | Explicit later ADR only |
| Replacing `docker-compose.yml` Keycloak service | M19 |

---

## 3. Topology (ADR-0021)

```text
Internet / gateway
        │
        ├── Kratos public (auth flows)     [M2]
        └── Hydra public (OAuth/OIDC)      [M3]

Private network only
        │
        ├── Kratos admin  ◄── baobab-iam adapter
        ├── Hydra admin   ◄── baobab-iam adapter
        ├── Postgres DB: kratos
        └── Postgres DB: hydra
```

No shared tables with Keycloak, CP, Trade, ERP, or CMS.

---

## 4. Deliverables

### 4.1–4.4 Version lock, Compose, Kratos config, Hydra config — landed

See prior revisions. Paths:

- `provider.lock.yaml`
- `docker-compose.ory.yml`
- `config/ory/kratos/{kratos.yml,identity.schema.json}`
- `config/ory/hydra/hydra.yml`

### 4.5 Adapter smoke (M2/M3-C) — **scaffold landed**

| Path | Role |
|------|------|
| `internal/provider/ory/smoke_test.go` | Opt-in (`ORY_SMOKE=1`) ProviderInfo against local admin planes |
| `docs/operations/ory-foundation-smoke.md` | Operator steps |

Live green evidence still requires image pull + `docker compose up` on a machine with registry access.

---

## 5. Work breakdown

| Step | Content | Status |
|------|---------|--------|
| **M2-A** | Scope, lock, Compose overlay | Done |
| **M2-B** | Kratos config + identity schema | Done |
| **M3-B** | Hydra config + Compose `-c` | Done |
| **M2/M3-C** | Smoke test + ops note | **Scaffold done; live run pending** |
| **M2/M3-D** | Resolve image digests | Open (registry egress) |

---

## 6. Exit criteria

1. [x] `provider.lock.yaml` pins Kratos and Hydra versions used by Compose.
2. [ ] Digests resolved **or** residual risk accepted (same pattern as Keycloak R-1).
3. [x] Compose overlay defines separate Postgres databases for Kratos and Hydra.
4. [x] Admin ports bound to localhost in Compose.
5. [ ] Kratos and Hydra health/ready succeed locally (requires image pull).
6. [ ] At least one adapter call against the stack succeeds (`ORY_SMOKE=1`).
7. [x] No production IssuerTrust or client redirect changes.
8. [ ] This document marked Complete with evidence.

---

## 7. Risks

| ID | Risk | Mitigation |
|----|------|------------|
| **M23-R1** | Image digests unresolved | UNRESOLVED marker |
| **M23-R2** | Accidental admin exposure | 127.0.0.1 binds |
| **M23-R3** | Shared DB with Keycloak | Separate services and DB names |
| **M23-R4** | Business fields in identity schema | §37 schema |
| **M23-R5** | Courier SMTP stub | Admin API foundation does not require mail |
| **M23-R6** | Hydra treated as human IdP | §11 in hydra.yml + docs |

---

## 8. Next gates after M2/M3

- **IAM-M4** — Workload clients on Hydra (first runtime migration slice)
- **IAM-M5** — Migration ledger + human identity path

In-repo work that can still proceed without live Ory images: M1-D evidence when PR opens; M4 design notes only (no production client moves).

---

## 9. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | M2-A scaffold |
| 0.2 | 2026-09-27 | M2-B Kratos |
| 0.3 | 2026-09-27 | M3-B Hydra |
| 0.4 | 2026-09-27 | M2/M3-C smoke scaffold |
