# Gate IAM-M2 / M3 — Ory Foundation (Kratos + Hydra)

**Status:** In progress (M2-A/B, M3-B; **M2/M3-C CheckReady + offline tests**; **M2/M3-D digests resolved**; live Compose evidence residual)  
**Date:** 2026-09-30  
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
- Versions and image digests are pinned in `provider.lock.yaml`.
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

### 4.5 Adapter smoke (M2/M3-C) — **code landed; live residual**

| Path | Role |
|------|------|
| `internal/provider/ory/readiness.go` | `Adapter.CheckReady` — both admin planes (ADR-0021 §8/§10) |
| `internal/provider/ory/readiness_test.go` | Offline httptest coverage (both OK, fallback path, fail-closed) |
| `internal/provider/ory/smoke_test.go` | Opt-in (`ORY_SMOKE=1`) CheckReady + ProviderInfo |
| `docs/operations/ory-foundation-smoke.md` | Operator steps |

Live green evidence still requires image pull + `docker compose up` on a machine with registry access. `Adapter.CheckReady` is covered offline with httptest; opt-in `ORY_SMOKE=1` calls CheckReady + ProviderInfo against the Compose stack.

### 4.6 Image digests (M2/M3-D) — resolved 2026-09-30

| Image | Tag | Multi-arch index digest |
|-------|-----|-------------------------|
| `oryd/kratos` | `v26.2.0` | `sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643` |
| `oryd/hydra` | `v26.2.0` | `sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9` |

**Correction:** the earlier draft pin `v26.3.17` is **not** published on Docker Hub `oryd/*`. Latest v26 line as of resolution is `v26.2.0`.

Architecture-specific digests (informational):

| Image | amd64 | arm64 |
|-------|-------|-------|
| kratos | `sha256:92eedc292ff8e1a918ac442c88ed0abe44610c75121700963114549908a45ac3` | `sha256:eaf37b0c1b7b5308ad7a3247706eee032588c9ef8a13fc59dd6422eaa4e079d6` |
| hydra | `sha256:f59c2f7f4969269b154fa34c57bc4b849263ebedbcaf8114aaeb1658a3007b4b` | `sha256:7a4626d20bcec1e90c69bdbe4f9de50a2d4374656ca6b285f9228862efb5fce7` |

`docker-compose.ory.yml` pins `image:tag@sha256:…` using the multi-arch index digests above.

---

## 5. Work breakdown

| Step | Content | Status |
|------|---------|--------|
| **M2-A** | Scope, lock, Compose overlay | Done |
| **M2-B** | Kratos config + identity schema | Done |
| **M3-B** | Hydra config + Compose `-c` | Done |
| **M2/M3-C** | Smoke + CheckReady | **Code + offline tests done; live Compose residual** |
| **M2/M3-D** | Resolve image digests | **Done 2026-09-30** — pin corrected to published `v26.2.0`; multi-arch digests in `provider.lock.yaml` |

---

## 6. Exit criteria

1. [x] `provider.lock.yaml` pins Kratos and Hydra versions used by Compose.
2. [x] Digests resolved for published `v26.2.0` (multi-arch index). Production promotion still requires operator re-verify against the intended registry mirror.
3. [x] Compose overlay defines separate Postgres databases for Kratos and Hydra.
4. [x] Admin ports bound to localhost in Compose.
5. [ ] Kratos and Hydra health/ready succeed locally (requires image pull) — **offline httptest coverage landed; live residual**.
6. [ ] At least one adapter call against the stack succeeds (`ORY_SMOKE=1`) — **residual: no Docker in agent environment 2026-09-30**.
7. [x] No production IssuerTrust or client redirect changes.
8. [ ] This document marked Complete with evidence.

---

## 7. Risks

| ID | Risk | Mitigation |
|----|------|------------|
| **M23-R1** | Image digests / wrong tag | Resolved to `v26.2.0` digests; re-verify on private mirrors |
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
| 0.5 | 2026-09-30 | **M2/M3-D:** `v26.3.17` not published; pin corrected to `v26.2.0` with multi-arch digests |
| 0.6 | 2026-09-30 | **M2/M3-C code:** `CheckReady` + httptest tests; live Compose residual documented |
