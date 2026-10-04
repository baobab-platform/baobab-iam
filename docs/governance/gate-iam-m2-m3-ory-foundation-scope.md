# Gate IAM-M2 / M3 — Ory Foundation (Kratos + Hydra)

**Status:** Complete for isolated non-production foundation — live M2/M3-C evidence recorded  
**Date:** 2026-10-04  
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
- CI boots the isolated Ory stack for live adapter integration tests.

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

### 4.5 Adapter smoke (M2/M3-C) — **live CI verified**

| Path | Role |
|------|------|
| `internal/provider/ory/readiness.go` | `Adapter.CheckReady` — both admin planes (ADR-0021 §8/§10) |
| `internal/provider/ory/readiness_test.go` | Offline httptest coverage (both OK, fallback path, fail-closed) |
| `internal/provider/ory/smoke_test.go` | Opt-in (`ORY_SMOKE=1`) CheckReady + ProviderInfo |
| `docs/operations/ory-foundation-smoke.md` | Operator steps |

Live CI pulled the pinned images, migrated the isolated databases and passed readiness, adapter smoke, authorized human provisioning/lifecycle and real session revocation. See §10 for the tested commit and artifact.

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
| **M2/M3-C** | Smoke + CheckReady | **Live CI verified — see §10** |
| **M2/M3-D** | Resolve image digests | **Done 2026-09-30** — pin corrected to published `v26.2.0`; multi-arch digests in `provider.lock.yaml` |

---

## 6. Exit criteria

1. [x] `provider.lock.yaml` pins Kratos and Hydra versions used by Compose.
2. [x] Digests resolved for published `v26.2.0` (multi-arch index). Production promotion still requires operator re-verify against the intended registry mirror.
3. [x] Compose overlay defines separate Postgres databases for Kratos and Hydra.
4. [x] Admin ports bound to localhost in Compose.
5. [x] Kratos and Hydra health/ready succeed against the isolated CI stack — §10.
6. [x] Adapter smoke and human provisioning/lifecycle succeed against real Kratos/Hydra — §10.
7. [x] No production IssuerTrust or client redirect changes.
8. [x] Non-production foundation completion recorded with live CI evidence — §10.

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

Next: M4 live token exchange and consumer evidence. This foundation completion does not authorize production client moves.

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


## 10. M2/M3-C automated evidence follow-up

The `Ory Foundation Live` workflow now runs the pinned Compose overlay on PRs.
`tests/ory-foundation/run.sh` requires explicit PASS events for readiness smoke,
authorized human migration/lifecycle, and effective real-session revocation.
Startup is bounded, diagnostic evidence sanitized, and CI teardown unconditional.

Verified at commit `c63e0ed08f1e7aa9a0d9d9d7b4d5e727f1dd28a8`:
[Ory Foundation Live run 37157590467](https://github.com/baobab-platform/baobab-iam/actions/runs/37157590467)
completed successfully, including all four required test PASS events, artifact upload,
and container/volume teardown. Artifact: `ory-foundation-evidence` on that run.
The later documentation commit records this evidence; it does not change tested runtime code.
Production mirror verification and M4 token/resource-server evidence remain separate.
