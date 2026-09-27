# Gate IAM-M2 / M3 — Ory Foundation (Kratos + Hydra)

**Status:** Ready to start  
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

### 4.1 Version lock

| File | Content |
|------|---------|
| `provider.lock.yaml` | Kratos + Hydra version tags; digest fields (UNRESOLVED until registry egress) |

Initial target tag (both components, OSS images): **26.3.17** (aligned September 2026 releases). Confirm supported PostgreSQL versions against upstream release notes before production promotion.

### 4.2 Local Compose overlay

| File | Content |
|------|---------|
| `docker-compose.ory.yml` | `postgres-kratos`, `postgres-hydra`, `kratos`, `hydra` services |

Usage (non-prod only):

```bash
docker compose -f docker-compose.ory.yml up -d
```

Does **not** remove or alter the Keycloak stack in `docker-compose.yml`.

### 4.3 Config ownership

| Path | Purpose |
|------|---------|
| `config/ory/` | Placeholder for Kratos identity schema / Hydra config as-code (filled as stack hardens) |

Secrets stay in the secret store / Compose env — never committed.

### 4.4 Adapter readiness

- `internal/provider/ory` already targets admin HTTP APIs.
- M2/M3 exit requires at least one **live** smoke against the Compose stack (ProviderInfo + one read or provision path) — may land in a follow-up commit once digests/network allow image pulls.

### 4.5 Documentation

- This scope document
- Notes in `config/ory/README.md`
- Link from ADR index / M0 next-gate section (already points at M2/M3)

---

## 5. Work breakdown

| Step | Content | Status |
|------|---------|--------|
| **M2-A** | Scope doc + `provider.lock.yaml` + Compose overlay + config/ory README | **This commit** |
| **M2-B** | Minimal Kratos config (identity schema, courier stub), migrate + serve | Next |
| **M3-B** | Minimal Hydra config (URLs, secrets from env), migrate + serve | Next |
| **M2/M3-C** | Adapter smoke test job (optional CI profile) | After B |
| **M2/M3-D** | Resolve image digests when registry egress available | Parallel |

---

## 6. Exit criteria

Gate IAM-M2/M3 is **complete** when:

1. [ ] `provider.lock.yaml` pins Kratos and Hydra versions used by Compose/CI.
2. [ ] Digests resolved **or** explicitly accepted residual risk documented (same pattern as Keycloak R-1).
3. [ ] Compose overlay brings up Kratos + Hydra with **separate** Postgres databases.
4. [ ] Admin ports are not published as the default public surface (or documented as local-dev-only binds).
5. [ ] Kratos and Hydra health/ready endpoints succeed locally.
6. [ ] At least one adapter call against the stack succeeds (ProviderInfo or GetIdentity/Provision smoke).
7. [ ] No production IssuerTrust or client redirect changes.
8. [ ] This document marked Complete with evidence (compose logs / test output).

---

## 7. Risks

| ID | Risk | Mitigation |
|----|------|------------|
| **M23-R1** | Image digests unresolved | UNRESOLVED marker; resolve with registry egress |
| **M23-R2** | Accidental admin exposure | Compose binds admin to localhost only; prod network policy in infra |
| **M23-R3** | Shared DB with Keycloak | Separate service names and DB names in overlay |
| **M23-R4** | Version skew Kratos vs Hydra | Pin both to same minor line in lock file |
| **M23-R5** | Treating local stack as production-ready | Explicit non-prod only; M17/M18 for acceptance |

---

## 8. Next gates after M2/M3

- **IAM-M4** — Workload clients on Hydra (first runtime migration slice)
- **IAM-M5** — Migration ledger + human identity adapter path

---

## 9. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial M2/M3 scope; lock + compose overlay scaffold |
