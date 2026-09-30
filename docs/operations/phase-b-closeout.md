# Phase B closeout — Ory foundation + M4 residual (greenfield)

**Status:** Closed for in-repo scaffolding (2026-09-30)  
**Branch / PR:** `feat/adr-iam-ory-migration` — [PR #42](https://github.com/baobab-platform/baobab-iam/pull/42)  
**Normative ADRs:** ADR-IAM-0019 (M0–M19 order), ADR-IAM-0020, ADR-IAM-0021, ADR-0007  
**Environment posture:** **Greenfield** — no production dual-run, no IssuerTrust change, no Keycloak retirement  

---

## 1. What Phase B covered

| Action | Gate | Outcome |
|--------|------|--------|
| **B-1** Image pin correction | M2/M3-D | `oryd/kratos` + `oryd/hydra` **v26.2.0** with multi-arch digests in `provider.lock.yaml` + Compose digest pins |
| **B-2** Admin-plane readiness | M2/M3-C | `Adapter.CheckReady`, httptest offline tests, expanded `ORY_SMOKE=1` path |
| **B-3** M4 residual hygiene | M4 | `NormalizeAllowedScopes` (`context:resolve` → `context-resolve`), offline provision/disable tests, CLI `CheckReady` |

Phase A (M0 waivers, M1-B/C cross-repo, rollback baseline v0.2) remains prerequisite context; this note does not re-open those gates.

---

## 2. In-repo deliverables (done)

### Foundation (M2/M3)

| Artifact | Path |
|----------|------|
| Version + digests | `provider.lock.yaml` |
| Compose overlay | `docker-compose.ory.yml` |
| Kratos / Hydra config | `config/ory/**` |
| Readiness | `internal/provider/ory/readiness.go` |
| Smoke (opt-in) | `internal/provider/ory/smoke_test.go` |
| Scope | `docs/governance/gate-iam-m2-m3-ory-foundation-scope.md` (v0.6) |
| Operator smoke | `docs/operations/ory-foundation-smoke.md` |

### Workload path (M4)

| Artifact | Path |
|----------|------|
| Client inventory | `docs/governance/gate-iam-m4-client-inventory.md` |
| Scope | `docs/governance/gate-iam-m4-workload-hydra-scope.md` (v0.3) |
| Provision CLI | `cmd/provision-workload` |
| Scope TRANSLATE | `provider.NormalizeAllowedScopes` + hydra adapter |
| Offline tests | `internal/provider/ory/hydra_workload_test.go` |
| **Live evidence checklist** | `docs/operations/m4-live-evidence-checklist.md` |

### Offline verification (agent / CI)

```text
go test ./internal/provider/ ./internal/provider/ory/ ./internal/migration/ -count=1
```

Live Docker Compose and `ORY_SMOKE` / `ORY_PROVISION` were **not** executable in the agent environment (no Docker). That residual is **explicit**, not silent.

---

## 3. Explicit non-claims (Phase B)

Phase B does **not**:

- Authorize production dual-issuer or CP `IssuerTrust` changes (M18)
- Retire or disable production Keycloak (M19)
- Bulk-migrate human identities (M5 runtime)
- Treat offline httptest coverage as a substitute for operator live evidence
- Change freeze-list client IDs or scope **meanings**

---

## 4. Residual register (must clear before claiming M2/M3/M4 Complete)

| ID | Residual | Owner | Blocks |
|----|----------|-------|--------|
| **PB-R1** | Live Compose up + health/ready on pinned digests | Operator workstation | M2/M3 exit criteria 5–6 |
| **PB-R2** | `ORY_SMOKE=1` green log attached to PR or ops ticket | Operator | M2/M3-C evidence |
| **PB-R3** | `ORY_PROVISION=1` for `baobab-trade-workload` + client_credentials token | Operator | M4 exit criteria 1, 5 |
| **PB-R4** | Rotate credentials exercised once on non-prod Hydra | Operator | M4 exit criterion 4 (rotate leg) |
| **PB-R5** | Re-verify digests against intended registry mirror before any shared non-prod promotion | Platform | Production-adjacent envs only |

Use **`docs/operations/m4-live-evidence-checklist.md`** (and foundation smoke ops note) to capture PB-R1–R4.

---

## 5. Exit decision

| Question | Answer |
|----------|--------|
| May Phase **C / Gate IAM-M5 design** start? | **Yes** — design and in-memory ledger domain only |
| May production or shared dual-run start? | **No** — blocked until rollback baseline Scenario C/D authorization + residuals above |
| Is M2/M3/M4 “Complete”? | **No** — scaffolding + offline tests Complete; live evidence open |

---

## 6. Document control

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-09-30 | Phase B closeout after pin, CheckReady, M4 residual hygiene |
