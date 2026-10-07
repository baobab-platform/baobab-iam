# Migration Rollback Baseline (Keycloak → Ory)

**Governing ADRs:** ADR-IAM-0019 §55–90; ADR-IAM-0022 (dual-issuer, cutover, continuity); ADR-0018 (DR invariants)  
**Related:** [gate-iam-m0-migration-baseline.md](../governance/gate-iam-m0-migration-baseline.md) §12; [disaster-recovery-runbook.md](./disaster-recovery-runbook.md); [break-glass-runbook.md](./break-glass-runbook.md); [m0-live-verify-playbook.md](./m0-live-verify-playbook.md)  
**Owner:** `baobab-platform/baobab-iam` (jointly with `baobab-cp`, `infrastructure` for IssuerTrust and data plane)  
**Status:** **Phase A baseline accepted for greenfield scaffolding** — dual-run / production abort procedures documented but not yet executable  
**Date:** 2026-09-30  

---

## Current authority and scope

Accepted ADR-IAM-0033 supersedes global Keycloak retirement assumptions in this
historical baseline. Keycloak remains the permanent enterprise federation/SSO
provider. Apply rollback only to the explicitly approved capability and tenant
scope; preserve retained federation realms, databases, clients, trust and SSO
infrastructure. A native-human or workload rollback does not authorise changing
enterprise federation authority. Historical Phase A statements below are dated
construction evidence, not a current deployment census or acceptance record.

The capability-specific migration ledger and live rollback proof remain open
under MP18. See [current execution evidence](../governance/iam-33-execution-evidence.md).
No production cutover or retirement is authorised by this runbook.

## 1. Purpose

This runbook defines the **rollback baseline** for the Keycloak → Ory migration.

It is **not** a substitute for the general [disaster-recovery-runbook.md](./disaster-recovery-runbook.md). DR covers “IAM is down / data is lost.” This document covers:

1. Establishing a **known-good Keycloak-era restore point** before dual-run or cutover.
2. **Aborting dual-run** (both issuers trusted) and returning to Keycloak-only trust.
3. **Aborting cutover** after Ory is primary but before Keycloak is retired.
4. Preserving **break-glass** and **kill-switch** capability on the path that remains authoritative.
5. **Greenfield / non-prod Ory foundation abort** (the only scenario that applies while production Keycloak is absent).

**Invariant (ADR-0018 / ADR-0022):** a rollback or restore MUST NOT silently resurrect revoked authority. Prefer “actors stay denied” over “availability at any cost.”

---

## 1.1 Greenfield context (Phase A — 2026-09-30)

The programme is still **greenfield** relative to production Keycloak:

| Fact | Implication for this baseline |
|------|-------------------------------|
| No production Keycloak traffic or LIVE-VERIFY against live KC | §3.1 realm export, §3.2 KC snapshot drill, §3.4 legacy break-glass re-verify, and §3.5 dual-run abort drill are **deferred** until a Keycloak environment exists (same class of waiver as M0 LIVE-VERIFY) |
| Ory work is scaffolding + optional local Compose | **Scenario C** is the active abort path for Phase A–B foundation work |
| CP Principal resolve is issuer+subject only (M1-C) | Abort never depends on `provider_type`; dual ExternalIdentity rows are independent |
| IssuerTrust dual-run not implemented in CP | Scenarios A/B cannot be executed in production until CP lands IssuerTrust switches |

**Phase A does not authorize dual-run or production issuer changes.** It only requires that abort procedures are written, ownership is clear, and non-prod Ory can be torn down without harming the Keycloak-oriented developer path.

Cross-links (Phase A hygiene):

| Work | Location |
|------|----------|
| IAM scaffolding M0–M5 | `baobab-iam` PR #42 (`feat/adr-iam-ory-migration`) |
| M1-B provider_type neutrality | `shared` PR #147 |
| M1-C resolve evidence | `baobab-cp` PR #224 |

---

## 2. When to use which document

| Situation | Document |
|-----------|----------|
| Keycloak or Ory data loss, infra failure, full IAM outage | [disaster-recovery-runbook.md](./disaster-recovery-runbook.md) |
| Governed admins locked out of realm admin path | [break-glass-runbook.md](./break-glass-runbook.md) |
| Dual-run or cutover must be reversed; migration decision undone | **This document** (Scenarios A/B) |
| Non-prod Ory foundation failed or abandoned | **This document** (Scenario C) |
| Compromised client/credential during migration window | [security-incident-runbook.md](./security-incident-runbook.md) first, then this if issuer trust must change |

---

## 3. Preconditions (must exist before dual-run traffic)

Complete these under Gate IAM-M0 / before Gate IAM-M18 production dual-run.

### 3.1 Git / artifact baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Git tag on `baobab-iam` | Annotated tag e.g. `pre-ory-dual-run-YYYYMMDD` pointing at last known-good Keycloak-oriented commit | IAM | **Deferred (greenfield)** — create immediately before first dual-run window; tip of Keycloak-safe main is interim baseline |
| Related tags | Matching tags or recorded SHAs for `baobab-cp`, `shared` if IssuerTrust or contracts changed for dual-run | CP / shared | **Deferred** — record PR #147 / #224 SHAs when dual-run is scheduled |
| Realm export | Off-box export of realm (clients, roles, flows) with **secrets redacted or referenced by secret-store ID only** | IAM + SecOps | **Deferred (greenfield)** — no production realm |
| Config freeze note | List of `config/clients/*`, `config/scopes/*`, `config/realm/*` SHAs included in the tag | IAM | **Process defined** — freeze at dual-run tag time from `config/` tree |

### 3.2 Data baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Keycloak DB snapshot procedure | Documented PITR or snapshot job that has been **executed once successfully in non-prod** | Infrastructure | **Deferred (greenfield)** — required before production dual-run |
| Snapshot retention | Retention covers at least the planned dual-run + cutover observation window | Infrastructure | **Deferred** with snapshot procedure |
| Secret inventory | Map of workload client secret IDs, bootstrap admin secret ID, signing material IDs (no secret values in Git) | Infrastructure + IAM | **Partial** — client inventory in M4 docs; secret-store IDs still operator-owned |

### 3.3 Trust / control-plane baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| IssuerTrust Keycloak-only config | Documented “production trusts only Keycloak issuer” configuration (code or config-as-code) | `baobab-cp` | **TODO** before dual-run |
| IssuerTrust dual-run config | Documented enable/disable procedure for accepting Keycloak **and** Hydra issuers | `baobab-cp` | **TODO** (M18) |
| IssuerTrust Ory-only config | Documented final state after successful cutover | `baobab-cp` | **TODO** (M18/M19) |
| Feature flag or config switch | Prefer explicit, auditable switch over silent code deploy for issuer set changes | CP + IAM | **TODO** |
| Principal resolve neutrality | Resolve by `(issuer, subject)` only; no authz on `provider_type` | `baobab-cp` | **Done (M1-C)** — PR #224 evidence |

### 3.4 Break-glass continuity

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Legacy break-glass tested | Master-realm bootstrap path still works per [break-glass-runbook.md](./break-glass-runbook.md) | IAM | **Deferred (greenfield)** — re-verify when KC environment exists |
| Target break-glass provisioned | Ory/Kratos admin or approved emergency path tested **before** Keycloak retirement (ADR-0022 §23) | IAM | Required before M19 |
| No gap rule | Never retire legacy break-glass until target path is verified | SecOps | Process |

### 3.5 Non-prod exercise

| Item | Requirement | Status |
|------|-------------|--------|
| Non-prod: tag → export → snapshot → restore Keycloak → `make bootstrap` (if needed) → `tests/integration/run.sh` | At least one successful drill | **Deferred (greenfield)** — blocks **production** dual-run only |
| Non-prod: enable dual IssuerTrust → disable dual → Keycloak-only still authenticates | Drill recorded | **Deferred** until IssuerTrust exists |
| Non-prod: Scenario C drill (stop Ory Compose, Keycloak path still default) | Documented once | **Required for Phase B M2/M3 residual** — operator may record when Compose is available |

Until §3.5 Keycloak dual-run drills are done, dual-run against **production** traffic is not authorized. Isolated non-prod Ory foundation (M2/M3) may still proceed under Scenario C.

---

## 4. Roles and authority

| Role | Authority |
|------|-----------|
| Platform Architecture / IAM lead | Declares migration abort or rollback |
| Security | Approves production issuer-trust changes; break-glass use |
| Infrastructure | Executes DB snapshot/restore; secret retrieval |
| `baobab-cp` on-call | Applies IssuerTrust configuration changes |
| Domain engine owners | Validate auth after re-point (smoke only unless full incident) |

Production issuer changes and production Keycloak restore require the same class of authority as DR declaration (ADR-0018 §88–89): not unilateral by a single engineer without recorded approval.

**Greenfield:** stopping local/non-prod Ory Compose (Scenario C) does **not** require Security dual-run approval; it is a developer hygiene action. Destroying shared non-prod Ory data stores still requires team agreement if others rely on that environment.

---

## 5. Scenario A — Abort dual-run (both issuers trusted → Keycloak only)

**Goal:** Stop accepting Ory/Hydra tokens; leave Keycloak as sole trusted issuer. Ory stack may remain running offline for diagnosis.

**Executable when:** IssuerTrust dual-run is live in the target environment (not Phase A).

### 5.1 Immediate actions

1. **Declare abort** — record time, reason, approver in the incident/migration log.
2. **Disable dual IssuerTrust in CP** — apply Keycloak-only trust config (§3.3).  
   - Do **not** delete Ory identities or Hydra clients yet (needed for forensics and possible retry).
3. **Confirm CP rejects Hydra-issued tokens** — negative test: known Hydra access token fails validation/context resolution.
4. **Confirm Keycloak path still works** — workforce admin login, one workload `client_credentials`, discovery + JWKS.
5. **Notify** domain engine owners and estate owners if any traffic had switched to Ory endpoints.
6. **Do not** mass-revoke Ory sessions unless security requires it; dual-run abort is a trust-boundary change, not necessarily a compromise.
7. **Ledger** — for any migration ledger rows advanced during dual-run, transition to `ROLLED_BACK` (or leave `DUAL_RUN` with explicit abandon note per ADR-0022); never leave false `CUTOVER`.

### 5.2 Verification checklist

- [ ] CP IssuerTrust lists only Keycloak issuer
- [ ] Keycloak OIDC discovery and JWKS reachable
- [ ] One human admin login succeeds (or workload-only if human path was never cut over)
- [ ] One workload client_credentials succeeds against Keycloak
- [ ] Hydra token is rejected by CP
- [ ] Break-glass Keycloak path still available
- [ ] Migration log updated; dual-run window closed in tracking
- [ ] Ory ExternalIdentity rows left in place or marked inactive — **not** bulk-deleted; Principal rows unchanged

### 5.3 What not to do

- Do not wipe the Ory databases on abort without Architecture + Security approval (destroys evidence and retry path).
- Do not re-enable dual-run without a new written decision and fresh baseline check.
- Do not “fix” CanonicalIdentity / Principal rows that were linked to Ory ExternalIdentity during dual-run; mark target ExternalIdentity inactive per ADR-0022 if abandoning that path.
- Do not gate abort success on `provider_type` values.

---

## 6. Scenario B — Abort cutover (Ory primary → return to Keycloak primary)

**Goal:** Ory was made primary; rollback makes Keycloak primary again and stops relying on Ory for production auth.

**Executable when:** Cutover window was opened (M18+) and Keycloak is not yet retired (pre-M19).

### 6.1 Preconditions for this scenario to be possible

- Keycloak runtime and DB still available (not yet decommissioned).
- Keycloak issuer still in IssuerTrust or can be re-added quickly.
- Client redirect URIs and secrets for Keycloak path still valid (or restorable from §3.1 export + secret store).
- Break-glass on Keycloak still works.

If Keycloak was already decommissioned (post M19), this scenario is **unavailable** — use full DR from Keycloak-era snapshots only if those snapshots still exist and policy allows.

### 6.2 Sequence

1. **Declare cutover abort** — time, reason, approver.
2. **Re-point IssuerTrust** to Keycloak primary (and optionally keep Hydra trusted briefly for drain — prefer short, explicit window).
3. **Re-point application OIDC endpoints** (discovery, authorization, token) to Keycloak where clients were switched to Hydra.
4. **Drain** — allow in-flight Ory sessions to expire or force re-login on Keycloak after a published time.
5. **Validate** Keycloak human + workload paths; CP context resolution; one engine smoke test each (Trade/CMS/ERP as applicable).
6. **Disable Hydra issuance for production clients** (Hydra admin: clear grant types or disable clients) if abort is permanent.
7. **Reconcile migration ledger** — mark affected rows `ROLLED_BACK` or equivalent (ADR-0022 state machine); do not leave rows in `CUTOVER` falsely.
8. **Security journal** — any identities disabled/revoked during the Ory-primary window must remain denied on Keycloak (manual list until automated journal exists; same gap as DR steps 10–11).

### 6.3 Verification checklist

- [ ] Production auth traffic uses Keycloak issuer
- [ ] CP does not require Hydra for success path
- [ ] Kill-switch still works on Keycloak (disable user + logout sessions)
- [ ] Break-glass Keycloak path verified
- [ ] Migration ledger updated
- [ ] Post-abort revocation list applied on Keycloak

---

## 7. Scenario C — Rollback after failed Ory-only foundation (non-prod) — **Phase A active path**

**Goal:** Non-prod Ory stack is broken or abandoned; return developers to Keycloak-only local/CI workflow without affecting production (there is no production dual-run).

### 7.1 Immediate actions

1. Stop Ory Compose/services (`docker compose -f docker-compose.ory.yml down` or environment equivalent).
2. Leave Keycloak Compose / default `make dev-up` as the documented local path.
3. Reset local `.env` / shell exports that pointed at Hydra/Kratos URLs back to Keycloak issuer URLs if any were set.
4. Confirm default CI remains offline for Ory (`provider-contract` job only; no forced image pull).
5. **No** CP production IssuerTrust change (production never dual-ran).
6. Keep Ory config and migration packages in Git on the feature branch; do **not** delete migration work to “clean up.”

### 7.2 Verification checklist

- [ ] Ory containers stopped (or never started)
- [ ] Keycloak-oriented local path documented as default
- [ ] CI green without `ORY_SMOKE` / `ORY_PROVISION`
- [ ] No production config changed
- [ ] Decision recorded if shared non-prod Ory data was wiped

### 7.3 What not to do

- Do not delete `internal/provider`, `internal/migration`, or `config/ory/` solely because a smoke failed.
- Do not enable production dual-run to “test rollback.”

---

## 8. Relationship to Keycloak DR restore

If rollback requires **restoring Keycloak data** from backup (corruption, bad migration script against KC):

1. Follow [disaster-recovery-runbook.md](./disaster-recovery-runbook.md) steps owned by Infrastructure + IAM (deploy pin, bootstrap caveats, integration suite).
2. Then re-apply §5 or §6 issuer trust as appropriate.
3. Re-apply any post-backup revocations (DR steps 10–11 gap still applies).
4. **R-1:** production image digest may still be unresolved; record actual running image ID during restore.

Bootstrap limitations (from DR runbook) still apply: `make bootstrap` fills **missing** objects; it does not fully reconcile drift on existing objects. Diff against `config/` if restore yields stale clients/scopes.

**Greenfield:** this section activates when a Keycloak environment and backups exist.

---

## 9. Evidence to retain after any rollback

| Evidence | Retention note |
|----------|----------------|
| Declaration time, approver, reason | Incident / migration log |
| IssuerTrust config before/after | CP change record |
| Migration ledger state transitions | IAM |
| Admin-event / security-event extracts for the window | SecOps |
| Integration / smoke test output | IAM |
| Whether Ory data was retained or wiped | Architecture decision record |
| Scenario C: Compose stop time + operator | Team channel / PR comment acceptable for non-prod |

---

## 10. Exit criteria

### 10.1 Phase A — rollback baseline ready for greenfield continuation

Phase A may mark this document **accepted for scaffolding continuation** when:

- [x] Scenarios A/B/C written with clear ownership
- [x] Greenfield deferrals explicit (do not block M1–M5 scaffolding)
- [x] Scenario C is the documented abort path for non-prod Ory foundation
- [x] CP resolve neutrality recorded (M1-C) — abort does not depend on `provider_type`
- [x] Dual-run / production issuer change explicitly **not** authorized by Phase A
- [x] Open gaps listed without papering over

### 10.2 Gate IAM-M0 §12 — ready for non-prod dual-run experiments

- [ ] §3.1 Git tag procedure agreed (tag need not exist until immediately before dual-run)
- [ ] §3.2 DB snapshot procedure documented and non-prod tested once
- [ ] §3.3 IssuerTrust enable/disable steps drafted with CP
- [ ] §3.4 Legacy break-glass re-verified
- [ ] §3.5 Non-prod restore or dual-run abort drill completed **or** explicitly deferred with owner/date (defer blocks **production** dual-run only)

### 10.3 Gate IAM-M18 — production dual-run

- [ ] All of §10.2 without deferral on §3.5
- [ ] Target (Ory) break-glass path tested if cutover is in scope for that window
- [ ] Communication plan for forced re-login if abort occurs

---

## 11. Open gaps (do not paper over)

| Gap | Impact | Tracking |
|-----|--------|----------|
| No automated post-backup security journal | Manual revocation re-apply on restore/abort | IAM-14 / M15; DR runbook steps 10–11 |
| Bootstrap does not fully reconcile existing objects | Manual diff after KC restore | DR runbook; IAM-14 |
| R-1 image digest unresolved | Pin integrity for KC restore | gate-iam-0 / upstream.lock.yaml |
| IssuerTrust not yet implemented in CP | Dual-run/abort cannot be executed in prod | ADR-0022; CP backlog (post M1-C) |
| Ory break-glass not designed in detail | Blocks safe M19 | ADR-0022 §23; M6/M18 |
| Greenfield: no production KC | Snapshot/export/break-glass drills deferred | M0 LIVE-VERIFY waivers; this §1.1 |

---

## 12. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial migration rollback baseline for Gate IAM-M0; drills and CP IssuerTrust steps TODO |
| 0.2 | 2026-09-30 | Phase A greenfield status; Scenario C active path; M1-B/C links; Phase A exit criteria; deferrals explicit |
