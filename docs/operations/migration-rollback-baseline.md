# Migration Rollback Baseline (Keycloak → Ory)

**Governing ADRs:** ADR-IAM-0019 §55–90; ADR-IAM-0022 (dual-issuer, cutover, continuity); ADR-0018 (DR invariants)  
**Related:** [gate-iam-m0-migration-baseline.md](../governance/gate-iam-m0-migration-baseline.md) §12; [disaster-recovery-runbook.md](./disaster-recovery-runbook.md); [break-glass-runbook.md](./break-glass-runbook.md)  
**Owner:** `baobab-platform/baobab-iam` (jointly with `baobab-cp`, `infrastructure` for IssuerTrust and data plane)  
**Status:** Draft — Phase 0 (Gate IAM-M0)  
**Date:** 2026-09-27  

---

## 1. Purpose

This runbook defines the **rollback baseline** for the Keycloak → Ory migration.

It is **not** a substitute for the general [disaster-recovery-runbook.md](./disaster-recovery-runbook.md). DR covers “IAM is down / data is lost.” This document covers:

1. Establishing a **known-good Keycloak-era restore point** before dual-run or cutover.
2. **Aborting dual-run** (both issuers trusted) and returning to Keycloak-only trust.
3. **Aborting cutover** after Ory is primary but before Keycloak is retired.
4. Preserving **break-glass** and **kill-switch** capability on the path that remains authoritative.

**Invariant (ADR-0018 / ADR-0022):** a rollback or restore MUST NOT silently resurrect revoked authority. Prefer “actors stay denied” over “availability at any cost.”

---

## 2. When to use which document

| Situation | Document |
|-----------|----------|
| Keycloak or Ory data loss, infra failure, full IAM outage | [disaster-recovery-runbook.md](./disaster-recovery-runbook.md) |
| Governed admins locked out of realm admin path | [break-glass-runbook.md](./break-glass-runbook.md) |
| Dual-run or cutover must be reversed; migration decision undone | **This document** |
| Compromised client/credential during migration window | [security-incident-runbook.md](./security-incident-runbook.md) first, then this if issuer trust must change |

---

## 3. Preconditions (must exist before dual-run traffic)

Complete these under Gate IAM-M0 / before Gate IAM-M18 production dual-run.

### 3.1 Git / artifact baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Git tag on `baobab-iam` | Annotated tag e.g. `pre-ory-dual-run-YYYYMMDD` pointing at last known-good Keycloak-oriented commit | IAM | **TODO** |
| Related tags | Matching tags or recorded SHAs for `baobab-cp`, `shared` if IssuerTrust or contracts changed for dual-run | CP / shared | **TODO** |
| Realm export | Off-box export of realm (clients, roles, flows) with **secrets redacted or referenced by secret-store ID only** | IAM + SecOps | **TODO** |
| Config freeze note | List of `config/clients/*`, `config/scopes/*`, `config/realm/*` SHAs included in the tag | IAM | **TODO** |

### 3.2 Data baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Keycloak DB snapshot procedure | Documented PITR or snapshot job that has been **executed once successfully in non-prod** | Infrastructure | **TODO** |
| Snapshot retention | Retention covers at least the planned dual-run + cutover observation window | Infrastructure | **TODO** |
| Secret inventory | Map of workload client secret IDs, bootstrap admin secret ID, signing material IDs (no secret values in Git) | Infrastructure + IAM | **TODO** |

### 3.3 Trust / control-plane baseline

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| IssuerTrust Keycloak-only config | Documented “production trusts only Keycloak issuer” configuration (code or config-as-code) | `baobab-cp` | **TODO** (before dual-run) |
| IssuerTrust dual-run config | Documented enable/disable procedure for accepting Keycloak **and** Hydra issuers | `baobab-cp` | **TODO** |
| IssuerTrust Ory-only config | Documented final state after successful cutover | `baobab-cp` | **TODO** |
| Feature flag or config switch | Prefer explicit, auditable switch over silent code deploy for issuer set changes | CP + IAM | **TODO** |

### 3.4 Break-glass continuity

| Item | Requirement | Owner | Status |
|------|-------------|-------|--------|
| Legacy break-glass tested | Master-realm bootstrap path still works per [break-glass-runbook.md](./break-glass-runbook.md) | IAM | **TODO** re-verify |
| Target break-glass provisioned | Ory/Kratos admin or approved emergency path tested **before** Keycloak retirement (ADR-0022 §23) | IAM | Required before M19 |
| No gap rule | Never retire legacy break-glass until target path is verified | SecOps | Process |

### 3.5 Non-prod exercise

| Item | Requirement | Status |
|------|-------------|--------|
| Non-prod: tag → export → snapshot → restore Keycloak → `make bootstrap` (if needed) → `tests/integration/run.sh` | At least one successful drill | **TODO** |
| Non-prod: enable dual IssuerTrust → disable dual → Keycloak-only still authenticates | Drill recorded | **TODO** |

Until §3.5 is done, dual-run against **production** traffic is not authorized. Isolated non-prod Ory foundation (M2/M3) may still proceed.

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

---

## 5. Scenario A — Abort dual-run (both issuers trusted → Keycloak only)

**Goal:** Stop accepting Ory/Hydra tokens; leave Keycloak as sole trusted issuer. Ory stack may remain running offline for diagnosis.

### 5.1 Immediate actions

1. **Declare abort** — record time, reason, approver in the incident/migration log.
2. **Disable dual IssuerTrust in CP** — apply Keycloak-only trust config (§3.3).  
   - Do **not** delete Ory identities or Hydra clients yet (needed for forensics and possible retry).
3. **Confirm CP rejects Hydra-issued tokens** — negative test: known Hydra access token fails validation/context resolution.
4. **Confirm Keycloak path still works** — workforce admin login, one workload `client_credentials`, discovery + JWKS.
5. **Notify** domain engine owners and estate owners if any traffic had switched to Ory endpoints.
6. **Do not** mass-revoke Ory sessions unless security requires it; dual-run abort is a trust-boundary change, not necessarily a compromise.

### 5.2 Verification checklist

- [ ] CP IssuerTrust lists only Keycloak issuer
- [ ] Keycloak OIDC discovery and JWKS reachable
- [ ] One human admin login succeeds (or workload-only if human path was never cut over)
- [ ] One workload client_credentials succeeds against Keycloak
- [ ] Hydra token is rejected by CP
- [ ] Break-glass Keycloak path still available
- [ ] Migration log updated; dual-run window closed in tracking

### 5.3 What not to do

- Do not wipe the Ory databases on abort without Architecture + Security approval (destroys evidence and retry path).
- Do not re-enable dual-run without a new written decision and fresh baseline check.
- Do not “fix” CanonicalIdentity rows that were linked to Ory ExternalIdentity during dual-run; mark target ExternalIdentity inactive per ADR-0022 if abandoning that path.

---

## 6. Scenario B — Abort cutover (Ory primary → return to Keycloak primary)

**Goal:** Ory was made primary; rollback makes Keycloak primary again and stops relying on Ory for production auth.

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

## 7. Scenario C — Rollback after failed Ory-only foundation (non-prod)

**Goal:** Non-prod Ory stack is broken; return developers to Keycloak-only local/CI workflow.

1. Stop Ory compose/services; leave Keycloak compose as default `make dev-up`.
2. Reset local `.env` / docs to Keycloak issuer URLs.
3. No CP production IssuerTrust change required if production never dual-ran.
4. Keep Ory config in Git on a branch; do not delete migration work.

---

## 8. Relationship to Keycloak DR restore

If rollback requires **restoring Keycloak data** from backup (corruption, bad migration script against KC):

1. Follow [disaster-recovery-runbook.md](./disaster-recovery-runbook.md) steps owned by Infrastructure + IAM (deploy pin, bootstrap caveats, integration suite).
2. Then re-apply §5 or §6 issuer trust as appropriate.
3. Re-apply any post-backup revocations (DR steps 10–11 gap still applies).
4. **R-1:** production image digest may still be unresolved; record actual running image ID during restore.

Bootstrap limitations (from DR runbook) still apply: `make bootstrap` fills **missing** objects; it does not fully reconcile drift on existing objects. Diff against `config/` if restore yields stale clients/scopes.

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

---

## 10. Exit criteria for “rollback baseline ready” (Gate IAM-M0 §12)

Gate IAM-M0 may mark rollback baseline **ready for non-prod dual-run experiments** when:

- [ ] §3.1 Git tag procedure agreed (tag need not exist until immediately before dual-run)
- [ ] §3.2 DB snapshot procedure documented and non-prod tested once
- [ ] §3.3 IssuerTrust enable/disable steps drafted with CP
- [ ] §3.4 Legacy break-glass re-verified
- [ ] §3.5 Non-prod restore or dual-run abort drill completed **or** explicitly deferred with owner/date (defer blocks **production** dual-run only)

Gate IAM-M18 production dual-run additionally requires:

- [ ] All of the above without deferral on §3.5
- [ ] Target (Ory) break-glass path tested if cutover is in scope for that window
- [ ] Communication plan for forced re-login if abort occurs

---

## 11. Open gaps (do not paper over)

| Gap | Impact | Tracking |
|-----|--------|----------|
| No automated post-backup security journal | Manual revocation re-apply on restore/abort | IAM-14 / M15; DR runbook steps 10–11 |
| Bootstrap does not fully reconcile existing objects | Manual diff after KC restore | DR runbook; IAM-14 |
| R-1 image digest unresolved | Pin integrity for KC restore | gate-iam-0 / upstream.lock.yaml |
| IssuerTrust not yet implemented in CP | Dual-run/abort cannot be executed in prod | ADR-0022; CP backlog |
| Ory break-glass not designed in detail | Blocks safe M19 | ADR-0022 §23; M6/M18 |

---

## 12. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial migration rollback baseline for Gate IAM-M0; drills and CP IssuerTrust steps TODO |
