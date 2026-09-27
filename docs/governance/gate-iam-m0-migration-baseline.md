# Gate IAM-M0 — Migration Baseline (Keycloak → Ory)

**Status:** Draft — Phase 0 in progress  
**Date:** 2026-09-27  
**Gate:** IAM-M0 (ADR-IAM-0019 §56 / §90; ADR-IAM-0022)  
**Primary repository:** `baobab-platform/baobab-iam`  
**Supersedes for migration purposes:** `docs/governance/gate-iam-0-discovery.md` (Keycloak-era programme discovery, 2026-09-10)  
**Does not supersede:** historical findings in Gate IAM-0; those remain the audit trail for the Keycloak programme  

---

## 1. Purpose

Gate IAM-M0 establishes the **migration-specific baseline** before any Ory runtime is introduced or any production identity is cut over.

This gate produces:

1. Keycloak asset inventory (config + known live behaviour)
2. Classification of every artifact: **PRESERVE / TRANSLATE / REPLACE / RETIRE / DEFER**
3. Implemented-capability roll-up (gates IAM-0…16 vs migration gates M1…)
4. ADR traceability matrix (0001–0032 → evidence → target)
5. Migration risk register
6. Rollback baseline requirements
7. Explicit freeze list for Phase 1 (contracts)

**No runtime migration occurs under this gate.**

---

## 2. Method

- Static inventory from committed config under `config/`, `scripts/`, `docs/`, `upstream.lock.yaml`, CI workflows.
- Cross-reference with Gate IAM-0…16 scope documents and README status as of `main` @ `6891527d…`.
- Classification rules from ADR-IAM-0019 §56 and ADR-IAM-0022 (preserve canonical identity; migrate provider bindings).
- Live Admin API export (users, credentials, MFA, Organizations, sessions, admin events) is **still required** where marked `LIVE-VERIFY` below; this draft is pre-filled from repository state only.

---

## 3. Classification legend

| Class | Meaning |
|-------|---------|
| **PRESERVE** | Baobab architectural asset; survives migration unchanged in meaning |
| **TRANSLATE** | Same intent; new provider form (e.g. Keycloak client JSON → Hydra client) |
| **REPLACE** | Keycloak-specific mechanism replaced by Ory + Baobab combination |
| **RETIRE** | Not carried forward |
| **DEFER** | Open product/architecture decision; do not implement against Keycloak solely to rewrite |

---

## 4. Client inventory

Source: `config/clients/*.json` on `main`.

| Logical client ID (filename) | Class | Typical use | Target (Ory) | Notes |
|------------------------------|-------|-------------|--------------|-------|
| `baobab-control-plane` | TRANSLATE | Resource server / audience | Hydra client (resource) | Bearer-style audience |
| `baobab-control-plane-admin` | TRANSLATE | Workforce admin (PKCE) | Hydra public/confidential + Kratos login | Onboarding roles attached |
| `baobab-trade` | TRANSLATE | Trade resource server | Hydra | |
| `baobab-trade-admin` | TRANSLATE | Trade workforce SSO | Hydra + Kratos | Gate IAM-5 phase 2a done |
| `baobab-trade-workload` | TRANSLATE | Trade service account | Hydra client_credentials | Prefer first in Gate IAM-M4 |
| `baobab-cms` | TRANSLATE | CMS resource server | Hydra | |
| `baobab-cms-admin` | TRANSLATE | CMS workforce SSO | Hydra + Kratos | Gate IAM-5 phase 2b done |
| `baobab-cms-workload` | TRANSLATE | CMS service account | Hydra client_credentials | |
| `baobab-erp` | TRANSLATE | ERP resource server | Hydra | |
| `baobab-erp-admin` | TRANSLATE | iDempiere workforce SSO | Hydra + Kratos | ADR-0014 §9 email match deviation remains |
| `baobab-erp-workload` | TRANSLATE | ERP service account | Hydra client_credentials | |
| `baobab-pulse` | TRANSLATE | Pulse resource server | Hydra | |
| `baobab-pulse-workload` | TRANSLATE | Pulse service account | Hydra client_credentials | |
| `zuribeans-web` | TRANSLATE | ZuriBeans browser | Hydra + estate UX (Kratos) | Isolation tests PRESERVE |
| `zuribeans-backend-workload` | TRANSLATE | ZuriBeans backend | Hydra client_credentials | |
| `thamani-web` | TRANSLATE / DEFER | Thamani browser | Hydra + estate UX | B2C/B2B architecture forks open (Gate IAM-7) |
| `thamani-backend-workload` | TRANSLATE | Thamani backend | Hydra client_credentials | |

**Stability rule (ADR-0019 §50):** keep logical client IDs stable where practical so CP and engines need not rename references.

**LIVE-VERIFY:** redirect URIs, secret storage location, service-account role bindings, actual token claims (`actor_type`, scopes).

---

## 5. Scope inventory

Source: `config/scopes/*.json`.

| Scope name | Class | Target | Notes |
|------------|-------|--------|-------|
| `actor-type-human` | PRESERVE (name) / TRANSLATE (issuance) | Hydra scope + token profile | Semantic must survive |
| `actor-type-workload` | PRESERVE / TRANSLATE | Hydra scope | Workload path Gate IAM-M4 |
| `context-resolve` | PRESERVE / TRANSLATE | Hydra scope | CP context resolution |
| `erp-integrate` | PRESERVE / TRANSLATE | Hydra scope | ERP integration |
| `onboarding-request` | PRESERVE / TRANSLATE | Hydra scope | CP onboarding |
| `onboarding-authorise` | PRESERVE / TRANSLATE | Hydra scope | CP onboarding |
| `organization` | TRANSLATE / REPLACE | Review | May be Keycloak Organizations–coupled; re-map to CP/Trade affiliation, not Ory org |

**Rule:** do not rename stable Baobab scopes merely because the provider changed (ADR-0019 §51).

---

## 6. Role / governance inventory

| Artifact | Class | Target | Notes |
|----------|-------|--------|-------|
| `config/governance/role-policy.json` toxic combination `onboarding-maker-checker` | PRESERVE (policy intent) / TRANSLATE (enforcement) | CP AdministrativeGrant / admission rules; keep `scripts/check-role-policy.sh` until CP owns it | Maker-checker must not live only in IdP |
| Client roles on `baobab-control-plane-admin` (`onboarding-requester`, `onboarding-authoriser`) | TRANSLATE | Hydra/Kratos + CP entitlement model | Prerequisites require `cp:platform-admin` realm role |
| Keycloak realm roles (e.g. `cp:platform-admin`) | REPLACE | CP membership / capability model | Do not copy roles into Ory as business authority (ADR-0022 §26–27) |
| Keycloak client roles generally | CLASSIFY per role | IAM admin vs OAuth vs domain | Mechanical “copy all roles” is forbidden |

---

## 7. Realm / provider-specific inventory

| Artifact | Class | Target | Notes |
|----------|-------|--------|-------|
| `config/realm/baobab-realm.json` | REPLACE | Kratos schemas + Hydra config + adapter | Export is Keycloak-shaped |
| Keycloak Organizations (Gate IAM-6 phase 1) | REPLACE | CP + Trade buyer affiliation; isolation **requirements** PRESERVE | Org *objects* are provider-specific |
| Browser flows / conditional OTP | REPLACE | Kratos flows + assurance policy (ADR-0024) | |
| Themes (`loginTheme`/`accountTheme: baobab`) | RETIRE / REPLACE | Digital Estate UX (ADR-0023); known missing theme left open under IAM-14 | |
| Admin Events API / event-listener SPI choice | REPLACE | Ory events → Baobab security events via adapter (Gate IAM-M14) | Architectural fork under IAM-12 |
| `scripts/bootstrap.sh` Keycloak kcadm paths | REPLACE | Ory bootstrap + adapter provisioning | |
| `upstream.lock.yaml` Keycloak 26.7.4 + **UNRESOLVED** digest | RETIRE after cutover; **R-1 still open** for remaining Keycloak life | New `provider.lock.yaml` for Kratos/Hydra digests | |
| Dockerfile Keycloak image | REPLACE | Kratos + Hydra images (digest-pinned) | ADR-0021 |
| `docker-compose.yml` Keycloak + Postgres | TRANSLATE / REPLACE | Kratos + Hydra + separate DBs | ADR-0021 §14 |

---

## 8. Baobab assets to PRESERVE (do not redesign)

| Asset | Owner | Evidence / notes |
|-------|--------|------------------|
| `CanonicalIdentity` / `ExternalIdentity` (issuer+subject) | `baobab-cp` | Gate IAM-3 complete |
| Workload registry semantics | `baobab-cp` / IAM | Gate IAM-4 complete |
| Scope *names* and actor-type distinction | shared / IAM | Config + CP enforcement |
| CP context resolution | `baobab-cp` | |
| Domain authorization (Trade, ERP, CMS) | domain engines | |
| Kill-switch intent (disable + revoke sessions) | IAM + CP | Gate IAM-12 phase 1 proven on Keycloak |
| Cross-estate isolation tests (ZuriBeans ≠ Thamani) | IAM tests | PRESERVE as tests against new issuer |
| Audit redaction requirements | IAM + CP | Gate IAM-13 phase 1 |
| DR invariants (revoked remains revoked after restore) | IAM + infra | Still unproven end-to-end — see risks |
| SBOM / secret scan / foundation CI patterns | shared workflows | |

---

## 9. Implemented-capability roll-up (original gates → migration)

| Original gate | Phase-1 status (approx.) | Migration disposition |
|---------------|--------------------------|------------------------|
| IAM-0 Discovery | Complete (Keycloak-era) | Superseded by **this** document for migration |
| IAM-2 Keycloak foundation | Partial; R-1 open | Do not further harden Keycloak except security fixes; foundation work moves to M2/M3 |
| IAM-3 Canonical identity | Complete in CP | PRESERVE; dual ExternalIdentity under ADR-0022 |
| IAM-4 Workload identity | Complete | **IAM-M4** first migration slice |
| IAM-5 Workforce SSO | Phase 1–2b complete; later phases open | **IAM-M6** |
| IAM-6 ZuriBeans B2B | Phase 1 complete; isolation later | **IAM-M7**; Organizations → REPLACE |
| IAM-7 Thamani B2C | Scoped; forks open | **DEFER** product decisions; **IAM-M8** |
| IAM-8 Supplier | Scoped; domain ownership open | **DEFER**; **IAM-M9** |
| IAM-9 Medusa | Mostly satisfied via IAM-5 | **IAM-M10** |
| IAM-10 ERP | Partial; §9 deviation open | **IAM-M11** |
| IAM-11 Credentials/MFA | Phase 1; passkeys/step-up open | **IAM-M12** + ADR-0024 |
| IAM-12 Lifecycle | Phase 1; event SPI fork open | **IAM-M13** |
| IAM-13 Audit | Phase 1 | **IAM-M14** |
| IAM-14 DR | Phase 1; theme/R-1/open | **IAM-M15** |
| IAM-15 Multi-region | Phase A OK | **IAM-M16** + ADR-0027 |
| IAM-16 Hardening | Phase 1 | **IAM-M17** |

Deferred original work **must not** be finished on Keycloak only to be rewritten; implement on provider-neutral/Ory path where applicable (ADR-0019 §88).

---

## 10. ADR traceability (summary)

| ADR band | Migration stance |
|----------|------------------|
| 0001–0018 | Preserve architecture; amend provider-specific assumptions |
| 0019 | Decision to migrate; gate plan M0–M19 |
| 0020 | Provider-neutral adapter contract |
| 0021 | Kratos/Hydra runtime |
| 0022 | Dual-issuer, ledger, cutover, credential strategies |
| 0023–0032 | UX, assurance, proofing, federation, multi-region, crypto, SecOps, privacy, admin, production governance — implement on Ory path |

Full row-level matrix (requirement → evidence → Keycloak-specific? → target component → M-gate) is a living appendix; maintain under `docs/governance/gate-iam-m0-adr-matrix.md` or a spreadsheet linked from this doc once filled.

---

## 11. Migration risk register

| ID | Risk | Severity | Mitigation / owner | Status |
|----|------|----------|--------------------|--------|
| **R-1** | Keycloak image digest still `UNRESOLVED` in `upstream.lock.yaml` | High (while Keycloak remains) | Resolve from environment with quay.io egress; do not treat as production pin | **Open** (carried from IAM-0) |
| **M-R1** | Password/TOTP/passkey import incomplete for some identities | High | Per-identity credential strategy (ADR-0022 §16–20); test fixtures before bulk | Open |
| **M-R2** | Dual-issuer window too long or misconfigured in CP | High | Explicit IssuerTrust registry; time-boxed; metrics on both issuers | Open |
| **M-R3** | Admin APIs of Kratos/Hydra exposed beyond adapter | Critical | Network policy; only `baobab-iam` + controlled tooling (ADR-0021) | Open |
| **M-R4** | CanonicalIdentity duplicated on migration | Critical | Migration ledger keyed by source issuer+subject → existing CI (ADR-0022 §7–9) | Open |
| **M-R5** | Session continuity / forced mass re-login | Medium | Communicate cutover; optional dual session acceptance window | Open |
| **M-R6** | Break-glass gap during cutover | High | Provision and test target break-glass before retiring legacy (ADR-0022 §23) | Open |
| **M-R7** | Theme / UX ownership lag (estates not ready) | Medium | ADR-0023; workforce can use interim UI; estates own final UX | Open |
| **M-R8** | Thamani architecture forks block M8 | Medium | Product decision before IAM-M8 code | Open (DEFER) |
| **M-R9** | Supplier-domain ownership blocks M9 | Medium | Ownership decision before IAM-M9 | Open (DEFER) |
| **M-R10** | DR “revoked survives restore” still unproven | High | Required under IAM-M15; do not claim complete until exercised | Open |
| **M-R11** | Keycloak Organizations semantics assumed in tests/docs | Medium | Rewrite tests for CP/Trade isolation, not KC Org objects | Open |
| **M-R12** | Role policy still only enforced by IAM script | Medium | Move toxic-combination rules to CP grants (already noted in role-policy.json) | Open |

---

## 12. Rollback baseline (required before Phase 2+)

Document and store:

1. **Git tag** of last known-good Keycloak-oriented `baobab-iam` (and related CP/shared commits if dual-run is live).
2. **Realm export** (or automated export job) stored off-box with secrets redacted / secrets referenced by ID only.
3. **Postgres snapshot procedure** for the Keycloak database that has been tested at least once in non-prod.
4. **Re-point procedure:** how clients and CP IssuerTrust revert to Keycloak-only if dual-run or cutover is aborted.
5. **Break-glass verification** on the legacy path still works after any failed cutover attempt.

Until these exist, Phase 2+ (Ory foundation in shared environments) may proceed in **isolated non-prod** only; no dual-run against production traffic.

---

## 13. Phase 1 freeze list (inputs to Gate IAM-M1)

Do not change the *meaning* of these without an ADR amendment:

- `CanonicalIdentity` / `ExternalIdentity` (issuer + subject)
- Logical client ID strings listed in §4
- Scope names in §5 (except explicit retirement of `organization` if classified REPLACE)
- Actor-type human vs workload distinction
- Toxic combination: onboarding requester ≠ authoriser
- Kill-switch semantics: disable identity + revoke sessions ⇒ cannot act
- Isolation requirement: ZuriBeans credentials/redirects must not authenticate as Thamani and vice versa

Provider-neutral Go contracts (`internal/provider`) may be introduced in M1 without changing the above meanings.

---

## 14. LIVE-VERIFY checklist (complete before closing M0)

- [ ] Export live client list and compare to `config/clients/*`
- [ ] Confirm redirect URIs and PKCE settings per public client
- [ ] Count human users; sample password hash algorithms; MFA/WebAuthn enrolment rates
- [ ] List Organizations and map each to PRESERVE requirement vs REPLACE object
- [ ] Capture authentication flow graph (browser, conditional OTP)
- [ ] Confirm admin event logging still enabled (Gate IAM-12/13)
- [ ] Confirm break-glass accounts and runbook still valid
- [ ] Record actual Keycloak version running vs `upstream.lock.yaml` 26.7.4
- [ ] Attempt digest resolution for R-1 from an environment with registry egress
- [ ] Inventory integration tests that assert Keycloak-specific URLs or claims

---

## 15. Exit criteria

Gate IAM-M0 is **closed** when:

1. This document (or successor) is merged with classification tables complete for all known assets.
2. LIVE-VERIFY checklist is done or explicitly waived with owner and date.
3. Migration risk register is accepted by Platform Architecture.
4. Rollback baseline §12 is documented (procedures exist; non-prod exercise preferred).
5. Phase 1 freeze list is acknowledged by `shared` / `baobab-cp` owners.
6. Explicit statement recorded: **no production identity cutover and no dual-issuer production traffic under M0.**

---

## 16. Next gate

**Gate IAM-M1 — Provider-neutral contracts**  
Stabilize Principal / ExternalSubject / capability interfaces in `baobab-iam` and published contracts in `shared`; ensure CP resolution does not require Keycloak-specific business fields.

Provider scaffold reference: `internal/provider` (interfaces + Ory/Keycloak adapter skeletons).

---

## 17. Document control

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 0.1 | 2026-09-27 | Platform Architecture (draft) | Initial migration baseline from repo config + ADR-0019/0022; LIVE-VERIFY pending |
