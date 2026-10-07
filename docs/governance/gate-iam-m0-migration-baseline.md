# Gate IAM-M0 / IAM-MP0 — Multi-Provider Migration Baseline

**Status:** IAM repository rebaseline reconciled to ADR-IAM-0033; MP0 cross-repository acceptance and runtime reduction remain open  
**Date:** 2026-10-04  
**Gate:** IAM-MP0 / MP1 (ADR-IAM-0033 §§124–125); preserves historical IAM-M0 evidence  
**Primary repository:** `baobab-platform/baobab-iam`  
**Supersedes for migration purposes:** `docs/governance/gate-iam-0-discovery.md` (Keycloak-era programme discovery, 2026-09-10)  
**Does not supersede:** historical findings in Gate IAM-0; those remain the audit trail for the Keycloak programme  

---

## 1. Purpose

This successor baseline reconciles the earlier IAM-M0 inventory to Accepted ADR-IAM-0033. Kratos and Hydra already have isolated live evidence; Keycloak remains a permanent, bounded enterprise federation runtime. Target native authentication is Kratos; target general OAuth/workload authority is Hydra. No production capability is reassigned by this document.

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
- Classification rules from ADR-IAM-0033 (amending ADR-IAM-0019/0022), preserving historical migration evidence (preserve canonical identity; migrate provider bindings).
- Live Admin API export (users, credentials, MFA, Organizations, sessions, admin events) is **still required** where marked `LIVE-VERIFY` below; this draft is pre-filled from repository state only.

---

## 3. Classification legend

| Class | Meaning |
|-------|---------|
| **PRESERVE** | Baobab architectural asset; survives migration unchanged in meaning |
| **TRANSLATE** | Same intent; new provider form (e.g. Keycloak client JSON → Hydra client) |
| **REPLACE** | Keycloak-specific mechanism replaced by Ory + Baobab combination |
| **RETIRE** | Retire a particular legacy binding/capability after evidence; retained Keycloak federation runtime survives |
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
| `baobab-trade-workload` | TRANSLATE | Trade service account | Hydra; governed Shared credential profile | Prefer first in Gate IAM-M4 |
| `baobab-cms` | TRANSLATE | CMS resource server | Hydra | |
| `baobab-cms-admin` | TRANSLATE | CMS workforce SSO | Hydra + Kratos | Gate IAM-5 phase 2b done |
| `baobab-cms-workload` | TRANSLATE | CMS service account | Hydra; governed Shared credential profile | |
| `baobab-erp` | TRANSLATE | ERP resource server | Hydra | |
| `baobab-erp-admin` | TRANSLATE | iDempiere workforce SSO | Hydra + Kratos | ADR-0014 §9 email match deviation remains |
| `baobab-erp-workload` | TRANSLATE | ERP service account | Hydra; governed Shared credential profile | |
| `baobab-pulse` | TRANSLATE | Pulse resource server | Hydra | |
| `baobab-pulse-workload` | TRANSLATE | Pulse service account | Hydra; governed Shared credential profile | |
| `zuribeans-web` | TRANSLATE | ZuriBeans browser | Hydra + estate UX (Kratos) | Isolation tests PRESERVE |
| `zuribeans-backend-workload` | TRANSLATE | ZuriBeans backend | Hydra; governed Shared credential profile | |
| `thamani-web` | TRANSLATE / DEFER | Thamani browser | Hydra + estate UX | B2C/B2B architecture forks open (Gate IAM-7) |
| `thamani-backend-workload` | TRANSLATE | Thamani backend | Hydra; governed Shared credential profile | |

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
| `organization` | RETAIN provider-local / REMOVE business-authority semantics | Explicit CP/domain mapping | Useful federation routing remains; the provider object is not a CanonicalOrganization or membership grant |

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

## 7. Keycloak asset disposition under ADR-IAM-0033

These classifications govern planning and are not deletion instructions. The
committed inventory is the current evidence boundary. Enterprise IdPs, trust
certificates, broker users and provider-local Organizations require a fresh
non-production/live census before reduction; their existence or portability is
not inferred from a product feature list.

| Asset / capability | Disposition | Target and enforcement boundary |
|---|---|---|
| `config/realm/baobab-realm.json`, realm container and Keycloak database | RETAIN / REDUCE | Federation runtime; remove unrelated ownership only after capability-specific evidence |
| Native users, passwords, passkeys, MFA, verification and recovery | MIGRATE | Kratos; per-identity credential strategy, no unsafe import or automatic email linking |
| Native browser authentication and native session authority | MIGRATE | Kratos / estate BFF boundary; retain necessary federation sessions and logout support |
| General OAuth clients and workload clients in `config/clients/` | MIGRATE | Hydra; governed Shared credential profile, scopes/audiences and actual-consumer proof |
| General Baobab token authority | MIGRATE | Hydra; retained Keycloak protocol signing material is not Hydra's Baobab issuer authority |
| Enterprise SAML/OIDC IdPs and identity-broker configuration, when configured | RETAIN | Permanent enterprise federation capability; MP7 census and MP8 adapter proof required |
| Federation signing/encryption certificates and broker keys | RETAIN | Separate trust domain, rotation, least-privilege administration and DR |
| Keycloak Organizations used for federation discovery/configuration | RETAIN PROVIDER-LOCALLY | Explicit FederationTrust binding; never equal CanonicalOrganization, Tenant or business membership |
| Provider Organization identifiers or groups used as business authority | REMOVE SEMANTICS / MIGRATE AUTHORITY | CP and authoritative domain mappings; retain useful provider-local routing objects |
| Domain/business roles in provider configuration | REMOVE AUTHORITY / MIGRATE POLICY | CP/domain grants; no removal before replacement and isolation evidence |
| Native login/account theme | MIGRATE / REMOVE AFTER PROOF | Estate-owned UX; keep necessary broker/federation UX support |
| Federation admin/login events | RETAIN + NORMALIZE | Baobab audit provenance; legacy native event coverage retires only after parity |
| `scripts/bootstrap.sh` and Keycloak administration tooling | RETAIN / REDUCE | Preserve reproducibility and scoped federation management; native/client migration is separate |
| `upstream.lock.yaml`, Dockerfile, `docker-compose.yml` and Keycloak PostgreSQL | RETAIN / HARDEN | Approved digest pin, independent runtime/database/secrets; no automatic global teardown |
| Keycloak backup, restore, break-glass and revocation checks | RETAIN / RECONCILE | Capability-specific failure domains, containment and revoked-after-restore proof |
| SCIM / directory synchronization | DEFER | Independent provider decision; not assigned to Keycloak merely because it is retained |

**Retirement invariant:** `LEGACY_RETIRED` must describe retirement of a
particular legacy provider binding/capability, not disappearance of Keycloak.
The ledger still lacks capability ownership fields; MP18 must implement and
verify that invariant before enabling cutover. Existing Phase-C policy gates
remain closed. Do not weaken state transitions merely to reconcile wording.

**Freeze:** do not delete Keycloak's realm/runtime, database, locks, federation
IdPs, certificates or useful Organization configuration under old IAM-M19.
Replace that objective with verified capability reduction, MP19 certification
and MP20 operational acceptance.

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
| IAM-2 Keycloak foundation | Partial operational proof; image pin resolved | Retain/harden federation runtime under MP7/MP15/MP16; native capabilities migrate to MP5/MP6 |
| IAM-3 Canonical identity | Complete in CP | PRESERVE; dual ExternalIdentity under ADR-0022 |
| IAM-4 Workload identity | Complete | **IAM-M4** first migration slice |
| IAM-5 Workforce SSO | Phase 1–2b complete; later phases open | **IAM-M6** |
| IAM-6 ZuriBeans B2B | Phase 1 complete; isolation later | **MP7/MP17**; retain provider-local federation Organizations, decouple business affiliation |
| IAM-7 Thamani B2C | Scoped; forks open | **DEFER** product decisions; **IAM-M8** |
| IAM-8 Supplier | Scoped; domain ownership open | **DEFER**; **IAM-M9** |
| IAM-9 Medusa | Mostly satisfied via IAM-5 | **IAM-M10** |
| IAM-10 ERP | Partial; §9 deviation open | **IAM-M11** |
| IAM-11 Credentials/MFA | Phase 1; passkeys/step-up open | **IAM-M12** + ADR-0024 |
| IAM-12 Lifecycle | Phase 1; event SPI fork open | **IAM-M13** |
| IAM-13 Audit | Phase 1 | **IAM-M14** |
| IAM-14 DR | Phase 1; theme/restore proof open, image pin resolved | **MP16** |
| IAM-15 Multi-region | Phase A OK | **IAM-M16** + ADR-0027 |
| IAM-16 Hardening | Phase 1 | **IAM-M17** |

Deferred original work **must not** be finished on Keycloak only to be rewritten; implement on its assigned provider through neutral ports (ADR-IAM-0033). Retained Keycloak federation work is not deferred merely because native capabilities migrate.

---

## 10. ADR traceability (summary)

| ADR band | Migration stance |
|----------|------------------|
| 0001–0018 | Preserve architecture; amend provider-specific assumptions |
| 0019 | Decision to migrate; gate plan M0–M19 |
| 0020 | Provider-neutral adapter contract |
| 0021 | Kratos/Hydra runtime |
| 0022 | Dual-issuer, ledger, cutover, credential strategies |
| 0023–0032 | Preserve UX, assurance, federation, crypto, privacy and operational invariants across each assigned provider |
| 0033 | Controls multi-provider target, retained Keycloak federation, capability-specific reduction and MP0–MP20 sequencing |

Full row-level matrix (requirement → evidence → Keycloak-specific? → target component → M-gate) is a living appendix; maintain under `docs/governance/gate-iam-m0-adr-matrix.md` or a spreadsheet linked from this doc once filled.

---

## 11. Migration risk register

| ID | Risk | Severity | Mitigation / owner | Status |
|----|------|----------|--------------------|--------|
| **R-1** | Historical unresolved Keycloak image pin | High | Current `upstream.lock.yaml` records a real digest; CI checks registry/Dockerfile agreement | Resolved as repository pin; deployed-version proof remains separate |
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
| **M-R11** | Keycloak Organizations semantics assumed in tests/docs | Medium | Preserve routing-object tests; test explicit mapping and CP/Trade isolation separately | Open |
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

**Programme posture (2026-09-30):** Baobab IAM migration is treated as **greenfield for production
identity cutover** — there is no production dual-issuer window and no customer production traffic
to protect under M0. Static inventory from `config/` is authoritative for classification.
LIVE-VERIFY items that require a *live* Keycloak Admin API / production census are **waived**
below with owner and date so M0 can close and Phase A can proceed. Re-run the playbook
(`docs/operations/m0-live-verify-playbook.md`) before any shared non-prod dual-run or M18.

| # | Item | Status | Owner / date | Notes |
|---|------|--------|--------------|-------|
| 1 | Export live client list vs `config/clients/*` | **Waived** | Platform Architecture / 2026-09-30 | Greenfield: committed `config/clients/*` is the inventory |
| 2 | Redirect URIs + PKCE on public/admin clients | **Waived** | Platform Architecture / 2026-09-30 | Greenfield: use committed client JSON; re-verify when non-prod KC is stood up for dual-run prep |
| 3 | Human user census; hash algs; MFA rates | **Waived** | Platform Architecture / 2026-09-30 | No production human identity population for this programme stage |
| 4 | Organizations list classification | **Waived** | Platform Architecture / 2026-09-30 | Historical waiver only; superseded by RETAIN PROVIDER-LOCALLY / REMOVE business semantics under ADR-IAM-0033; fresh census required before MP7 |
| 5 | Auth flow graph | **Waived** | Platform Architecture / 2026-09-30 | Flows REPLACE under Kratos (ADR-0024); no live graph required for greenfield M0 |
| 6 | Admin events enabled | **Waived** | Platform Architecture / 2026-09-30 | Gate IAM-13 phase 1 assumed from prior programme; re-check on live stack before dual-run |
| 7 | Break-glass accounts / runbook | **Open (doc only)** | Platform Architecture / 2026-09-30 | Runbook exists (`break-glass-runbook.md`); live account proof deferred to non-prod exercise |
| 8 | Running KC version vs lockfile | **Waived** | Platform Architecture / 2026-09-30 | Pinned retained runtime; no global Keycloak end-of-life assumption |
| 9 | R-1 / Ory digest resolution | **Open residual** | Operator with registry egress | Historical unresolved status superseded by current digest-pinned `provider.lock.yaml` and `upstream.lock.yaml`; runtime and production acceptance still require evidence |
| 10 | Tests asserting KC-only URLs/claims | **Partial** | Platform Architecture / 2026-09-30 | Inventory deferred to M7+ rewrite list; integration suite still Keycloak-oriented by design until dual-run |

**Current digest policy (ADR-IAM-0033):**

- Keep approved resolved digest locks for all retained runtimes; no deletion of the Keycloak pin after native cutover.
- Unresolved or inconsistent pins block promotion. Earlier isolated-test tag allowances are historical waivers, not operational acceptance or permission to replace the current pins.

---

## 15. Historical IAM-M0 exit criteria (not MP0/MP20 acceptance)

Gate IAM-M0 is **closed** when:

1. This document (or successor) is merged with classification tables complete for all known assets.
2. LIVE-VERIFY checklist is done or explicitly waived with owner and date.
3. Migration risk register is accepted by Platform Architecture.
4. Rollback baseline §12 is documented (procedures exist; non-prod exercise preferred).
5. Phase 1 freeze list is acknowledged by `shared` / `baobab-cp` owners.
6. Explicit statement recorded: **no production identity cutover and no dual-issuer production traffic under M0.**

---

## 16. Next gate

**Next: MP3 provider/runtime-support projection and MP4 CP resolution → IAM adapter dispatch.**
IAM #69–#75 added governed trust revisions, live CP authority integration,
private authority composition and the permanent OIDC/SAML Keycloak federation
adapter. IAM #77 added PostgreSQL shared authority state and recovery fencing.
These increments supersede the earlier MP8-scaffold claim; deployed acceptance
remains outstanding. See [current programme status](iam-mp-programme-status.md)
and the [MP plan](iam-mp-implementation-plan.md).

Preserve CP canonical/platform authority. MP7 reduction still requires
replacement, rollback and actual-consumer evidence; it never deletes retained
enterprise federation. `internal/provider/keycloak/enterprise.go` is the
permanent adapter; compatibility parsing is not provider selection.

---

## 17. Document control

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 0.1 | 2026-09-27 | Platform Architecture (draft) | Initial migration baseline from repo config + ADR-0019/0022; LIVE-VERIFY pending |
| 0.2 | 2026-09-30 | Platform Architecture | Greenfield LIVE-VERIFY waivers; digest policy for non-prod vs production |


## 18. ADR-IAM-0033 execution control

The earlier M0 LIVE-VERIFY waivers describe the 2026-09-30 greenfield posture.
They do not waive MP7 federation inventory, MP19 certification or MP20 acceptance.
The [MP implementation plan](iam-mp-implementation-plan.md) controls dependencies,
repository ownership, exit evidence and the mapping from M0–M19 to MP0–MP20.
The YAML capability matrix is canonical for this repository's target allocation;
its Markdown is generated. Neither is a replacement for Shared's capability
catalogue or CP's runtime provider/binding authority.

| Version | Date | Change |
|---|---|---|
| 0.3 | 2026-10-04 | Rebaseline to ADR-IAM-0033; retain federation assets, scope retirement to capabilities, reconcile resolved digest evidence and publish dependent MP plan |
