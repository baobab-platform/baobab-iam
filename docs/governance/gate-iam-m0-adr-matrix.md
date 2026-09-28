# Gate IAM-M0 — ADR Traceability Matrix (Migration Edition)

**Status:** Draft — Phase 0 (evidence refreshed 2026-09-28 for feature branch)  
**Date:** 2026-09-27  
**Parent:** [gate-iam-m0-migration-baseline.md](./gate-iam-m0-migration-baseline.md)  
**Purpose:** Map ADR-0001–0032 requirements to current evidence, provider coupling, migration target, and M-gate.  
**Rule:** No runtime change under M0. Update this matrix as LIVE-VERIFY completes.

---

## Legend

| Column | Meaning |
|--------|---------|
| **KC-specific?** | Yes = implementation depends on Keycloak mechanics; Partial = mixed; No = Baobab/standards |
| **Class** | PRESERVE / TRANSLATE / REPLACE / RETIRE / DEFER (see baseline §3) |
| **Target** | Where the requirement lands after migration |
| **M-gate** | Migration gate that proves or implements the requirement |

---

## Branch evidence snapshot (`feat/adr-iam-ory-migration`)

| Artifact | Path |
|----------|------|
| Provider contract (M1) | `internal/provider/` |
| Ory foundation config (M2/M3) | `config/ory/`, `docker-compose.ory.yml`, `provider.lock.yaml` |
| Workload CLI (M4) | `cmd/provision-workload/` |
| Migration ledger domain (M5) | `internal/migration/` |
| M1–M5 scope/evidence docs | `docs/governance/gate-iam-m*.md` |
| LIVE-VERIFY playbook | `docs/operations/m0-live-verify-playbook.md` |

---

## A. Original programme ADRs (0001–0018)

| ADR | Key requirements (summary) | Current evidence | KC-specific? | Class | Target | M-gate |
|-----|----------------------------|------------------|--------------|-------|--------|--------|
| **0001** | Auth ≠ authz; IAM proves identity; CP context; domain engines authorize | Authority model documented; layering tests incomplete | No | PRESERVE | Unchanged architecture | All (invariant) |
| **0002** | Keycloak as IdP; realm/clients/bootstrap; image pin | Realm/clients/bootstrap exist; digest **UNRESOLVED (R-1)** | Yes | RETIRE (as IdP choice) | Superseded by 0019 | M0 inventory; M19 retirement |
| **0003** | Trust boundaries; issuer validation; no IdP as business authority | CP OIDC verify + actor_type; issuer in Principal path | Partial | PRESERVE | CP + standards validation | M1, M6+ |
| **0004** | CanonicalIdentity; ExternalIdentity = issuer+subject; no email merge | Gate IAM-3 complete in CP; migration package rejects email-only resolve | No | PRESERVE | CP; dual ExternalIdentity in dual-run | M5, M18 (ADR-0022) |
| **0005** | Realm ≠ Tenant ≠ LegalEntity ≠ Org | Model in CP; KC Organizations used for ZuriBeans phase 1 | Partial | PRESERVE model / REPLACE KC Org objects | CP + Trade; not Ory org | M7 |
| **0006** | OIDC/OAuth token profile; actor_type; PKCE; scopes | Scopes in config; freeze list documented | Partial | PRESERVE profile / TRANSLATE issuance | Hydra token + same claims/scopes | M3, M4, M6 |
| **0007** | Workload identity; client credentials; isolation | Gate IAM-4 complete; M4 inventory + provision CLI on branch | Partial | PRESERVE semantics / TRANSLATE clients | Hydra client_credentials + CP registry | **M4** (first) |
| **0008** | Platform authorization in CP; fail-closed | CP resolve pipeline; domain engines separate | No | PRESERVE | CP | — (not IdP) |
| **0009** | Workforce SSO; privileged access; MFA for admins | IAM-5 phase 1–2b (Trade/CMS admin OIDC); later phases open | Partial | TRANSLATE | Hydra + Kratos + CP roles | **M6** |
| **0010** | ZuriBeans B2B; buyer isolation; multi-company | IAM-6 phase 1 (KC Organizations); isolation later open | Yes (Orgs) | REPLACE KC Org / PRESERVE isolation reqs | CP + Trade + estate UX | **M7** |
| **0011** | Thamani B2C customer identity | Scoped; OIDC termination + guest claim forks open | Partial | DEFER product / TRANSLATE when decided | Hydra + Kratos + estate | **M8** |
| **0012** | Supplier representative identity | Scoped; supplier-domain ownership open | Partial | DEFER ownership / TRANSLATE auth only | IAM auth + supplier domain | **M9** |
| **0013** | MedusaJS auth integration | Mostly via IAM-5 admin OIDC; authMethodsPerActor fixed | Partial | TRANSLATE | Hydra/OIDC config; minimal code | **M10** |
| **0014** | iDempiere SSO; issuer+subject mapping | Workforce client + context endpoints; **§9 email match deviation** | Partial | TRANSLATE / fix deviation | Hydra + mapping by iss+sub | **M11** |
| **0015** | Password policy; MFA; passkeys; recovery; step-up | Phase 1 password policy + conditional OTP; passkeys/step-up open | Yes (flows) | REPLACE flows / PRESERVE policy intent | Kratos + ADR-0024 | **M12** |
| **0016** | Disable; session revoke; deprovision; events | Kill-switch helper on provider interfaces (branch); KC proven historically | Partial | PRESERVE semantics / REPLACE provider ops | Adapter + CP | **M13** |
| **0017** | Audit; security events; secret redaction | Phase 1 redaction proven on KC admin events | Partial | PRESERVE contracts / TRANSLATE source | Ory events → Baobab events | **M14** |
| **0018** | HA; backup; DR; revoked survives restore | DR runbook exists; restore exercise **not** proven | Partial | PRESERVE objectives / REPLACE runtime | Kratos/Hydra DB + ADR-0021/0027 | **M15** |

---

## B. Migration and successor ADRs (0019–0032)

| ADR | Key requirements (summary) | Current evidence | KC-specific? | Class | Target | M-gate |
|-----|----------------------------|------------------|--------------|-------|--------|--------|
| **0019** | Migrate to Kratos+Hydra; provider-neutral architecture; M0–M19 gates | ADR accepted; baseline + matrix; branch implements M1–M5 scaffolding | N/A (decision) | PRESERVE decision | Entire programme | **M0** (this gate) |
| **0020** | Provider contract; capability interfaces; no business semantics in IdP | `internal/provider` on feature branch + CI | No | PRESERVE | `baobab-iam` adapter + `shared` contracts | **M1** |
| **0021** | Separate Kratos/Hydra; separate DBs; public vs admin; pinned images | `docker-compose.ory.yml`, `config/ory/*`, `provider.lock.yaml` (digests UNRESOLVED) | No | PRESERVE | Deployments + lock file | **M2 / M3** |
| **0022** | Dual ExternalIdentity; migration ledger; credential strategies; dual-issuer | `internal/migration` domain + memory store; M5 scope doc; dual-issuer still CP | N/A | PRESERVE | CP IssuerTrust + IAM ledger | **M5, M18, M19** |
| **0023** | Estate-owned auth UX; BFF/session boundary | ADR only | No | PRESERVE | ZuriBeans/Thamani UX | **M7 / M8** |
| **0024** | Assurance levels; MFA/passkeys; step-up | Partially IAM-11; policy ADR new | No | PRESERVE policy | Kratos + CP policy | **M12** |
| **0025** | Identity proofing; recovery; high-risk rebinding | Not implemented | No | PRESERVE | Kratos + business rules | **M12 / M13** |
| **0026** | Enterprise federation; B2B SSO; org trust | Not started | Deployment-dep. | DEFER until needed | Kratos federation + CP | Later / M6+ |
| **0027** | Multi-region; residency; HA/DR topology | IAM-15 phase A; later phases open | No | PRESERVE | Infra + Ory topology ≠ Market | **M16** |
| **0028** | Signing keys; rotation; secrets; trust distribution | Secrets ops partial; Hydra keys Tier-0 | Partial | PRESERVE | Secret store + Hydra JWKS | **M3, M17** |
| **0029** | SecOps; threat detection; compromise containment | Incident runbook exists | No | PRESERVE | Ops + adapter events | **M14 / M17** |
| **0030** | Privacy; retention; erasure; compliance | Not migration-blocking | No | PRESERVE | CP + Kratos retention config | Parallel |
| **0031** | Admin; delegated admin; break-glass governance | Break-glass runbook exists | Partial | PRESERVE / TRANSLATE | CP + dual break-glass in cutover | **M6, M18** |
| **0032** | SLOs; capacity; upgrade; operational acceptance | Partial hardening (IAM-16) | No | PRESERVE | Ops acceptance for cutover | **M17 / M18** |

---

## C. Cross-cutting invariants (must remain true after migration)

From ADR-0019 §116 and baseline §13. These are not optional rows — they are exit checks for M18/M19.

| Invariant | KC-specific today? | How verified post-migration |
|-----------|--------------------|-----------------------------|
| Authentication ≠ Authorization | No | CP + domain engines still own authz |
| Identity Provider ≠ Control Plane | No | Adapter does not resolve Tenant/Capability |
| IdP Organization ≠ Tenant / LegalEntity / BuyerOrg | Yes (KC Orgs) | No Ory org treated as Tenant; CP is SoR |
| CanonicalIdentity ≠ provider subject | No | Dual ExternalIdentity; CI id stable |
| Valid token ≠ valid Baobab context | No | CP context resolution still required |
| Valid Ory session ≠ active entitlement | No | Membership revoke independent of session |
| Workload identity ≠ human identity | Partial | Separate Hydra clients; actor_type claims |
| Supplier auth ≠ supplier approval | No | Domain ownership unchanged |
| Successful DR restore ≠ restored authorization | Partial | M15 exercise: revoked stays revoked |

---

## D. Gap list (matrix-driven; blocks or shapes later gates)

| Gap | Source ADR / gate | Blocks | Action |
|-----|-------------------|--------|--------|
| R-1 unresolved Keycloak digest | 0002, IAM-0 | Production KC pin only | Resolve or accept residual risk until M19 |
| LIVE-VERIFY user/credential/MFA census | 0015, 0022 | M5 credential strategy mix | Follow `m0-live-verify-playbook.md` |
| KC Organizations still in isolation story | 0010, IAM-6 | M7 test rewrite | Classify each Org object; rewrite tests for CP/Trade |
| Thamani OIDC termination + guest claim | 0011 | M8 | Product decision |
| Supplier-domain ownership | 0012 | M9 | Ownership decision |
| ADR-0014 §9 email vs iss+sub | 0014 | Clean M11 | Fix mapping on Ory path |
| Event SPI vs Admin Events poll | 0016 | M13 design | Prefer adapter normalization over KC SPI |
| DR restore + reconciliation unproven | 0018 | M15 exit | Schedule non-prod exercise |
| Provider interfaces not on `main` | 0020 | M1 close | Open/merge PR for this branch |
| Ory image digests UNRESOLVED | 0021 | M2/M3 hard pin | Registry egress |
| Durable migration ledger store | 0022 | M5 production | Memory store is pilot-only |
| IssuerTrust dual-issuer not in CP | 0022 | M18 | CP change before dual-run traffic |

---

## E. Suggested matrix maintenance

1. After each LIVE-VERIFY item, update **Current evidence** and **Class** if classification changes.
2. When an M-gate closes, set evidence to the gate scope doc + PR links.
3. Do not delete rows; mark **RETIRE** with date when Keycloak-only requirements are dropped.

---

## F. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Initial migration matrix from baseline + ADR set 0001–0032 |
| 0.2 | 2026-09-28 | Branch evidence snapshot; refresh 0020–0022 / 0007 / 0016 rows |
