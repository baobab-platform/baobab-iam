# IAM-N04 — Canonical support registration and connected development qualification

> **STATUS (31 October 2026): N04 SOURCE IN PROGRESS — DEVELOPMENT NOT CERTIFIED.**
> N01–N03 remain under their independent [development-completion hold](../governance/iam-n01-n03-development-closure-audit-2026-10-31.md). N04 must **not** reinterpret those held cases as staging/production-only, re-pin Shared, mark any canonical provider IMPLEMENTED, publish CP support, activate CP bindings or merge solely because this source or its fixture tests exist.

**Source PR:** N04 stacked above IAM #148 → #147 → #146 → #145; no PR has been merged by this increment.

**Architectural authorities:** Accepted ADR-IAM-0033 and 0020/0024/0025, Shared ADR-SHARED-042/043, [EA v2.3](https://github.com/baobab-platform/shared/blob/main/docs/architecture/EA-implementation-plan-v2.3-2026-10-20.md), [EA-DEV](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-v2.3-development-enablement-implementation-plan-2026-10-23.md) DEV-03/04/11/12/14/15 and [EA-XB v1.1](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-xb-v1.1-enterprise-corrective-architecture-2026-10-29.md). No new ADR, provider protocol, CP authority or canonical case ID is introduced.

## Ownership and required outcome

N04 delivers a **governed source-to-registered-runtime qualification** for native human and workload identity capabilities before protected approval. It does not transfer any owner's responsibilities.

| Required authority | Owner / supported path | What may be evidenced in isolated development | Explicitly forbidden inference |
| --- | --- | --- | --- |
| Native human credential, recovery, AAL and sessions | IAM → **Ory Kratos** | Signed/current human handoff, consent, recovery, AAL2, session and logout tests with real synthetic credentials | IAM creates a canonical CP Principal, a Market grant or enterprise client authorisation |
| OAuth/OIDC and workload issuer | IAM → **Ory Hydra** | Exact audience/scope client registration, real signed token and RFC7662 live status and revocation, independent issuer readback | An unexpired JWT alone grants a Tenant/business operation; an opaque admin-health probe certifies issued-token acceptance |
| Enterprise OIDC/SAML federation | IAM → **Keycloak**, retained permanently for federation | Real broker assertions and independently qualified federation identity mapping | Keycloak becomes native workload issuer or universal Baobab Principal authority; Kratos logout proves external enterprise-wide SLO |
| Canonical context, provider support/binding, grants, targets, current activity | **Control Plane** only | CP-registered development support and target lifecycle, current fresh resolution, artifact/profile/instance/tenant checks and withdrawal | A local IAM implementation flag or acceptance document registers or promotes CP support |
| Native resource/business action | **Consumer engine or estate owner** | Real Pulse/Payments/estate HTTP operation with own-native PEP, PostgreSQL/Qdrant/engine state, legitimate negatives and independently verified teardown | Mock, code-only middleware or simulated PSP settlement is real provider acceptance |

N04 must distinguish the **support-registration lifecycle**, which CP controls, from **construction conformance** (the existing executable provider census), **readiness observation** (C4-04A), **actual resource acceptance** (C4-04C) and **protected deployment approval** (DEV-13). All three published canonical provider supports currently remain **PARTIAL**. Nothing in N04 changes them.

## N04 engineering increment implemented on this branch

1. **`scripts/n04_development_gate.py`** checks original, owner-private, checksum-bound development receipts **without modifying them**. It reuses the N02/DEV-04 original seven-case verifier and recognises the existing C4-03B–E complete-case vocabulary rather than redefining them.
2. It requires all fourteen original C4-03B–E case booleans plus actual registered service contact, observed CP withdrawal while the bearer is still unexpired, exact IAM source SHA and refusal to claim production or physical-passkey certification. C4-03A's smaller read-only receipt cannot substitute.
3. It requires the original Infrastructure ENG-ONB-01..09 completed host receipts for **both** Shared-defined `pulse-intelligence` → `baobab-pulse` and `payments-sandbox` → `baobab-payments`: matching immutable IAM/Shared/CP/**Infrastructure** pins; exact run ID; independent native CP audit, four authority denials, Principal denial, CP/Hydra outage, observed capabilities, issuer/host teardown; and absence of protected/production claims.
4. It binds the actual N02 browser and original DEV-04 completed receipts to the **same** IAM SHA, Infrastructure run ID and pinned Shared/CP source; independent Pulse and Payments leases must have distinct run IDs. Unknown, missing, partial, drifted, duplicated or altered original evidence refuses the observation.
5. **`tests/unit/test_n04_development_gate.py`** provides negative-first fixture cases (tampered digests, extra/omitted cases, source and engine/profile drift, pending engine case, unverified native consequences, teardown/custody overclaims, stale/duplicate leases). **These are synthetic fixture tests, not actual evidence.**
6. CI now runs the N04 source-only and negative fixture tests under provider-contract. It **does not run** the real N04 gate against fabricated fixtures to assert acceptance.

**Important:** This gate intentionally exits **nonzero**, even when every supplied original receipt has internally consistent case labels and digests. Its highest classification is `N04_ORIGINAL_EVIDENCE_RECONCILED_UNATTESTED` (exit 3). A digest does not independently authenticate who produced a report or prove a current CP support/binding. Without evidence, exit 2 is HELD. There is no code path that turns this check into `IMPLEMENTED`, `PRODUCTION_READY` or a CP activation. A later independently reviewed acceptance process must verify live runtime provenance, exact registered owners and protected controls through their own sources.

## How to exercise the owner-qualified development lane

**Prerequisites:** Work at an immutable reviewed IAM source SHA and exact current reviewed Shared/CP pins; use a clean isolated development profile. Reconcile the frozen old Infrastructure source locks through **Infrastructure-owned** reviewed changes and keep native maker/checker Principals distinct. The immutable development suite must run and prove **real** Kratos, Hydra, CP, source-pinned BFF/estate and engine services; it must clean up the created clients, identities, databases and containers.

The first three original proofs are independent original sources: N02 Playwright (`browser-observation.json`), Infrastructure DEV-04 (`completed/receipt.json`) and full C4-03B–E (`receipt.json`, SHA-256-sum style checksum). The final two are **separate** actual Infrastructure engine-integration completed receipts for Pulse and Payments (the latter may record simulation, never a real PSP success). Never use `pkg/workloadresource` in-process fixture output as a substitute for the actual engine receipt.

The private receipt verifier can be invoked when these **already exist**:

```sh
python3 -B scripts/n04_development_gate.py \
  --iam-sha "$REVIEWED_IAM_SHA" \
  --shared-sha "$REVIEWED_SHARED_SHA" \
  --cp-sha "$REVIEWED_CP_SHA" \
  --infrastructure-sha "$REVIEWED_INFRASTRUCTURE_SHA" \
  --browser "$PRIVATE_RUN/n02/browser-observation.json" \
  --browser-digest "$PRIVATE_RUN/n02/browser-observation.sha256" \
  --int03c "$PRIVATE_RUN/int03c/completed/receipt.json" \
  --int03c-digest "$PRIVATE_RUN/int03c/completed/receipt.sha256.json" \
  --c403 "$PRIVATE_RUN/c403/receipt.json" \
  --c403-digest "$PRIVATE_RUN/c403/receipt.sha256" \
  --pulse "$PRIVATE_RUN/pulse/completed/receipt.json" \
  --pulse-digest "$PRIVATE_RUN/pulse/completed/receipt.sha256.json" \
  --payments "$PRIVATE_RUN/payments/completed/receipt.json" \
  --payments-digest "$PRIVATE_RUN/payments/completed/receipt.sha256.json"
```

All inputs must be **absolute owner-private paths to original evidence**, readable by the current process owner with mode 0600, and checksum sidecars must match the producer's original bytes. It will **not** contact IAM, CP, Keycloak, engine or Docker, and consequently **cannot independently certify** the claimed observations. Missing raw receipts and provenance remain BLOCKED.

Run the existing `go run ./cmd/c4-04-readiness -config ...` separately with **actual** reviewed private HTTPS/Ory/CP inputs. Its `OBSERVED_CURRENT` is transient and cannot be converted to a recorded CP registration or granted operation by this gate. CP's native registration/support/activation and C4-04B/C acceptance must be separately produced by **CP-owner** source and genuine actual consumers. Do not manufacture a C4-04 receipt until a reviewed producer and provenance schema exist.

## N04 remaining mandatory *development* work

- **N04-D01**: Reconcile N01's held Shared workload/scope registry. Validate the real compiled Kratos/Hydra/Keycloak adapters and the new profiles' exact registration bundles against the current immutable Shared checkout. No support-state promotion or synthetic provider grant.
- **N04-D02**: Implement owner-governed **CP** registration lifecycle and readback of actual development ProviderCapabilitySupport, provider instance, scoped binding, current configuration/security-domain reference and deployed artifact. Test wrong scope, version, facet, lifecycle, revoked credential and drift denial. A live C4-04A observation is not enough; CP owns its write operations and contract.
- **N04-D03**: Complete real same-source N02/DEV-04 browser + actual C4-03B–E and C4-04B/C development tests. Verify genuine identity, exact current caller, market/organisation/tenant, unexpired issuer and CP withdrawal, no automatic Keycloak fallback and negative coverage. Do not invent proof to resolve N02/N03 source-only holds.
- **N04-D04**: Validate real Pulse/Payments DEV-14/15 independent run receipts and engine-native PEP consequences under current IAM/CP authority, including replay, issuer/provider outage, revocation and teardown. Actual PSP settlement is a different qualification.
- **N04-D05**: Establish **reviewed** original producer authentication and independent source/run/artifact readback for C4-04B/C, plus deterministic orchestration/evidence archiving. N04's checksum-only readback deliberately **does not** claim this trust anchor.
- **N04-D06**: Pass all final-head CI/security/PG17/Ory/Keycloak and actual owner qualification cases. Remove inherited temporary source-format readback workflow files after review and re-run exact final heads.

**N04 development exit:** The owner-verified current CP support/binding, genuine provider+CP resource positive and all mandatory negative cases, engine receipts, exact reviewed source/artifact/provenance and full teardown are **actually observed**. Only after N01–N04 development exit may the independently approved **staging/production** gates of C4-03/C4-04, DEV-13 and EA-REL be the sole remaining work. Do not count a mere absence of configured protected resources as a development acceptance.

## Rollback and security

The N04 source gate is read-only. Discarding this branch removes the evidence readback and CI unit checks; it requires **no** CP/issuer/provider rollback because it grants nothing. A real development qualification run must revoke its own bounded client/identity credentials and remove its CP-owned synthetic context and labelled host resources through the Infrastructure owner, then retain original redacted receipts. Never commit tokens, DSNs, raw browser traces, real identity data, PII or production credentials.
