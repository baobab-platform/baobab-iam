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

## Registered provider gate — executable resource-side adapter (N04-D02 source increment)

N04 now adds **`pkg/workloadresource/cp_binding.go`**, **`registered.go`** and corresponding TLS/HTTP negative tests. The provider-neutral resource SDK reads **CP's existing** `POST /internal/identity-runtime/v1/binding` using a distinct reviewed `identity-runtime:read` workload credential, exact CP-minted ProviderID/EngineInstanceID, Organisation/DigitalEstate scope, configuration/security-domain references and facet `WORKLOAD_TOKEN_ISSUANCE`. The read validates registered ACTIVE provider, instance and binding, VERIFIED support, nonzero profile revision, matching deployment artifact SHA-256 and fresh CP evidence. Missing/ambiguous/unknown fields, duplicate scope, foreign target, scope/facet drift, revoked reader or TLS error DENY without cache/retry/failover.

**Use in an actual owner resource:** create the N03 `workloadresource.Gate` from the directly authenticated issuer/JWKS, RFC7662, independently registered `context:validate` CP caller and the **native engine's own PEP**. Construct `NewCPRegisteredBinding` with independently approved IAM provider target and a *different* private CP read credential. Wrap the actual signed-token `*workloadresource.Gate` with `NewRegisteredGate(resourceGate, cpBinding)` and install the result using `NewMiddleware`. The public constructor and HTTP middleware reject arbitrary unsigned `ResourceAuthorizer` implementations: unit-test fakes are not a supported deployment admission path. The request requires current CP-registered issuer support → N03 signed/original issuer current and native CP/business authority → **CP issuer registration re-read** before forwarding to the actual engine handler. A withdrawn/moved support binding during the request must DENY. A successful read is not a transaction or durable support grant; the native business commit fence must recheck as appropriate.

This read-only SDK **does not insert provider rows**, certify a capability, create CP Profiles, obtain AdministrativeGrants or grant a new client a scope. CP's existing `identityRuntimeAuthorityHandler`, `IdentityRuntimeProfileRepository`, current PostgreSQL snapshot and provider certification/changeset lifecycle remain the only registration authorities. The unit tests use **local TLS fake CP services**, not a live CP/engine qualification. The protected production host will refuse missing TLS and caller credentials.

**Development blocker remains:** no N04 evidence currently proves a real CP-governed ProviderCapabilitySupport activation/withdrawal with the current IAM client, nor actual Pulse/Payments external-engine resource operation. Do not rewrite this source implementation as a live PASS.

## Independent CI producer/archive identity (N04-D05 source increment)

`scripts/n04_github_archive_readback.py` provides a **separate trusted provenance check** for an original *private* GitHub Actions artifact archive. It obtains the actual workflow run and artifact digest from GitHub's authenticated HTTPS API, verifies the exact allowlisted repository/workflow name, immutable executed source SHA, completed/**successful** run, artifact-to-run relation, unexpired artifact and SHA-256 of the **original ZIP archive**. It uses a read-only `GH_TOKEN` from the runtime environment, refuses HTTP redirects, proxies, foreign repositories, missing digest or silently paginated artifact results, and never logs a token. Retained output is `GITHUB_ACTIONS_ORIGINAL_ARCHIVE_DIGEST_ONLY` with every support/production/consumer acceptance flag **false**.

```sh
# Private owner-only original GitHub Actions artifact archive, 0600.
# GH_TOKEN is supplied by a dedicated read-only secret boundary.
python3 -B scripts/n04_github_archive_readback.py \
  --repository baobab-platform/infrastructure \
  --workflow .github/workflows/dev15-connected.yml \
  --run-id "$REVIEWED_RUN_ID" \
  --artifact-id "$REVIEWED_ARTIFACT_ID" \
  --run-source-sha "$REVIEWED_INFRASTRUCTURE_SHA" \
  --original-archive "$PRIVATE_RUN/original-actions-artifact.zip"
```

A GitHub artifact hash independently anchors the archive and its claimed *CI job*, **not** the authenticity of a particular extracted runtime observation, current CP permission, accepted engine outcome or self-asserted receipt booleans. The N04 original-receipt check, producer-specific semantics, actual CP/engine execution and independent reviewer/teardown evidence remain additional compulsory gates. In particular, existing Infrastructure DEV-15 connected CI may correctly exit successfully while Payments cases remain **BLOCKED**; a successful job alone must never change those case results to PASS. The N04 source-negative tests are in `tests/unit/test_n04_github_archive_readback.py`. 

## Evidence audit: earlier real DEV-15 connected run (29 October 2026) — source-stale, not an N04 qualification

To distinguish **existing** real developer capability from missing N04 requalification, inspect Infrastructure's original [DEV-15 connected workflow run 40831958626](https://github.com/baobab-platform/infrastructure/actions/runs/40831958626), executed at Infrastructure commit `712c140eefb923408cf6d7fe08b2329f80f51940`. This is a successful *workflow* containing a successful Pulse suite and a correctly **BLOCKED** Payments suite, not a successful N04 packet. Job logs and sanitized completed host receipts explicitly show:

| Original development owner | Observed case results | Required N04 disposition |
| --- | --- | --- |
| **Pulse** `pulse-intelligence` | All original ENG-ONB-01..09 and all listed PULSE native scenarios **PASS**; genuine issuer, CP, PostgreSQL/Qdrant, cross-tenant and replay/teardown evidence reported. `native_audits_joined=10`, 4 authority denials; independent host and issuer cleanup true. | **Historical real-component source run only**. It pinned IAM `0ad103606b9705fcb33c468ea01b54d8ce76f9ae`, CP `055568a6ce2f2c22dd76273329b57b12429188bd`, Shared `32b71f3335e566daeb58246f17fcbbf162cf7f53` and Infrastructure observed harness `d2ee4e8a2182d7b04b53a5bb858217b049ee5ef0` — not the N04 stacked heads. Requalify with current reviewed pins, newly registered CP provider-read authority and N04 double-read gate. |
| **Payments** `payments-sandbox` | Original ENG-ONB-01,02,04,05,07,08,09 **PASS** with synthetic money-only service, revocation, outage, idempotency/teardown. **ENG-ONB-03** BLOCKED/AUTHORITY_UNQUALIFIED, **ENG-ONB-06** BLOCKED/NATIVE_NOT_IMPLEMENTED. Native **PAYMENTS-ACTOR-MARKET-CURRENCY**, **PAYMENTS-MISSING-MANDATE** BLOCKED/AUTHORITY_UNQUALIFIED, **PAYMENTS-EVENT-REPLAY** BLOCKED/NATIVE_NOT_IMPLEMENTED. `native_audits_joined=0` (not an accepted join). | **DEVELOPMENT INCOMPLETE**, independent of protected staging. The five original case meanings must be implemented in their authoritative Payments/CP/IAM owners, rerun against genuine current runtime and only then admitted as pass. Real PSP settlement remains separately unqualified; never relabel simulated capture/refund as real funds. |

The original success of an Infrastructure CI job with an **expected nonzero Payments qualifier** does not mean Payments or IAM-N04 passed. Its workflow explicitly verifies the correct BLOCKED matrix. These observations are **older immutable source receipts**, not a new run by this N04 PR; do not modify or reissue them as current evidence. This row remains open until actual owner commits and original receipts are re-created and independently inspected.

## Read current development CP registration with executable N04 operator command

`cmd/n04-development-read` implements a **real, read-only CP HTTPS call**, rather than consuming an operator's `healthy=true` statement. It requires `BAOBAB_ENVIRONMENT=development`, an absolute mode-`0600` configuration file, dedicated private CA trust bundle and dedicated mode-`0600` short-lived CP `identity-runtime:read` bearer file. The canonical target is a **CP-issued** ProviderID, EngineInstanceID, Organisation, DigitalEstate, configuration and security-domain reference, under the reviewed source pins. This command is for disposable development operators, not browser/tenant supplied input.

Example **shape only** (replace every placeholder from a genuinely reviewed development CP/Shared/IAM owner receipt; do not treat these as valid IDs or URLs):

```json
{
  "schema": "baobab.iam.n04.dev-read-config.v1",
  "environment": "development",
  "run_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "iam_source_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "shared_source_sha": "cccccccccccccccccccccccccccccccccccccccc",
  "cp_source_sha": "dddddddddddddddddddddddddddddddddddddddd",
  "cp_origin": "https://cp.example.invalid",
  "ca_root_file": "/private/n04/cp-root.pem",
  "token_file": "/private/n04/cp-runtime-reader.jwt",
  "target": {
    "provider_id": "provider_example",
    "engine_instance_id": "ei_example",
    "organisation_id": "org_example",
    "estate_id": "estate_example",
    "configuration_reference": "ref_configexample",
    "security_domain_reference": "ref_securityexample"
  }
}
```

```sh
BAOBAB_ENVIRONMENT=development go run ./cmd/n04-development-read \
  --settings /private/n04/exact-reviewed-source.json \
  > /private/n04/actual-cp-read-observation.json
```

Only a genuine, current `200 no-store` CP binding reply with ACTIVE provider/instance/binding, VERIFIED support, correct immutable target and artifact, and fresh evidence produces `cp_current_registered_read_observed=true`. **Even then** it emits `classification=UNATTESTED_LIVE_CP_READ_ONLY`, `native_engine_qualified=false`, `independent_witness=false`, `protected_accepted=false`. It cannot bootstrap its own OAuth client or CP AdministrativeGrant. The owner must separately produce and independently read back those authorities, invoke native Pulse/Payments resources and witness teardown. Failed or unavailable CP/issuer never yields a PASS receipt. Local TLS tests and private source negatives are enforced in CI; they do **not** replace the actual developer execution.

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
