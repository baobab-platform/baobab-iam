# ADR-IAM-0033 implementation plan

**Status:** Sequenced implementation plan; repository MP0/MP1 reconciliation proposed.
No runtime reduction, cutover or production acceptance is authorised by this plan.
**Date:** 2026-10-04.
**Authority:** Accepted ADR-IAM-0033, preserving the security and canonical-authority
invariants of ADR-IAM-0019–0032 where not amended.

## 1. Verified baseline and audit corrections

| Repository | Reviewed immutable main | Finding |
|---|---|---|
| IAM | `a7d205bdbe6390e35be45cba5fe50b35342d845e` | ADR-0033 Accepted; Ory/provider-neutral foundations preserved; matrix/baseline still implied global Keycloak retirement |
| Shared | `540b4aa627afacaee9f7f2ad5889723ff08d3bd5` | Canonical capability provider/support/binding, principal, external identity and assurance contracts already exist; dedicated federation trust/provider-instance contracts not found in the reviewed contract tree |
| CP | `c84063cb07dce76e1ffac4b12fa29c5e4e5ec855` | Existing capability-domain resolver and provider/binding persistence must be evaluated for reuse; current context authority is after #255 |
| Infrastructure | `4996cc9e0410f0d4ffb08ce71bd19432fdc158c1` | Accepted infrastructure/workload identity ADR-Infra-0013 remains relevant; deployment/residency/DR integration needs a focused MP7/MP15/MP16 audit |

The IAM branch inventory contains main, the M4 route-proof branch and an unrelated
Dependabot branch. The only open migration PR is [IAM #63](https://github.com/baobab-platform/baobab-iam/pull/63),
with all five workflows green at `a54af49d9a757faf9e0e12b9fbdffbaae3a84cc6`.
It is not merged into the reviewed main. Preserve its current-CP fixture proof;
do not promote it to deployed resource acceptance or canonical activation.
Shared/CP open PRs are dependency updates; infrastructure has no open PR.

Two audit qualifications matter:

- Generic Shared provider/binding contracts and CP resolution already exist.
  MP2–MP4 must extend/reuse them where semantics fit, rather than create an
  independent IAM copy of platform capability resolution.
- The old M0 unresolved-digest finding is stale: committed Keycloak and Ory locks
  contain resolved image digests. A repository pin and CI verification are not
  evidence of a deployed version, HA or production acceptance.

No progress percentage is used: the audit's approximate two-thirds estimate is
not an exit criterion. Missing federation adapters, contracts and operational
proof remain explicit gates.

## 2. Immediate bounded increment

| Item | Implemented in this proposal | Still open |
|---|---|---|
| MP0 repository reconciliation | Retain/reduce asset inventory, scoped retirement, current digest evidence, README and permanent adapter-boundary wording | Complete cross-repository operational inventory, owner acceptance and live federation census |
| MP1 ownership matrix | Target provider column; Keycloak enterprise federation retained; Kratos native humans; Hydra OAuth/workloads; generated Markdown and regression guards | Production instance/support/binding declarations depend on MP2–MP4 |
| MP2–MP4 | Dependency and acceptance plan below | Shared schema work, CP persistence/resolution integration, IAM registry and resolver execution |

The matrix remains an IAM architectural control surface, not a runtime registry.
Only Shared-catalogued keys are PLATFORM_RESOLVABLE_CAPABILITY. Provider labels
such as SAML_FEDERATION do not automatically become new platform capability keys.
The Keycloak adapter is still incomplete; wording corrections do not implement
EnterpriseFederationProvider or turn deployment-dependent support into verified
support. Existing Ory runtime, M4 tests, ledger, policy gates and production
configuration remain unchanged.

## 3. MP2–MP4 dependency and PR sequence

Each stage gets its own reviewable PR and contract/regression evidence. Dependent
branches may be stacked, but consumers must pin the accepted immutable Shared
commit before their evidence can be promoted. Do not merge a consumer that
requires an unpublished schema or invent a local canonical schema as a shortcut.

| Order | Gate / repository | Concrete implementation | Required exit evidence |
|---|---|---|---|
| 1 | MP2-A / Shared | Compare ADR-0033 IdentityCapability/IdentityCapabilityProvider/ProviderCapabilityBinding to existing CapabilityProvider, ProviderCapabilitySupport, CapabilityBinding, scope, topology and health contracts. Document reuse versus necessary extensions, including provider instance versus implementation identity. Define the smallest secret-free schema changes for capability-specific support, lifecycle, security-domain/residency constraints and configuration references. | Compatibility assessment; schema examples and negative fixtures; existing contract suites pass; no duplicate identity/tenant authority or promotion of candidate keys |
| 2 | MP2-B / Shared | Define FederationTrust provider binding and normalized external-principal/assurance evidence by referencing existing principal, external identity and AuthenticationAssurance contracts. Reuse issuer+subject identity; explicit mapping; reference trust material rather than include keys/secrets. Define protocol-neutral assurance provenance, lifecycle and disabled-trust semantics. | OIDC/SAML examples; reject secrets, unknown fields, invalid references, email-derived canonical identity and unsupported assurance claims; exact contract version/lock handling |
| 3 | MP2-C / CP + IAM | Pin approved Shared contracts, map existing CP capability/provider/binding storage and authority to the extensions. Add narrow provider-neutral federation ports/models, with unsupported/unverified outcomes explicit. Keep compatibility factory parsing separate from capability selection. | Contract tests and migrations where required; existing identity/context/grant/isolation suites pass; no product-specific fields in canonical identity or business grants |
| 4 | MP3 / IAM + CP | Implement registry/projection of approved provider instances and capability support; separate desired lifecycle, observed health and verified support. Carry approved environment, security domain, region/residency and non-secret configuration references. CP remains platform binding authority; IAM executes provider mechanics. | Duplicate/unknown capability rejection, immutable/provenance-checked projection, reference validation, invalid/stale configuration fail-closed, no secrets in registry/audit output |
| 5 | MP4 / CP + IAM | Reuse CP deterministic platform resolution; add only the IAM capability-to-adapter dispatch needed by the approved result. Filter by capability support, lifecycle, security domain, residency and approved health policy. Reject ambiguity, missing support, unavailable eligible providers and arbitrary caller-supplied product selection. | Table-driven deterministic selection and denial tests; policy-approved configuration only; unavailable Keycloak does not silently become native Kratos login; unavailable Hydra does not fall back to legacy Keycloak workload issuance; credential/profile downgrade prohibited; safe resolution audit evidence |

MP4 completes only when a real composition root consumes the approved resolution,
not when a parser or an isolated Go helper exists. Unknown capabilities fail
closed. Health must not automatically alter authority, assurance or credential
policy. Canonical entitlements and runtime support are distinct checks.

## 4. Remaining programme and acceptance boundaries

| Gate | Implementation scope | Dependency / proof |
|---|---|---|
| MP5 | Confirm Kratos native credential, recovery, MFA/passkey and session boundary | MP2 contracts; pinned-version capability proof and ADR-0024/0025; imports stay unverified until fixtures pass |
| MP6 | Confirm Hydra OAuth/workload boundary; preserve M4 and #63 | Governed Shared workload profile; actual consumer proof distinct from issuance; resolve M4-F projected-token/resource-audience blocker without static-secret fallback |
| MP7 | Inventory and reduce Keycloak to federation; retain locks, runtime, database and useful Organization routing | MP2–MP4 plus export/rollback inventory; no bulk removal of native clients/users before replacement proof |
| MP8 | Permanent EnterpriseFederationProvider / Keycloak adapter using pinned supported APIs | MP2 ports and MP3/MP4 dispatch; protocol conformance tests; actual adapter support rather than product capability claims |
| MP9 | FederationTrust lifecycle, provider-instance binding, references and reconciliation | MP2 Shared binding; issuer, audience, certificate and disabled-trust constraints; explicit scoped configuration |
| MP10 | Enterprise login discovery in IAM/BFF boundary | MP9 trust and approved resolution; domain hints are discovery input, not identity or membership proof; estates do not select products |
| MP11 | Federated external-principal normalization to existing CP canonical identity | MP8/MP9; exact issuer+subject; no duplicate person, email linking or automatic domain/business membership |
| MP12 | Normalize federation assurance and step-up evidence | ADR-0024; approved upstream claim/protocol mappings; unknown/unverified assurance never upgraded |
| MP13 | Independent SCIM/directory provider decision and portability contract | Explicit decision before adapter work; provisioning cannot grant domain access |
| MP14 | Cross-provider events, redaction, audit lineage and drift reconciliation | MP9/MP11; provider provenance retained; disabled/revoked state cannot be resurrected by replay |
| MP15 | Separate provider administrative credentials, signing keys, federation certificates and rotation | Retained Keycloak is a distinct cryptographic trust domain; negative isolation and overlap-rotation evidence |
| MP16 | Capability-specific HA/DR, residency, fencing, restore and containment | Infrastructure review; revocation survives restore; no unsafe authentication failover; each provider's failure impact proven |
| MP17 | ZuriBeans, Thamani, Nabhold and engine integration | Normalized identity/context, BFF session boundary, real registered consumer path and caller ownership; no group/Organization-derived domain grants |
| MP18 | Capability-aware migration ledger and cutover reconciliation | Add source/target capability ownership with persistence compatibility and rollback evidence; LEGACY_RETIRED is binding-specific; retained federation survives native retirement |
| MP19 | Security/resilience certification | Replay, substitution, disabled trust, logout, tenant/domain isolation, keys, incidents and provider failure evidence across the complete path |
| MP20 | Production operational acceptance | Registered consumer acceptance, approved runtime bindings, monitoring/runbooks, backup/restore and owner sign-off; zero unauthorized Keycloak capability ownership, not zero Keycloak instances |

MP5/MP6 verification and existing M4 work may continue independently of unfinished
federation functionality. MP15/MP16 threat modeling can proceed in parallel with
adapter development. Destructive MP7 reduction and MP18 cutover remain gated by
replacement, rollback and actual-consumer evidence.

## 5. Preserve, freeze and legacy gate mapping

Preserve Ory runtime separation and pins, provider-neutral interfaces, canonical
issuer+subject mapping, credential safety, ledger/error invariants, conformance
harnesses, current CI and M4 evidence. Retain Keycloak security maintenance,
enterprise brokering assets, federation audit and independent DR.

Freeze global Keycloak retirement and deletion of retained realm/database,
container/locks, IdPs, certificates or federation Organization configuration.
No automatic production scope grants, ACTIVE transitions, dual-issuer enablement
or deployment are implied by this reconciliation.

| Earlier programme | MP destination |
|---|---|
| M0 baseline | MP0/MP1 reconciliation |
| M1 provider-neutral contracts | MP2–MP4 |
| M2 Kratos / M3 Hydra | MP5 / MP6 |
| M4 workloads | MP6, MP17 consumer evidence, MP18 governed cutover |
| M5 human ledger/credentials | MP5, MP11, MP18 |
| M6–M17 estate, assurance, federation, operations | Corresponding MP capability/operational gates; preserve evidence, recheck assigned provider |
| M18 cutover | MP18 per-capability cutover |
| M19 global Keycloak retirement | Superseded by MP7 capability reduction plus MP19/MP20 acceptance |

EA-04 remains ADVANCED. Completion requires operational and real registered
consumer evidence, including the outstanding federated workload path; the new
provider allocation does not waive those gates.
