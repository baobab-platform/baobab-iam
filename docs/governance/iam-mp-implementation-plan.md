# ADR-IAM-0033 implementation plan

**Status:** Advanced implementation; production acceptance not reached. Permanent
Keycloak OIDC/SAML federation and PostgreSQL shared authority/recovery fencing
are implemented. MP3 projection and MP4 dispatch remain the next runtime increment.
**Date:** 2026-10-05.
**Current evidence:** [Programme status](iam-mp-programme-status.md), reconciled
against IAM `a927259753a0d2dee16f8df6f5509c5dc9cb18e9`.
No runtime reduction, cutover or production acceptance is authorised by this plan.
**Authority:** Accepted ADR-IAM-0033, preserving the security and canonical-authority
invariants of ADR-IAM-0019–0032 where not amended.

## IAM-33-C1 — owner-aware mapping consumption (2026-10-07)

The current construction increment uses the existing Shared ownership policy at
`363e0ead9ebb5aa87f5f813b63b785b7f63cc39e`; it introduces no canonical entity,
public API, grant, provider activation or mapping authority in IAM.

`OpenGovernanceComposition` supports an explicit protected CP canonical reader.
The federation-authority executable supplies it. CP-owned mapping targets are
validated through exact current issuer/subject evidence, reference, principal,
external identity, lifecycle and digest, bracketed by CP registration reads.
IAM's durable maker/checker ledger owns permission to consume that exact target
at the approved trust revision/snapshot/scope. Missing canonical authority keeps
mapping consumption unsupported. IAM-native targets still require native bytes.

The coordinated CP increment fixes the assumption that a CP mapping's owner
instance equals its IAM provider instance. Its PostgreSQL query proves owner
placement independently and checks the live human relationship, fingerprint and
five-minute verification window in the same read snapshot. Deploy CP first.

| Evidence | Classification | Limit |
|---|---|---|
| `internal/federation/canonical_composition_test.go` | Executable construction integration | Actual governance composition and TLS authority handler, signed OIDC verification and durable replay; remote CP boundary simulated |
| Successful mapping approval and `Consumer.Consume` | Integration test | Not an estate BFF/session acceptance or staging result |
| Missing approval, substitution, wrong trust revision/scope/principal, revoked mapping, changed digest, expired approval, CP outage | Negative construction tests | Live target revocation and owner-instance SQL additionally require CP PostgreSQL CI |
| Concurrent approval and consumption | Race tests | One checker decision and one event consumption; not deployed HA/DR |
| CP repository mapping target tests | PostgreSQL integration harness | Requires `TEST_DATABASE_URL` against PostgreSQL 17; no database substitute |

C1 is not production accepted. Promotion requires both PRs merged with required
CI green and a protected registered CP/IAM staging composition. MP3/MP4,
estate acceptance and MP19/MP20 remain independent gates.

## 1. Verified baseline and audit corrections

| Repository | Reviewed immutable main | Finding |
|---|---|---|
| IAM | `a7d205bdbe6390e35be45cba5fe50b35342d845e` | ADR-0033 Accepted; Ory/provider-neutral foundations preserved; matrix/baseline still implied global Keycloak retirement |
| Shared | `540b4aa627afacaee9f7f2ad5889723ff08d3bd5` | Canonical capability provider/support/binding, principal, external identity and assurance contracts already exist; dedicated federation trust/provider-instance contracts not found in the reviewed contract tree |
| CP | `c84063cb07dce76e1ffac4b12fa29c5e4e5ec855` | Existing capability-domain resolver and provider/binding persistence must be evaluated for reuse; current context authority is after #255 |
| Infrastructure | `4996cc9e0410f0d4ffb08ce71bd19432fdc158c1` | Accepted infrastructure/workload identity ADR-Infra-0013 remains relevant; deployment/residency/DR integration needs a focused MP7/MP15/MP16 audit |

The table above records the original MP0 discovery snapshot, not current branch
heads. The following merged evidence supersedes its implementation-gap claims
(original MP2 snapshot; superseded where noted by the 2026-10-05 programme status):

| Increment | Current evidence | Claim boundary |
|---|---|---|
| MP0/MP1 | IAM #64 merged | Repository controls; fresh MP7 federation census remains open |
| Current-CP Hydra route proof | IAM #63 merged at `3be4d69e` | Fixture proof; not deployed resource acceptance or canonical activation |
| MP2-A/B contracts | Shared #213 and #214 merged; contract pin `b10388460c23ac6d7d99bb8a22e2ee4821ad22f6` | Published contracts; not live support or trust activation |
| MP2-C canonical reader | CP #257 merged | Atomic existing human mapping reader; authenticated source integration remains open |
| MP2-C consumption | IAM #65 merged; IAM #65 baseline `ccb3852d76b26fef94b1f280f0ea021363808d23` | Consumer boundary, without production authority composition |
| MP2-C executable plumbing | IAM #66 merged at `e4e3cbef7ff7f5ec5379cc456892ae57660417bf`; review follow-ups in #68 | Authenticated transport, durable approvals and actual OIDC verification; no mounted live sources, SAML conformance or multi-replica acceptance |

MP8 enterprise federation execution is implemented in #75, with shared durable
authority state/recovery fencing in #77. MP3 production support projection and
MP4 CP-resolution-driven dispatch remain open. Green CI is construction evidence,
not production consumption evidence.

Two audit qualifications matter:

- Generic Shared provider/binding contracts and CP resolution already exist.
  MP2–MP4 must extend/reuse them where semantics fit, rather than create an
  independent IAM copy of platform capability resolution.
- The old M0 unresolved-digest finding is stale: committed Keycloak and Ory locks
  contain resolved image digests. A repository pin and CI verification are not
  evidence of a deployed version, HA or production acceptance.

No progress percentage is used: the audit's approximate two-thirds estimate is
not an exit criterion. Remaining runtime projection/dispatch and operational proof remain explicit gates.

## 2. Immediate bounded increment

| Item | Merged repository increment | Still open |
|---|---|---|
| MP0 repository reconciliation | Retain/reduce asset inventory, scoped retirement, current digest evidence, README and permanent adapter-boundary wording | Complete cross-repository operational inventory, owner acceptance and live federation census |
| MP1 ownership matrix | Target provider column; Keycloak enterprise federation retained; Kratos native humans; Hydra OAuth/workloads; generated Markdown and regression guards | Production instance/support/binding declarations depend on MP2–MP4 |
| MP2–MP4 | Shared contracts, live CP/IAM federation authority composition and CP runtime-profile persistence implemented | Production support projection and CP resolution → IAM dispatch; staging evidence |

The matrix remains an IAM architectural control surface, not a runtime registry.
Only Shared-catalogued keys are PLATFORM_RESOLVABLE_CAPABILITY. Provider labels
such as SAML_FEDERATION do not automatically become new platform capability keys.
The permanent Keycloak enterprise adapter now implements the provider-neutral
port and independently verifies original upstream OIDC/SAML evidence. Runtime
facet verification is separate from canonical capability support and activation.
No wording change can promote support or waive deployed evidence. Existing
Ory runtime, M4 tests, ledger and migration policy gates remain required.

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

## 6. Bounded enterprise MP3/MP4 convergence

The authority composition now projects current CP federation profile/deployment
evidence and redeems a caller-owned CP context for
`identity.authentication.perform` major 1 before dispatching an exact bound
EnterpriseFederationProvider. Begin, callback and readiness recheck selection;
there is no fallback. The production enterprise service requires this dispatch.
See [enterprise dispatch operations](../operations/enterprise-capability-dispatch.md)
for context ownership, independent scope/activation requirements and evidence.
Broader MP3 support publication, native/workload dispatch/conformance and
provider-neutral discovery remain open; fixture tests cannot close operational
acceptance. The candidate enterprise key remains outside Shared's catalogue.
