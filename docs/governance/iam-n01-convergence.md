# IAM-N01 — ADR, Shared-contract and development convergence

**Review date:** 31 October 2026
**IAM audited baseline:** 7958a93808bf23dca8752598ca97fb0292a7ac4d
**Immutable Shared consumer pin:** 1517429bcae601a1b0288ca0279e524ce48a3d77
**Shared main compared:** c97387ed8e27eeffb0c0382e043db98cb450b900

**Classification: SOURCE CONVERGENCE ONLY.** N01 creates no actual provider/client registration, workload credential, scope grant, CP binding, enterprise, synthetic fixture, token or acceptance evidence. Separate N02/N03/N04 implementation and real-provider qualification remain required.

## ADR precedence (not a new architectural decision)

- The original ADR-0001 through ADR-0018 files remain historically **Proposed**. Their canonical-identity, security, context, business-authority and tenant-boundary constraints are retained to the extent the accepted successor architecture explicitly preserves them. Their file statuses are not silently rewritten.
- ADR-IAM-0019 through ADR-IAM-0032 are **Accepted**. Accepted **ADR-IAM-0033** amends inconsistent provider-allocation and global-Keycloak-retirement assumptions. Native human identity/credential/session belongs to Kratos; OAuth/OIDC and workload issuance to Hydra; Keycloak is retained for bounded enterprise OIDC/SAML federation. CP, not IAM, owns canonical identity, organisation, context, grants and tenant authority. Engines own business authorization.
- ADR-IAM-0034 remains **Proposed**, subordinate to accepted Shared ADR-SHARED-042 Decision 9. Its native-commitment submit scope is still unallocated; no commitment authorization follows.
- Accepted **ADR-SHARED-043** supersedes earlier *development-time* per-run independent-human-approval and official incorporation requirements. It does not supersede protected staging/production controls, nor the underlying CP/IAM auth, maker/checker or tenancy rules.

## Exact Shared contract comparison and decision

| Contract source | Pinned vs reviewed Shared main | Decision |
| --- | --- | --- |
| Identity capability definitions | Unchanged blob c79162167ef09cd3789f3bd057e2fb49027c391d | Keep only existing catalogued identity capability keys |
| Capability catalogue | Unchanged blob a45797a2a7cebf92f39fe663ab5983ef8a9f8c88 | No new platform-resolvable capability |
| Federation and runtime authority policies | Unchanged blobs 4c30fde3 and e22de144 | Preserve CP-governed dispatch |
| Estate resource-assignment schema | Unchanged blob 8a718729 | No native commitment activation |
| CP security policy | Unchanged blob 5cbfbc02 | No token policy relaxation |
| Workload registry | Changed blob 550e67ab to 3ff5fd44 | HOLD re-pin: new development-only ACTIVE entries need consumer qualification |
| Scope registry | Changed blob d111e7de to 24f3650f | HOLD re-pin: subscription scope additions and DEV-07 text need exact issuance review |
| Development enterprise profile contract | Absent at old pin, present at reviewed main | Adopt in separately reviewed consumer re-pin and DEV-14 onboarding |

The later Shared registry now contains active **development-only** CMS consumer/validator, Nabhold/ZuriBeans/Thamani/Equator estate callers, external API/Pulse, Subscriptions, Payments and DEV-07 buyer-test identities. Those are synthetic **registry ceilings** for isolated development, not statements that IAM has provisioned credentials or that a CP binding, real consumer or protected scope exists. Re-pinning IAM without updating its Keycloak integration inventory, Hydra profile builders, owner/validator issuers, environment separation, negative tests, lease/teardown and CP registered-consumer evidence could produce false readiness or unintended issuance.

**Decision: retain the current immutable pin.** The code constant in internal/federation/consume.go, contracts.lock.yaml and proposed ADR-IAM-0034 all remain aligned. A later explicitly reviewed re-pin must validate the full changed workload and scope registries and prove actual narrow development issuance, wrong-audience and cross-tenant denials, no production cross-over, replays and teardown. A future PR is not automatically authorized merely because a newer Shared main exists.

## Development versus protected execution

ADR-SHARED-043 permits synthetic Nabhold, ZuriBeans, Thamani, Equator & Estate and independent external-client cases in local development, disposable CI or isolated shared development. The CP owns its default-off, development-marked bootstrap and canonical identifiers. IAM still must obtain provider-issued, authentic random bounded credentials, and actual consumers must verify the signed token and current CP authority. One CI/developer job may coordinate distinct synthetic maker/checker Principals, but **one Principal cannot self-approve**.

The canonical reusable fixture/profile contract stays in Shared development/v1. N01's JSON record is a review-time drift checklist, **not** a forked CP authority source, workload registry, development bootstrap, actual config or schema for other engines. No local or fabricated issuer success counts as an integrated PASS. A reusable isolated development lease is at most 24 hours, with shorter bounded access tokens, private run credentials, revocation, crash recovery and verifiable cleanup. Developer actual-component evidence may be classified REAL_COMPONENT_SYNTHETIC_DATA; a synthetic datum alone, a stub or a source-only test never qualifies.

Protected staging retains actual independent approved operators, private credentials, approved infrastructure/trust, record custody, security review and acceptance. Production additionally needs explicit provider, legal and operational authority. **No protected staging/production signoff or provider support promotion is performed here.**

## Capability declarations and follow-on gates

All three provider declarations remain PARTIAL: Kratos identity.authentication.perform; Hydra identity.workload-token.issue; Keycloak identity.authentication.perform solely through enterprise federation. Candidate management operations are not Shared catalogued platform keys. Current published support/health/role assignments remain CP-owned. Source and local CI construction do not justify changing PARTIAL to IMPLEMENTED.

- **N02**: real Kratos → Hydra → BFF → CP human journey with current context, callback, session and revocation negatives.
- **N03**: real signed Hydra issuance → current CP runtime/authority → protected resource acceptance with wrong-audience, foreign-tenant and unexpired-token withdrawal.
- **N04**: registered CP support/binding/artifact acceptance, full C4-03 and C4-04 qualification, then independently reviewed canonical-support promotion.

## N01 audit correction — governance guard hardening (31 October 2026)

This PR has been re-audited as a **source-only** governance change.
The original source guard compared selected YAML/JSON values after using parsers
that silently permitted duplicate keys. Inconsistent parsers can therefore
interpret ambiguous source documents differently. It also did not check the
provider adapter/simulation flag, full provenance, evidence existence, planned
provider targets or an actual Go pin declaration rather than a matching comment.

The guard now fails closed on duplicate YAML and JSON mapping keys; enforces
the unchanged reviewed Shared pin and lock review policy; checks exactly one
Go SharedCommit declaration; requires genuine PARTIAL provider adapter
declarations with non-simulated support, repository-owned ADR-IAM-0033
provenance, actual source and integration-test paths, and reviewed planned
capability targets. The regression tests include positive source acceptance,
ambiguous input, comment spoofing, provenance drift, simulated provider
promotion, invalid evidence paths, duplicate planned capabilities and
protected-environment restrictions.

**Boundary:** these are offline source-integrity and contract-drift checks,
not real provider tokens, CP provenance, issuer activation, credential
issuance or live C4-03/C4-04 acceptance. Future intentional changes to
provider capabilities, Shared registry or contract pins require a separately
reviewed source update and actual consumer qualification. The narrow
development exception in ADR-SHARED-043 remains unchanged.

## Verification and rollback

The N01 source check is scripts/check_iam_n01.py, with negative cases in tests/unit/test_iam_n01.py. The existing scripts/iam_capability_matrix.py independently verifies the exact pinned Shared capability catalogue and generated matrix; the current CI scope, Ory/Keycloak/provider, Go/race, PostgreSQL and security gates remain required. Do **not** interpret a successful source guard as operational readiness.

Reversing N01 reverts source checks, records and documentation only; issuer state, CP entities, credentials, bindings and provider deployments are unchanged. A later failed re-pin must return to the preceding immutable pin by explicit review, with aligned code, locks and tests, not by assuming rollback revoked issued tokens.
