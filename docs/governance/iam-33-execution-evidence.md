# ADR-IAM-0033 execution and acceptance evidence

Date: 2026-10-07. Authority: Accepted ADR-IAM-0033; Shared immutable IAM pin
`363e0ead9ebb5aa87f5f813b63b785b7f63cc39e`. This dossier records the bounded
C1/C2 implementation and C3 declaration reconciliation. It does not certify
MP0–MP20 or close unimplemented requirements.

Classification order: Designed → Implemented → Integration Verified → Staging
Accepted → Production Accepted. A bounded integration result applies only to
the tested boundary, not the whole gate. No gate below has supplied staging or
production acceptance evidence. CI PostgreSQL tests are construction integration,
not deployed multi-replica/failover/DR acceptance.

## Implemented increments

| Increment | Repository / branch / PR | Commit and result |
|---|---|---|
| C1 CP owner-aware evidence | baobab-cp / fix/iam-33-c1-canonical-target-authority / [#282](https://github.com/baobab-platform/baobab-cp/pull/282) | Head 9b11cc10069247ee2fc84db04209f8434e26be83; merged 72e54afbe48ca3a121308e599f76c778657d8d63; PostgreSQL 17/race, readiness, foundation and security CI passed |
| C1 IAM consumption composition | baobab-iam / feat/iam-33-c1-owner-aware-mapping / [#85](https://github.com/baobab-platform/baobab-iam/pull/85) | Head abd67bc94fda911ed24d7e9f0fa5ac0633cdbf69; merged 9129bf1acd0953f2c9487a5708e385cb555c74c8; all CI workflows passed |
| C2 status reconciliation | baobab-iam / docs/iam-mp-status-reconciliation / [#79](https://github.com/baobab-platform/baobab-iam/pull/79) | Head 8570f3a13a204a5b29aedd58f8cc8bb36038edff; merged 23f0d2fbbe2bdf12819ea76ce9e7908fb5fd5e5c; all CI workflows passed |
| C2 enterprise dispatch | baobab-iam / feat/iam-mp3-mp4-enterprise-dispatch / [#80](https://github.com/baobab-platform/baobab-iam/pull/80) | Head 9b8724fd2fe11b8c0fa202974d87da2b8a349bc1; merged a2d977877df8139ec649e61598045d730f56c420; all current-head CI workflows passed; preserve authority outage semantics, reject invalid trust and clock rollback |

C1 uses the real executable governance factory, native targets, four-eyes
approval ledger, trust lifecycle, TLS authority handler, signed OIDC verifier
and durable event/replay ledger. The remote CP boundary in that IAM test is
simulated. CP's independent PostgreSQL test verifies exact live mapping target
attestation and distinct owner/provider instances. A real registered CP/IAM
estate journey is still missing; these tests do not substitute for it.

C3 declarations use canonical PARTIAL where the complete capability contract is
not proved. Shared explicitly excludes PARTIAL from EngineRegistration and
ProviderCapabilitySupport. Naming executable mechanics in a declaration does
not authorise registration of unsupported support. No provider/runtime profile,
binding, trust, grant, workload or estate is activated by this change.

Current C1 construction workflow receipts:
[CP Go/PostgreSQL CI](https://github.com/baobab-platform/baobab-cp/actions/runs/37689586084),
[IAM CI](https://github.com/baobab-platform/baobab-iam/actions/runs/37689281831),
[IAM Ory live](https://github.com/baobab-platform/baobab-iam/actions/runs/37689281860),
[IAM foundation](https://github.com/baobab-platform/baobab-iam/actions/runs/37689284219)
and [IAM secret scan](https://github.com/baobab-platform/baobab-iam/actions/runs/37689282825).
PR #79's current-head workflows also passed. PR #80's reconciled-head
[CI](https://github.com/baobab-platform/baobab-iam/actions/runs/37690974317),
[Ory live](https://github.com/baobab-platform/baobab-iam/actions/runs/37690974150),
[foundation](https://github.com/baobab-platform/baobab-iam/actions/runs/37690975984)
and [secret scan](https://github.com/baobab-platform/baobab-iam/actions/runs/37690974839)
passed before merge. C3 declaration/evidence reconciliation is tracked in
[#86](https://github.com/baobab-platform/baobab-iam/pull/86) on
feat/iam-33-c3-provider-declarations; this does not complete C3 registration.

## MP0–MP20 matrix

All rows retain Accepted ADR-IAM-0033 and its implementation plan as normative
requirements. The code/test column identifies construction evidence, not an
assertion that every accepted requirement in that gate is finished.

| Gate | Verified code/tests or contract | Highest bounded evidence / remaining implementation and acceptance | Blocker owner |
|---|---|---|---|
| MP0 baseline | #64; #79; implementation plan | Implemented reconciliation; deployed census and owner acceptance open | IAM / Operations |
| MP1 allocation | .baobab/iam-capability-matrix.yaml; scripts/iam_capability_matrix.py; Python tests | Implemented ownership matrix; runtime declarations and acceptance independent | IAM / CP |
| MP2 contracts/composition | Shared identity/v1; governance_composition.go; canonical_composition_test.go; CP #282 | Bounded Integration Verified in C1; real protected registered service/estate acceptance open | IAM / CP / Operations |
| MP3 registry | .baobab/capability-provider.yaml; CP identity_runtime_profile_handler.go | Designed plus partial implementation declarations; full contract support, real profiles, registration and drift convergence open | IAM / CP / Operations |
| MP4 resolver | #80; enterprise_dispatch.go/tests; CP capability resolution | Bounded enterprise Integration Verified in #80; native/workload governed dispatch and supervised context renewal open | IAM / CP |
| MP5 native identity | internal/provider/ory/kratos.go; foundation_live_test.go; ory foundation CI | Partial implementation; credential/recovery/MFA/passkey/session/step-up journey conformance open; imports unverified | IAM / Estate owners |
| MP6 workloads | internal/provider/ory/hydra.go; hydra_federated_workload_test.go; consumer_live_test.go | Partial implementation; M4-F intended audience, projected issuer, real registered consumer acceptance open | IAM / CP / Consumer owners |
| MP7 Keycloak reduction | allocation matrix; provider docs; retained enterprise assets | Designed safe reduction; deployed capability census and rollback-approved per-capability retirement open | IAM / Operations |
| MP8 enterprise federation | internal/provider/keycloak/enterprise.go; enterprise_live_test.go; enterprise CI | Bounded broker Integration Verified; no accepted estate or controlled Hydra/session handoff yet | IAM / Estate owners |
| MP9 trust lifecycle | trust_ledger.go; approvals.go; governance tests; #85 | Bounded governance Integration Verified; provisioning/reconciliation and deployed lifecycle acceptance open | IAM / CP / Security |
| MP10 login discovery | service_broker.go; #80 | Partial broker routing; tenant/organisation neutral discovery and native/enterprise selection open | IAM / CP / Estate owners |
| MP11 canonical normalization | consume.go; CP identity evidence; canonical_composition_test.go | Bounded Integration Verified in C1; registered estate journey open; exact issuer/subject only | IAM / CP / Estate owners |
| MP12 assurance | native_protocol.go; broker_verification.go; protocol tests | Bounded normalization implemented; estate step-up, provenance and operational enforcement acceptance open | IAM / Security / Estates |
| MP13 SCIM | ADR-IAM-0033; provider capabilities report unsupported | Designed/unactivated; independent provider decision and approved portable lifecycle contract open | Architecture owner |
| MP14 events/audit | durable broker/OIDC ledgers; DispatchObservation | Partial implementation; durable cross-provider correlation/lifecycle reconciliation/drift open | IAM / Shared |
| MP15 cryptographic separation | provider locks/configuration; OIDC/SAML verifier; image security CI | Construction separation and protocol negatives; deployed overlap/rollover/compromise containment proof open | Security / Operations |
| MP16 HA/DR/residency | postgres_storage.go; recovery tests; federation-postgres CI | Shared consistency/recovery Integration Verified only; deployed replicas, failover/restore/residency and measured RPO/RTO open | Infrastructure / Operations |
| MP17 estates | ZuriBeans auth callback/login/SSO files | No accepted multi-provider estate journey; ZuriBeans, Thamani and Nabhold tracked separately | Estate owners / IAM / CP |
| MP18 migration | internal/migration; ADR-IAM-0033 allocation | Partial legacy migration implementation; capability-specific ownership, compatibility migration and rollback governance open | IAM / CP / Operations |
| MP19 certification | protocol negatives; race; container/security CI | Construction evidence only; deployed security/resilience/compatibility matrix and approval open | Security / Operations |
| MP20 acceptance | implementation plan; this dossier; operations runbooks | Designed, not accepted; registered consumer, staging/production operational evidence and owner sign-off open | Platform owners |

## Estate-specific acceptance dependencies

| Estate / inspected main | Repository reality | Independent remaining work |
|---|---|---|
| ZuriBeans / a03690116ce5cd4727e5fe8284996a97e479a3f3 | src/app/api/auth/callback/route.ts forwards OIDC code/state to Trade's zuribeans-oidc provider; src/lib/auth/sso.ts keeps a bounded return cookie | Prove native and enterprise paths through registered CP/IAM and Trade, canonical normalization, correlation, session expiry/revocation and required step-up |
| Thamani / 8dd76e97a358e3aeb27e7b9d27f6f2177a5bd2c3 | README, docs/medusa-integration.md and Accepted ADR-0002 keep accounts/authentication gated; supplier applicantIdentityRef is unimplemented | Implement the approved account/BFF integration after canonical IAM entry paths and estate contracts; native and enterprise acceptance independently open |
| Nabhold / 9336d49dfd4cabcb4bf894b81d3835c5edc3301e | src/lib/auth/session.ts returns null by default and permits a nonproduction preview only; sign-in explicitly says federation is unconnected | Implement registered workforce federation and canonical session integration; preserve preview denial in production; operational/administrative step-up acceptance open |

These are implementation dependencies as well as missing live configuration.
Thamani is accessible through repository APIs; its private visibility is not
classified as an inability to inspect it. No estate code was modified in C1–C3.

## Verification ledger

| Check | Outcome | Evidence / limitation |
|---|---|---|
| IAM go test ./... | Passed | Re-run on C1 and reconciled C2 with Go 1.27 |
| IAM federation/authority race tests | Passed | Includes actual governance/TLS composition and concurrent mapping approval/consumption |
| IAM go vet ./... and go build ./... | Passed | C1 and reconciled C2 |
| Existing Python unit suite | Passed | 19 tests re-run on C1, #79 reconciliation and #80 reconciliation |
| Provider capability declaration | Passed | Pinned Shared schema/catalogue and evidence paths; all support PARTIAL; Shared generation rejects each provider because no IMPLEMENTED support exists |
| Capability matrix | Passed | Exact immutable Shared catalogue |
| Federation and CP resolution wire contracts | Passed | Pinned Shared validator plus emitted Go records, C1/C2 respectively |
| CP go test ./... and focused race/vet | Passed | Local database suites skipped without TEST_DATABASE_URL |
| CP PostgreSQL 17 integration/race | Passed | #282 Go CI after correcting archived reference status; no simulated DB |
| IAM executable authority and OIDC/SAML broker integration | Passed | #85 construction/live CI; remote CP boundary simulated in IAM composition test |
| IAM PostgreSQL concurrency/recovery | Passed | #85 federation-postgres CI; not cloud HA/DR |
| Container build and security checks | Passed | #85 CI authority/image/Trivy/SBOM and main image; no production certification |
| Actual registered estate/consumer acceptance | Blocked | Canonical entry/BFF integration work remains; approved live IAM/CP/estate/resource configuration and protected access unavailable in this execution |
| Staging deployment/smoke | Blocked | Account-specific reviewed infrastructure declaration and protected account/environment configuration absent |
| Deployed HA/DR, residency and key compromise/rotation drills | Blocked | Live environment, approved objectives and operational authority absent |
| Destructive Keycloak retirement / production cutover | Not run | Explicitly outside this execution's authorisation |
| SCIM activation | Not applicable | No accepted independent provider decision; retain unactivated |

## Exact external inputs and next actions

Infrastructure main `e9044308ae40439cfc06cd1c2d19db9f6c242909` contains release
publisher receipts and coordination metadata. It does not contain the reviewed
account-specific `deploy/releases/staging/v0.1.0-staging.tfvars.json`. Published
images/SBOMs are not deployed service acceptance. The synthetic Terraform release
fixture must not be promoted into account configuration.

The environment owner must supply approved STAGING_ACCOUNT_ID,
STAGING_PLAN_ROLE_ARN, STAGING_APPLY_ROLE_ARN and STAGING_STATE_BUCKET in the
correct protected environments, plus the reviewed account-specific release
inputs defined by terraform/environments/staging/workload_variables.tf. The
established staging region is af-south-1; no other account value is invented.

The CP/IAM owners must identify actual registered provider IDs, engine-instance
IDs, approved runtime configuration/security-domain reference IDs, deployed
artifact digests and revisions, eligible scope/bindings/support, the protected
CP origin/CA and a provisioned scoped workload authority source. Human
maker/checker administrative grants and trust/mapping approval references must
be independently reviewed. Supply protected credentials through deployment
secrets, not through a document or chat transcript.

Estate owners must identify registered OIDC clients, exact redirects, intended
issuers/audiences, native/enterprise eligibility policy, required step-up and
BFF/session handoff configuration. Workload consumer owners must identify the
actual projected issuer/subject, intended resource audience/scopes and active
canonical principal/consumer registration. Success at issuance is insufficient.

Next executable increment is C3 completion followed by C4 native/workload
resolver convergence, then C5/C6 login discovery and the first registered estate
acceptance. C7–C11 and the remaining implementation work in the matrix remain
open. Repository readiness is bounded; full integration readiness, staging
acceptance and production acceptance are not established.
