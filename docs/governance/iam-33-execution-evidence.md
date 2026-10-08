# ADR-IAM-0033 execution and acceptance evidence

Date: 2026-10-08. Authority: Accepted ADR-IAM-0033; Shared immutable IAM pin
`70f92ee179888e9fd38e31ae9225060d76833944`. This dossier records the bounded
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

2026-10-08 refresh: main `cef8d0210f128352b2d3a264f349e5c12e646d4d`
includes #85, #79, #80, #86 and staging-evidence provisioning work #87/#88.
C3 declaration reconciliation #86 is merged; it did not publish support.
The C3 publication preflight on `feat/iam-33-c3-publication-preflight` uses the
exact Shared generator, excludes PARTIAL/planned support and compares reviewed
registration exports. It is implemented construction tooling, not completed
registry convergence. All three providers remain blocked for registration.
See [publication procedure](../operations/provider-support-publication.md).

Fresh local verification: `go test ./...`, federation and authority race tests,
`go vet ./...`, `go build ./...`, all 29 Python tests, declaration/matrix and
federation/resolution wire validation Passed. The strict publication command
returned the expected Blocked result (exit 2). Live provider tests, PostgreSQL
concurrency/recovery, container builds/scans and new GitHub Actions are Not run
locally; Docker/PostgreSQL/security executables are unavailable. Staging and
production remain Blocked on protected configuration and owner evidence.
Historical CI receipts below are historical, not fresh results for this branch.

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

### C3 canonical workload response boundary (2026-10-08)

Baseline: merged IAM #96 at `3866f12`. The response envelope now mirrors the exact
Shared `70f92ee179888e9fd38e31ae9225060d76833944` workload-token response contract:
closed properties, required Bearer type, 60–86400-second lifetime and optional
nonempty scope. Duplicate/null/trailing input is rejected. Scope binding requires
an explicit exact admitted scope set; omission never supplies permissions.
The real Hydra ACTIVE fixture checks this boundary before its existing token
verification. The Shared pin is unchanged; both workload schemas are now explicit
consumer-lock entries. Unit/contract corpus and race tests cover malformed
responses, scope inflation, duplicate grants and missing scope.

Classification: repository implementation only. Current-head Docker/composed CI
is required. The boundary does not verify token signatures or establish current CP
registration, resource consumption, staging or production acceptance. Provider
support remains PARTIAL. C3 registration and C4 dispatch remain open.

### C3 registration input integrity (2026-10-08)

Canonical response boundary #97 merged at `cc900620`; registration wire-input
integrity #98 merged at `1a8296a`. Each exact head passed all four PR workflows,
including CI and both Ory live variants. These are bounded construction and
fixture integration receipts, not live registration or staging acceptance.

Executable support comparison now rejects boolean, floating-point, string,
nonpositive, empty and duplicate contract versions before equality comparison.
Python equality must not collapse malformed evidence such as `true` into canonical
major version `1`. Closed support entries and unique capability keys are checked
independently before comparing with the pinned-Shared-validated declaration.
All providers remain PARTIAL. Full canonical conformance, owner-approved CP
registration inputs and registered consumer acceptance still gate C3 completion.

### C3 OAuth-to-canonical workload response projection

Based on main `509e0c0` (#99 merged), the Ory adapter now exposes a reusable
successful-response projection. It bounds input to 1 MiB, rejects duplicate and
trailing wire input and OAuth error envelopes, normalizes bearer spelling, and
validates the pinned canonical response plus exact admitted scopes. OAuth
extensions and refresh credentials are excluded from the returned envelope;
failures return no token. The ACTIVE live fixture invokes the same adapter
projection on actual raw Hydra response bytes before its independent verifier.
Repository unit and race tests cover projection and malformed-response denial.
Current-head composed CI is required; no staging or production proof is supplied.

This closes the fixture-only response projection gap, not C3 as a whole.
Canonical issuance entry-path/default-scope conformance, current CP authority,
registered resource consumption and full human Authorization Code/PKCE handoff
remain open. All provider declarations remain PARTIAL, so strict registration
remains blocked. Owner-approved targets, references, artifacts, evidence,
protected CP origin/CA and scoped observer credentials remain live dependencies.

### C3 canonical issuance-to-resource composed fixture

The isolated production-mode hook now admits two explicitly ACTIVE CI identities
through authenticated Hydra callback fields, issues their signed and
audience-bound tokens, projects the raw OAuth responses into the canonical Shared
envelope, and presents them to the current immutable CP source's production
verifier, middleware and `POST /v1/platform-context/validate` handler. The test
requires HTTP 200, matching bounded context, no-store response semantics, absent
legal-entity disclosure and absence of credentials from output and audit data.
The existing PROVISIONED denial remains in the same canonical-hook phase.

This is composed integration evidence with disposable provider, registry,
principal, tenant and context fixtures. It does not prove current live CP
registration, deployed resource consumption, staging acceptance or production
acceptance. Provider declarations remain PARTIAL pending complete capability
entry-path evidence and owner-approved live registration inputs.
### C3 human authentication canonical boundary

The IAM domain now mirrors the pinned Shared human authentication request and
response envelopes for Authorization Code with S256 PKCE. Closed decoding rejects
unknown, duplicate, null and trailing fields; transaction bindings, redirect URI,
token lifetime and optional token fields retain the exact Shared bounds. Exact
numeric parsing prevents fractional lifetimes from crossing the integer contract.
The Shared validator independently checks the common corpus at the immutable pin.

This establishes provider-neutral wire types only. Kratos native authentication
and permanent Keycloak enterprise federation remain PARTIAL until their real
browser entry paths project into this boundary, verify returned tokens and prove
estate consumption, replay denial, assurance and session behavior.

### C3 enterprise canonical handoff (2026-10-08)

Prerequisite [#102](https://github.com/baobab-platform/baobab-iam/pull/102)
merged as `4df2be20f0e0a9f01356574aad1acca3d5d1ba18` after all five workflows
passed on `080c153b6f8cd16176659c1ca3830d03dc592b6e` and the Unicode/CI review
findings were corrected. These are prerequisite receipts, not this increment's
current-head integration result.

The governed Keycloak enterprise entry path now constructs and validates the
canonical Shared Authorization Code/S256 request before persisting a browser
transaction. Its direct standards token exchange projects the provider response
through the canonical human response boundary, normalizes OAuth Bearer casing,
and excludes provider extensions. Malformed, duplicate, null, error, fractional
lifetime and trailing responses fail closed before any ID token is released to
the independent signature/issuer/audience/nonce verifier. Refresh and access
credentials are not persisted or exposed by the enterprise event result.

Repository verification: Go 1.27 build and race tests for human authentication,
federation and Keycloak pass. The composed broker tests retain private upstream
evidence, current configuration rechecks, assurance mapping and durable replay
fences. The existing real Keycloak OIDC/SAML browser workflow must pass on the
new head to establish this increment's CI integration evidence; local unit
results are not a live browser result.

The executable support census agrees with the declarations. Strict pinned
Shared publication preflight returns the expected blocked result (exit 2),
excluding all three PARTIAL providers and producing zero draft registrations;
runtime authority is not verified. The 27 selected Python human/workload
contract and publication tests pass locally.

This advances the MP3/MP4 entry boundary but does not complete C3. Native
Kratos/Hydra human OAuth handoff, registered estate acceptance, complete session
and assurance evidence, and real CP-owned registration inputs remain open.
MP0–MP20 staging and production acceptance remain unproved; all provider
declarations remain PARTIAL. No live targets, authority records or credentials
were invented and no production activation was performed.

### C3 native human canonical handoff (2026-10-08)

Prerequisite enterprise handoff #103 merged as
`260cb5578f49bcb4b5c7730d516ac5835369470c`; its applicable current-head workflows
passed, including actual Keycloak OIDC and SAML browser composition.

The native provider bridge verifies live Kratos session state and exact subject,
then accepts only Hydra challenges matching the retained canonical
Authorization Code/S256 intent. It rechecks revocation before acceptance,
requires explicit exact-scope consent, rejects resource/business grants and
does not infer CP mappings or readiness. Local Go race, vet and formatting
checks pass. The newly required real-provider CI journey covers Kratos session,
Hydra login/consent, direct code exchange, canonical response, independently
verified ID token, exact subject/nonce and replay denial on both Hydra variants.
That CI journey is pending until a current-head PASS receipt exists.

MP3/MP4/MP5 estate composition and real registered acceptance remain open.
Repository tests and disposable provider CI are separate from staging and
production acceptance. All three providers remain PARTIAL; no live registration,
synthetic authority, production activation or certification is claimed.

### Native handoff merge receipt and governed registration review (2026-10-08)

Native handoff [#104](https://github.com/baobab-platform/baobab-iam/pull/104)
merged normally as `2ab14a480cf882514c0474725f1297e6e524f856`, with expected
head `0af385e0dec50568032ef3f3193e0b396b2b483e`. Current-head
[CI](https://github.com/baobab-platform/baobab-iam/actions/runs/37827491593),
[Ory Foundation Live](https://github.com/baobab-platform/baobab-iam/actions/runs/37827491478),
[Foundation](https://github.com/baobab-platform/baobab-iam/actions/runs/37827493324)
and [secret scanning](https://github.com/baobab-platform/baobab-iam/actions/runs/37827492613)
all passed. Action pinning was inspected and its workflow-path filter did not
apply to this code/docs increment. The browser-cookie review blocker was fixed
and resolved. This supersedes the preceding pending native CI statement.

Both real Hydra variants passed the canonical native journey using actual
CSRF-bound Kratos browser login cookies and API session tokens, direct S256
exchange, independently verified ID token with exact issuer/client/subject/nonce,
wrong-verifier denial, replay and revocation. The real PostgreSQL race suite
passed independent-replica native challenge consumption and recovery-epoch
fencing. IAM's shared ledger burns a hash before acceptance and never releases
uncertain consumption. Local build, vet, full Go tests and selected race tests
passed; those local live tests skip without Docker and are not the CI receipt.

Governed registration tooling now prepares prospective reviewed Shared bundles
and the explicit index used by CP's existing embedded registration importer.
It requires a clean exact source revision, exact pinned Shared/index digest,
fresh executable support census and canonical IMPLEMENTED support. It preserves
existing index entries, rejects global provider/path collisions and unsafe
existing output, and emits only DRAFT support plus a construction receipt.
Fifteen publication tests pass, including synthetic positive bundle fixtures
and negative PARTIAL, ACTIVE, foreign membership, path and output cases.
Candidate preparation requires a separate clean Shared checkout outside IAM;
nested preflight checkouts receive an explicit diagnostic, preserving source
cleanliness rather than excluding untracked directories from that check.
Actual current PARTIAL declarations, an unreviewed source revision and a changed
index digest each deny candidate preparation; no candidate was published.

MP3 registration preparation is repository construction evidence. MP4/MP5 native
provider mechanics have disposable integration evidence; current CP-governed
native/workload dispatch, registered estate consumers and full operational
session/assurance composition remain open. The MP0–MP20 staging/production rows
remain unproved. All provider declarations stay PARTIAL.

Live registration/profile publication still needs reviewed full composed support
proof, actual CP-allocated targets and provider/instance IDs, approved references,
artifact digests/evidence, registered estate clients, scoped observer credentials
and protected CP origin/CA. No owner inputs were fabricated, no Shared bundle
was submitted as IMPLEMENTED, and no production activation or certification
was performed. Registration candidates do not resolve or override CP authority.
