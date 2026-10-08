# Governed provider support publication

Authority: ADR-IAM-0033 MP3/MP4, ADR-SHARED-017. This procedure prepares
canonical registration documents; it neither registers nor activates a provider.

## Construction preflight

Use a clean Shared checkout at the exact `contracts.lock.yaml` commit:

```sh
python3 scripts/provider_publication.py --shared-checkout .shared-contracts
python3 scripts/provider_publication.py --shared-checkout .shared-contracts --require-registrable
```

The first command validates construction and reports exclusions. The second is
the publication gate: exit 2 means one or more providers have no IMPLEMENTED
canonical support. Exit 1 is invalid input or contract validation failure.
Only Shared's canonical generator emits EngineRegistration, always DRAFT.
PARTIAL and planned support never enter the generated documents. An empty
registration list is not readiness. A source revision marked dirty is local
construction evidence and must not be used as a release receipt.

Optional `--registration-export reviewed-registrations.json` compares a JSON
array of previously reviewed canonical DRAFT EngineRegistration documents.
Missing, additional, substituted or changed declarations cause exit 2. Invalid,
duplicate or foreign documents cause exit 1. These are registration documents,
not live CapabilityProvider resources; ACTIVE resources are not valid exports.
The tool does not contact CP and makes no claim about export freshness, live
drift, binding eligibility, health, certification or runtime readiness.

## Current publication dependency

At IAM main `cef8d0210f128352b2d3a264f349e5c12e646d4d`, Kratos, Hydra and
Keycloak each declare PARTIAL support. Their canonical contracts require full
interactive Authorization Code/PKCE/token handoff or registered workload token
issuance respectively. Existing credential/session and broker mechanics are
not the complete human authentication capability. Do not change PARTIAL simply
to obtain a registration document. Complete the contract, add composed tests,
and review the declaration evidence before rerunning the gate.

## Owner-approved registry convergence

After construction eligibility, CP owners must supply real provider and
engine-instance IDs, approved configuration/security-domain references, exact
artifact digest and revision, scoped runtime profiles, and governed binding
inputs. Use CP's existing registration and changeset mechanisms. Registering
DRAFT support does not authorise activation, grants, binding or certification.
Read the current authoritative CP projection and resolution before dispatch;
never substitute this offline report for CP authority or cache it as readiness.

Live acceptance additionally requires the protected CP origin/CA and provisioned
workload admission, independent maker/checker approval, real registered estate
clients and workload consumers. Supply secrets through protected deployment
configuration. Retain Keycloak permanently for enterprise federation and SSO.

## Verification of this increment

29 Python tests passed, including eight publication tests. Go `test ./...`,
federation/executable-authority race tests, vet and build passed on the current
baseline. Pinned Shared declaration, matrix and federation/resolution wire
checks passed. The strict publication gate returned exit 2 with three blocked
providers and zero registrations, as required. No live publication was run.
Docker/container scanning, live OIDC/SAML providers and PostgreSQL tests were
not run here because their executable environments are unavailable. Staging
and production acceptance remain open.

## C3 runtime profile publication client

`scripts/runtime_profile_publication.py` consumes an owner-supplied, secret-free
Shared `IdentityProviderRuntimeProfile`. It never derives VERIFIED evidence
from local tests or invents CP provider, instance or reference identifiers.
Use the exact clean Shared pin and independently reviewed target arguments:

```sh
python3 scripts/runtime_profile_publication.py \
  --shared-checkout .shared-contracts --profile approved-runtime-profile.json \
  --provider-id "$CP_PROVIDER_ID" --engine-instance-id "$CP_ENGINE_INSTANCE_ID" \
  --artifact-digest "$APPROVED_ARTIFACT_DIGEST" \
  --configuration-reference "$CP_CONFIGURATION_REFERENCE" \
  --security-domain-reference "$CP_SECURITY_DOMAIN_REFERENCE"
```

The default is validation only. To submit, append `--publish --cp-origin` with
the protected HTTPS CP origin, and optionally `--ca-file` for its trust bundle.
Supply `CP_RUNTIME_OBSERVER_TOKEN` through protected environment configuration;
never put credentials in arguments, profile documents or evidence receipts.
CP must independently admit that workload for `identity-runtime:observe` and
the target environment/regions. The existing
`POST /internal/identity-runtime/v1/profiles` API checks registered targets,
current authority, references, artifact, revisions and idempotent replay.
The client rejects duplicate JSON, duplicated facets, substituted targets,
future publication, mismatched/expired evidence, non-HTTPS origins and
redirects. TLS verification stays enabled; publication is bounded to ten seconds
(default), at most thirty seconds, and has no automatic retries or fallback.

An exact 201 RECORDED or 200 REPLAY receipt is accepted only for the submitted
provider, instance and revision. The output includes a digest of the submitted
wire bytes, not a CP content digest. `CP_PROFILE_RECORDED` means the API accepted
an observation; `runtime_authority_verified` remains false. It proves neither
ACTIVE support, a current capability binding, runtime health nor readiness.
Consumers still need current CP resolution and readiness revalidation.

Construction tests cover the canonical profile, negative evidence/target
validation, bounded publication, exact replay/receipts and failure handling.
No live publication was executed: protected CP origin/trust configuration,
registered observer credentials, independently approved targets/evidence and
release digests remain required. All three full capability declarations remain
PARTIAL and the strict registration gate remains blocked. Hydra's isolated
candidate now passes fixture CP-verifier acceptance (#90); this is not a live
registered resource-server or estate acceptance claim. C4 native/workload
adapter dispatch remains open and must not activate from these receipts.

Validation on the C3 publication-client branch based on IAM `4c7f57a`:
40 Python tests passed, including 11 runtime-publication tests; IAM `go test
./...`, `go vet ./...`, `go build ./...`, and race tests for federation, Ory and
the executable authority command passed. Pinned Shared declaration validation
passed. Live provider/container/PostgreSQL/staging runs require their environments;
local unit successes are not operational acceptance.
