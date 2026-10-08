# Canonical workload request admission

ADR-IAM-0033 MP3/MP4; pinned Shared
`identity/v1/workload-token-request.schema.json`.

`tokenprofile.WorkloadTokenRequest` carries only workload ID, logical audience
and scopes. Its closed JSON decoder denies extra provider/credential/business
fields, duplicate properties, missing/null fields, trailing JSON and requests
over 4096 bytes. Scope omission survives round trips separately from an explicit
empty list. Go and the exact pinned Shared schema validate the same corpus.

`Config.AdmitRequest` consumes provider-authenticated `Evidence` after credential
verification. It checks the canonical workload's ACTIVE status, issuer environment,
exact client ID and resource audience. Requested and granted scopes must match
the canonical intent exactly; granted audiences must contain exactly that one
resource. Existing `Config.Claims` still enforces the registered credential type,
exact projected issuer/subject and scope allocation. PROVISIONED remains usable
only through the existing provider-mechanics path; it is denied by canonical
admission. No registry status is promoted or persisted by this function.

Omitted scopes require an independently governed per-workload/per-audience
least-privilege default. Missing defaults, an explicit empty list and defaults
outside the registration fail closed. Never derive defaults from all allowed
scopes, and never accept defaults from a token requester. Evidence must come
from credential verification; constructing an Evidence value is not proof of
successful verification. Configuration is an immutable projection for the call,
not a replacement CP registry or a cached readiness decision.

This increment implements an admission library, not an HTTP endpoint, token
proxy, issuer, credential verifier or CP dispatch path. Standards token issuance
and resource verification stay direct. C3 full workload support remains PARTIAL:
the composed caller must invoke admission with genuine verified evidence and
current approved registration/binding authority. C4 must resolve and revalidate
CP authority before actual native/workload dispatch. Native human authorization,
actual registered resource consumption, live registration, staging and production
acceptance remain open.

Validation: 44 Python tests passed, including pinned Shared corpus validation;
Go test/vet/build passed; token-profile race tests cover both credential types,
concurrent admission, identity/environment/lifecycle mismatches, audience/scope
inflation, malformed wire input and default-policy failures. Local live provider,
container, PostgreSQL and staging tests were not run for this increment. CI
adds the contract corpus and token-profile race checks; current PR checks must
pass before merge. No credentials, production activation or Keycloak reduction
are introduced.

## Authenticated Hydra hook composition

`NewCanonicalTokenProfileHook` reconstructs canonical intent from Hydra's
authenticated callback fields: exactly one granted audience, nonempty requested
scopes, and the verified client ID. Admission uses
the existing credential-bound evidence and rejects any mismatch with granted
scopes or audiences before emitting workload claims. This path requires explicit
scopes; no default is inferred inside the hook.

The executable `ory-token-profile-hook` selects this stricter constructor for
a `production` profile. PROVISIONED cannot pass that production path. Staging/
development retain the mechanics constructor for existing bounded fixtures.
The port remains a private authenticated Hydra callback, not a proprietary
public token endpoint. Production callbacks with empty requested scopes or multiple granted resources
are denied. The sanitized callback cannot establish whether an audience parameter
was explicitly present on the original OAuth wire request. No production deployment or
activation was performed.

Composition tests exercise both credential types, ACTIVE success and denied
PROVISIONED/revoked registrations, unauthenticated senders, missing/substituted/
extra audiences, scope inflation and subject mismatch. The executable factory
test proves production cannot select mechanics-only admission. These fixtures
represent Hydra after credential verification; they do not independently prove
assertion signatures or current CP registration. Full workload support remains
PARTIAL until current CP authority, actual issuance and consumer acceptance are
composed and proven. Runtime projection freshness/revocation is still a C4
dependency, not established by this immutable hook configuration.

The Ory live mechanics harness uses `tests/ory-foundation/mechanics-hook`, a disposable launcher for PROVISIONED provider mechanics. It does not use the production executable and cannot establish canonical activation or production acceptance. The production factory remains ACTIVE-only; its authenticated canonical composition and negative cases are covered by Go and race tests.

Pinned Hydra exposes requested scopes and granted audience as authenticated callback fields, and sanitizes payload to assertion only. Canonical admission uses those fields and requires one granted resource, nonempty requested scopes, exact granted scopes and ACTIVE status. The callback cannot prove that an audience parameter was explicitly supplied; explicit wire-parameter provenance remains unproven and is not a support claim.
