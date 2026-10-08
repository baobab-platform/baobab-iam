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
