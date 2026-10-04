# Pinned CP consumer verifier compatibility

The nested Go module compiles the **unchanged** production `internal/auth/oidc.go`
from baobab-cp commit `20235ac2c4e1c0285e747a5a4b41c1eefb3a4dd7`, with that
revision's unchanged go.mod, go.sum and Apache 2.0 license. `provenance.json`
records SHA-256 checksums; `verify_snapshot.py` prevents accidental fixture edits.
Updates require reviewing the upstream verifier and refreshing the complete
snapshot and provenance together. This is test-only source, not an IAM verifier
or an alternative CP implementation. A pinned snapshot keeps private cross-repo
checkout credentials out of pull-request execution.

The probe calls `auth.NewOIDCVerifier`, `Verify` and `Principal.HasScope` directly.
It discovers the disposable Hydra issuer and fetches its actual public JWKS.
Tokens enter through stdin, never command arguments, environment variables,
files or logs. Output contains only three booleans. Infrastructure failures exit
nonzero and cannot count as security rejection.

Run `bash tests/ory-foundation/run.sh`, then
`bash tests/ory-foundation/token_profile.sh`. The latter compiles the probe and
requires PASS evidence for all six consumer scenarios:

- genuine Hydra token accepted, with workload identity and requested scope;
- same signed token rejected for another audience;
- same signed token rejected by a differently configured issuer using the same
  JWKS origin;
- valid identity lacks an ungranted required scope (`HasScope` returns false);
- corrupted signature with unchanged valid claims rejected;
- genuine five-second Hydra token rejected after expiry.

The expiry fixture updates only the disposable client's native token lifetime.
It neither rewrites a signed token nor changes CP's clock or verifier rules.

This proves **CP verifier compatibility at the recorded revision**. It does not
run the CP HTTP router, workload registry checks, canonical principal mapping,
context ownership, tenant isolation, grants, PostgreSQL or gateway mTLS. Missing
scope evidence is a scope-membership check, not a route-level HTTP 403 claim.
Artifacts explicitly retain `deployed_resource_route_tested=false` and
`canonical_activation_proven=false`. The previous provider-only artifacts keep
their own `actual_consumer_tested=false`; consumer evidence is recorded separately.

Accepted ADR-IAM-0020/0022 preserve consumer trust and forbid token-mechanics
proof being promoted into platform authority. CP ADR-BCP-003/004/009 require
context, grants and isolation beyond authentication. No provider pin, consumer
trust configuration, Shared registry or production deployment changes here.


## Current protected context route (bounded M4 increment)

The historical snapshot above stays pinned to #60's reviewed revision. The
separate `current/provenance.json` pins CP after #255 to
`c84063cb07dce76e1ffac4b12fa29c5e4e5ec855`. CI checks out that entire immutable
repository and verifies a clean HEAD before adding only a test command. It
builds with `-mod=readonly`; no production source or dependency lock is patched.
The cross-repository checkout uses the existing read token with credential
persistence disabled. Missing checkout access fails the proof, never substitutes
an older verifier or a stub.

`current/main.go` runs CP's production HTTP router, middleware, schema,
`TokenVerifier`/`SubjectVerifiers` (`AudienceVerifiers` JWT implementation),
registry parser, canonical identity repository and context handler. Both the
validator bearer and subject credential are real tokens signed by disposable
Hydra. Their audiences differ: the validator authenticates to
`baobab-control-plane`; its registered subject audience is `baobab-erp`.
No test verifier replaces CP authentication. CP's own auth/API regression tests
also run; their opaque-token abstraction coverage is not live introspection
proof.

Sixteen cases prove bounded context acceptance without a tenant claim, refreshed
subject acceptance, and rejection of wrong audience, tampering, genuine expiry,
missing bearer/scope, unregistered or revoked validators, foreign or validator
ownership, unknown/expired/unbounded contexts, revoked external mappings and
suspended tenants. Context-not-found responses keep the same public code and
detail. Tokens travel only over private stdin and loopback HTTP. The harness
asserts response/audit credential absence and emits only safe decisions.

The `m4-ci-*` clients, ACTIVE validator registration, canonical principals,
stored contexts and tenant store are **CI fixtures**. They do not allocate
`context:validate` or validator audiences to any Shared workload. CI appends
these profiles only to private temporary hook input; the canonical projection,
registry and production configuration stay unchanged. The in-memory context
repository and stub tenant store do not prove production PostgreSQL, deployed
registry configuration, a deployed resource server, ERP business authorization,
gateway mTLS or production trust. Refreshed tokens resolve the same canonical
owner independently in freshly seeded fixtures; this is not deployed session
continuity evidence.

`cp-context-route.json` records the current pin and all HTTP decisions, with
`actual_protected_route_tested_in_fixture=true`,
`deployed_resource_route_tested=false` and `canonical_activation_proven=false`.
This advances M4 compatibility evidence only. Actual registered resource-server
acceptance, governed validator allocation, M4-F projected-token issuance and
Shared activation remain separate gates. No Ory cutover or Keycloak retirement
is authorised by this fixture.
