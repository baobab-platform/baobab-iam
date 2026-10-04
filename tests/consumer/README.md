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
- tampered signed content rejected;
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
