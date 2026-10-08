# Hydra audience backport acceptance candidate

Authority: ADR-IAM-0033 MP6 / M4-F and ADR-0007 audience separation.
This is an isolated test candidate, not a production provider release or support
activation. The existing provider.lock.yaml and deployed image references stay
unchanged. Keycloak remains permanent enterprise federation/SSO infrastructure.

## Exact source and change

Base: Ory Hydra v26.2.0, commit
`0b84568fffccf151dc5e6c7955fdfb738555bf4b`.
Upstream fix: `92bd3eab9864453d72edc3d0bc51f004ff986c06`.

The build fetches these exact Git objects and applies the upstream diff for the
configuration, schema, Fosite handler and their unit tests verbatim. No other
master changes are adopted. The upstream commit's OAuth HTTP test hunk also
applies, with one exception: it sits on top of a later upstream test (an
unrelated "issuer-derived audience" subtest) that is not in v26.2.0. The
repository holds that hunk with only that unrelated subtest removed
(`tests/ory-foundation/hydra-audience/oauth2-jwt-bearer-test.patch`); it keeps
upstream's own edit that pins the released HTTP suite to the legacy copy
behavior and adds upstream's test that the assertion audience is omitted when
the option is enabled (opaque and JWT access-token strategies). The build
fails unless that subtest passes, and the receipt records its patch hash. IAM's
live candidate suite separately tests the new behavior with the existing
governed hook and unchanged CP verifier source.

The fix introduces `oauth2.grant.jwt.omit_assertion_audience`. Candidate hook
configuration explicitly sets it true. The incoming assertion still names the
Hydra token endpoint and still requires exact issuer/subject, signature, expiry
and replay verification. The requested resource audience comes from the OAuth
`audience` parameter and the client's registered audience. IAM's hook independently
checks the granted audience against its Shared-derived workload projection.
No reserved claim is rewritten and no verification fallback is introduced.

Upstream sources:
- https://github.com/ory/hydra/commit/92bd3eab9864453d72edc3d0bc51f004ff986c06
- https://www.ory.com/docs/hydra/guides/jwt

## Isolated build and acceptance

```sh
bash tests/ory-foundation/hydra-audience/build.sh
export ORY_HYDRA_AUDIENCE_CANDIDATE=1
bash tests/ory-foundation/run.sh
# Prepare the existing pinned CP consumer checkout as in Ory Foundation Live.
bash tests/ory-foundation/token_profile.sh
```

The source build executes upstream RFC7523/config race tests and the released
OAuth JWT-bearer HTTP suite before building. CI exposed vulnerable released
runtime libraries and Go modules. The candidate now uses a scratch runtime with
the exact digest-pinned trust bundle and nonroot account; the static binary needs
no OpenSSL, musl or zlib. An explicit USER retains UID/GID 65532.

`security.patch` pins Go dependency fixes and their checksum closure, isolates
Ory's Docker schema-dump helper behind an explicit integration-test build tag,
and removes redundant legacy pgconn imports. Transaction retries still use exact
SQLSTATE 40001 through the error interface, including wrapped errors. No retry,
replay or recovery fencing is disabled. The runtime dependency graph rejects
Docker, pgconn and pgproto3/v2; original Docker helpers remain compiled in the
upstream HTTP tests with `hydra_integration_tests`.

The exact released Pop module is copied into a local candidate replacement;
only its configuration parser import moves to pgx/v5, the driver already used for
actual connections. Compatibility tests compare consumed fields and rejection
for URI/keyword DSNs, IPv6, Unix sockets and TLS modes. pgx/v5 deliberately rejects
nonexistent certificate files even with TLS disabled; the released disabled-TLS
test uses a valid DSN, and an additional test requires that rejection. No SQL
migrations or connection runtime are substituted. No other Pop release is adopted.

Build receipts record base/fix commits, audience/security patch hashes, module
manifest/checksum hashes and binary hash. The fixture
records the resulting local image ID and refuses image substitution before use.
The build context contains only the binary and Dockerfile, never source .git
metadata, credentials or temporary tests.

The existing Ory Foundation workflow now tests released and backport images
independently. The candidate must pass a HIGH/CRITICAL image vulnerability gate
and emits a CycloneDX SBOM. Each matrix leg uploads separate evidence. Candidate
federated tokens for the existing production-environment disposable fixtures
must have exact subjects, client identities, requested scope and resource
audience; the real CP verifier must accept them and reject wrong audiences,
issuers and tampered signatures. Replay and absent/unregistered resource audience
are denied. The original workload negative/revocation/rotation tests also run.
The staging-only evidence workload is not admitted to a production hook.

These are disposable registered-provider fixtures and CP verifier construction
results. They do not prove an active deployed workload, resource route or
production consumer. Receipts explicitly retain fixture-only classification,
no canonical activation and no production acceptance. Skipped required live
tests cannot satisfy the evidence check.

## Production promotion and rollback

Production adoption requires reviewed image publication/provenance and registry
digest, security scan/SBOM acceptance, migration compatibility, staging issuer
and consumer acceptance, and provider runtime-profile/artifact reconciliation
through CP. Those are separate from this PR. Hydra support remains PARTIAL.

Retain the released v26.2.0 digest and configuration as the rollback target.
Rolling back restores the prior fail-closed audience behavior and therefore
blocks affected federated issuance; do not loosen the hook to hide that outage.
Never assume binary downgrade implies database compatibility. Review any
migration delta before promotion; this backport changes no SQL migration files.

## Local verification, 2026-10-08

| Check | Result |
|---|---|
| IAM go test ./..., vet and build | Passed |
| IAM Ory/federation race tests | Passed |
| Existing Python tests | Passed, 21 tests |
| Upstream RFC7523/config race tests on backported source | Passed |
| Released OAuth JWT bearer HTTP suite, SQLite enabled | Passed |
| Candidate Pop PostgreSQL parser compatibility/race tests | Passed |
| Shell syntax, workflow YAML parsing, unchanged CP source provenance | Passed |
| Container/image security and live Hydra/CP acceptance | Not run locally; Docker unavailable; required CI matrix |
| Staging/production acceptance | Open; no deployment/promotion performed |
