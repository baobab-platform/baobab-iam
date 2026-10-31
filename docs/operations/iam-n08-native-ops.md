# IAM-N08 — Native operational hardening

31 October 2026 | DRAFT, CONNECTED QUALIFICATION HELD

Accepted sequence: N01 architecture; N02 native Kratos→Hydra→CP human login; N03 workload/resource; N04 provider qualification; N05 lifecycle; N06 assurance/security; N07 connected estates/engines; N08 native operational hardening. Source branch is stacked on N07 #152 and N06 #151. N03 #148 and N04 #149 remain separately reviewed dependencies.

Scope and acceptance: reproducible native images, dependency gates, real restore/replay negatives, operational observability, performance evaluation, and maintenance guidance. Kratos owns native humans; Hydra OAuth/workload issuance; Keycloak bounded federation; CP canonical Principal/Context/business authority.

## Source implementation

1. Dockerfile.native-browser-bff pins the exact Go 1.27.3 Alpine digest already used by federation-authority, verifies go.sum, uses GOTOOLCHAIN=local / CGO_ENABLED=0, strips VCS/path/buildid metadata and produces a scratch, rootless (65532) native runtime with CA roots. No shell, secret-bearing copy or mutable runtime image.
2. scripts/n08_verify_supply_chain.py enforces the exact immutable base, module digest verification, non-root, explicit context and secret exclusions; test_n08_native_supply_chain.py contains tampering negatives. Independent CI builds two uncached images, compares IDs, invokes the true binary without owner secrets under a read-only/network-disabled/no-capabilities container and requires safe startup denial. Trivy HIGH/CRITICAL gate and CycloneDX SBOM remain mandatory independent checks.
3. cmd/native-browser-bff/main.go now explicitly enables IAM-N06 fresh Kratos A1/A2 provider-backed assurance at every login, consent and callback. The only reviewed issuer-login scope is openid trade:buy and its owner-side mapping is to authentication-only buyer.read; it does not authorize a purchase. High-risk buyer.commit/approve still needs a separate real current risk, A2/A3 and CP/native operation fence. Missing risk proof DENIES, with no fabricated low-risk or A3/A4 witness.
4. internal/nativebff/n08_observability.go is wired to the actual HTTPS handler. It issues independently generated response request IDs and records fixed-cardinality route, status class and latency bucket. It never stores access tokens, principal, email, IP, request path/query, cookie, provider URL, raw HTTP response or user-controlled metric labels. On shutdown, only bounded aggregate counts are emitted. TestN08 checks privacy, concurrency, status and unit-only microbenchmark.
5. The N06 PostgreSQL 17 CI service runs tests/operations/n08_postgres_restore_replay.sh. It performs real pg_dump → digest → pg_restore into a new disposable database, then proves the restored security event and recovery hold, duplicate replay denial, immutable event update/delete veto, hold-shortening veto, corrupt-backup refusal and independent synthetic cleanup. This is actual PostgreSQL behavior, but NOT an issuer/CP/Redis backup certification.

## Live development acceptance outstanding

- Independently provision exact-source-pinned, TLS-verified disposable Kratos, Hydra, CP, Redis, estates and Pulse/Payments/TMS resource owners with synthetic real CP Principals, clients, memberships, current grants and owner-private credentials. No public PR or source test can provision a real legal actor.
- Execute same-run IAM N02/N03/N04/N06/N07 original browser, resource-server and issuer/CP/native negatives including AAL2, revoked unexpired human and workload tokens, foreign Tenant/Market/Organisation, missing mandate, outage, stale capability revision, replay and complete teardown. Native RP-verified A3/A4 remains held.
- Measure actual issuer/CP/BFF/resource p50/p95/p99 with reviewed load/latency limits and independent non-sensitive correlations; local Go unit microbenchmarks are not real production-latency evidence.
- Restore real *disposable* provider databases, browser vault, Redis custody, CP authority, outbox/replay, encryption key rotation and activation history, then verify no revoked Principal, session or native booking authorization is resurrected. Obtain independent original and cleanup evidence.
- Require complete exact-head CI, current advisories, reviewed Go module/images, source manifest and release/rollback packet. Protected staging and production are independent gates; this programme does not activate them.

## Operations guide

Image drift: stop release, pin and review base/library upgrades with separate supply-chain and security verification; do not bypass go.sum or suppress severe vulnerabilities simply to make CI pass.

Kratos/Hydra/CP outage: fail closed and deny login/resource access, never infer CP mandate or fall back to a corporate group role. A local BFF logout may terminate private custody, but it does not imply global issuer revocation.

Database restore/replay: stop mutations when provenance is uncertain; preserve independent originals; restore to a separate environment/epoch; prove revoked sessions do not reappear and security holds cannot shorten. Never overwrite or delete append-only security evidence to hide a failure.

Rotation: maintain dual-key/JWKS overlap until all actual consumers and original tokens are independently checked and expiry/approval confirmed, then retire old trust. Two-person authority for security-critical actions remains mandatory.

Observability: low-cardinality sanitized metrics only, isolate private raw incident evidence, alert on sustained provider faults, denied-rate and latency regression without logging secrets/PII. A response request ID is not an authorization credential.

Rollback: restore only the exact reviewed prior image and compatible schema under independent CP/IAM witness, without rolling back credential revocation or evidence append-only state. Safe rollback includes replay and teardown proof.

Current status: source implementation and CI instrumentation; connected N08 operational acceptance HELD. Do not merge on source or fixtures alone.
