# Consolidated IAM Gates — Source-Audit and Qualification Disposition (2026-11-10)

**Authority:** Accepted ADR-IAM-0019 through ADR-IAM-0033, especially ADR-IAM-0033. ADR-IAM-0034 remains Proposed; Shared ADR-SHARED-042 Decision 9 governs native commitment. This crosswalk reinterprets the historical Consolidated Technical Specification Gates IAM-0–16, but neither activates CP authority nor certifies any environment.

**Runtime:** Kratos owns native human identity, Hydra owns OAuth/workloads, permanently retained Keycloak owns bounded enterprise OIDC/SAML federation. CP owns canonical issuer+subject identity, context and grants; Trade/ERP/CMS own domain authorization. Thamani's historical B2C gate is not the accepted B2B logistics direction.

| Gate | Current source evidence | Outstanding exit / qualification |
| --- | --- | --- |
| IAM-0 Architecture | 34 sequential ADR source rows now audited, accepted successors and proposal precedence documented | Architecture and implementation conformance not equivalent; independent acceptance remains |
| IAM-1 Shared Contracts | Canonical identity/v1, capability/v1 and approved runtime lock | Exact issuer/consumer compatibility; new read-only catalogue declaration in IAM #169 remains separate from issuer pin |
| IAM-2 Provider Foundation | Pinned Ory Kratos/Hydra, permanent Keycloak federation, PostgreSQL target | Real separate databases/migrations, administrative network isolation and restored release compatibility |
| IAM-3 CP Identity Spine | Native BFF CP resolver, federation canonical consumer, issuer+subject checks | Original CP + IAM + estate same-run positive/negative with no email-based identity merge |
| IAM-4 Workloads | Hydra client/JWT, client credentials/RFC7523, scoped token hook, resource validator | Original CP-registered ACTIVE workload and actual resource positive/denials; N03/DEV-14 |
| IAM-5 Workforce SSO | Native BFF and Keycloak enterprise brokering | Nabhold, CMS, Trade, ERP and Pulse real users; independent admin role and A3/A4 |
| IAM-6 ZuriBeans Buyer | Buyer BFF profile, current Kratos assurance, Trade Medusa B2B scaffolding | Original governed buyer order with real CP Principal, spend fencing, native commitments/outbox |
| IAM-7 Thamani | Historical customer B2C gate only | SUPERSEDED scope: re-architect B2B shipper/logistics identity; no automatic B2C/guest grant |
| IAM-8 Supplier | Source actor isolation, IAM subject and supplier domain separation | Actual representative membership/vetting, bank-change denial, cross-market tests |
| IAM-9 Medusa | Auth Module actor-bound providers; Trade draft #231 production credential and callback hardening | Real Medusa AuthIdentity issuer+subject, local-account migration, buyer/administrator original login |
| IAM-10 ERP | CP mapping, iDempiere 13 native posting and AD_Client/AD_Org/AD_Role | **HELD**: stock OIDC AD_User email/username lookup must be replaced with immutable CP issuer+subject and real JVM evidence |
| IAM-11 Credentials | Kratos AAL2, native AMR evidence, IAM #171/#173 safeguards | Original UV passkeys, RP-bound A3 and privileged A4, recovery/cooling/four-eyes/risk proof |
| IAM-12 Lifecycle | Kratos disable/session revoke, Hydra client lifecycle, IAM #170 verified double readback | CP/domain revocation saga, outbox/journal, crash/replay, no resurrected authority |
| IAM-13 Audit | Federation approval ledger and source redaction | Original exported OpenTelemetry lineage, IAM security event bus, privacy-safe custody and loss/replay |
| IAM-14 HA/DR | Version pins, durable federation state, recovery runbooks | PostgreSQL 17 separate provider backups/PITR, revocation journal, measured RPO/RTO and failover drill |
| IAM-15 Multi-region | ADR-IAM-0027 security domain/residency target | Independent single-writer fencing, issuer stability, regional routing and cross-region revocation |
| IAM-16 Production | CI, security policies, component tests | **NOT ACCEPTED:** pentest, load, capacity/SLI/SLO, dependency SAML advisory, SBOM, key rotation, DR, independent approvals |

## Engineering corrections implemented in open draft PRs

- **Trade #231:** Production Medusa actor authentication requires configured IAM OIDC; emailpass fallback exists only with explicit development/test environment, not an unset runtime.
- **IAM #170:** Nested Kratos trait domain-authority rejection; actual provider disable readback before and after session revocation; redaction of all Kratos/Hydra administrative response-body errors.
- **IAM #171:** No false OTP/MFA from Kratos lookup/recovery/email codes.
- **IAM #172:** No password hashes, recovery tokens, signing private keys, bearer/refresh tokens or ID documents in Kratos traits or metadata; typed nested maps/slices also checked.
- **IAM #173:** Direct native commitment workload Claims path repeats server-versus-BFF identity fence; direct human token hook checks MFA claim consistency (AAL2 and at least two distinct observed factor classes).
- **IAM #169:** Separate read-only newer capability catalogue pin; runtime issuer Shared pin remains unchanged. This independent PR is NOT folded into the sequential audit stack.

## Minimum connected development qualification

The following are **development** blockers, not protected staging approvals that can be deferred away:
1. N02 browser/estate/CP: Real Kratos+Hydra confidential client, BFF session, original seven browser cases, exact CP Principal, native recovery/logout, revocation, cross-estate failures, independent evidence and teardown.
2. N03/DEV-14: Live issuer -> CP registered workload -> Trade/ERP/CMS/Pulse/Payments native resource conformance, audience/scopes, revocation and replay, deny-on-missing authority.
3. DEV-07/09/11: Genuine Medusa customer buyer and one durable Trade order/commitment/outbox event, RabbitMQ published event, native ERP JVM consequence and independent exported OpenTelemetry trace under one business transaction ID.
4. Security: Verified A3/A4, reviewed Keycloak federation, optional SCIM lifecycle, IAM security journal, data-subject erasure/restriction and PG17 restore non-resurrection, crypto rotation, incident containment.

The historical gate specification's **Definition of Done** requires code, tests, documentation, security, migration, review, merged PR and post-merge verification. Therefore none of this stacked source-audit series by itself closes all gates or IAM-MP20. Do not promote provider support, CP bindings, protected staging/production deployment or release without separately reviewed original evidence.
