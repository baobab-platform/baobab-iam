# ADR-IAM-0033 programme status

Reviewed 2026-10-05 against IAM main
`a927259753a0d2dee16f8df6f5509c5dc9cb18e9`. This is a repository evidence
reconciliation, not certification or authority activation. The original MP0
snapshots and bounded-increment documents remain historical evidence; this
document supersedes their claims that MP8 and shared state are still planned.

## Current implementation and acceptance

| Gate | Repository assessment | Remaining exit evidence |
| --- | --- | --- |
| MP0 | Baseline reconciled in #64 | Operational inventory and owner acceptance |
| MP1 | Capability ownership matrix established | Runtime declarations and production evidence are independent |
| MP2 | Shared contracts and live CP/IAM authority composition implemented | Deployed authority/consumer acceptance |
| MP3 | CP provider/support/profile foundations exist | IAM production support projection; no competing local registry |
| MP4 | CP generic resolver exists; enterprise adapter explicitly bound | CP resolution consumed by IAM composition root and adapter dispatch |
| MP5 | Kratos native lifecycle/session boundary implemented in part | Full assigned-capability conformance and deployed proof |
| MP6 | Hydra issuance, RFC 7523 and CP verifier fixture evidence advanced | Canonical activation and actual consumers, including M4-F |
| MP7 | Permanent federation allocation reconciled | Capability-specific native Keycloak inventory/reduction with rollback proof |
| MP8 | Permanent Keycloak adapter; actual OIDC/SAML brokering in #75 | Production conformance/operational acceptance |
| MP9 | Durable trust revisions, four-eyes approval and containment | Deployed governance acceptance |
| MP10 | Governed broker route after trust selection | Provider-neutral login discovery; domain hints confer no identity or access |
| MP11 | Exact upstream issuer+subject resolves through CP | Real estate acceptance; no email linking or automatic membership |
| MP12 | Governed OIDC/SAML normalization to A1–A3 | Estate step-up and deployed assurance acceptance; federation cannot claim A4 |
| MP13 | Independent SCIM/directory decision outstanding | Concrete lifecycle requirement, accepted provider decision and portability proof |
| MP14 | Durable event/replay foundations | Broader cross-provider drift/event reconciliation |
| MP15 | Separate trust roots, credentials and verified signing material | Deployed rotation, overlap and compromise drills |
| MP16 | PostgreSQL shared state and recovery fencing in #77 | Cloud HA/failover/restore, residency and measured approved RPO/RTO |
| MP17 | No final multi-provider estate acceptance | ZuriBeans B2B; Thamani B2C/B2B logistics; Nabhold workforce/executives |
| MP18 | Global Keycloak deletion cancelled | Capability-aware native cutover and migration reconciliation |
| MP19 | Protocol/adversarial/race/live CI construction evidence | Deployed compromise, rotation and resilience certification |
| MP20 | Not accepted | Staging/production operational evidence and owner sign-off |

## Evidence pointers

| Implemented boundary | Executable evidence |
| --- | --- |
| Permanent federation port/adapter | `internal/provider/enterprise.go`, `internal/provider/keycloak/enterprise.go` |
| Original upstream proof and downstream digest binding | `internal/federation/broker_verification.go`, `providers/evidence-bridge/` |
| OIDC/SAML protocol verification and normalized assurance | `internal/federation/broker_configuration.go`, `internal/federation/native_protocol.go`, `tests/enterprise/` |
| Governed trust revisions and independent approvals | `internal/federation/trust_ledger.go`, `internal/federation/approvals.go` |
| Live CP canonical/platform authority | `internal/federation/http_authorities.go`, `cmd/federation-authority/main.go` |
| Shared durable state and externally controlled recovery epoch | `internal/federation/postgres_storage.go`, `scripts/operations/federation-recovery.sql` |

These files demonstrate construction, not production deployment. A VERIFIED
runtime facet does not establish canonical support, ACTIVE lifecycle, health,
entitlement or a business grant. CI fixtures do not activate trust or workloads.

## Next bounded convergence

Use CP's existing `identity.authentication.perform` capability and the approved
OIDC_FEDERATION/SAML_FEDERATION runtime facet. The candidate
`identity.federation.enterprise` key remains outside the pinned catalogue.
Do not manufacture a new platform key or equate a runtime facet with a grant.

1. Consume current CP provider/instance/profile/deployed-artifact evidence as a
   read-only projection. Keep canonical registry, lifecycle, topology and
   placement authority in CP; keep adapter mechanics in IAM.
2. Resolve the catalogued capability using a caller-owned, bounded CP context.
   A BFF-owned context cannot be redeemed with IAM's workload token. Any context
   provisioning/renewal must preserve exact canonical caller ownership.
3. Dispatch only to a locally composed adapter whose provider and instance match
   both the resolution and the governed FederationTrust. Check profile freshness,
   exact artifact, scope, protocol and approved configuration. No provider name,
   endpoint, email domain or organisation hint may choose an adapter.
4. Deny expired/revoked/ambiguous resolution, absent adapters, unverified support,
   changed trust/profile and authority outages. Revalidate on callback. Never
   fall back from enterprise federation to native login or workload issuance.
5. Exercise the composed runtime and deny paths. Record the bounded enterprise
   scope separately from MP5/MP6 conformance, MP10 discovery and MP17 adoption.

The [implementation plan](iam-mp-implementation-plan.md) retains the full
programme dependencies. [Shared-state recovery](../operations/federation-shared-storage.md)
controls restored federation authority; it does not substitute for independent
Kratos, Hydra and retained Keycloak recovery and revocation certification.

## Bounded MP3/MP4 enterprise convergence increment

The enterprise authority-service composition now consumes CP capability
resolution and its current federation runtime projection before begin/callback
adapter dispatch. Production enterprise startup requires this mode; readiness
uses the same selection path. Adapter inventory confers no activation authority.
See [configuration and claim boundary](../operations/enterprise-capability-dispatch.md).

The baseline MP3/MP4 table above describes the audited main. This increment
closes the bounded enterprise dispatch gap, not production support publication,
native/workload dispatch, neutral discovery, supervised deployed context renewal
or MP17/MP19/MP20 acceptance. No registry or Shared capability is duplicated.
