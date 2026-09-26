# ADR-IAM-0032 — IAM Production Governance, SLOs, Capacity, Compatibility, Upgrade and Operational Acceptance Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / IAM Engineering / Security Engineering / Platform Operations  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold and all future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0031  
**Decision Type:** Production Governance / Reliability / Operations / Release Engineering / Compatibility  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Persistence Baseline:** PostgreSQL 17, subject to supported Ory compatibility  
**Deployment Model:** Containerized, independently deployable IAM components  
**Canonical Identity Authority:** Baobab Control Plane

---

# 1. Decision

Baobab SHALL consider IAM production-ready only when the identity platform is demonstrably:

```text
CORRECT
   +
SECURE
   +
AVAILABLE
   +
OBSERVABLE
   +
RECOVERABLE
   +
SCALABLE
   +
COMPATIBLE
   +
UPGRADEABLE
   +
OPERABLE
   +
AUDITABLE
```

Passing unit tests or successfully starting containers SHALL NOT constitute production readiness.

Production acceptance SHALL require evidence across:

```text
Architecture
Security
Functional Correctness
Reliability
Performance
Capacity
Availability
Recovery
Observability
Compatibility
Upgrade Safety
Operational Readiness
```

The governing principle is:

> **Baobab IAM is production-ready only when the platform can prove not merely that authentication works, but that identity remains trustworthy during load, failure, deployment, upgrade, recovery and human operational error.**

---

# 2. Closure Role of This ADR

ADR-IAM-0032 closes the foundational IAM architecture sequence.

ADRs IAM-0001 through IAM-0031 define:

```text
WHAT IAM MEANS
WHO OWNS WHICH AUTHORITY
HOW IDENTITY IS ESTABLISHED
HOW AUTHENTICATION WORKS
HOW AUTHORIZATION IS SEPARATED
HOW IDENTITY IS MIGRATED
HOW ASSURANCE IS ESTABLISHED
HOW PRIVACY IS GOVERNED
HOW SECURITY IS MONITORED
HOW ADMINISTRATION IS CONTROLLED
```

ADR-IAM-0032 defines:

```text
HOW WE PROVE
THAT ALL OF IT
IS SAFE TO OPERATE
IN PRODUCTION
```

---

# 3. Architecture Precedence

This ADR does not supersede the architectural boundaries established by IAM-0001 through IAM-0031.

Operational convenience SHALL NOT be used to bypass an accepted architectural invariant.

Examples:

```text
"We need lower latency"
        ≠
cache authorization forever

"We need availability"
        ≠
fail open

"We need easier operations"
        ≠
shared super-admin

"We need easier deployment"
        ≠
skip migration validation

"We need faster recovery"
        ≠
restore revoked identities

"We need scale"
        ≠
duplicate identity authority
```

---

# 4. Production Governance Model

Baobab SHALL govern IAM through:

```text
DESIGN
  ↓
IMPLEMENT
  ↓
VERIFY
  ↓
LOAD TEST
  ↓
SECURITY TEST
  ↓
RECOVERY TEST
  ↓
RELEASE
  ↓
OBSERVE
  ↓
MEASURE
  ↓
REVIEW
  ↓
IMPROVE
```

Production readiness is therefore continuous rather than a one-time certification.

---

# 5. Service Catalogue

IAM operations SHALL maintain an explicit catalogue of production capabilities.

At minimum:

```text
Authentication
Registration
Verification
Account Recovery
Session Management
MFA
Passkeys
OAuth Authorization
OAuth Token Issuance
OIDC Discovery
JWKS Distribution
Workload Authentication
Federation
SCIM
Identity Administration
Privileged Administration
Identity Mapping
Security Events
Privacy Operations
```

---

# 6. Service Ownership

Every production capability SHALL have an identified owner.

Conceptually:

```text
ServiceCapability
├── capability_id
├── owning_team
├── technical_owner
├── operational_owner
├── security_owner
├── dependencies[]
├── SLO_profile
├── runbook
└── escalation_policy
```

---

# 7. No Ownerless Tier-0 Capability

A Tier-0 IAM function SHALL NOT enter production without operational ownership.

---

# 8. Criticality Classes

Baobab SHOULD classify IAM capabilities by operational criticality.

Example:

```text
TIER 0
Authentication
Token issuance
JWKS
Critical session validation
Workload authentication

TIER 1
Registration
Recovery
Federation
SCIM
Identity administration

TIER 2
Reporting
Administrative analytics
Non-critical reconciliation UI
```

Exact classifications SHALL be maintained in the service catalogue.

---

# 9. SLI Before SLO

Baobab SHALL define measurable Service Level Indicators before declaring Service Level Objectives.

---

# 10. Core SLIs

IAM SHOULD measure at least:

```text
availability

successful authentication rate

authentication latency

token issuance latency

registration success rate

recovery success rate

federation success rate

SCIM processing success rate

administrative operation success rate

error rate

saturation

database health

replication health

queue/backlog depth

JWKS availability

dependency availability
```

---

# 11. Availability SLI

Availability SHALL measure successful service responses from the user's or relying system's perspective.

Process uptime alone is insufficient.

---

# 12. Authentication Availability

Example conceptual measurement:

```text
successful valid authentication requests
─────────────────────────────────────────
eligible valid authentication requests
```

The exact denominator and exclusions SHALL be formally documented.

---

# 13. Do Not Hide Failures

SLO calculations SHALL NOT remove inconvenient failures merely to improve reported availability.

---

# 14. Planned Maintenance

Treatment of planned maintenance SHALL be explicitly defined rather than silently excluded.

---

# 15. Latency

Latency SHALL be measured using percentiles.

Prefer:

```text
p50
p95
p99
```

where operationally useful.

Averages alone are insufficient.

---

# 16. Separate Endpoint Classes

Baobab SHALL NOT combine fundamentally different operations into one meaningless latency metric.

Measure separately:

```text
login
token issuance
JWKS
registration
recovery
admin mutation
federation
SCIM
```

---

# 17. SLO Profiles

Conceptually:

```text
ServiceLevelObjective
├── capability
├── SLI
├── target
├── measurement_window
├── exclusions
├── error_budget
├── owner
└── version
```

---

# 18. Initial SLO Values

This ADR SHALL NOT invent final production SLO percentages or latency thresholds before representative load measurements exist.

Instead:

```text
measure
   ↓
baseline
   ↓
capacity test
   ↓
business requirement
   ↓
approve SLO
```

---

# 19. SLO Approval

Production SLOs SHALL be jointly reviewed by:

```text
Platform Architecture
IAM Engineering
Operations
Security
Business/Product owner where appropriate
```

---

# 20. Error Budgets

Where SLOs are used operationally, Baobab SHOULD maintain error budgets.

Conceptually:

```text
SLO
 ↓
Permitted Unreliability
 ↓
Error Budget
```

---

# 21. Error Budget Governance

Excessive error-budget consumption SHOULD affect:

```text
release velocity
risk acceptance
reliability work
change freeze decisions
```

rather than merely generating dashboards.

---

# 22. Security Is Not an Error Budget

Baobab SHALL NOT knowingly accept:

```text
authentication bypass
cross-tenant authorization
credential disclosure
signing-key compromise
```

because an availability error budget remains.

---

# 23. Security Invariants Override Availability Targets

If maintaining availability would require weakening security:

```text
SECURITY
   >
WRITE AVAILABILITY
```

for security-critical identity mutations.

This preserves ADR-IAM-0027.

---

# 24. Capacity Model

IAM SHALL maintain a capacity model.

At minimum consider:

```text
registered identities
active identities
concurrent sessions
authentication requests/sec
token requests/sec
registration requests/sec
recovery requests/sec
federation volume
SCIM volume
workload token volume
database connections
database IOPS
CPU
memory
network
storage
event throughput
```

---

# 25. Capacity Is Multi-Dimensional

IAM capacity SHALL NOT be described merely as:

```text
supports 1 million users
```

because one million mostly inactive users and one million simultaneously authenticating users are radically different workloads.

---

# 26. Capacity Envelope

Conceptually:

```text
CapacityEnvelope
├── identity_count
├── active_session_count
├── auth_rps
├── token_rps
├── federation_rps
├── workload_rps
├── database_connections
├── cpu
├── memory
├── storage
├── tested_at
└── configuration_reference
```

---

# 27. Tested Capacity

Capacity claims SHALL be associated with:

```text
software version
configuration
replica count
database configuration
hardware/resource class
test workload
test date
```

---

# 28. Headroom

Production SHALL maintain operational headroom above normal demand.

Exact headroom thresholds SHALL be determined from measured traffic, scaling latency and failure behaviour.

---

# 29. Saturation

Baobab SHALL monitor:

```text
CPU saturation
memory pressure
database connection exhaustion
connection-pool saturation
disk capacity
IO latency
network saturation
thread/goroutine saturation where applicable
queue depth
```

---

# 30. Autoscaling

Stateless IAM components MAY autoscale where safe.

Autoscaling SHALL NOT replace capacity planning.

---

# 31. Scaling Signals

Scaling SHOULD use meaningful signals rather than CPU alone where workload characteristics justify it.

---

# 32. Database Scaling

Kratos and Hydra database scaling SHALL remain governed by PostgreSQL architecture and Ory compatibility.

Application replicas SHALL NOT create uncontrolled database connection growth.

---

# 33. Connection Budget

Each service SHALL have an explicit database connection budget.

---

# 34. Connection Pooling

Connection pools SHALL be bounded.

```text
replicas
×
max pool
≤
safe database connection envelope
```

---

# 35. Load Testing

IAM SHALL undergo representative load testing before production acceptance.

---

# 36. Load Profiles

Tests SHOULD include:

```text
steady state

peak login

token burst

registration burst

workload token burst

federation burst

administrative burst

recovery surge
```

---

# 37. Failure Under Load

Capacity testing SHALL also evaluate degraded conditions.

Example:

```text
normal load
+
one replica unavailable
```

---

# 38. Database Degradation

Test behaviour under:

```text
database latency
connection pressure
replica lag
temporary database unavailability
```

where safely reproducible.

---

# 39. Dependency Degradation

Test degraded:

```text
email provider
SMS provider if used
federation IdP
DNS
secret manager
event infrastructure
CP
```

according to applicable architecture.

---

# 40. Load Tests Are Not Production DoS

Load tests SHALL use isolated/non-production environments unless an explicitly approved controlled production exercise exists.

---

# 41. Performance Regression

CI/release processes SHOULD detect material performance regressions for critical IAM paths.

---

# 42. Compatibility Governance

Baobab SHALL maintain an explicit compatibility matrix.

---

# 43. Compatibility Matrix

At minimum:

| Component | Compatibility Tracked Against |
|---|---|
| Kratos | PostgreSQL, deployment chart, identity schemas, adapter |
| Hydra | PostgreSQL, deployment chart, OAuth clients, login/consent integration |
| `baobab-iam` | Kratos, Hydra, CP contracts |
| CP | IAM contracts and token profile |
| APISIX | routing/auth integration |
| PostgreSQL | Ory support, extensions, backup tooling |
| Digital Estates | OAuth/OIDC/BFF contracts |
| Trade | identity/context contracts |
| ERP | OIDC/mapping contracts |
| CMS | identity/context contracts |
| infrastructure | runtime versions and manifests |

---

# 44. Version Pinning

Production artifacts SHALL use explicit versions.

Avoid:

```text
latest
main
master
floating-major
```

for production runtime dependencies.

---

# 45. Immutable Artifacts

Production deployment SHOULD use immutable artifact identifiers/digests where practical.

---

# 46. Reproducibility

Baobab SHALL be able to determine exactly what software version is running.

---

# 47. Software Bill of Materials

Production build pipelines SHOULD generate appropriate dependency/SBOM evidence.

---

# 48. Dependency Provenance

Critical production dependencies SHOULD have verifiable provenance according to platform supply-chain policy.

---

# 49. Vulnerability Management

Dependency vulnerabilities SHALL be:

```text
detected
triaged
risk assessed
patched/mitigated
tracked
```

---

# 50. Compatibility Is Not Assumed

A new Ory release SHALL NOT enter production merely because:

```text
container starts
```

---

# 51. Ory Upgrade Policy

Kratos and Hydra upgrades SHALL independently evaluate:

```text
release notes
breaking changes
database migrations
configuration changes
API changes
security changes
identity schema compatibility
client compatibility
rollback implications
```

---

# 52. Kratos and Hydra Are Independent

Do not assume:

```text
Kratos version X
requires
Hydra version X
```

unless the supported integration matrix actually requires it.

Their versions SHALL be managed according to verified compatibility.

---

# 53. Provider Upgrade Workflow

```text
RELEASE DISCOVERED
       ↓
CHANGE REVIEW
       ↓
COMPATIBILITY ANALYSIS
       ↓
MIGRATION ANALYSIS
       ↓
NON-PROD TEST
       ↓
INTEGRATION TEST
       ↓
LOAD TEST IF MATERIAL
       ↓
SECURITY TEST
       ↓
BACKUP / ROLLBACK READY
       ↓
CONTROLLED RELEASE
       ↓
OBSERVE
       ↓
ACCEPT / ROLLBACK
```

---

# 54. Database Migration Ownership

Ory SHALL own its own database migrations.

Baobab SHALL NOT manually modify Ory internal schemas to bypass migration requirements.

---

# 55. Migration Jobs

Database migrations SHOULD run as explicit controlled jobs rather than uncontrolled side effects of every application replica starting.

---

# 56. Migration Serialization

Only the intended migration process SHALL own schema migration at deployment time.

---

# 57. Expand / Contract

Baobab-owned database schema changes SHOULD prefer backward-compatible expand/contract migration where feasible.

```text
EXPAND
  ↓
DEPLOY COMPATIBLE CODE
  ↓
BACKFILL / MIGRATE
  ↓
VERIFY
  ↓
CONTRACT
```

---

# 58. Mixed-Version Operation

Rolling deployments create periods where old and new application versions coexist.

Schema/API changes SHALL account for this.

---

# 59. Destructive Migration

A destructive migration SHALL NOT occur before all active software versions have stopped depending on the removed structure.

---

# 60. Rollback Compatibility

Before deployment Baobab SHALL know:

```text
Can application code roll back?

Can schema roll back?

Can provider version roll back?

Can configuration roll back?

Can signing/trust state roll back safely?
```

---

# 61. Rollback Is Not Always Downgrade

For some migrations:

```text
rollback
```

may mean:

```text
roll forward with corrective release
```

rather than downgrading database state.

This SHALL be documented before release.

---

# 62. PostgreSQL Baseline

Baobab's current IAM persistence baseline is PostgreSQL 17, subject to compatibility with the deployed Ory versions.

---

# 63. PostgreSQL Minor Updates

Minor PostgreSQL updates SHOULD be applied according to PostgreSQL security/maintenance guidance and tested platform procedures.

---

# 64. PostgreSQL Major Upgrades

Major PostgreSQL upgrades SHALL be treated as planned migration events.

Possible supported approaches include:

```text
pg_upgrade
logical replication
dump / restore
managed-service migration mechanism
```

according to architecture and operational constraints.

---

# 65. PostgreSQL Major Upgrade Checklist

Before a major upgrade:

```text
read release notes
review migration notes
verify extensions
verify drivers
verify Ory support
verify backup
test upgrade
test rollback/fallback
measure downtime
verify replication
verify applications
```

---

# 66. PostgreSQL Upgrade Rehearsal

Production database major upgrades SHALL be rehearsed against representative non-production data/configuration.

---

# 67. Backup Before Upgrade

A recoverable backup/checkpoint SHALL exist before high-risk persistence upgrades.

---

# 68. Backup Is Not Rollback Plan

A backup alone SHALL NOT be considered a complete rollback strategy.

Recovery time and restore correctness must be known.

---

# 69. Deployment Strategy

IAM runtime services SHOULD support rolling deployment where architecture and migration compatibility permit.

---

# 70. Availability During Deployment

Deployment strategy SHALL account for:

```text
replica count
readiness
termination
connection draining
migration state
dependency compatibility
```

---

# 71. Readiness

A process being alive does not make it ready.

Readiness SHALL indicate ability to safely receive production traffic.

---

# 72. Liveness

Liveness SHALL detect processes that require restart.

Liveness SHALL NOT be abused to restart healthy services merely because a downstream dependency is temporarily unavailable.

---

# 73. Startup

Startup checks MAY be used for components with legitimate initialization time.

---

# 74. Graceful Termination

IAM services SHALL support sufficient graceful shutdown to avoid unnecessary:

```text
request loss
partial operations
connection corruption
```

---

# 75. Disruption Budgets

Highly available IAM workloads SHOULD use disruption controls appropriate to their replica architecture.

---

# 76. Rolling Update Configuration

Rolling update parameters SHALL be intentionally configured.

Do not rely blindly on orchestration defaults.

---

# 77. Canary Deployment

Materially risky IAM releases SHOULD support canary or equivalent progressive exposure where technically feasible.

---

# 78. Canary Evaluation

Canary decisions SHOULD consider:

```text
error rate
latency
authentication success
token success
database errors
security anomalies
resource saturation
```

---

# 79. Automatic Rollback

Automatic rollback MAY be used for clearly measurable technical regressions.

It SHALL NOT automatically roll back security state in ways that resurrect revoked authority.

---

# 80. Feature Flags

Feature flags MAY decouple deployment from activation.

---

# 81. Security-Sensitive Flags

Security-sensitive feature flags SHALL themselves be:

```text
authorized
audited
environment-scoped
```

---

# 82. Kill Switches

Critical integrations SHOULD support controlled disablement where failure/compromise requires containment.

Examples:

```text
federation trust
SCIM integration
OAuth client
identity provider
risky feature
```

---

# 83. Configuration Governance

Production configuration SHALL be:

```text
version controlled where non-secret
reviewed
validated
environment-specific
auditable
```

---

# 84. Secrets Are Not Configuration Files

Secret material SHALL follow ADR-IAM-0028.

---

# 85. Configuration Validation

Invalid security-critical configuration SHALL fail deployment rather than silently fall back to insecure defaults.

---

# 86. Configuration Drift

Baobab SHALL detect material production configuration drift from approved desired state.

---

# 87. Manual Production Changes

Manual production changes SHALL be exceptional.

Where performed, they SHALL be:

```text
authorized
audited
reconciled back to desired state
```

---

# 88. Infrastructure as Code

Production IAM infrastructure SHOULD be reproducibly defined as code.

---

# 89. Snowflake Prevention

A production environment SHALL NOT depend on undocumented manual configuration that cannot be recreated.

---

# 90. Environment Parity

Development, test, staging and production need not have identical scale.

They SHOULD preserve material architectural behavior.

---

# 91. Production-Like Staging

Staging SHOULD reproduce critical production characteristics such as:

```text
Ory topology
database separation
routing
TLS
secret injection
migration workflow
observability
```

where feasible.

---

# 92. Test Environment Isolation

Non-production SHALL NOT share production:

```text
credentials
signing keys
sessions
databases
OAuth client secrets
```

---

# 93. Synthetic Identity Testing

Production smoke tests SHOULD prefer dedicated synthetic identities.

---

# 94. Synthetic Identity Marking

Synthetic production identities SHALL be clearly distinguishable and prevented from acquiring unintended real business authority.

---

# 95. Contract Testing

Cross-repository IAM contracts SHALL have automated compatibility tests.

---

# 96. Contract Categories

At minimum test:

```text
JWT profile
issuer
audience
JWKS
ExternalPrincipal
CanonicalIdentity mapping
Context
capability semantics
normalized IAM events
administrative contracts
privacy contracts
```

---

# 97. Shared Contracts

`baobab-platform/shared` SHALL define stable cross-repository contracts where justified.

It SHALL NOT become a runtime dependency service.

---

# 98. Contract Versioning

Breaking shared-contract changes SHALL be versioned and coordinated.

---

# 99. Consumer-Driven Compatibility

Where useful, consumers SHOULD test that a proposed IAM change remains compatible with their expected contracts.

---

# 100. API Compatibility

IAM APIs SHALL follow an explicit compatibility policy.

---

# 101. Breaking API Change

A breaking change SHALL require:

```text
versioning
migration path
consumer identification
communication
compatibility window
```

unless correcting an active security vulnerability requires accelerated action.

---

# 102. Security Emergency

Security fixes MAY shorten normal compatibility windows.

The exception SHALL be documented and communicated.

---

# 103. Event Compatibility

Identity events SHALL evolve compatibly.

Consumers SHALL ignore unknown additive fields unless contract rules specify otherwise.

---

# 104. Event Schema Version

Material event schema changes SHALL be versioned.

---

# 105. Replay Compatibility

Event consumers SHALL consider older event versions when replay is supported.

---

# 106. OAuth/OIDC Compatibility

Changes to:

```text
issuer
audience
scope
claims
redirect URIs
JWKS
token lifetime
client authentication
```

SHALL undergo relying-party compatibility review.

---

# 107. Issuer Stability

Issuer identifiers SHALL not casually change during deployment, region failover or upgrade.

This preserves ADR-IAM-0027.

---

# 108. JWKS Compatibility

Signing-key rotation SHALL follow ADR-IAM-0028 overlap and publication requirements.

Deployment SHALL not remove a verification key while valid tokens signed by it may still exist.

---

# 109. Client Compatibility Registry

Baobab SHOULD maintain an inventory of registered relying clients and their critical compatibility characteristics.

---

# 110. Operational Observability

ADR-IAM-0017 and ADR-IAM-0029 observability requirements SHALL be operational prerequisites.

---

# 111. Golden Signals

IAM SHOULD monitor at least:

```text
LATENCY
TRAFFIC
ERRORS
SATURATION
```

plus identity/security-specific signals.

---

# 112. Identity-Specific Signals

Examples:

```text
login success/failure
token issuance
session creation/revocation
recovery volume
MFA failures
passkey failures
federation failures
SCIM backlog
unknown kid
mapping failures
privileged actions
```

---

# 113. Database Signals

Monitor:

```text
connections
pool usage
transaction rate
lock contention
query latency
storage
WAL
replication lag
backup age
vacuum health
```

as applicable.

---

# 114. Dependency Signals

Observe material dependencies independently so IAM failures can be attributed correctly.

---

# 115. Correlation

Requests SHOULD carry correlation/trace identifiers across:

```text
Digital Estate
   ↓
BFF
   ↓
IAM
   ↓
CP
   ↓
Domain
```

without propagating secrets.

---

# 116. Distributed Tracing

Tracing MAY be used for production diagnostics.

Sensitive identity and credential information SHALL be excluded or appropriately protected.

---

# 117. Alerting

Alerts SHALL be:

```text
actionable
owned
severity-classified
runbook-linked
```

---

# 118. Alert Fatigue

A permanently firing alert is not an operational control.

Noisy alerts SHALL be tuned rather than ignored.

---

# 119. Alert Ownership

Every production-critical alert SHALL have an escalation destination.

---

# 120. Runbooks

Tier-0 failures SHALL have runbooks.

---

# 121. Required Runbooks

At minimum:

```text
authentication outage
Hydra outage
Kratos outage
PostgreSQL outage
database saturation
replication failure
signing-key incident
unknown-kid incident
federation failure
SCIM failure
CP dependency failure
region failover
backup restore
break-glass
credential compromise
privileged account compromise
```

---

# 122. Runbook Quality

A runbook SHALL identify:

```text
symptoms
diagnosis
safe actions
unsafe actions
escalation
rollback/recovery
verification
```

---

# 123. Runbooks Must Be Exercised

A runbook that has never been tested is documentation, not demonstrated recovery capability.

---

# 124. Incident Severity

IAM SHALL define incident severity classes appropriate to operational impact.

---

# 125. Security Severity

Operational severity and security severity MAY differ.

Both SHALL be represented where relevant.

---

# 126. Incident Command

Major IAM incidents SHALL have a clear incident owner/commander.

---

# 127. Communication

Major outages SHALL define communication paths for:

```text
engineering
security
business owners
affected estates
affected customers
```

where appropriate.

---

# 128. Post-Incident Review

Material incidents SHALL receive blameless technical review focused on:

```text
what happened
impact
detection
response
recovery
root/contributing causes
control failures
corrective actions
```

---

# 129. Corrective Actions

Post-incident actions SHALL have:

```text
owner
priority
due state
verification
```

---

# 130. Recovery Objectives

ADR-IAM-0018 and 0027 RPO/RTO requirements SHALL be operationally measured.

---

# 131. No Invented RPO/RTO

Production documents SHALL not claim:

```text
RPO = 0
RTO = 5 minutes
```

unless architecture and exercises demonstrate those values.

---

# 132. Recovery Exercise

IAM SHALL periodically test:

```text
database restore
regional failover
key recovery
security journal replay
privacy erasure replay
issuer continuity
client validation
```

as applicable.

---

# 133. Recovery Verification

A recovered system SHALL not be declared healthy merely because processes start.

Verify:

```text
authentication
token issuance
JWKS
revocations
CanonicalIdentity mapping
CP context
privacy state
security state
federation
workload identity
```

---

# 134. Restore Integrity

Restored IAM SHALL reconcile restrictive security state before becoming authoritative.

---

# 135. Disaster Recovery Acceptance

DR capability is accepted only after demonstrated recovery.

---

# 136. Backup Verification

Backups SHALL be periodically restored in controlled environments.

---

# 137. Backup Metrics

At minimum monitor:

```text
backup success
backup age
restore-test age
retention
encryption
```

---

# 138. Operational Change Classes

Baobab SHOULD classify changes such as:

```text
STANDARD
NORMAL
HIGH_RISK
EMERGENCY
```

---

# 139. High-Risk Changes

Examples:

```text
issuer change
signing-key change
database major upgrade
Ory major upgrade
identity schema change
federation trust change
region promotion
authorization model change
```

---

# 140. High-Risk Change Requirements

High-risk changes SHOULD require:

```text
documented plan
compatibility analysis
test evidence
rollback/recovery plan
approval
observation window
```

---

# 141. Emergency Changes

Emergency changes MAY shorten normal process.

They SHALL NOT eliminate:

```text
audit
authorization
post-change review
```

---

# 142. Change Freeze

Baobab MAY freeze non-essential IAM changes during:

```text
major incident
DR operation
critical business event
severe error-budget exhaustion
```

---

# 143. Release Candidate

Every production IAM release SHALL correspond to an immutable candidate artifact.

---

# 144. Release Evidence

A release SHOULD provide:

```text
source commit
artifact digest
dependency manifest
test results
security scan results
migration status
compatibility evidence
```

---

# 145. CI Gates

IAM CI SHALL include appropriate:

```text
format/lint
unit tests
integration tests
contract tests
migration tests
security scans
dependency scans
container scans
configuration validation
```

---

# 146. Real Ory Integration Testing

Critical integration tests SHOULD exercise real compatible Kratos/Hydra instances rather than relying exclusively on mocks.

---

# 147. PostgreSQL Integration Testing

Persistence integration tests SHOULD exercise the supported PostgreSQL baseline.

---

# 148. Migration Testing

CI or release qualification SHALL test migrations from the currently deployed supported state to the candidate state.

---

# 149. Downgrade Testing

Where rollback depends on software downgrade, downgrade safety SHALL be tested.

If downgrade is unsupported, that fact SHALL be explicit.

---

# 150. Security Testing

Before production acceptance IAM SHALL undergo appropriate:

```text
authentication testing
authorization testing
tenant-isolation testing
session testing
OAuth/OIDC testing
CSRF testing
redirect URI testing
credential recovery testing
privileged-access testing
rate-limit testing
```

---

# 151. Abuse Testing

Test abuse cases such as:

```text
credential stuffing simulation
login enumeration
recovery abuse
registration abuse
token replay
cross-tenant access
privilege escalation
federation confusion
SCIM abuse
```

within safe controlled environments.

---

# 152. Fuzzing

Security-sensitive parsers/endpoints MAY use fuzz testing where appropriate.

---

# 153. Penetration Testing

Production IAM SHOULD undergo periodic independent penetration/security testing proportional to risk.

---

# 154. Findings

Security findings SHALL have:

```text
severity
owner
remediation
risk acceptance if applicable
expiry/review
```

---

# 155. No Silent Permanent Risk Acceptance

Risk acceptance SHALL be explicit and reviewable.

---

# 156. Operational Access

Production access SHALL follow ADR-IAM-0031.

---

# 157. Deployment Identity

Deployments SHOULD use workload identity rather than shared human credentials.

---

# 158. CI/CD Authentication

Where supported, CI/CD SHOULD use short-lived federated credentials instead of permanent cloud credentials.

---

# 159. Separation of Deployment and Runtime

Deployment identity SHALL be distinct from application runtime identity.

---

# 160. Runtime Least Privilege

Each runtime component SHALL receive only required:

```text
network access
database permissions
secrets
filesystem access
service permissions
```

---

# 161. Container Runtime

Production containers SHALL be hardened according to infrastructure policy.

Prefer:

```text
non-root
read-only filesystem where practical
dropped capabilities
minimal image
pinned artifact
```

---

# 162. Image Baselines

Baobab-owned Node.js runtime services SHALL follow the platform's approved Node 24 production baseline where Node is used.

Ory images SHALL use the approved upstream/pinned Ory artifacts rather than being rebuilt onto an unrelated Node runtime.

---

# 163. Go Services

Go-based `baobab-iam` components SHALL use pinned toolchain/runtime/build policies defined by the repository/platform standards.

---

# 164. Dependency Independence

A language/runtime upgrade in one Baobab repository SHALL not force unrelated polyglot repositories to upgrade simultaneously unless contract compatibility requires it.

---

# 165. Polyrepo Release Governance

Baobab SHALL preserve independent repository deployment while coordinating contract-breaking changes.

---

# 166. Cross-Repository Release

When multiple repositories must change:

```text
shared contract
     ↓
backward-compatible provider
     ↓
consumer adoption
     ↓
migration
     ↓
old contract retirement
```

is preferred.

---

# 167. No Flag-Day by Default

Avoid requiring every Baobab repository to deploy simultaneously.

---

# 168. Compatibility Window

Cross-repository migrations SHALL define a compatibility window.

---

# 169. Repository Readiness

Each affected repository SHALL demonstrate:

```text
build
tests
security
configuration
contract compatibility
deployment assets
observability
rollback/recovery
documentation
```

before coordinated production rollout.

---

# 170. GitHub Actions

CI workflows SHALL be production-grade and reusable where appropriate across the polyrepo environment.

---

# 171. Reusable Workflow Governance

Reusable workflows SHALL:

```text
pin trusted actions
minimize permissions
support private repositories correctly
avoid secret overexposure
produce clear evidence
```

---

# 172. Workflow Permissions

GitHub Actions SHALL use least-privilege permissions.

---

# 173. Pull Request Trust Boundary

Untrusted pull-request execution SHALL NOT receive production secrets.

---

# 174. Protected Deployment

Production deployment SHOULD use controlled environment approvals/authorization appropriate to operational maturity.

---

# 175. Branch Protection

Production source branches SHOULD require appropriate:

```text
review
required checks
protected changes
```

according to repository governance.

---

# 176. Failed CI

A failing required check SHALL block normal production release.

---

# 177. Waivers

Emergency waiver of a release gate SHALL be:

```text
explicit
authorized
audited
time-bound
reviewed afterward
```

---

# 178. Documentation as Production Artifact

Operational documentation is part of production readiness.

---

# 179. Required Documentation

At minimum:

```text
architecture
ADRs
deployment guide
configuration reference
runbooks
DR guide
upgrade guide
rollback/recovery guide
security operations
service catalogue
compatibility matrix
```

---

# 180. Documentation Drift

Documentation SHALL be updated with material architectural/operational change.

---

# 181. Ownership Registry

Production IAM SHALL have known ownership for:

```text
service
repository
database
secrets
alerts
runbooks
deployment
incident response
```

---

# 182. Operational Acceptance Record

Before initial production launch, Baobab SHALL create an operational acceptance record.

Conceptually:

```text
ProductionAcceptance
├── release
├── architecture_status
├── ADR_compliance
├── security_status
├── compatibility_status
├── performance_status
├── capacity_status
├── SLO_status
├── DR_status
├── observability_status
├── runbook_status
├── known_risks[]
├── approvers[]
├── accepted_at
└── review_at
```

---

# 183. Known Risks

Production acceptance MAY contain known risks.

They SHALL be explicit.

---

# 184. Blocking Risks

Some risks SHALL block production.

Examples:

```text
known authentication bypass

known cross-tenant authorization flaw

unrecoverable signing keys

untested database migration

no recoverable backup

public Ory admin interface

uncontrolled universal admin

unknown production issuer

no revocation path

unresolved critical vulnerability
```

---

# 185. Conditional Acceptance

Non-critical deficiencies MAY receive conditional acceptance with:

```text
owner
deadline
mitigation
review
```

---

# 186. Production Readiness Is Revocable

A system previously accepted for production MAY lose production-ready status following:

```text
critical vulnerability
unsupported dependency
failed recovery test
unresolved reliability regression
major architectural drift
```

---

# 187. Version Support Policy

Baobab SHALL maintain a support policy for:

```text
Ory versions
PostgreSQL versions
Go versions
Node versions
Kubernetes versions
API versions
contract versions
```

used by IAM.

---

# 188. End-of-Life Dependencies

Unsupported dependencies SHALL trigger migration planning before end-of-life where reasonably foreseeable.

---

# 189. Upgrade Cadence

Baobab SHALL avoid both extremes:

```text
upgrade immediately without validation
```

and:

```text
never upgrade
```

---

# 190. Security Patch Priority

Security updates SHALL be prioritized according to:

```text
severity
exploitability
exposure
business impact
mitigation availability
```

---

# 191. Operational Metrics Retention

Operational telemetry retention SHALL comply with ADR-IAM-0030.

---

# 192. SLO Data Integrity

SLO measurement systems SHALL be protected against accidental/manipulated data loss sufficient to make operational decisions misleading.

---

# 193. Dashboards

Dashboards SHOULD expose:

```text
current availability
latency
traffic
errors
saturation
database health
dependency health
security signals
deployment version
```

for appropriate operators.

---

# 194. Executive Reporting

High-level reliability reporting MAY aggregate technical SLOs.

It SHALL NOT replace engineering telemetry.

---

# 195. Capacity Review

Capacity SHALL be reviewed when:

```text
traffic materially changes
new market launches
large customer onboards
new federation added
architecture changes
SLO changes
```

---

# 196. Market Launch

Launching:

```text
new market
```

SHALL trigger assessment of:

```text
capacity
latency
residency
regional topology
support hours
dependencies
```

without assuming each Market requires a new IAM region.

---

# 197. Large Enterprise Onboarding

Large B2B federation onboarding SHOULD include expected:

```text
user count
login pattern
SCIM volume
peak synchronization
token demand
```

in capacity planning.

---

# 198. Thundering Herd

IAM SHALL test/mitigate scenarios such as:

```text
mass session expiry
morning workforce login
large SCIM synchronization
regional recovery
client retry storm
```

---

# 199. Retry Governance

Retries SHALL use:

```text
bounded attempts
backoff
jitter where appropriate
idempotency
```

rather than uncontrolled retry loops.

---

# 200. Timeout Governance

Network calls SHALL have explicit bounded timeouts.

---

# 201. Circuit Breaking

Critical external dependencies MAY use circuit breaking where appropriate.

Circuit breaking SHALL not bypass identity/security decisions.

---

# 202. Graceful Degradation

Degraded mode MAY preserve:

```text
valid existing short-lived token validation
cached JWKS
read-only diagnostics
```

where earlier ADRs permit.

---

# 203. No Security-Degraded Mode

Baobab SHALL NOT implement degraded modes such as:

```text
skip signature validation
trust email instead
ignore tenant context
accept expired token
disable MFA requirement
```

---

# 204. Operational Invariants

The following SHALL remain true:

```text
Running ≠ Ready

Ready ≠ Healthy Forever

Available ≠ Secure

Fast ≠ Correct

Replica Count ≠ Capacity

User Count ≠ Load

Average Latency ≠ Tail Latency

Backup ≠ Recovery

Backup Success ≠ Restore Success

Failover ≠ Recovery Complete

Deployment ≠ Release

Release ≠ Production Acceptance

Rollback ≠ Database Downgrade

Version Upgrade ≠ Compatibility

Container Starts ≠ Migration Safe

Passing Unit Tests ≠ Production Ready

SLO ≠ Security Exception

Error Budget ≠ Permission to Breach Trust

Autoscaling ≠ Capacity Planning

Monitoring ≠ Operational Ownership

Dashboard ≠ Runbook

Runbook ≠ Tested Recovery

IAM Availability ≠ Business Authorization

Market ≠ Region

Repository ≠ Platform

Shared Contract ≠ Shared Runtime

Production Acceptance ≠ Permanent Certification
```

---

# 205. Implementation Gates

## IAM-OPS0 — ADR Conformance Audit

Audit implementation against ADR-IAM-0001 through ADR-IAM-0032.

Produce:

```text
ADR
Requirement
Repository
Implementation
Test
Evidence
Gap
```

traceability.

---

## IAM-OPS1 — Service Catalogue and Ownership

Define:

```text
capabilities
criticality
owners
dependencies
runbooks
```

---

## IAM-OPS2 — SLI Instrumentation

Implement measurable:

```text
availability
latency
errors
traffic
saturation
identity-specific metrics
```

---

## IAM-OPS3 — SLO Baseline

Run representative measurement and establish proposed SLOs.

Do not invent them.

---

## IAM-OPS4 — Capacity Model

Benchmark:

```text
Kratos
Hydra
baobab-iam
PostgreSQL
CP dependencies
```

and define initial tested capacity envelopes.

---

## IAM-OPS5 — Compatibility Matrix

Pin and document:

```text
Ory
PostgreSQL
Go
deployment tooling
contracts
clients
```

---

## IAM-OPS6 — Migration and Upgrade Framework

Implement:

```text
migration jobs
compatibility checks
expand/contract rules
upgrade rehearsals
rollback/recovery plans
```

---

## IAM-OPS7 — Production Deployment Hardening

Implement:

```text
readiness
liveness
startup
graceful termination
rolling update
disruption controls
resource limits
autoscaling where justified
```

---

## IAM-OPS8 — Release Engineering

Implement:

```text
immutable artifacts
SBOM
security scans
release evidence
progressive deployment
rollback
```

---

## IAM-OPS9 — Cross-Repo Contract Verification

Test IAM against:

```text
CP
Trade
ERP
CMS
Digital Estates
shared contracts
```

---

## IAM-OPS10 — Observability and Alerting

Implement:

```text
metrics
logs
traces
dashboards
alerts
ownership
correlation
```

---

## IAM-OPS11 — Runbooks and Incident Operations

Complete and exercise Tier-0 runbooks.

---

## IAM-OPS12 — DR Certification

Exercise:

```text
restore
failover
security journal
privacy journal
key recovery
issuer continuity
```

---

## IAM-OPS13 — Security Qualification

Complete:

```text
threat verification
authorization tests
tenant isolation
OAuth tests
privileged-access tests
abuse tests
vulnerability review
```

---

## IAM-OPS14 — Performance and Failure Testing

Execute:

```text
steady load
peak load
burst
dependency degradation
replica loss
database pressure
retry storm
```

---

## IAM-OPS15 — Documentation and Ownership

Verify:

```text
deployment
upgrade
recovery
runbooks
configuration
compatibility
ownership
```

---

## IAM-OPS16 — Production Acceptance

Create and approve:

```text
ProductionAcceptance
```

with evidence from all prior gates.

---

# 206. Required Production Test Matrix

| Scenario | Required Outcome |
|---|---|
| Normal authentication | Meets approved SLO |
| Peak login burst | Remains within tested envelope |
| Token issuance burst | Controlled and measurable |
| One Kratos replica lost | Service remains within architecture target |
| One Hydra replica lost | Service remains within architecture target |
| Database latency rises | Degradation detected |
| DB connections near exhaustion | Alert before uncontrolled failure |
| Invalid release | Readiness prevents traffic |
| New pod starts | No uncontrolled migration race |
| Rolling deployment | Compatible old/new versions coexist |
| Failed canary | Release halted/rolled back safely |
| Schema migration fails | Production not partially promoted |
| Old app against expanded schema | Works during compatibility window |
| Destructive migration too early | CI/release blocks |
| PostgreSQL upgrade | Rehearsed and verified |
| Ory upgrade | Compatibility tests pass |
| Unknown signing `kid` | Refresh/fail-safe behaviour works |
| Key rotation | Existing valid tokens remain verifiable as designed |
| CP unavailable | Security-sensitive operations fail according to ADRs |
| Federation IdP unavailable | Failure isolated appropriately |
| SCIM provider sends burst | Controlled processing/backpressure |
| Email provider unavailable | Authentication core remains appropriately isolated |
| Region failure | DR procedure executes |
| Backup restored | Security/privacy state reapplied |
| Revoked identity in backup | Not resurrected |
| Erased identity in backup | Privacy state reapplied |
| Break-glass used | Fully audited and expires |
| Cross-tenant access attempted | Denied |
| Critical vulnerability discovered | Release/governance process responds |
| Alert fires | Named owner/runbook exists |
| Restore test | Recovery demonstrated |
| Unsupported dependency detected | Upgrade/migration action triggered |

---

# 207. Production Acceptance Checklist

## Architecture

- [ ] ADR-IAM-0001–0032 reviewed
- [ ] architectural invariants implemented
- [ ] provider-neutral boundaries preserved
- [ ] no unauthorized cross-repository coupling
- [ ] CP/domain authority boundaries preserved

## Runtime

- [ ] Kratos version pinned
- [ ] Hydra version pinned
- [ ] `baobab-iam` artifact pinned
- [ ] PostgreSQL compatibility verified
- [ ] immutable deployment artifacts
- [ ] configuration validated

## Reliability

- [ ] SLIs implemented
- [ ] SLOs approved from evidence
- [ ] error budgets defined where used
- [ ] HA tested
- [ ] graceful degradation tested
- [ ] saturation alerts

## Capacity

- [ ] load model documented
- [ ] peak tests completed
- [ ] capacity envelope recorded
- [ ] DB connection budget
- [ ] operational headroom
- [ ] scaling tested

## Deployment

- [ ] readiness
- [ ] liveness
- [ ] startup handling where needed
- [ ] graceful shutdown
- [ ] rolling strategy
- [ ] disruption controls
- [ ] progressive rollout
- [ ] rollback/recovery procedure

## Database

- [ ] separate Kratos/Hydra logical persistence
- [ ] migrations controlled
- [ ] backups verified
- [ ] restore tested
- [ ] replication monitored
- [ ] major upgrade procedure
- [ ] PostgreSQL version supported

## Compatibility

- [ ] compatibility matrix
- [ ] contract tests
- [ ] OAuth/OIDC compatibility
- [ ] event compatibility
- [ ] client inventory
- [ ] cross-repo migration strategy
- [ ] no flag-day dependency unless explicitly approved

## Security

- [ ] authentication tests
- [ ] authorization tests
- [ ] tenant isolation tests
- [ ] OAuth/OIDC tests
- [ ] recovery tests
- [ ] MFA/passkey tests
- [ ] privileged access tests
- [ ] break-glass tests
- [ ] vulnerability scanning
- [ ] dependency scanning
- [ ] container scanning
- [ ] secrets controls
- [ ] administrative APIs private

## Observability

- [ ] metrics
- [ ] logs
- [ ] traces where applicable
- [ ] dashboards
- [ ] alerts
- [ ] alert owners
- [ ] correlation IDs
- [ ] database monitoring
- [ ] security monitoring

## DR

- [ ] RPO measured
- [ ] RTO measured
- [ ] regional recovery tested
- [ ] signing-key recovery tested
- [ ] security-state reconciliation
- [ ] privacy-state reconciliation
- [ ] issuer continuity verified

## Operations

- [ ] service catalogue
- [ ] service owners
- [ ] escalation paths
- [ ] incident severity model
- [ ] runbooks
- [ ] runbooks exercised
- [ ] post-incident process
- [ ] change-management model

## CI/CD

- [ ] required checks
- [ ] least-privilege workflow permissions
- [ ] trusted actions pinned
- [ ] untrusted PRs isolated from production secrets
- [ ] immutable release evidence
- [ ] production deployment controls
- [ ] emergency waiver process

## Documentation

- [ ] architecture current
- [ ] ADRs current
- [ ] deployment guide
- [ ] configuration guide
- [ ] upgrade guide
- [ ] recovery guide
- [ ] DR guide
- [ ] security operations guide
- [ ] compatibility matrix
- [ ] ownership registry

## Acceptance

- [ ] no unresolved production-blocking risk
- [ ] known risks documented
- [ ] conditional risks owned
- [ ] operational acceptance signed
- [ ] review date established

---

# 208. Production Decision Flow

```text
                    RELEASE CANDIDATE
                           │
                           ▼
                   Architecture Check
                           │
                           ▼
                     Build / Test
                           │
                           ▼
                    Security Gates
                           │
                           ▼
                  Contract Compatibility
                           │
                           ▼
                    Migration Check
                           │
                           ▼
                  Performance / Capacity
                           │
                           ▼
                     Recovery Check
                           │
                           ▼
                  Operational Readiness
                           │
                           ▼
                    Progressive Release
                           │
                           ▼
                       Observe
                           │
                 ┌─────────┴─────────┐
                 │                   │
              HEALTHY             REGRESSION
                 │                   │
                 ▼                   ▼
              ACCEPT           HALT / ROLLBACK
                 │                   │
                 ▼                   ▼
            PRODUCTION          INVESTIGATE
```

---

# 209. Platform Relationship

```text
                         USERS / WORKLOADS
                                │
                                ▼
                         DIGITAL ESTATES
                                │
                                ▼
                            APISIX
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
              Ory Kratos                  Ory Hydra
                  │                           │
                  └─────────────┬─────────────┘
                                ▼
                          baobab-iam
                                │
                                ▼
                           Baobab CP
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
               Trade           ERP            CMS
```

Production governance surrounds the entire path:

```text
              ┌─────────────────────────────────┐
              │          OBSERVABILITY          │
              │                                 │
              │  ┌───────────────────────────┐  │
              │  │                           │  │
              │  │      IAM PLATFORM         │  │
              │  │                           │  │
              │  └───────────────────────────┘  │
              │                                 │
              │ SECURITY       RELIABILITY      │
              │                                 │
              │ CAPACITY       RECOVERY         │
              │                                 │
              │ RELEASE        OPERATIONS       │
              └─────────────────────────────────┘
```

---

# 210. Production Blocking Conditions

Baobab IAM SHALL NOT be declared production-ready while any of the following remains knowingly unresolved:

```text
authentication bypass

cross-tenant authorization flaw

uncontrolled privileged access

unprotected Ory admin plane

unrecoverable Tier-0 cryptographic material

no working backup

no tested restore

unknown migration safety

unvalidated provider upgrade

critical unmitigated vulnerability

no revocation mechanism

no production observability

no incident ownership

no operational runbook for Tier-0 failure

no compatibility evidence

no production deployment rollback/recovery strategy

security/privacy state resurrection during DR
```

---

# 211. Conditional Production Risks

Examples that MAY be conditionally accepted after documented assessment include:

```text
non-critical dashboard deficiency

manual low-frequency operational step

minor non-security performance optimisation

non-critical automation gap
```

provided:

```text
risk
+
mitigation
+
owner
+
deadline
```

are explicit.

---

# 212. Consequences

## Positive

This decision gives Baobab:

- measurable IAM reliability;
- explicit operational ownership;
- evidence-based SLOs;
- capacity engineering;
- controlled Ory upgrades;
- controlled PostgreSQL upgrades;
- migration safety;
- polyrepo compatibility governance;
- progressive deployment;
- rollback/recovery discipline;
- tested disaster recovery;
- security-integrated operations;
- production-grade observability;
- reproducible releases;
- explicit production acceptance;
- a clear end-state for the IAM ADR programme.

## Costs

Baobab must maintain:

```text
SLOs
capacity tests
compatibility matrices
release evidence
upgrade rehearsals
runbooks
DR exercises
security qualification
operational ownership
production acceptance records
```

This is intentional.

Tier-0 identity infrastructure cannot be responsibly operated as:

```text
build
  ↓
deploy
  ↓
hope
```

---

# 213. Explicitly Deferred

This ADR does not mandate:

```text
one cloud provider

one Kubernetes distribution

one observability vendor

one SIEM

one incident-management platform

one managed PostgreSQL provider

one load-testing framework

one deployment-controller product

one commercial SRE platform
```

Those remain infrastructure/tooling choices provided they satisfy this architecture.

---

# 214. Closure of the Foundational IAM ADR Series

With ADR-IAM-0032 accepted, the foundational architecture sequence is complete.

The sequence now covers:

```text
IDENTITY
   ↓
TRUST
   ↓
CANONICALIZATION
   ↓
TENANCY
   ↓
AUTHENTICATION
   ↓
WORKLOAD IDENTITY
   ↓
AUTHORIZATION
   ↓
WORKFORCE
   ↓
B2B / B2C / SUPPLIER IDENTITY
   ↓
DOMAIN INTEGRATION
   ↓
CREDENTIAL SECURITY
   ↓
LIFECYCLE
   ↓
OBSERVABILITY
   ↓
RESILIENCE
   ↓
PROVIDER NEUTRALITY
   ↓
ORY RUNTIME
   ↓
MIGRATION
   ↓
DIGITAL ESTATE SECURITY
   ↓
ASSURANCE
   ↓
PROOFING
   ↓
FEDERATION
   ↓
MULTI-REGION / RESIDENCY
   ↓
CRYPTOGRAPHIC GOVERNANCE
   ↓
SECURITY OPERATIONS
   ↓
PRIVACY
   ↓
PRIVILEGED ADMINISTRATION
   ↓
PRODUCTION GOVERNANCE
```

Future IAM ADRs SHALL therefore be written only when a genuinely new architectural decision arises.

They SHALL NOT be created merely to continue numbering.

---

# 215. Transition From Architecture to Execution

The next phase is no longer:

```text
WRITE MORE FOUNDATIONAL ADRs
```

It is:

```text
ADRs IAM-0001–0032
        │
        ▼
CONSOLIDATED IAM TECHNICAL SPECIFICATION
        │
        ▼
THREAT MODEL
        │
        ▼
ADR → CODE TRACEABILITY MATRIX
        │
        ▼
REPOSITORY GAP ANALYSIS
        │
        ▼
IMPLEMENTATION GATES
        │
        ▼
STACKED / COORDINATED PRs
        │
        ▼
CI + SECURITY + INTEGRATION TESTING
        │
        ▼
STAGING
        │
        ▼
LOAD / FAILURE / DR QUALIFICATION
        │
        ▼
PRODUCTION ACCEPTANCE
        │
        ▼
GO LIVE
```

---

# 216. Final Decision Principle

The final operational model is:

```text
Architecture
     ↓
Implementation
     ↓
Evidence
     ↓
Measurement
     ↓
Controlled Release
     ↓
Observation
     ↓
Recovery Capability
     ↓
Operational Acceptance
```

Never:

```text
"It works on my machine"
          ↓
      Production
```

Nor:

```text
"CI is green"
      ↓
"Therefore IAM is production-ready"
```

Nor:

```text
"We have backups"
      ↓
"Therefore we can recover"
```

Nor:

```text
"We have multiple replicas"
      ↓
"Therefore we are highly available"
```

Baobab SHALL demonstrate these properties.

Therefore:

> **Reliability is measured, capacity is tested, compatibility is verified, upgrades are rehearsed, recovery is exercised, releases are observable, and production acceptance is evidence-based.**

The architectural closure principle is:

> **Identity infrastructure earns production trust continuously. It does not inherit trust merely because its architecture is sound.**

And finally:

> **ADR-IAM-0001 through ADR-IAM-0032 define the foundational identity architecture of Baobab Platform. From this point forward, implementation must prove conformance to that architecture, and operations must prove that the implementation remains trustworthy under real production conditions.**