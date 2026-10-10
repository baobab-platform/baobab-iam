# ADR-0018: IAM Availability, Backup, Recovery and Disaster Resilience

**Status:** Proposed  
**Date:** 2026-09-09  
**Decision Owners:** NABHOLD / Baobab Platform Architecture, Security and Infrastructure  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Related Repositories:** `baobab-platform/infrastructure`, `baobab-platform/baobab-cp`, `baobab-platform/shared`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, Digital Estate repositories  
**Primary Runtime:** Keycloak  
**Primary Persistence:** PostgreSQL 17  
**Scope:** High availability, failure domains, database durability, persistent sessions, backup, restore, disaster recovery, cryptographic-key recovery, secrets recovery, RPO/RTO, site failure, database failure, cache failure, partial outage behaviour, degraded operation, split-brain avoidance, revocation preservation, backup security, restore sequencing, disaster-recovery exercises and operational resilience  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:** ADR-0001 through ADR-0017

---

# 1. Context

Baobab IAM is not an ordinary supporting application.

It establishes authentication for:

```text
Customers
Buyers
Suppliers
Nabhold workforce
Administrators
Engine operators
Workloads
```

and is consequently upstream of:

```text
Baobab Control Plane
Baobab Trade
Baobab ERP
Baobab CMS
Baobab Pulse
Zuribeans
Thamani
Nabhold
future Digital Estates
```

An IAM outage can therefore become a platform-wide authentication outage.

A catastrophic IAM recovery error can be even more dangerous.

For example:

```text
Day 1: privileged account compromised

Day 1: account disabled
       sessions revoked
       credential revoked

Day 2: IAM database lost

Day 2: restore backup from Day 0
```

A naive restoration could resurrect:

```text
ACTIVE account
+
valid credential
+
valid session state
```

that security operations had already revoked.

This is unacceptable.

Baobab therefore requires IAM resilience that protects not only **availability**, but also the correctness of identity and revocation state during failures and recovery.

---

# 2. Decision

Baobab IAM SHALL be operated as a **Tier-0 security service**.

Production architecture SHALL provide:

```text
redundant Keycloak instances
+
highly available PostgreSQL
+
failure-domain separation
+
durable backups
+
protected cryptographic material
+
tested restore procedures
+
post-restore security reconciliation
+
observability
+
regular disaster-recovery exercises
```

IAM disaster recovery SHALL optimize simultaneously for:

```text
Availability
Integrity
Confidentiality
Revocation correctness
Audit continuity
```

Availability SHALL NOT override security correctness.

---

# 3. Governing Principle

> **Baobab IAM shall remain available through ordinary infrastructure failures, recover predictably from catastrophic failures, and never restore availability by resurrecting identity authority that security operations had already revoked.**

---

# 4. IAM Criticality Classification

Baobab IAM SHALL be classified as:

```text
Tier 0
```

alongside other security-critical platform infrastructure.

This means IAM receives elevated requirements for:

- availability;
- monitoring;
- change management;
- backup;
- disaster recovery;
- access control;
- security testing;
- operational documentation.

---

# 5. Failure Domains

The production architecture SHALL consider at least:

```text
process failure
container/pod failure
host/node failure
availability-zone failure
network failure
load-balancer failure
database-node failure
database corruption
cache failure
secret-store failure
certificate failure
DNS failure
site/region failure
operator error
malicious administrative action
software upgrade failure
```

---

# 6. Availability Architecture

The baseline production topology SHALL avoid a single Keycloak instance.

Conceptually:

```text
                  USERS / WORKLOADS
                         │
                         ▼
                  GLOBAL / REGIONAL
                   TRAFFIC LAYER
                         │
                  ┌──────┴──────┐
                  ▼             ▼
             Keycloak A     Keycloak B
                  │             │
                  └──────┬──────┘
                         ▼
                 HA PostgreSQL
```

---

# 7. Minimum Runtime Redundancy

Production SHALL run multiple Keycloak instances.

A single process or pod SHALL NOT constitute the production IAM architecture.

---

# 8. Failure-Domain Separation

Keycloak instances SHOULD be distributed across distinct infrastructure failure domains.

Where Kubernetes is used:

```text
Pod anti-affinity
+
topology spread
```

SHOULD prevent all IAM replicas from being concentrated on one node.

---

# 9. Multi-AZ Baseline

Where the selected cloud environment supports availability zones, the preferred initial production architecture is:

```text
one region
+
multiple availability zones
+
redundant Keycloak runtime
+
highly available PostgreSQL
```

before introducing materially more complex cross-region IAM topology.

---

# 10. Why Multi-AZ First

Multi-AZ provides protection against common infrastructure failures while reducing:

- replication complexity;
- network latency;
- operational burden;
- split-brain risk;
- cross-region consistency challenges.

---

# 11. Multi-Region Is Not Automatically Better

Baobab SHALL NOT introduce multi-region active-active IAM merely because multiple regions exist.

The architecture SHALL first demonstrate:

```text
latency suitability
database replication semantics
failure handling
operational maturity
cost justification
data-residency compatibility
```

---

# 12. Current Keycloak Multi-Site Guidance

Where Baobab later requires Keycloak's supported multi-site HA architecture, the design SHALL follow the production-supported architecture of the pinned Keycloak release.

Baobab SHALL NOT copy assumptions from obsolete Keycloak versions.

---

# 13. Preview Features

Keycloak features marked:

```text
preview
experimental
```

SHALL NOT become the default production IAM resilience mechanism without:

- explicit evaluation;
- failure testing;
- security review;
- separate ADR approval.

---

# 14. Multi-Cluster v2 / Stateless Architecture

The Keycloak 26.7-era multi-cluster v2/stateless architecture SHALL therefore remain an evaluation candidate rather than Baobab's initial production dependency while upstream classifies it as preview.

When it becomes stable/supported, Baobab MAY reassess this decision.

---

# 15. Keycloak Version Pinning

`baobab-iam` SHALL pin the exact production Keycloak version.

Example repository control:

```text
upstream.lock.yaml
```

SHALL identify the approved upstream version and image digest.

Floating tags such as:

```text
latest
```

are prohibited.

---

# 16. Production Mode

Production SHALL use Keycloak production configuration.

Development modes SHALL NOT be deployed as production IAM.

---

# 17. Cache Architecture

Keycloak's supported distributed caching architecture SHALL be used according to the pinned release.

Custom Infinispan modifications SHALL be minimized.

---

# 18. Cache Is Not Global Identity Authority

This remains binding:

```text
Cache ≠ Authoritative Identity Database
```

---

# 19. Persistent State

Identity-critical persistent data SHALL reside in durable supported storage.

This includes, depending on Keycloak's selected configuration:

- users;
- realms;
- clients;
- credentials;
- organizations;
- sessions;
- authentication state;
- required security metadata.

---

# 20. PostgreSQL

Baobab IAM SHALL use a dedicated PostgreSQL database.

The production target SHALL align with:

```text
PostgreSQL 17
```

subject to compatibility with the pinned Keycloak release.

---

# 21. Database Isolation

The IAM database SHALL NOT be shared as an application schema with:

```text
baobab-cp
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
```

---

# 22. No Direct Database Consumers

Other Baobab systems SHALL NOT read the Keycloak database directly.

Integration SHALL occur through supported IAM interfaces and canonical Baobab contracts.

---

# 23. Database High Availability

Production PostgreSQL SHALL provide:

```text
primary/writer redundancy
replication
automatic or controlled failover
durable storage
backup
point-in-time recovery capability
```

where supported by the selected infrastructure.

---

# 24. Synchronous Replication for Zero-Loss HA

Where Baobab requires:

```text
RPO = 0
```

for an HA failure scenario, synchronous database replication is required across the participating failure domains.

---

# 25. Database Durability Is IAM Durability

This relationship SHALL be explicit:

```text
IAM availability
      │
      ▼
Database availability
```

A highly available Keycloak tier with a fragile single database is not highly available IAM.

---

# 26. Database Connection Management

Connection pools SHALL be sized jointly with:

- Keycloak replica count;
- PostgreSQL capacity;
- authentication load;
- failover behavior.

Horizontal Keycloak scaling SHALL NOT accidentally exhaust PostgreSQL connections.

---

# 27. Session Persistence

Production session behavior SHALL follow the supported persistent-session architecture of the pinned Keycloak release.

Session persistence SHALL be deliberately tested during:

```text
pod restart
rolling deployment
node failure
database failover
site failover
```

---

# 28. Session Availability

A routine Keycloak node restart SHOULD NOT require all Baobab users to reauthenticate.

---

# 29. Session Security

Session availability SHALL NOT prevent deliberate:

```text
session revocation
identity suspension
credential revocation
```

---

# 30. Existing Access Tokens During IAM Failure

Because Baobab uses short-lived signed access tokens, resource servers MAY continue validating already-issued tokens locally while IAM is temporarily unavailable, provided:

```text
signature valid
issuer valid
audience valid
exp valid
nbf valid
algorithm allowed
CP/domain authorization remains valid
```

---

# 31. IAM Failure Does Not Extend Tokens

No service SHALL extend token lifetime merely because IAM is unavailable.

---

# 32. No Emergency Accept-All Mode

This is prohibited:

```text
IAM unavailable
      │
      ▼
skip authentication
```

---

# 33. No Static Emergency User Token

Baobab SHALL NOT maintain a universal long-lived bearer token as an IAM outage workaround.

---

# 34. New Authentication During IAM Outage

If IAM is unavailable:

```text
new login
token refresh
credential enrollment
recovery
```

MAY become unavailable.

The platform SHALL fail securely.

---

# 35. Existing Application Sessions

Applications MAY continue bounded sessions where security policy permits and all required downstream authorization remains valid.

---

# 36. Privileged Operations During IAM Degradation

Privileged operations MAY adopt stricter behavior than ordinary customer operations.

For example:

```text
IAM degraded
+
fresh MFA assurance unavailable
=
deny high-risk administrative action
```

---

# 37. CP Availability Is Separate

A valid IAM token does not make the platform usable if Control Plane context cannot be resolved.

This remains:

```text
IAM availability
≠
CP availability
```

---

# 38. Engine Availability Is Separate

Likewise:

```text
IAM healthy
≠
Trade healthy
≠
ERP healthy
```

Each service retains its own resilience architecture.

---

# 39. Health Checks

IAM infrastructure SHALL expose and monitor:

```text
startup health
liveness
readiness
```

using supported Keycloak mechanisms.

---

# 40. Readiness

Traffic SHALL only reach Keycloak instances ready to safely serve requests.

---

# 41. Liveness

Liveness checks SHALL identify unhealthy instances without creating restart loops during recoverable dependency problems.

---

# 42. Dependency Health

Monitoring SHALL cover:

```text
Keycloak
PostgreSQL
cache
load balancer
DNS
certificates
secret store
event pipeline
```

---

# 43. Health Check ≠ User Transaction

Infrastructure health alone SHALL not prove that login works.

---

# 44. Synthetic Authentication Tests

Production monitoring SHOULD include safe synthetic checks capable of validating selected authentication paths without exposing real credentials.

---

# 45. Failure Detection

Traffic infrastructure SHALL remove unhealthy IAM instances from service promptly.

---

# 46. Graceful Shutdown

Keycloak instances SHOULD be given appropriate termination grace to complete or safely stop in-flight work during controlled deployments.

---

# 47. Rolling Deployments

Routine patch deployments SHOULD preserve service availability where supported.

---

# 48. Version Compatibility

Baobab SHALL follow Keycloak's documented compatibility requirements during rolling upgrades.

---

# 49. Major/Minor Upgrades

Major or minor Keycloak upgrades SHALL use the upstream-supported upgrade procedure rather than assuming arbitrary mixed-version operation is safe.

---

# 50. Database Migration

Database schema migrations triggered by Keycloak upgrades SHALL be:

- rehearsed;
- backed up;
- monitored;
- rollback-aware.

---

# 51. Backup Is Distinct From High Availability

This is binding:

```text
Replication ≠ Backup
```

Replication protects availability.

Backup protects recovery from:

```text
corruption
operator error
malicious change
catastrophic deletion
```

---

# 52. IAM Backup Scope

Backups SHALL cover at minimum:

```text
Keycloak PostgreSQL
realm/client configuration source
custom providers/extensions
themes
bootstrap configuration
deployment configuration
required cryptographic material
required secrets references
audit/revocation recovery data
```

---

# 53. Configuration as Code

Recoverable IAM configuration SHALL be maintained in:

```text
baobab-platform/baobab-iam
```

where appropriate.

Examples:

```text
realm configuration
client definitions
scopes
policies
provider configuration
themes
bootstrap scripts
```

---

# 54. Secrets Are Not Git Configuration

The repository SHALL NOT contain production:

```text
client secrets
database passwords
private keys
recovery credentials
```

---

# 55. Secret References

Configuration SHOULD reference secret-management locations or injected runtime values.

---

# 56. Database Backup

IAM PostgreSQL SHALL have automated encrypted backups.

---

# 57. Point-in-Time Recovery

Production SHOULD support point-in-time recovery.

This provides recovery from corruption or destructive administrative changes between full backups.

---

# 58. Backup Frequency

Backup frequency SHALL be chosen to satisfy the approved IAM RPO.

---

# 59. Backup Retention

Backups SHALL use tiered retention appropriate to:

- operational recovery;
- security investigation;
- legal requirements;
- storage cost.

---

# 60. Backup Encryption

IAM backups SHALL be encrypted:

```text
in transit
+
at rest
```

---

# 61. Backup Access

Access to IAM backups SHALL be more restricted than ordinary application data.

---

# 62. Backup Contains Credential Material

IAM database backups can contain highly sensitive credential/security information.

They SHALL be classified accordingly.

---

# 63. Production IAM Backup Classification

At minimum:

```text
CONFIDENTIAL / SECURITY CRITICAL
```

under Baobab's data classification taxonomy.

---

# 64. Backup Location

At least one recoverable backup copy SHOULD survive failure of the primary production infrastructure.

---

# 65. Backup Account Separation

Where practical, backup storage SHOULD be protected through administrative separation from the runtime IAM environment.

---

# 66. Backup Immutability

High-value backup copies SHOULD use:

```text
immutability
retention lock
object versioning
```

or equivalent protection where available.

---

# 67. Backup Deletion Protection

A compromised production IAM administrator SHOULD NOT automatically be able to erase every recoverable IAM backup.

---

# 68. Backup Verification

Successful backup job completion does not prove recoverability.

Backups SHALL be periodically restored and verified.

---

# 69. Restore Testing

A restore exercise SHALL verify:

```text
database recovery
Keycloak startup
realm integrity
client integrity
credential behavior
session behavior
OIDC discovery
JWKS
CP integration
revocation reconciliation
```

---

# 70. Backup Integrity

Backup artifacts SHOULD support integrity verification.

---

# 71. Signing Keys

OIDC signing keys are critical security assets.

Loss may invalidate authentication continuity.

Compromise may permit token forgery.

---

# 72. Signing-Key Protection

Signing private keys SHALL receive strong protection.

Where infrastructure permits, prefer:

```text
KMS / HSM-backed protection
```

or equivalent managed cryptographic protection.

---

# 73. Private Key Export

Private signing keys SHALL NOT be routinely exported into:

```text
Git
developer machines
CI logs
ordinary backups
```

---

# 74. Signing-Key Recovery

Disaster recovery SHALL define how signing capability is recovered.

---

# 75. Signing-Key Loss

If private signing keys are permanently lost:

```text
previous sessions/tokens
```

may become unusable depending on the recovery architecture.

This SHALL be treated as a planned disaster scenario.

---

# 76. Signing-Key Compromise

If a signing key is suspected compromised:

```text
availability
```

SHALL NOT take precedence over cryptographic trust.

The compromised key SHALL be retired according to incident procedures.

---

# 77. Key Rotation

Normal signing-key rotation SHALL preserve an appropriate verification overlap so resource servers can validate still-legitimate previously issued short-lived tokens.

---

# 78. JWKS Recovery

Disaster recovery SHALL verify:

```text
OIDC discovery
JWKS availability
kid correctness
algorithm policy
```

before reopening IAM traffic.

---

# 79. Secret Store

IAM runtime secrets SHALL be stored in the approved production secrets system.

---

# 80. Secret Store Availability

The secrets system is itself an IAM dependency and SHALL have resilience appropriate to Tier-0 infrastructure.

---

# 81. Secret Recovery

DR procedures SHALL define recovery for:

```text
database credentials
Keycloak client secrets
SMTP credentials
external IdP credentials
TLS material
administrative bootstrap credentials
```

where applicable.

---

# 82. Secret Rotation After Disaster

Depending on incident type, recovery MAY require rotating:

```text
database credentials
client secrets
signing keys
TLS certificates
administrative credentials
```

before returning to service.

---

# 83. Bootstrap Administration

Emergency/bootstrap IAM administration SHALL be deliberately designed.

---

# 84. Bootstrap Account

A bootstrap administrative path MAY exist for disaster recovery.

It SHALL NOT be a normal daily-use account.

---

# 85. Bootstrap Protection

Bootstrap credentials SHALL be:

```text
strongly protected
offline or tightly controlled
monitored
tested
rotated
```

---

# 86. Break-Glass ≠ Authentication Bypass

Break-glass means:

```text
controlled emergency administrative authentication
```

not:

```text
disable authentication
```

---

# 87. Break-Glass Audit

Emergency access SHALL produce audit as soon as technically possible.

If central audit infrastructure is unavailable, a durable alternative evidence mechanism SHALL be used.

---

# 88. Disaster Declaration

DR activation SHALL require an explicit operational decision.

Examples:

```text
database unrecoverable
region unavailable
IAM corruption
security compromise
catastrophic operator error
```

---

# 89. DR Authority

Only authorized operations/security roles SHALL initiate production IAM disaster recovery.

---

# 90. Recovery Runbook

`baobab-platform/baobab-iam` and/or `baobab-platform/infrastructure` SHALL maintain a version-controlled DR runbook.

---

# 91. Recovery Sequencing

A general recovery sequence SHALL be:

```text
1. Contain incident
2. Determine trusted recovery point
3. Restore infrastructure dependencies
4. Restore PostgreSQL
5. Restore cryptographic/secrets dependencies
6. Deploy pinned Keycloak
7. Validate database/schema
8. Validate realm/client configuration
9. Validate signing/JWKS
10. Apply post-backup security changes
11. Reconcile revocations
12. Validate CP integration
13. Validate engine authentication
14. Run security smoke tests
15. Reopen traffic gradually
16. Monitor
17. Complete incident review
```

---

# 92. Restore Must Not Immediately Reopen Traffic

A successful Keycloak process startup SHALL NOT automatically mean:

```text
safe to serve production
```

---

# 93. Recovery Gate

Production traffic SHALL remain restricted until critical security validation succeeds.

---

# 94. Revocation Resurrection Problem

Consider:

```text
T0  backup created

T1  credential compromised

T2  credential revoked

T3  sessions revoked

T4  IAM disaster

T5  restore T0 backup
```

The restored database may not know about T2/T3.

---

# 95. Security Resurrection Is Prohibited

The following SHALL be a binding invariant:

> **A backup restore SHALL NOT intentionally return previously revoked identity authority to service.**

---

# 96. Revocation Recovery Record

Baobab SHALL maintain sufficient security-state history outside the single restored IAM snapshot to identify security-critical changes made after a backup.

---

# 97. Post-Backup Security Journal

The resilience architecture SHOULD maintain a durable security/revocation journal or equivalent recoverable record containing critical events such as:

```text
identity disabled
identity suspended
credential compromised
credential revoked
session revoked
privileged role revoked
workload revoked
tenant suspended
```

---

# 98. Journal Independence

The recovery copy of this security state SHOULD not share exactly the same failure fate as the IAM database snapshot being restored.

---

# 99. Security Journal ≠ Full Identity Database

The journal exists to preserve security-critical state transitions required for recovery correctness.

It does not become a second IAM authority.

---

# 100. Restore Reconciliation

Before production reopening:

```text
restored IAM state
        │
        ▼
security journal
        │
        ▼
CP lifecycle state
        │
        ▼
domain security state
        │
        ▼
reconciliation
        │
        ▼
safe recovered state
```

---

# 101. Deny Wins During Reconciliation

If restored state says:

```text
ACTIVE
```

but a trusted later security record says:

```text
DISABLED
```

the result SHALL be:

```text
DISABLED
```

---

# 102. Credential Revocation Wins

Likewise:

```text
backup credential = ACTIVE
later journal = REVOKED
```

SHALL resolve:

```text
REVOKED
```

---

# 103. Session Safety After Restore

Where session correctness cannot be proven after catastrophic restoration, Baobab SHOULD prefer:

```text
invalidate affected sessions
```

and require reauthentication.

---

# 104. Security Over Convenience

Forced reauthentication is preferable to resurrecting a compromised session.

---

# 105. Privileged Sessions

After significant IAM disaster recovery, privileged sessions SHOULD normally be invalidated unless their safety can be established.

---

# 106. Workload Credentials

Workload revocations SHALL also survive IAM restoration.

---

# 107. Tenant Suspension

A tenant suspended after the backup SHALL remain suspended after IAM recovery through CP authority regardless of restored IAM organization state.

---

# 108. CP as Independent Security Authority

Because CP independently owns:

```text
CanonicalIdentity
Tenant Membership
Capability Entitlement
Context
```

restored IAM state SHALL not override newer CP security state.

---

# 109. Domain Authority After Restore

Similarly:

```text
Trade suspension
ERP role revocation
CMS role revocation
supplier suspension
```

remain authoritative in their owning systems.

---

# 110. Cross-System Reconciliation

DR SHALL therefore include:

```text
IAM
 ↕
CP
 ↕
Trade / ERP / CMS / Pulse / Supplier Domain
```

reconciliation.

---

# 111. No Email-Based Reconciliation

Recovery SHALL use immutable identifiers and mappings.

This is prohibited:

```text
same email
=
same restored authority
```

---

# 112. RPO

Baobab SHALL define a formal Recovery Point Objective for IAM.

---

# 113. HA RPO

For ordinary infrastructure failure covered by synchronous HA replication, the target SHOULD be:

```text
RPO = 0
```

where the selected infrastructure supports it.

---

# 114. Catastrophic DR RPO

For catastrophic restore from backup, the target SHOULD be significantly tighter than ordinary application systems because IAM state is security critical.

A proposed initial objective is:

```text
RPO ≤ 5 minutes
```

subject to infrastructure feasibility and cost validation.

---

# 115. Security Revocation RPO

Security-critical revocation state SHOULD target effectively:

```text
RPO = 0
```

through independent durable security-state preservation where feasible.

---

# 116. RTO

Baobab SHALL define a formal Recovery Time Objective.

A proposed initial production objective is:

```text
IAM catastrophic RTO ≤ 60 minutes
```

with a stricter target for ordinary node/AZ failure.

---

# 117. Ordinary Failure RTO

Routine failures such as:

```text
pod failure
node failure
database instance failover
```

SHOULD recover automatically or near-automatically in:

```text
seconds to low minutes
```

depending on infrastructure.

---

# 118. RPO/RTO Are Tested Objectives

Documenting an RPO/RTO without exercising it is insufficient.

---

# 119. DR Exercise

At least periodically, Baobab SHALL perform controlled IAM disaster-recovery exercises.

---

# 120. Exercise Scenarios

Exercises SHOULD include:

```text
Keycloak node loss
availability-zone loss
database primary failure
database corruption
accidental realm configuration change
secret loss
signing-key scenario
backup restore
post-backup revocation
failed upgrade
event pipeline failure
```

---

# 121. Revocation Resurrection Test

A mandatory DR test SHALL be:

```text
1. create identity
2. create backup
3. revoke identity/credential
4. restore backup
5. reconcile
6. prove revoked access remains denied
```

---

# 122. Workload Resurrection Test

Repeat equivalent testing for a revoked workload identity.

---

# 123. Tenant Suspension Test

Repeat for a suspended tenant.

---

# 124. Recovery Exercise Evidence

Each exercise SHALL record:

```text
scenario
start time
recovery point
steps
actual RPO
actual RTO
failures
manual interventions
security validation
improvements
```

---

# 125. DR Runbook Testing

A runbook that has never been exercised SHALL be considered unverified.

---

# 126. Dependency Recovery Order

IAM dependencies SHALL have documented ordering.

Example:

```text
Network / DNS
      │
      ▼
Secret / Key Infrastructure
      │
      ▼
PostgreSQL
      │
      ▼
Keycloak
      │
      ▼
Control Plane integration
      │
      ▼
Domain integrations
      │
      ▼
Digital Estates
```

---

# 127. DNS

DNS configuration SHALL avoid unnecessary single points of failure.

---

# 128. TLS

IAM TLS certificates SHALL have:

```text
automated renewal
expiry monitoring
recovery procedure
```

---

# 129. Certificate Expiry

Certificate expiration SHALL generate alerts well before service impact.

---

# 130. Load Balancer

The IAM load-balancing layer SHALL itself be highly available.

---

# 131. Session Affinity

Baobab SHALL not rely on session affinity as a substitute for correct Keycloak clustering/session architecture.

---

# 132. Database Failover

Database failover SHALL be tested with live Keycloak workloads.

---

# 133. Connection Recovery

Keycloak SHALL recover database connections after supported failover without requiring unsafe manual database changes.

---

# 134. Cache Failure

Cache-related failures SHALL be tested according to the selected Keycloak topology.

---

# 135. Cache Rebuild

The platform SHALL understand which cache state:

```text
can be rebuilt
```

and which persistent state:

```text
must survive
```

---

# 136. Split-Brain

Baobab SHALL avoid architectures where isolated IAM sites can independently accept conflicting authoritative writes without a supported reconciliation model.

---

# 137. Consistency Over Dual Availability

During ambiguous partition scenarios:

```text
security consistency
```

SHOULD take precedence over maintaining two independently writable IAM partitions.

---

# 138. Fencing

Where the selected Keycloak multi-site architecture requires site isolation/fencing behavior, Baobab SHALL implement and test it exactly according to the supported upstream architecture.

---

# 139. No Improvised Multi-Master

A custom:

```text
two Keycloak clusters
+
async PostgreSQL
+
hope
```

architecture is prohibited.

---

# 140. Regional Data Residency

Cross-region IAM replication SHALL consider:

```text
POPIA
Ugandan requirements
contractual obligations
future market regulation
```

before identity data crosses jurisdictional boundaries.

---

# 141. Disaster Recovery Region

A DR region SHALL not automatically receive unrestricted identity replication merely because it is technically convenient.

---

# 142. Residency vs Availability

Where residency prevents cross-border replication, Baobab SHALL design regionally compliant recovery rather than bypass regulatory boundaries.

---

# 143. Backups and Residency

Backup location is also subject to residency requirements.

---

# 144. Backup Restoration Environment

Production IAM backups SHALL not be casually restored into development environments.

---

# 145. DR Test Data

DR testing SHOULD use:

```text
isolated production-grade test environments
```

with appropriately protected data.

---

# 146. Production Backup Testing

Where real production backups must be used for restore verification, access and environment controls SHALL match their sensitivity.

---

# 147. Recovery Administration

DR operators SHALL use named, auditable identities where technically possible.

---

# 148. Shared Recovery Accounts

Routine shared administrator accounts are prohibited.

---

# 149. Emergency Credentials

If emergency credentials must be shared by design, their access SHALL use controlled custody, audit and post-use rotation.

---

# 150. IAM Configuration Drift

Production IAM configuration SHALL be monitored for drift from approved configuration where feasible.

---

# 151. Drift Detection

Unexpected changes to:

```text
realm
client
redirect URI
scope
identity provider
authentication flow
admin role
signing key
```

SHOULD generate security visibility.

---

# 152. Drift Recovery

Configuration-as-code SHALL enable reconstruction of approved configuration without blindly overwriting legitimate runtime identity state.

---

# 153. Realm Export Is Not Complete DR

A Keycloak realm export SHALL NOT be considered a substitute for:

```text
database backup
+
secret recovery
+
key recovery
+
security reconciliation
```

---

# 154. Database Dump Alone Is Not Complete DR

Likewise:

```text
pg_dump
```

alone does not constitute a complete IAM recovery architecture.

---

# 155. Container Image Is Not Backup

The Keycloak container image contains software, not production identity state.

---

# 156. Infrastructure-as-Code

IAM infrastructure SHOULD be reconstructable through:

```text
Infrastructure as Code
```

maintained in `baobab-platform/infrastructure`.

---

# 157. IAM Repository

`baobab-platform/baobab-iam` SHOULD contain recoverable application-specific artifacts:

```text
config/
themes/
providers/
bootstrap/
tests/
docs/
runtime/
```

---

# 158. Separation of Responsibilities

Conceptually:

```text
baobab-iam
    │
    ├── IAM configuration
    ├── extensions
    ├── realm/client definitions
    └── IAM DR procedures

infrastructure
    │
    ├── runtime platform
    ├── PostgreSQL
    ├── secret store
    ├── load balancing
    ├── certificates
    ├── backup infrastructure
    └── monitoring
```

---

# 159. Restore Compatibility

A database backup SHALL be restored using a compatible Keycloak version and database schema.

---

# 160. Pinned Recovery Artifact

DR SHALL identify the exact Keycloak image/digest required to restore a given backup generation where necessary.

---

# 161. Artifact Retention

Required recovery artifacts SHOULD remain available for the backup retention horizon.

---

# 162. Extension Compatibility

Custom Keycloak providers SHALL be versioned with Keycloak compatibility.

---

# 163. Extension Failure

A custom extension SHALL NOT be allowed to make the entire IAM environment unrecoverable without a documented safe-disable/recovery path.

---

# 164. Minimal Extensions

ADR-0002's preference remains:

```text
native capability
>
standards configuration
>
external adapter
>
minimal SPI
>
fork
```

This also reduces DR risk.

---

# 165. Restore Validation Suite

`baobab-iam` SHOULD include automated recovery smoke tests.

At minimum:

```text
OIDC discovery works
JWKS works
authorization-code flow works
PKCE works
client credentials work
CP token validation works
canonical identity resolution works
disabled identity denied
revoked membership denied
workload authentication works
```

---

# 166. Digital Estate Validation

Recovery testing SHOULD validate:

```text
Thamani login
Zuribeans login
Nabhold workforce SSO
```

without requiring every downstream business workflow to complete before IAM is declared healthy.

---

# 167. ERP Validation

At minimum:

```text
Keycloak → iDempiere OIDC
```

SHALL be tested after material IAM recovery.

---

# 168. Trade Validation

At minimum:

```text
Keycloak → Baobab Medusa Auth Provider
```

SHALL be tested.

---

# 169. CP Validation

At minimum:

```text
token
  │
  ▼
CP validation
  │
  ▼
CanonicalIdentity
  │
  ▼
Context resolution
```

SHALL succeed for known-good identities.

---

# 170. Known-Bad Validation

Recovery testing SHALL also prove:

```text
disabled identity → denied
revoked workload → denied
wrong audience → denied
expired token → denied
suspended tenant → denied
```

---

# 171. Positive Tests Are Insufficient

IAM recovery SHALL NOT be approved based only on:

```text
login works
```

Negative security tests are mandatory.

---

# 172. Recovery Observability

Recovery procedures SHALL expose:

```text
database restore status
Keycloak health
JWKS health
event backlog
reconciliation status
security test results
```

---

# 173. Recovery Correlation

Major DR operations SHOULD carry an:

```text
incident_id
```

or:

```text
recovery_id
```

for audit correlation.

---

# 174. Recovery Audit

Record:

```text
who declared disaster
who restored
backup selected
recovery point
configuration version
Keycloak version
reconciliation performed
security validation
traffic reopened
```

---

# 175. Recovery Completion

IAM recovery SHALL not be considered complete until:

```text
service restored
+
security state reconciled
+
monitoring healthy
+
critical integrations validated
```

---

# 176. Post-Recovery Monitoring

IAM SHALL receive elevated monitoring after significant recovery.

---

# 177. Incident Review

Every real catastrophic IAM recovery SHALL result in a post-incident review.

---

# 178. Lessons to Code

Where possible, incident findings SHALL become:

```text
automated tests
runbook changes
monitoring
infrastructure changes
ADR amendments
```

---

# 179. Capacity Resilience

IAM SHALL retain sufficient capacity to survive the loss of one ordinary runtime failure domain without immediate overload.

---

# 180. N+1 Principle

For normal HA design:

```text
remaining capacity after one failure
```

SHOULD still handle expected production authentication load.

---

# 181. Authentication Storm

Capacity planning SHALL consider sudden login storms after:

```text
outage
session invalidation
deployment
regional failover
```

---

# 182. Recovery-Induced Load

Mass forced reauthentication after DR can create more load than normal traffic.

This SHALL be load-tested.

---

# 183. Rate Limiting During Recovery

Security controls SHALL not simply be disabled to handle recovery load.

Rate limits MAY be tuned deliberately.

---

# 184. Brute-Force Protection

Brute-force protections SHALL remain active during recovery unless an explicit security-approved change is required.

---

# 185. Email Dependency

Registration/recovery flows may depend on email infrastructure.

Email failure SHALL not be confused with IAM core failure.

---

# 186. External Identity Providers

Federated identity providers introduce additional failure dependencies.

---

# 187. External IdP Outage

Failure of one external IdP SHOULD affect only authentication paths dependent on that IdP where possible.

---

# 188. Local Recovery

Users with another valid authentication path MAY continue using it.

---

# 189. Federation ≠ IAM Availability

Baobab SHALL not make every identity dependent on one external social/enterprise IdP unless business requirements explicitly demand it.

---

# 190. Recovery Communication

Major IAM outages SHALL have an operational communication plan covering:

```text
internal operators
executives
support
affected estates
customers/partners where appropriate
```

without exposing exploitable security details.

---

# 191. Maintenance Windows

Planned IAM maintenance SHOULD minimize user impact.

---

# 192. Zero-Downtime Claims

Baobab SHALL not claim zero downtime unless the architecture has demonstrated it under representative failure testing.

---

# 193. Error Budget

IAM availability SHOULD eventually have an explicit SLO/error budget.

---

# 194. Proposed Availability Objective

An initial production target SHOULD be evaluated around:

```text
≥ 99.95%
```

with higher targets considered as Baobab commercial dependence grows.

---

# 195. Tier-0 Metrics

Monitor at minimum:

```text
iam_availability
authentication_success_rate
authentication_latency
database_availability
database_replication_health
keycloak_ready_instances
session_error_rate
token_issue_failure_rate
jwks_failure_rate
backup_success
backup_age
restore_test_age
revocation_reconciliation_lag
```

---

# 196. Alerts

Critical alerts SHOULD include:

```text
all Keycloak instances unavailable
database writer unavailable
replication unhealthy
backup failed
backup too old
certificate nearing expiry
signing key problem
secret store unavailable
JWKS unavailable
revocation reconciliation failed
DR security test failed
```

---

# 197. Backup Success ≠ Recovery Success

Dashboarding SHALL distinguish:

```text
last backup successful
```

from:

```text
last restore test successful
```

---

# 198. Recovery Readiness Metric

A useful control is:

```text
time_since_last_successful_restore_test
```

---

# 199. Runbook Freshness

Runbooks SHOULD be reviewed after:

```text
Keycloak upgrade
database architecture change
cloud migration
secret-store change
major IAM feature change
```

---

# 200. Rejected Alternative — Single Keycloak Instance

### Decision

Rejected for production.

---

# 201. Rejected Alternative — Single PostgreSQL Instance Without HA

### Decision

Rejected for production Tier-0 IAM.

---

# 202. Rejected Alternative — Replication as Backup

### Decision

Rejected.

---

# 203. Rejected Alternative — Realm Export as Complete Backup

### Decision

Rejected.

---

# 204. Rejected Alternative — Restore and Immediately Reopen Traffic

### Decision

Rejected.

Security reconciliation is mandatory.

---

# 205. Rejected Alternative — Ignore Post-Backup Revocations

### Decision

Prohibited.

---

# 206. Rejected Alternative — Universal Emergency Bearer Token

### Decision

Prohibited.

---

# 207. Rejected Alternative — Authentication Bypass During IAM Outage

### Decision

Prohibited.

---

# 208. Rejected Alternative — Async Multi-Master IAM Without Supported Conflict Handling

### Decision

Rejected.

---

# 209. Rejected Alternative — Preview Multi-Cluster Architecture as Immediate Production Baseline

### Decision

Rejected while the selected upstream feature remains preview.

It MAY be reevaluated once stable and production-supported.

---

# 210. Rejected Alternative — Restore Production Backup Into Developer Laptop

### Decision

Prohibited.

---

# 211. Rejected Alternative — Delete Old Signing Keys Immediately

### Decision

Rejected where still-valid issued tokens require verification overlap.

---

# 212. Rejected Alternative — Backup Private Keys in Ordinary Git Repository

### Decision

Prohibited.

---

# 213. Rejected Alternative — DR Without Negative Security Tests

### Decision

Rejected.

---

# 214. Consequences

## Positive

This decision provides:

- resilient authentication;
- reduced single points of failure;
- controlled IAM disaster recovery;
- PostgreSQL durability;
- protected cryptographic recovery;
- explicit RPO/RTO;
- revocation-safe restoration;
- workload recovery safety;
- tenant suspension preservation;
- stronger incident response;
- testable recovery readiness.

## Negative

It requires:

- redundant infrastructure;
- HA PostgreSQL;
- secure backup infrastructure;
- secrets/key-management infrastructure;
- DR automation;
- reconciliation mechanisms;
- recovery testing;
- operational expertise;
- additional cost.

These costs are accepted because IAM is a Tier-0 security dependency.

---

# 215. Implementation Ownership

| Concern | Owner |
|---|---|
| Keycloak application configuration | `baobab-iam` |
| IAM runtime | `baobab-platform/infrastructure` |
| PostgreSQL HA | `baobab-platform/infrastructure` |
| Database backup/PITR | `baobab-platform/infrastructure` |
| Secret management | `baobab-platform/infrastructure` |
| TLS/PKI | `baobab-platform/infrastructure` |
| Keycloak signing configuration | `baobab-iam` + Infrastructure |
| Security/revocation contracts | `baobab-platform/shared` |
| Canonical identity reconciliation | `baobab-cp` |
| Trade reconciliation | `baobab-trade` |
| ERP reconciliation | `baobab-erp` |
| CMS reconciliation | `baobab-cms` |
| Pulse reconciliation | `baobab-pulse` |
| DR runbooks | IAM + Infrastructure |
| DR exercises | Platform Operations + Security |

---

# 216. Target Production Architecture

```text
                        INTERNET / WORKLOADS
                                │
                                ▼
                       EDGE / TRAFFIC LAYER
                                │
                  ┌─────────────┴─────────────┐
                  │                           │
                  ▼                           ▼
            Failure Domain A            Failure Domain B
                  │                           │
             Keycloak A1                  Keycloak B1
             Keycloak A2                  Keycloak B2
                  │                           │
                  └─────────────┬─────────────┘
                                │
                                ▼
                     HA POSTGRESQL 17
                      ┌────────┴────────┐
                      ▼                 ▼
                   Primary           Replica
                      │                 │
                      └────────┬────────┘
                               ▼
                         PITR / BACKUP
                               │
                               ▼
                   PROTECTED RECOVERY COPY

        Separate but coordinated recovery dependencies:

        ┌────────────────┬────────────────┬───────────────┐
        ▼                ▼                ▼               ▼
     Secrets          Signing Keys       IaC       Security Journal
```

---

# 217. Disaster Recovery Architecture

```text
                    PRODUCTION FAILURE
                           │
                           ▼
                    CONTAIN INCIDENT
                           │
                           ▼
                  SELECT TRUSTED POINT
                           │
                           ▼
                  RESTORE POSTGRESQL
                           │
                           ▼
                  RESTORE KEYS/SECRETS
                           │
                           ▼
                  DEPLOY PINNED KEYCLOAK
                           │
                           ▼
                     KEEP TRAFFIC CLOSED
                           │
                           ▼
                  SECURITY RECONCILIATION
             ┌─────────────┼──────────────┐
             ▼             ▼              ▼
       Revocation      Control Plane    Domains
         Journal           State          State
             │             │              │
             └─────────────┼──────────────┘
                           ▼
                     SAFE IAM STATE
                           │
                           ▼
                    SECURITY TESTS
                           │
                   ┌───────┴────────┐
                   ▼                ▼
                 PASS              FAIL
                   │                │
                   ▼                ▼
            REOPEN TRAFFIC      KEEP CLOSED
                                    │
                                    ▼
                              INVESTIGATE
```

---

# 218. Revocation-Safe Restore

```text
Backup T0
   │
   │   T1 identity ACTIVE
   │
   │   T2 security incident
   │
   │   T3 identity DISABLED
   │
   │   T4 sessions REVOKED
   │
   ▼
Disaster T5
   │
   ▼
Restore T0
   │
   ▼
Restored state says ACTIVE
   │
   ▼
Read trusted security journal
   │
   ▼
Later state says DISABLED
   │
   ▼
DENY WINS
   │
   ▼
Identity remains DISABLED
```

---

# 219. Failure Behaviour Matrix

| Failure | Expected Behaviour |
|---|---|
| One Keycloak instance | Other replicas serve traffic |
| One compute node | Replicas on other nodes serve |
| One AZ | Surviving failure domain serves where architecture supports it |
| DB node | HA DB failover |
| IAM entirely unavailable | No authentication bypass |
| Existing short-lived token | May remain usable until expiry subject to CP/domain authorization |
| CP unavailable | Context-dependent access fails closed |
| Signing key compromised | Retire/rotate key; security over availability |
| Backup restore | Reconcile before traffic |
| Old revoked identity appears active after restore | Reapply revocation |
| Workload revoked after backup | Remains revoked |
| Tenant suspended after backup | CP continues to deny |
| External IdP unavailable | Only dependent authentication path affected where possible |

---

# 220. RPO/RTO Baseline

| Scenario | Initial Target |
|---|---:|
| Keycloak process failure | RPO 0; recovery seconds |
| Compute/node failure | RPO 0; recovery seconds/minutes |
| HA database node failure | RPO 0 where synchronous replication applies |
| AZ failure | RPO 0 target where topology supports it |
| Catastrophic IAM restore | RPO ≤ 5 minutes proposed |
| Security revocation state | Effective RPO 0 target |
| Catastrophic IAM RTO | ≤ 60 minutes proposed |
| Revoked privileged identity | Near-immediate denial |

These targets SHALL be validated against the chosen production cloud architecture and cost model before becoming contractual SLOs.

---

# 221. Production-Readiness Checklist

IAM SHALL NOT be declared production-ready until:

- multiple Keycloak instances run in production;
- replicas are separated across failure domains;
- anti-affinity/topology spreading exists;
- Keycloak uses production mode;
- exact Keycloak version/image digest is pinned;
- PostgreSQL 17 compatibility is verified;
- IAM database is dedicated;
- database HA is configured;
- database failover is tested;
- session behavior across node failure is tested;
- short-lived-token outage behavior is documented;
- no authentication bypass exists;
- no universal emergency token exists;
- automated database backups exist;
- PITR is configured where supported;
- backups are encrypted;
- backup access is restricted;
- at least one protected recovery copy exists;
- backup deletion protection exists;
- restore testing succeeds;
- signing-key recovery is documented;
- secrets recovery is documented;
- certificate expiry monitoring exists;
- configuration-as-code exists;
- DR infrastructure can be reconstructed;
- DR runbook exists;
- RPO/RTO targets are approved;
- DR exercises occur periodically;
- post-backup revocation reconciliation exists;
- revoked identities cannot be resurrected by restore;
- revoked workload identities survive restore;
- suspended tenants survive restore;
- privileged sessions are safely handled after DR;
- negative security recovery tests pass;
- Keycloak → CP integration is tested after restore;
- Keycloak → Trade integration is tested;
- Keycloak → ERP integration is tested;
- monitoring covers IAM dependencies;
- backup age is alerted;
- restore-test age is monitored;
- recovery audit exists;
- production traffic remains gated until security validation passes.

---

# 222. Required Failure Tests

Automated and operational testing SHALL include:

```text
kill one Keycloak instance
kill one compute node
restart all Keycloak instances sequentially
simulate PostgreSQL failover
simulate database connection interruption
rotate TLS certificate
rotate signing key
restore database backup
restore configuration
invalidate sessions
disable identity
restore older backup
verify identity remains disabled
revoke workload
restore older backup
verify workload remains revoked
suspend tenant
restore IAM
verify tenant remains suspended
```

---

# 223. Required Security Recovery Tests

At minimum:

```text
restored disabled identity cannot authenticate

restored revoked credential cannot authenticate

restored stale IAM membership cannot override CP denial

restored Keycloak Organization cannot create supplier approval

restored IAM role cannot create ERP AD_Role

restored session cannot bypass Trade suspension

wrong-audience token remains rejected

expired token remains rejected

revoked workload remains rejected

break-glass use remains auditable
```

---

# 224. Architectural Invariants

The following become binding:

```text
High Availability ≠ Backup

Replication ≠ Backup

Backup Success ≠ Restore Success

Restore Success ≠ Security Recovery Success

Keycloak Healthy ≠ IAM Recovery Complete

Realm Export ≠ Complete IAM Backup

Container Image ≠ Identity Backup

Cache ≠ Identity Authority

IAM Availability ≠ CP Availability

IAM Availability ≠ Engine Availability

Existing Token ≠ Permission to Ignore Current Authorization

IAM Outage ≠ Authentication Bypass

Break-Glass ≠ Authentication Bypass

Preview Feature ≠ Production Baseline

Multi-Region ≠ Automatically More Resilient

Restore ≠ Permission Resurrection

Backup State ≠ Latest Security State

Old Credential in Backup ≠ Valid Credential

Old Session in Backup ≠ Valid Session

Database Restore ≠ Revocation Restore

Security Revocation Survives Disaster Recovery

Security Revocation Survives Migration

Security Revocation Survives Rollback

Security Consistency > Dual-Site Availability During Ambiguous Partition

Production Backup ≠ Development Test Data

Signing Private Key ≠ Ordinary Configuration Artifact
```

---

# 225. Decision Summary

Baobab IAM SHALL operate as Tier-0 infrastructure.

The resilience hierarchy is:

```text
CAN A SINGLE PROCESS FAIL?
        │
        ▼
Multiple Keycloak instances

CAN A NODE/AZ FAIL?
        │
        ▼
Failure-domain separation

CAN THE DATABASE FAIL?
        │
        ▼
HA PostgreSQL

CAN DATA BE CORRUPTED?
        │
        ▼
Backup + PITR

CAN THE PRIMARY ENVIRONMENT BE LOST?
        │
        ▼
Protected recovery infrastructure

CAN IAM BE RESTORED?
        │
        ▼
Pinned software + configuration + keys + secrets

CAN AN OLD BACKUP RESURRECT ACCESS?
        │
        ▼
Security journal + reconciliation

IS THE RECOVERED SYSTEM ACTUALLY SAFE?
        │
        ▼
Positive + negative security tests

HAS THE ARCHITECTURE REALLY BEEN PROVEN?
        │
        ▼
Regular DR exercises
```

Availability and disaster recovery SHALL therefore not be measured merely by whether Keycloak starts.

A successful recovery requires:

```text
IAM runtime healthy
+
database healthy
+
cryptographic trust healthy
+
security state reconciled
+
revocations preserved
+
CP integration healthy
+
critical engine integrations healthy
+
monitoring healthy
```

Only then may production traffic be fully restored.

The most important recovery invariant is:

> **No Baobab IAM backup, rollback, migration, failover or disaster-recovery operation may knowingly resurrect a credential, identity, membership, session, workload or privilege that a newer authoritative security decision had already revoked.**

And the governing resilience principle is:

> **Baobab shall design IAM not merely to survive failure, but to survive failure without forgetting who must no longer be trusted.**