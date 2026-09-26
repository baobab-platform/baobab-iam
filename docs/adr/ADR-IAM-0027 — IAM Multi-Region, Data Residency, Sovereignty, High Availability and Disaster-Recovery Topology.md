# ADR-IAM-0027 — IAM Multi-Region, Data Residency, Sovereignty, High Availability and Disaster-Recovery Topology

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture / Infrastructure  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, all Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0026  
**Extends:** ADR-IAM-0017, ADR-IAM-0018, ADR-IAM-0019, ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022, ADR-IAM-0023, ADR-IAM-0024, ADR-IAM-0025, ADR-IAM-0026  
**Decision Type:** Multi-Region / Data Residency / Sovereignty / HA / DR / Identity Routing  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Persistence Baseline:** PostgreSQL 17, subject to pinned Ory compatibility validation  
**Initial Markets:** Uganda and South Africa  
**Future Markets:** Kenya, Tanzania, Rwanda and others

---

# 1. Decision

Baobab SHALL adopt a **regionalized, single-writer identity-authority architecture with in-region high availability and explicitly controlled cross-region disaster recovery**.

Baobab SHALL NOT initially deploy unrestricted active-active, multi-writer Ory Kratos or Hydra persistence across regions.

The initial production topology SHALL distinguish:

```text id="1vn6qk"
GLOBAL IDENTITY LOGIC
        │
        ▼
REGIONAL IDENTITY RUNTIME
        │
        ▼
REGIONAL AUTHORITATIVE PERSISTENCE
        │
        ▼
CONTROLLED DR REPLICA
```

Each identity security domain SHALL have:

- one authoritative write region at a time;
- redundant Ory runtime replicas within that region;
- highly available PostgreSQL persistence within the region;
- encrypted backups;
- controlled cross-region disaster-recovery replication where permitted;
- explicit promotion procedures;
- split-brain prevention;
- revocation-safe recovery;
- residency-aware routing;
- tested RPO and RTO;
- immutable infrastructure/configuration;
- regional observability and security controls.

The architectural principle is:

> **Baobab may distribute authentication infrastructure globally, but every mutable identity security domain must have an unambiguous authority at every point in time.**

---

# 2. The Critical Distinctions

The following SHALL remain distinct:

```text id="04rt45"
Market
   ≠
Region
   ≠
Cloud Region
   ≠
Data Residency Zone
   ≠
Tenant
   ≠
Legal Entity
   ≠
Digital Estate
   ≠
Identity Security Domain
```

These concepts SHALL NOT be collapsed for deployment convenience.

---

# 3. Market Is Not Region

Example:

```text id="ad70zx"
Market:
South Africa

Identity Runtime:
Africa IAM Region A
```

or:

```text id="h1qfdc"
Market:
Uganda

Identity Runtime:
Africa IAM Region A
```

may both be valid.

Conversely, future regulation or contractual obligations MAY require:

```text id="cft4fh"
Market:
Country X

Identity Residency:
Country X only
```

The relationship is policy-driven.

---

# 4. Region Is Not Tenant

A single regional IAM runtime MAY securely serve many tenants.

```text id="shfqr1"
Africa Region
│
├── Nabhold
├── ZuriBeans
├── Thamani
├── External Customer A
└── External Customer B
```

provided Baobab's tenancy, context and isolation rules remain intact.

Region SHALL NOT become a tenant identifier.

---

# 5. Tenant Is Not Physical Database Placement

Likewise:

```text id="44hz9e"
Tenant A
```

does not automatically imply:

```text id="jbsj17"
Database A
```

unless its IsolationProfile, regulation, contractual obligations or risk require physical isolation.

---

# 6. Identity Security Domain

Baobab introduces the architectural concept:

```text id="5o9wft"
IdentitySecurityDomain
```

A security domain represents the authoritative identity-runtime and persistence boundary within which mutable identity security state is coordinated.

Conceptually:

```text id="4npwqm"
IdentitySecurityDomain
├── id
├── authority_region
├── residency_policy
├── issuer_profile
├── kratos_runtime
├── hydra_runtime
├── persistence_profile
├── cryptographic_profile
├── backup_profile
├── dr_profile
└── status
```

---

# 7. Identity Security Domain Is Not a Business Entity

An IdentitySecurityDomain SHALL NOT represent:

```text id="i5w3w8"
Tenant
LegalEntity
BuyerOrganization
SupplierOrganization
Market
```

It is an infrastructure/security boundary.

---

# 8. Initial Deployment Principle

Baobab SHALL begin with the **smallest number of identity security domains that satisfies security, availability, regulatory and contractual requirements**.

Do not create:

```text id="n0zthb"
one Kratos/Hydra deployment
per country
```

merely because Baobab operates in multiple countries.

---

# 9. Avoid Premature Regional Fragmentation

Premature regional fragmentation increases:

- operational complexity;
- issuer complexity;
- key management;
- identity mapping complexity;
- reconciliation complexity;
- failover complexity;
- federation complexity;
- migration complexity;
- incident-response complexity.

Regionalization SHALL therefore be driven by explicit requirements.

---

# 10. Regionalization Triggers

A new identity security domain MAY be justified by:

```text id="f1pugz"
data residency law
data sovereignty requirement
customer contract
latency requirement
availability requirement
regulatory isolation
material blast-radius reduction
extreme scale
```

---

# 11. Initial Logical Topology

Conceptually:

```text id="3tks3x"
                     GLOBAL USERS
                         │
                         ▼
                  ┌──────────────┐
                  │ DNS / EDGE   │
                  │ APISIX       │
                  └──────┬───────┘
                         │
                  Region Resolution
                         │
              ┌──────────┴───────────┐
              │                      │
              ▼                      ▼
      ┌────────────────┐     ┌────────────────┐
      │ IAM REGION A   │     │ IAM REGION B   │
      │                │     │                │
      │ Kratos x N     │     │ DR / future   │
      │ Hydra x N      │     │ authority      │
      │ IAM Adapter    │     │                │
      │ PostgreSQL HA  │     │ PG replica     │
      └───────┬────────┘     └────────────────┘
              │
              ▼
      Baobab Control Plane
              │
              ▼
       Domain Engines
```

---

# 12. In-Region High Availability

Within an authoritative region:

```text id="17aev3"
                 Load Balancer
                      │
          ┌───────────┴───────────┐
          │                       │
      Kratos 1                Kratos 2+
          │                       │
          └───────────┬───────────┘
                      │
                Kratos DB HA

                 Load Balancer
                      │
          ┌───────────┴───────────┐
          │                       │
       Hydra 1                 Hydra 2+
          │                       │
          └───────────┬───────────┘
                      │
                 Hydra DB HA
```

Runtime replicas SHALL be horizontally replaceable.

Persistent identity state SHALL not depend on a specific runtime pod.

---

# 13. Availability Zones

Where the cloud provider supports multiple availability zones, production IAM SHOULD distribute:

```text id="zqcsqn"
Kratos replicas
Hydra replicas
IAM adapter replicas
PostgreSQL HA nodes
```

across failure domains.

---

# 14. Failure Domains

Baobab SHALL consider independently:

```text id="d3r1nu"
pod failure
node failure
availability-zone failure
database-primary failure
regional network failure
complete region failure
cloud-provider service failure
```

A design that survives a pod restart is not automatically highly available.

---

# 15. PostgreSQL Baseline

Kratos and Hydra SHALL continue to use separate logical databases and database credentials as established by ADR-IAM-0021.

Conceptually:

```text id="2e21qb"
PostgreSQL HA Cluster
│
├── kratos
│   └── kratos_role
│
└── hydra
    └── hydra_role
```

They MAY share a physical PostgreSQL HA cluster where justified.

They SHALL NOT share schemas or migration ownership.

---

# 16. PostgreSQL 17 Replication

PostgreSQL 17 supports warm/hot standby architectures using WAL/streaming replication. Streaming replication is asynchronous by default; synchronous replication can require commits to wait for one or more standbys.

Baobab SHALL exploit these mechanisms deliberately rather than assuming replication automatically provides zero-data-loss DR.

---

# 17. In-Region Database HA

For in-region HA, Baobab SHOULD use:

```text id="3cchke"
Primary
   │
   ├── synchronous or appropriately durable standby
   │
   └── additional standby where justified
```

subject to performance and infrastructure validation.

---

# 18. Synchronous Replication Trade-Off

PostgreSQL synchronous replication increases durability but requires transactions to wait for standby acknowledgement and therefore introduces latency.

Therefore Baobab SHALL NOT blindly enable synchronous replication across geographically distant regions.

---

# 19. Cross-Region Replication

Cross-region DR SHOULD generally use:

```text id="5k4k6c"
Authoritative Region
       │
       │ asynchronous replication
       ▼
DR Region
```

unless measured latency and business requirements justify synchronous behavior.

---

# 20. Cross-Region Asynchrony Means Non-Zero RPO

Asynchronous replication inherently permits a window in which committed transactions may not yet exist on the standby if the primary region is catastrophically lost. PostgreSQL documents this durability trade-off explicitly.

Therefore:

```text id="k3vru8"
Async DR
    ≠
Guaranteed RPO 0
```

---

# 21. No Invented RPO

Baobab SHALL NOT document:

```text id="z3uwdf"
RPO = 0
```

without measured and architecturally justified evidence.

---

# 22. No Invented RTO

Likewise:

```text id="h6rfkn"
RTO = 5 minutes
```

SHALL not be claimed merely because a standby exists.

RTO SHALL be measured through DR exercises.

---

# 23. Initial Recovery Objectives

Before production, Baobab SHALL establish explicit targets for:

```text id="13pgl7"
Kratos RPO
Kratos RTO
Hydra RPO
Hydra RTO
IAM Adapter RTO
federation configuration RPO/RTO
security journal RPO/RTO
```

These values SHALL be tested.

---

# 24. Single Writer

At any point in time:

```text id="a07vdo"
IdentitySecurityDomain
        │
        ▼
exactly one authoritative
write topology
```

SHALL exist.

---

# 25. No Uncontrolled Multi-Primary

Baobab SHALL NOT initially deploy:

```text id="jmw7nr"
Region A Kratos DB
      ⇅
Region B Kratos DB

both writable
```

without a future ADR establishing conflict resolution, transactional semantics, revocation guarantees and Ory support.

---

# 26. Why Multi-Primary Is Dangerous

Identity data includes:

```text id="am5mtr"
session creation
session revocation
credential binding
credential removal
recovery
identity disablement
OAuth client state
consent
token-related state
```

Conflicting writes to these objects are security decisions, not merely ordinary application conflicts.

---

# 27. Security Beats Write Availability

During a partition, Baobab SHALL prefer:

```text id="1g6n3f"
temporarily unavailable sensitive identity mutation
```

over:

```text id="gjn8iz"
two regions accepting contradictory
identity security mutations
```

---

# 28. Split-Brain Prohibition

A DR region SHALL NOT be promoted until Baobab has established that the previous authoritative writer cannot continue serving writes.

Promotion requires fencing.

---

# 29. Fencing

Failover automation/procedure SHALL include controls capable of preventing:

```text id="d2yopq"
Old Primary
      +
New Primary
```

from both becoming authoritative.

---

# 30. Promotion State

Conceptually:

```text id="ksh3mp"
PRIMARY
  │
  ▼
UNREACHABLE
  │
  ▼
FAILOVER_ASSESSMENT
  │
  ▼
OLD_PRIMARY_FENCED
  │
  ▼
REPLICATION_POSITION_VERIFIED
  │
  ▼
DR_PROMOTED
  │
  ▼
ROUTING_UPDATED
```

---

# 31. Hot Standby

PostgreSQL hot standby permits read-only queries while a standby is replaying WAL. It does not make that standby a concurrent writable primary.

Baobab SHALL preserve this distinction operationally.

---

# 32. Failover Is Not Load Balancing

A standby used for DR SHALL not be treated as a second writable identity region merely because it is reachable.

---

# 33. Revocation Is a Special Security Problem

Suppose:

```text id="i23nvl"
12:00 identity ACTIVE
12:01 identity DISABLED
12:02 primary region destroyed
```

and the DR replica only contains state through:

```text id="z9b3m4"
12:00:59
```

Naïve promotion could resurrect the identity as ACTIVE.

This is unacceptable.

---

# 34. Revocation-Safe Recovery

Baobab SHALL maintain a security recovery mechanism independent enough to prevent stale persistence restoration from silently resurrecting security-sensitive state.

Protected state SHALL include at least:

```text id="b9rz85"
disabled identities
revoked identities
revoked sessions where relevant
revoked workloads
disabled OAuth clients
compromised federation trusts
revoked administrative relationships
critical capability revocations
```

---

# 35. Security Recovery Journal

As established by earlier IAM ADRs, Baobab SHALL maintain a recoverable security journal/checkpoint mechanism.

Conceptually:

```text id="9bshdx"
SecurityRecoveryRecord
├── event_id
├── subject_type
├── subject_id
├── action
├── effective_at
├── authority
├── sequence/checkpoint
├── integrity_metadata
└── recovery_status
```

---

# 36. Security Journal Is Not General Event Bus

Its purpose is specifically to ensure:

```text id="96q75d"
restore/failover
      │
      ▼
does not undo
critical security state
```

It SHALL not become another general business database.

---

# 37. Recovery Rule

Where restored provider state conflicts with a newer authoritative security decision:

```text id="brh1i3"
newer restrictive decision
```

SHALL win.

---

# 38. Deny Wins During Ambiguity

When recovery cannot determine whether an identity or workload was revoked after the available database checkpoint:

```text id="0xll8k"
DENY / SUSPEND
```

SHALL be preferred over restoring authority.

---

# 39. CP Revocation Protection

The Control Plane's canonical lifecycle and authorization state provide another protection layer.

A valid Ory identity/session/token SHALL NOT override:

```text id="bjcg9h"
CanonicalIdentity DISABLED
Tenant suspended
CapabilityBinding revoked
membership revoked
```

---

# 40. Layered Revocation Safety

```text id="pv3jv7"
Ory State
    │
    ▼
ExternalIdentity
    │
    ▼
CanonicalIdentity
    │
    ▼
Context
    │
    ▼
Capability
    │
    ▼
Domain Authority
```

Every relevant layer retains the ability to deny.

---

# 41. Token Survival During Regional Failure

A short-lived token already issued before an IAM outage MAY remain usable if:

```text id="a7jjqm"
signature valid
issuer trusted
audience correct
token unexpired
CP identity/context valid
domain authority valid
```

This is controlled degraded operation.

---

# 42. Token Validity Is Not Current Authority

Even during disaster recovery:

```text id="ryrzbp"
valid JWT
   ≠
automatic authorization
```

ADR-IAM-0006 and ADR-IAM-0008 remain controlling.

---

# 43. New Authentication During IAM Outage

If the authoritative IAM region is unavailable and no DR promotion has occurred:

```text id="05sp57"
new login
new registration
new recovery
new passkey enrollment
new OAuth client mutation
```

MAY be unavailable.

Baobab SHALL NOT bypass IAM to preserve availability.

---

# 44. New Token Issuance

Hydra token issuance SHALL only resume in a DR region after the region has been formally promoted into the authoritative topology.

---

# 45. DNS and Routing

Public IAM endpoints SHOULD use stable Baobab-owned names.

Conceptually:

```text id="thb09e"
identity.baobab.example
auth.baobab.example
```

Actual domains are deployment configuration.

---

# 46. Stable Issuer Principle

Issuer design SHALL prioritize stable security semantics.

A disaster failover SHOULD NOT unnecessarily cause every consumer to perceive an entirely unrelated identity provider.

---

# 47. Issuer Strategy

Baobab SHOULD prefer a stable logical issuer per identity security domain where Ory's supported deployment semantics permit it.

Example:

```text id="itldwk"
https://identity.africa.baobab.example
```

rather than exposing ephemeral cloud-region hostnames.

---

# 48. Issuer Stability Is Security-Sensitive

Changing issuer changes the identity namespace because:

```text id="a13npo"
ExternalIdentity = issuer + subject
```

Therefore a region failover SHALL NOT casually change issuer.

---

# 49. Failover Must Preserve Subject Meaning

If failover uses the same logical security domain and persistence:

```text id="tstef4"
issuer
+
subject
```

SHOULD remain semantically stable.

---

# 50. New Residency Domain May Require New Issuer

A genuinely separate identity security domain MAY require a distinct issuer.

Such a change SHALL be treated as identity architecture, not DNS housekeeping.

---

# 51. JWKS Availability

JWT verification depends on access to trusted signing keys.

Consumers SHALL safely cache JWKS according to appropriate rotation policy.

---

# 52. JWKS During IAM Outage

Temporary inability to fetch JWKS SHOULD NOT necessarily invalidate already trusted unexpired signing keys.

However:

```text id="2cuz2o"
unknown signing key
```

SHALL fail safely.

---

# 53. Key Rotation and Multi-Region

Signing-key rotation SHALL account for:

```text id="1ew8gv"
primary region
DR region
JWKS caches
in-flight tokens
rollback
```

---

# 54. Cryptographic Material

Required cryptographic material SHALL be recoverable according to Tier-0 procedures.

It SHALL NOT be reconstructed ad hoc after a disaster.

---

# 55. Secret Replication

Secrets MAY require secure cross-region replication.

This SHALL use the approved secrets-management mechanism rather than application database replication.

---

# 56. Secret Residency

Some secrets MAY be restricted to particular regions/security domains.

Secret replication SHALL therefore obey residency policy.

---

# 57. Residency Policy

Baobab SHALL represent residency explicitly.

Conceptually:

```text id="ml8g4g"
ResidencyPolicy
├── id
├── allowed_regions
├── prohibited_regions
├── primary_region
├── backup_regions
├── replication_policy
├── evidence_policy
├── encryption_policy
└── legal_basis_reference
```

---

# 58. Residency Is a Constraint

Routing SHALL satisfy:

```text id="rfslfj"
User Request
     │
     ▼
IdentitySecurityDomain
     │
     ▼
ResidencyPolicy
     │
     ▼
Allowed Runtime
```

not merely lowest network latency.

---

# 59. Residency vs Availability

If regulation prohibits identity data from leaving a jurisdiction:

```text id="lgg1py"
cross-border DR
```

may be prohibited.

Baobab SHALL then design DR within the permitted geography.

---

# 60. Backup Residency

Residency requirements apply to:

```text id="1kfl0p"
primary database
replicas
backups
snapshots
WAL archives
proofing evidence
security journals
logs where personal data exists
```

not only the live database.

---

# 61. Identity Proofing Evidence

ADR-IAM-0025 proofing evidence MAY have stricter residency than basic identity profile data.

Evidence storage SHALL therefore have its own residency classification.

---

# 62. Federation Data

Enterprise federation configuration may contain:

```text id="um6xgi"
enterprise identifiers
domains
certificates
directory projections
user attributes
```

and SHALL follow appropriate residency controls.

---

# 63. Audit Residency

Security/audit events containing personal identifiers SHALL be classified and routed accordingly.

---

# 64. No Residency Through Claims Alone

A JWT claim such as:

```text id="kavtuk"
market = ZA
```

SHALL NOT be treated as proof of residency requirements.

Routing uses canonical configuration.

---

# 65. Region Resolver

Baobab SHALL introduce or extend a provider-neutral IAM region resolver.

Inputs MAY include:

```text id="p1e3sq"
identity security domain
tenant isolation profile
residency policy
digital estate
federation trust
migration state
```

---

# 66. Geography Is Not Sufficient

Do not route identity merely from:

```text id="l3o68n"
client IP geolocation
```

because a South African employee may legitimately belong to a Ugandan organization's identity security domain.

---

# 67. Home Identity Domain

An identity MAY have a designated:

```text id="7p13q8"
home_identity_security_domain
```

for mutable identity operations.

---

# 68. Home Domain Does Not Limit Business Context

Jane's identity may be homed in one identity security domain while she acts in several permitted business contexts.

```text id="xg1d5f"
Jane Identity
   │
   ▼
Africa IAM Domain
   │
   ├── ZuriBeans Uganda
   ├── ZuriBeans South Africa
   └── Thamani South Africa
```

---

# 69. Global CanonicalIdentity

CanonicalIdentity SHOULD remain globally meaningful within Baobab.

Regional IAM topology SHALL NOT create separate canonical people merely because the same person uses services in multiple regions.

---

# 70. Regional ExternalIdentity

A CanonicalIdentity MAY link to multiple external identities if separate security domains legitimately require them.

```text id="l9n82n"
CanonicalIdentity Jane
      │
      ├── ExternalIdentity Region A
      └── ExternalIdentity Region B
```

This SHALL be explicit and controlled.

---

# 71. No Automatic Cross-Region Linking

Email equality SHALL NOT link regional external identities.

ADR-IAM-0004 remains controlling.

---

# 72. Cross-Region Account Migration

Moving an identity between security domains SHALL be a governed migration:

```text id="12i9xj"
Source Domain
      │
      ▼
migration ledger
      │
      ▼
Target Domain
      │
      ▼
identity verification
      │
      ▼
CanonicalIdentity preserved
      │
      ▼
source retired
```

---

# 73. Migration vs Replication

Identity-domain migration SHALL NOT be confused with PostgreSQL replication.

Migration changes authority.

Replication copies persistence for HA/DR.

---

# 74. Regional Registration

Registration SHALL occur in the resolved authoritative identity security domain.

---

# 75. Regional Recovery

Account recovery SHALL execute against the authoritative identity security domain or formally promoted DR authority.

---

# 76. Regional Passkey Binding

Passkey enrollment modifies security state.

It SHALL therefore occur only against the authoritative writer.

---

# 77. Regional Session State

Kratos session state SHALL follow the authoritative persistence topology.

A region SHALL not independently manufacture divergent session state.

---

# 78. OAuth Client Authority

Hydra OAuth client configuration SHALL similarly have one authoritative management topology.

---

# 79. Workload Identity

Workload identity placement MAY differ from human identity placement.

A workload SHOULD authenticate against the security domain appropriate to its runtime and trust configuration.

---

# 80. Workload Region

```text id="gh4wdz"
Workload
├── runtime_region
├── identity_security_domain
├── allowed_audiences
└── capabilities
```

SHALL be explicit.

---

# 81. Runtime Region Is Not Authority

A service running in Region B MAY validate a token issued by Region A if trust policy permits.

It does not need Region B to become another identity writer.

---

# 82. Local Token Validation

Baobab SHOULD preserve local JWT validation where appropriate:

```text id="71ckm5"
Regional API
    │
    ▼
cached trusted JWKS
    │
    ▼
signature/audience/expiry
    │
    ▼
CP context
    │
    ▼
domain authorization
```

This reduces synchronous dependency on IAM.

---

# 83. No Global IAM Proxy Requirement

Every API request SHALL NOT require a synchronous round trip to the authoritative IAM region.

That would turn network latency or IAM-region failure into platform-wide failure.

---

# 84. Control Plane Dependency

CP SHALL maintain its own HA/DR architecture.

IAM multi-region design SHALL NOT assume CP is always available simply because Ory is available.

---

# 85. Failure Matrix

| IAM | CP | Domain | Result |
|---|---|---|---|
| Healthy | Healthy | Healthy | Normal |
| Down | Healthy | Healthy | Existing valid short-lived tokens may continue; new auth impaired |
| Healthy | Down | Healthy | Context-dependent operations fail closed |
| Healthy | Healthy | Down | Domain unavailable |
| DR promoted | Healthy | Healthy | Controlled recovery |
| IAM stale | CP newer deny | Healthy | Deny |
| IAM healthy | Domain denies | Healthy | Deny |

---

# 86. Regional Partition

During a partition between primary and DR region:

```text id="u2nly7"
PRIMARY remains authoritative
DR remains non-authoritative
```

unless formal failover occurs.

---

# 87. No Automatic Split-Brain Failover

Baobab SHALL be conservative about fully automatic cross-region promotion.

Automatic promotion is acceptable only if infrastructure can reliably:

```text id="pzkc2l"
detect failure
fence old primary
verify replication
promote safely
update routing
preserve security state
```

---

# 88. Manual Confirmation

Initial production SHOULD require controlled human confirmation for catastrophic cross-region IAM failover unless the managed database/platform proves safe automated fencing.

---

# 89. Failback

Recovery does not end when DR is promoted.

A failback procedure SHALL define:

```text id="bdq0he"
old primary disposition
data reconciliation
new replication direction
security journal reconciliation
routing
key state
session implications
validation
```

---

# 90. Never Simply Restart Old Primary

After failover, the old primary SHALL NOT simply return to service as writable.

It must rejoin according to the database failback procedure.

---

# 91. Backups

Baobab SHALL maintain encrypted backups of:

```text id="sq7s1z"
Kratos DB
Hydra DB
provider-neutral IAM state
federation configuration
identity schemas
OAuth client configuration
cryptographic material where required
security recovery journal
migration state
```

---

# 92. Backup Is Not DR

A backup proves only that data was captured.

DR requires proof that:

```text id="1on6iz"
backup can be restored
service can start
keys match
issuer works
identity works
revocations remain enforced
```

---

# 93. Restore Testing

Backups SHALL undergo scheduled restore testing.

---

# 94. Restore Test Scope

A restore exercise SHALL validate at least:

```text id="z49avb"
Kratos startup
Hydra startup
login
OIDC discovery
Auth Code + PKCE
token issuance
client credentials
session handling
identity disablement
workload revocation
federation configuration
recovery
passkeys where applicable
JWKS
CP identity resolution
```

---

# 95. Negative Restore Tests

The exercise SHALL also prove:

```text id="j1uz1e"
revoked identity stays denied
revoked workload stays denied
disabled OAuth client stays disabled
revoked membership stays revoked
compromised federation stays suspended
```

---

# 96. Point-in-Time Recovery

Where infrastructure supports PostgreSQL point-in-time recovery, Baobab SHOULD use it as part of the recovery strategy.

PITR SHALL still be followed by security-state reconciliation.

---

# 97. WAL Protection

WAL archives SHALL be:

```text id="1vkzo5"
encrypted
access-controlled
retained according to policy
residency-compliant
protected from ordinary workload identities
```

---

# 98. Backup Immutability

At least one recovery path SHOULD be protected against alteration by a compromised normal production workload.

---

# 99. Ransomware Consideration

A production credential capable of deleting:

```text id="f86jnj"
database
+
replicas
+
backups
```

creates unacceptable blast radius.

Backup authority SHALL be separated.

---

# 100. Restore Authority

Only narrowly authorized operational/security identities SHALL initiate IAM restoration.

---

# 101. DR Approval

Catastrophic IAM promotion SHALL require auditable authority.

---

# 102. DR Audit

Record:

```text id="l7lfsu"
incident
decision maker
old region
new region
replication checkpoint
security checkpoint
promotion time
routing change
validation result
failback
```

---

# 103. Regional Observability

Each IAM region SHALL expose:

```text id="hmc23e"
availability
latency
error rate
login rate
token rate
database health
replication lag
replication state
backup age
certificate/key status
security events
```

---

# 104. Replication Lag Is a Security Metric

For IAM:

```text id="qjs2oh"
replication lag
```

is not merely a database performance metric.

It represents potential:

```text id="0zn81e"
revocation loss
session-state loss
identity-state loss
OAuth-client-state loss
```

during catastrophic failover.

---

# 105. Replication Alerts

Alert on:

```text id="4dzv9f"
replica disconnected
replication lag above threshold
WAL archive failure
standby unhealthy
backup stale
restore test failure
```

---

# 106. Security Journal Alerts

Alert when:

```text id="h7hrvl"
security journal lag
checkpoint failure
journal integrity failure
reconciliation failure
```

occurs.

---

# 107. Regional SLOs

Measure independently:

```text id="30if8r"
authentication availability
token issuance availability
identity management availability
recovery availability
federation availability
SCIM availability
```

---

# 108. Latency

Authentication latency SHOULD be measured from actual target markets.

Regional expansion SHALL be evidence-driven.

---

# 109. No Premature Edge Authentication State

Baobab SHALL NOT place mutable credential/session authority into arbitrary edge locations merely for latency.

---

# 110. Edge Responsibilities

Edge infrastructure MAY perform:

```text id="m2m3fc"
TLS termination
DDoS mitigation
WAF
rate limiting
routing
cached static metadata
```

subject to security architecture.

It SHALL NOT become canonical identity authority.

---

# 111. OIDC Discovery

OIDC discovery endpoints SHOULD remain highly available and cacheable where standards permit.

---

# 112. Static Trust Material

Selected public trust material MAY be replicated broadly.

Sensitive mutable identity state SHALL remain governed by its authority domain.

---

# 113. Regional Federation

Enterprise federation SHALL resolve to the appropriate identity security domain.

---

# 114. Federation Trust Residency

A multinational customer MAY have one federation trust serving multiple markets if permitted.

Do not duplicate federation configuration per market without need.

---

# 115. SCIM Routing

SCIM requests SHALL target the authoritative identity/federation domain for that enterprise relationship.

---

# 116. SCIM During DR

SCIM writes SHALL pause or route to the promoted authority during failover.

They SHALL NOT write concurrently into old and new regions.

---

# 117. Proofing During DR

High-risk identity proofing/rebinding MAY be temporarily disabled during uncertain DR state.

Security-critical identity mutation SHALL not proceed when authoritative state cannot be established.

---

# 118. Privileged Operations During DR

Baobab MAY impose stricter controls during DR, including temporarily disabling:

```text id="d2wzuc"
new platform administrators
new federation trusts
high-risk identity merges
security-policy downgrades
```

until system integrity is verified.

---

# 119. Degraded Security Mode Is Not Weaker Security

A degraded mode MAY reduce functionality.

It SHALL NOT reduce assurance requirements merely to preserve availability.

---

# 120. Region Status

Conceptually:

```text id="x86ymp"
RegionStatus
├── ACTIVE
├── STANDBY
├── DEGRADED
├── FAILOVER_PENDING
├── PROMOTED
├── RECOVERING
└── RETIRED
```

---

# 121. Identity Domain Status

Separately:

```text id="4ryv5j"
IdentitySecurityDomainStatus
├── ACTIVE
├── MIGRATING
├── SUSPENDED
├── RECOVERY
└── RETIRED
```

---

# 122. Infrastructure as Code

All regional IAM infrastructure SHALL be reproducible from version-controlled infrastructure definitions.

---

# 123. No Snowflake DR

A DR region manually configured years earlier and never exercised SHALL NOT count as production DR.

---

# 124. Configuration Parity

Production and DR regions SHALL maintain controlled parity for:

```text id="3zgxfw"
Ory versions
identity schemas
OAuth configuration
network policy
secret references
observability
database compatibility
```

---

# 125. Immutable Runtime

Kratos, Hydra and Baobab IAM adapter deployments SHALL use immutable versioned artifacts.

---

# 126. Version Skew

Failover SHALL NOT depend on an untested combination such as:

```text id="y3ng53"
Primary Ory version N
DR Ory version N-3
```

---

# 127. Database Version Compatibility

PostgreSQL primary and physical standby topology SHALL maintain supported version compatibility.

PostgreSQL itself recommends keeping primary and standby servers at the same release level as much as possible.

---

# 128. Migration During Deployment

Database migrations SHALL not run concurrently from multiple regions.

---

# 129. Upgrade Sequence

A production upgrade SHOULD conceptually follow:

```text id="1u0fr7"
backup
   │
   ▼
verify DR
   │
   ▼
migration compatibility
   │
   ▼
controlled DB migration
   │
   ▼
runtime rollout
   │
   ▼
security validation
   │
   ▼
DR compatibility verification
```

---

# 130. Regional Migration Safety

Do not promote a DR region whose database/runtime version has not been proven compatible with current production state.

---

# 131. Multi-Region Future

Baobab MAY later evolve toward multiple simultaneously active identity security domains.

That is distinct from:

```text id="3jnrtf"
multi-writer same identity domain
```

---

# 132. Federated Regional Domains

A future architecture may be:

```text id="x1oz01"
        CanonicalIdentity Layer
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
   IAM ZA     IAM EA     IAM EU
   Domain     Domain     Domain
```

with each domain authoritative for its own identities.

This can provide regionalization without multi-primary mutation of the same persistence.

---

# 133. Global Person, Regional Credentials

Such a future topology MAY support:

```text id="wjd2mg"
Global CanonicalIdentity
        │
        ├── Regional ExternalIdentity A
        └── Regional ExternalIdentity B
```

when justified.

---

# 134. Cross-Domain Identity Operations

Any cross-domain identity linking, migration or recovery SHALL be explicit and audited.

---

# 135. No Hidden Replication Semantics

Applications SHALL not assume:

```text id="8u56u1"
write in ZA
immediately visible in UG
```

unless the architecture explicitly guarantees it.

---

# 136. Consistency Classes

Baobab SHALL classify identity data according to consistency needs.

### Security-Critical

```text id="m09ak3"
identity disablement
workload revocation
OAuth client disablement
federation suspension
privileged relationship revocation
```

Requires strong recovery semantics.

### Security-Sensitive

```text id="1yz28m"
credential enrollment
recovery
MFA changes
session changes
```

Requires authoritative writer.

### Low-Risk Profile

```text id="k95vkc"
display name
non-sensitive preferences
```

may tolerate greater eventual consistency where applicable.

---

# 137. CAP Trade-Off

During a severe network partition, Baobab SHALL not pretend it can simultaneously guarantee:

```text id="8qv60h"
unrestricted write availability
+
single authoritative identity state
```

across independent regions.

For security-sensitive identity mutation, Baobab chooses authority and consistency over unrestricted multi-region write availability.

---

# 138. Session Availability Trade-Off

Read/validation paths MAY remain more available than mutation paths.

This is intentional.

---

# 139. Example Regional Outage

```text id="v57f1p"
Africa IAM Primary Region
          │
          X
       outage
```

Existing services:

```text id="eexfgi"
valid JWT
+
cached JWKS
+
healthy CP
+
healthy domain
```

may continue selected operations.

But:

```text id="h7grlv"
new login
recovery
credential change
```

may fail until restoration/promotion.

---

# 140. Example DR Promotion

```text id="1z3kyg"
Primary outage
     │
     ▼
incident declared
     │
     ▼
old primary fenced
     │
     ▼
replication position checked
     │
     ▼
security journal checked
     │
     ▼
DR PostgreSQL promoted
     │
     ▼
Kratos/Hydra enabled
     │
     ▼
issuer/JWKS validated
     │
     ▼
routing changed
     │
     ▼
CP reconciliation
     │
     ▼
negative security tests
     │
     ▼
service restored
```

---

# 141. Recovery Validation

Before declaring IAM recovered, test:

```text id="m4d4qf"
known active user → succeeds
known disabled user → denied
known active workload → succeeds
known revoked workload → denied
known valid client → succeeds
known disabled client → denied
```

Positive tests alone are insufficient.

---

# 142. Region Loss and Passkeys

Passkeys themselves are user-held credentials, but server-side identity/credential metadata required to validate them must survive recovery.

DR testing SHALL include passkey authentication.

---

# 143. Recovery Flows

Recovery configuration and state SHALL be included in DR validation.

A region failure SHALL not accidentally enable weaker recovery.

---

# 144. Federation DR

DR testing SHALL include at least one representative enterprise federation.

---

# 145. SCIM DR

DR testing SHOULD verify enterprise lifecycle updates after promotion.

---

# 146. Workload DR

Client-credentials flows SHALL be tested after promotion.

---

# 147. ERP Integration DR

Where ERP relies on IAM authentication, post-promotion testing SHALL verify:

```text id="1smc11"
identity
→ CP context
→ AD_User
→ AD_Role
```

without bypassing iDempiere authority.

---

# 148. Trade Integration DR

Verify:

```text id="s1egql"
identity
→ CP
→ Trade actor
→ buyer/business relationship
```

and cross-tenant isolation.

---

# 149. Thamani DR

Verify both:

```text id="u03m0a"
B2C personal identity
```

and:

```text id="vv4qvs"
B2B organization identity/context
```

after recovery.

---

# 150. ZuriBeans DR

Verify B2B organization isolation and buyer-role preservation.

---

# 151. Security Invariants

The following SHALL always remain true:

```text id="t3wqpj"
Market ≠ Region

Region ≠ Tenant

Region ≠ LegalEntity

Region ≠ Identity

IAM Region ≠ Business Context

Replica ≠ Authority

Backup ≠ DR

Hot Standby ≠ Writable Primary

Availability ≠ Authorization

Valid Token ≠ Current Authority

DR Promotion ≠ Authorization Bypass

Restored State ≠ Automatically Trusted State

Old Primary ≠ Safe Primary After Failover

Async Replication ≠ RPO 0

Multiple Runtime Replicas ≠ Multi-Writer Persistence

Data Residency ≠ User Geolocation

Cloud Region ≠ Market

Issuer ≠ Cloud Hostname

Identity Security Domain ≠ Tenant

CanonicalIdentity ≠ Regional Provider Identity
```

---

# 152. Implementation Gates

## IAM-RG0 — Regulatory and Residency Inventory

Document:

```text id="gx47ar"
current markets
planned markets
identity data classes
proofing evidence
backup locations
logging locations
customer contractual constraints
```

No regional fragmentation based on assumptions.

---

## IAM-RG1 — Identity Security Domain Model

Define provider-neutral:

```text id="tk0g4u"
IdentitySecurityDomain
ResidencyPolicy
RegionStatus
AuthorityRegion
DRProfile
```

---

## IAM-RG2 — Initial Region Selection

Select initial authoritative and DR regions based on:

```text id="9lrdj3"
residency
latency
cloud capabilities
PostgreSQL HA
cost
operational maturity
```

Document the decision separately from Market configuration.

---

## IAM-RG3 — In-Region HA

Deploy and verify:

```text id="o69rmk"
Kratos ≥ 2
Hydra ≥ 2
IAM adapter ≥ 2
PostgreSQL HA
multi-zone placement
PDB/topology controls
```

subject to measured capacity requirements.

---

## IAM-RG4 — PostgreSQL Replication and Backup

Implement:

```text id="c8vzav"
streaming replication
WAL archiving
encrypted backups
PITR where supported
replication monitoring
```

---

## IAM-RG5 — Cross-Region DR

Implement non-authoritative DR topology with:

```text id="xq8l02"
replication
fencing
promotion
routing
failback
```

---

## IAM-RG6 — Revocation-Safe Recovery

Implement and test:

```text id="r5h3ap"
security journal/checkpoint
revocation reconciliation
deny-on-ambiguity
negative recovery tests
```

---

## IAM-RG7 — Stable Issuer and Routing

Implement:

```text id="2clfrw"
stable issuer
regional routing
JWKS strategy
region resolution
```

without exposing ephemeral infrastructure topology.

---

## IAM-RG8 — Residency Enforcement

Apply residency policy to:

```text id="7o4uxf"
databases
replicas
backups
WAL
proofing evidence
logs
federation data
```

---

## IAM-RG9 — Observability

Implement:

```text id="ox6j5x"
replication metrics
backup metrics
region health
IAM SLOs
security-journal health
alerts
```

---

## IAM-RG10 — DR Exercises

Execute controlled:

```text id="0khw0x"
database failover
availability-zone failure
region failure
restore from backup
issuer/JWKS recovery
workload recovery
federation recovery
```

---

## IAM-RG11 — Application Integration Verification

Validate:

```text id="swg6b1"
CP
Trade
ERP
ZuriBeans
Thamani
supplier identity
workloads
```

under degraded and recovered states.

---

## IAM-RG12 — Production Certification

Production readiness requires:

```text id="fmqavl"
measured RPO
measured RTO
successful restore
successful regional failover
successful failback
revocation-safe recovery
security approval
operational runbooks
```

---

# 153. Required Failure Test Matrix

| Failure | Required Behaviour |
|---|---|
| Kratos pod failure | Other replica serves |
| Hydra pod failure | Other replica serves |
| Node failure | Workload rescheduled |
| AZ failure | IAM remains available where topology permits |
| PG primary failure | Controlled DB failover |
| DR replica lag | Alert |
| WAL archive failure | Alert/escalate |
| Primary region partition | DR remains non-authoritative |
| Primary region destroyed | Controlled promotion |
| Old primary returns after promotion | Fenced/non-writable |
| Restored DB predates identity disable | Identity remains denied |
| Restored DB predates workload revocation | Workload remains denied |
| Restored DB predates federation suspension | Federation remains suspended |
| IAM unavailable | Valid short tokens may continue subject to CP/domain |
| Unknown JWKS key | Reject |
| CP denies identity after IAM restore | Deny |
| SCIM during failover | No dual-region writes |
| Recovery during uncertain authority | Fail closed |
| Backup corrupted | Alternate recovery path |
| DR runtime version incompatible | Promotion blocked |
| Region routing error | No cross-residency leakage |

---

# 154. Production Readiness Checklist

### Regional Architecture

- [ ] IdentitySecurityDomain defined
- [ ] authoritative region identified
- [ ] DR region identified
- [ ] Market/Region separation documented
- [ ] Tenant/Region separation documented
- [ ] residency policy documented

### Runtime

- [ ] multiple Kratos replicas
- [ ] multiple Hydra replicas
- [ ] multiple IAM adapter replicas
- [ ] multi-zone topology
- [ ] health/readiness configured
- [ ] immutable pinned artifacts

### PostgreSQL

- [ ] Kratos DB isolated
- [ ] Hydra DB isolated
- [ ] HA primary/standby
- [ ] replication monitored
- [ ] WAL archive
- [ ] encrypted backups
- [ ] PITR where supported
- [ ] restore tested
- [ ] version compatibility verified

### DR

- [ ] cross-region replica
- [ ] old-primary fencing
- [ ] controlled promotion
- [ ] routing procedure
- [ ] failback procedure
- [ ] DR exercised
- [ ] measured RPO
- [ ] measured RTO

### Security

- [ ] security recovery journal
- [ ] revocation-safe restore
- [ ] deny on ambiguity
- [ ] negative recovery tests
- [ ] signing keys recoverable
- [ ] secret replication controlled
- [ ] old primary cannot rejoin writable

### Identity

- [ ] stable issuer strategy
- [ ] issuer+subject semantics preserved
- [ ] CanonicalIdentity remains global
- [ ] no regional email auto-linking
- [ ] migration between domains governed

### Residency

- [ ] live DB residency
- [ ] replica residency
- [ ] backup residency
- [ ] WAL residency
- [ ] proofing evidence residency
- [ ] federation-data residency
- [ ] audit/log residency

### Integrations

- [ ] CP degraded-mode tested
- [ ] Trade tested
- [ ] ERP tested
- [ ] ZuriBeans tested
- [ ] Thamani B2B tested
- [ ] Thamani B2C tested
- [ ] supplier identities tested
- [ ] workload identities tested
- [ ] enterprise federation tested
- [ ] SCIM tested

### Operations

- [ ] region failure runbook
- [ ] database failure runbook
- [ ] restore runbook
- [ ] failover runbook
- [ ] failback runbook
- [ ] signing-key runbook
- [ ] replication alerts
- [ ] backup alerts
- [ ] DR exercises scheduled

---

# 155. Target Production Topology

```text id="d6a8zp"
                          INTERNET
                             │
                             ▼
                    ┌─────────────────┐
                    │ GLOBAL DNS/EDGE │
                    │ APISIX / WAF    │
                    └────────┬────────┘
                             │
                       IAM Routing
                             │
                             ▼
       ┌──────────────────────────────────────────┐
       │       AUTHORITATIVE IAM REGION A         │
       │                                          │
       │   ┌─────────┐       ┌─────────┐          │
       │   │ Kratos  │       │ Kratos  │          │
       │   │    1    │       │    2    │          │
       │   └────┬────┘       └────┬────┘          │
       │        └────────┬─────────┘               │
       │                 ▼                         │
       │          Kratos PostgreSQL HA             │
       │                                           │
       │   ┌─────────┐       ┌─────────┐           │
       │   │ Hydra 1 │       │ Hydra 2 │           │
       │   └────┬────┘       └────┬────┘           │
       │        └────────┬─────────┘                │
       │                 ▼                          │
       │          Hydra PostgreSQL HA               │
       │                                            │
       │      baobab-iam Adapter x N                │
       │                                            │
       └──────────────────┬─────────────────────────┘
                          │
                asynchronous DR replication
                          │
                          ▼
       ┌──────────────────────────────────────────┐
       │            DR IAM REGION B               │
       │                                          │
       │      PostgreSQL standby / backups        │
       │      Ory runtime definitions ready       │
       │      cryptographic recovery material     │
       │      security recovery journal           │
       │                                          │
       │        NON-AUTHORITATIVE                 │
       │        until promotion                   │
       └──────────────────────────────────────────┘

                          │
                          ▼
                 ┌─────────────────┐
                 │   BAOBAB CP     │
                 │                 │
                 │ Canonical ID    │
                 │ Context         │
                 │ Capability      │
                 │ Isolation       │
                 └────────┬────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
           Trade         ERP         Domains
        ZuriBeans     iDempiere      Thamani
```

---

# 156. Future Regional Expansion

When justified:

```text id="fz35ym"
                         GLOBAL BAOBAB
                              │
                    CanonicalIdentity
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
       IAM Domain ZA    IAM Domain EA    IAM Domain X
             │                │                │
          Primary           Primary           Primary
             │                │                │
            DR               DR               DR
```

Each security domain remains independently authoritative.

Cross-domain canonical identity relationships remain explicit.

This is preferred over assuming that one globally multi-writable Kratos/Hydra database is necessary.

---

# 157. Consequences

## Positive

This architecture provides:

- strong in-region availability;
- controlled disaster recovery;
- explicit residency architecture;
- a path toward sovereign deployments;
- stable canonical identity semantics;
- safer PostgreSQL replication;
- reduced split-brain risk;
- revocation-safe recovery;
- stable issuer design;
- controlled cross-region growth;
- regional failure containment;
- compatibility with Baobab's multi-market architecture.

## Costs

Baobab must operate:

- HA PostgreSQL;
- replication;
- WAL/archive management;
- cross-region DR;
- cryptographic recovery;
- security recovery journals;
- residency policies;
- regional routing;
- DR exercises;
- failover/failback procedures.

This operational complexity is justified because IAM is Tier-0 infrastructure.

## Explicitly Deferred

This ADR does **not** authorize:

```text id="7v9bg2"
global multi-writer Kratos
global multi-writer Hydra
active-active PostgreSQL writes
automatic cross-region identity conflict resolution
edge credential authority
per-market IAM deployments by default
```

Any such architecture requires a later ADR and proof that Ory, PostgreSQL and Baobab's security semantics support it safely.

---

# 158. Final Decision Principle

Baobab's multi-region identity architecture SHALL optimize for:

```text id="o6gl3y"
Availability
     +
Durability
     +
Residency
     +
Recoverability
```

without sacrificing:

```text id="w3o8qn"
Identity Authority
     +
Revocation
     +
Isolation
     +
Authorization Integrity
```

Therefore:

> **Identity may be globally consumed, regionally operated and geographically replicated, but mutable identity security state must always have a clearly identifiable authority.**

And during disaster recovery:

> **A stale identity system is not trusted merely because it is available.**

The decisive recovery rule is:

```text id="3q3qnv"
When availability
and security state
appear to conflict:

newer restrictive authority
        wins.
```

Baobab SHALL prefer a temporarily unavailable identity mutation over resurrecting revoked authority.

**Availability must never become a mechanism for restoring permissions that security has already removed.**