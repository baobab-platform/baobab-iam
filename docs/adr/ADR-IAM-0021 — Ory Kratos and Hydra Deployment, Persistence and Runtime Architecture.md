# ADR-IAM-0021 — Ory Kratos and Hydra Deployment, Persistence and Runtime Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/infrastructure`, `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold, and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0020  
**Supersedes:** Provider-specific Keycloak runtime/deployment provisions of ADR-IAM-0002 and corresponding Keycloak-specific portions of ADR-IAM-0018  
**Extends:** ADR-IAM-0015, ADR-IAM-0017, ADR-IAM-0018, ADR-IAM-0019, ADR-IAM-0020  
**Decision Type:** IAM Runtime / Deployment / Persistence / Security / Availability / Operations  
**Selected Identity Stack:** Ory Kratos + Ory Hydra  
**Deployment Model:** Self-hosted, Baobab-managed

---

# 1. Decision

Baobab SHALL deploy **Ory Kratos and Ory Hydra as separate, independently deployable IAM runtime components**, operated by Baobab and integrated through the provider-neutral architecture established by ADR-IAM-0020.

The production identity runtime SHALL comprise at minimum:

```text
Ory Kratos
    │
    ├── human identities
    ├── credentials
    ├── authentication sessions
    ├── registration
    ├── verification
    ├── recovery
    ├── MFA
    └── passkeys/WebAuthn

Ory Hydra
    │
    ├── OAuth 2.x
    ├── OpenID Connect
    ├── OAuth clients
    ├── authorization flows
    ├── token issuance
    ├── client credentials
    └── machine/workload OAuth

Baobab IAM Adapter
    │
    ├── provider lifecycle
    ├── provisioning
    ├── reconciliation
    ├── normalized events
    ├── migration
    └── provider configuration integration
```

Kratos and Hydra SHALL NOT be treated as one monolithic application merely because together they replace significant parts of the former Keycloak runtime.

They SHALL have:

- independent runtime processes;
- independent configuration;
- independently controlled administrative interfaces;
- independently scalable workloads;
- independently observable health;
- explicit persistence boundaries;
- explicit network policies;
- explicit migration procedures;
- explicit upgrade procedures.

They MAY share a PostgreSQL cluster operationally, but SHALL use **separate logical databases, database users, credentials and migration ownership**.

Neither SHALL share the Baobab Control Plane database or any domain-engine database.

---

# 2. Why This ADR Exists

ADR-IAM-0019 decides **why Baobab migrates from Keycloak to Ory**.

ADR-IAM-0020 decides **how Baobab remains provider-neutral**.

This ADR decides:

> **How the selected Ory implementation actually runs in production.**

These concerns must remain separate.

Otherwise operational choices such as:

```text
Kratos database topology
Hydra signing secrets
administrative endpoint exposure
Kubernetes replica counts
schema migration strategy
```

could accidentally become permanent platform-domain architecture.

This ADR therefore defines Ory's runtime architecture while preserving ADR-IAM-0020's principle:

> **Ory is Baobab's selected identity infrastructure, not Baobab's canonical identity model.**

---

# 3. Existing Architecture Is Preserved

The Ory deployment SHALL NOT replace:

- `CanonicalIdentity`;
- `ExternalIdentity`;
- Tenant;
- LegalEntity;
- Market;
- DigitalEstate;
- Capability;
- CapabilityBinding;
- Context;
- IsolationProfile;
- EngineInstance;
- workload meaning and lifecycle;
- Trade buyer/supplier authorization;
- ERP `AD_User` / `AD_Role` authorization;
- CMS domain authorization;
- canonical IAM events.

Those remain Baobab concepts.

The migration changes the provider implementation:

```text
BEFORE

Keycloak
   │
   ▼
Baobab identity boundary
   │
   ▼
Control Plane


AFTER

Kratos + Hydra
      │
      ▼
Baobab identity boundary
      │
      ▼
Control Plane
```

The lower half of the architecture remains substantially unchanged.

---

# 4. Ory Runtime Roles

Baobab SHALL explicitly distinguish the responsibilities of Kratos and Hydra.

| Concern | Kratos | Hydra | Baobab |
|---|---:|---:|---:|
| Human identity | ✓ | — | canonical mapping |
| Password credentials | ✓ | — | — |
| Passkeys | ✓ | — | assurance policy |
| MFA | ✓ | — | assurance policy |
| Recovery | ✓ | — | business recovery constraints |
| Verification | ✓ | — | lifecycle integration |
| Login session | ✓ | — | contextual validation |
| OAuth authorization | — | ✓ | client/scope governance |
| OIDC | — | ✓ | client/context integration |
| Access tokens | — | ✓ | resource validation |
| Client credentials | — | ✓ | workload registry |
| CanonicalIdentity | — | — | CP |
| Tenant | — | — | CP |
| LegalEntity | — | — | CP |
| Market | — | — | CP |
| Buyer authority | — | — | Trade |
| Supplier authority | — | — | supplier domain |
| ERP permissions | — | — | iDempiere |

---

# 5. Target Production Architecture

```text
                          INTERNET
                             │
                             ▼
                  ┌───────────────────────┐
                  │ CDN / WAF / Gateway   │
                  │ APISIX / ingress      │
                  └───────────┬───────────┘
                              │
                ┌─────────────┴──────────────┐
                │                            │
                ▼                            ▼
       ┌─────────────────┐          ┌─────────────────┐
       │ Digital Estates │          │ Public IAM      │
       │                 │          │ endpoints       │
       │ ZuriBeans       │          └───────┬─────────┘
       │ Thamani         │                  │
       │ Nabhold         │          ┌───────┴─────────┐
       └────────┬────────┘          │                 │
                │                   ▼                 ▼
                │              ┌────────┐        ┌────────┐
                │              │ Kratos │        │ Hydra  │
                │              │ Public │        │ Public │
                │              └───┬────┘        └───┬────┘
                │                  │                 │
                │           ┌──────┴─────────────────┴──────┐
                │           │        PRIVATE NETWORK         │
                │           │                                │
                │           │ Kratos Admin     Hydra Admin   │
                │           │      ▲               ▲         │
                │           │      └───────┬───────┘         │
                │           │              │                 │
                │           │        baobab-iam              │
                │           │       Identity Adapter         │
                │           └──────────────┬─────────────────┘
                │                          │
                ▼                          ▼
             baobab-cp ◄───────────────────┘
                │
       ┌────────┼────────┬────────┐
       ▼        ▼        ▼        ▼
     Trade     ERP      CMS      Pulse
```

---

# 6. Public and Administrative Planes

Kratos and Hydra expose different classes of endpoints.

Baobab SHALL maintain a strict distinction between:

```text
PUBLIC PLANE
```

and:

```text
ADMINISTRATIVE PLANE
```

Administrative APIs SHALL NOT be Internet-accessible.

---

# 7. Kratos Public Endpoint

Kratos public functionality required by Digital Estates MAY be reachable through controlled ingress.

Examples include:

- browser authentication flows;
- registration;
- verification;
- recovery;
- authenticated settings flows;
- session-related public operations required by the selected integration.

Exposure SHALL be:

```text
Internet
   │
   ▼
WAF / Gateway
   │
   ▼
Kratos Public
```

never:

```text
Internet
   │
   ▼
Kratos Admin
```

---

# 8. Kratos Administrative Endpoint

The Kratos administrative API SHALL be restricted to trusted internal workloads.

Primary consumers include:

```text
baobab-iam
migration tooling
controlled operational tooling
```

The expected topology is:

```text
baobab-iam
     │
     │ authenticated private communication
     ▼
Kratos Admin
```

Network policy SHALL deny arbitrary workload access.

---

# 9. Hydra Public Endpoint

Hydra's public OAuth/OIDC endpoint SHALL support standards-based interactions required by Baobab applications.

Examples include:

```text
authorization
token exchange
JWKS
discovery
introspection where architecture requires it
logout/revocation where applicable
```

Exact public routes SHALL follow the pinned Hydra version and deployment configuration.

---

# 10. Hydra Administrative Endpoint

Hydra administrative APIs SHALL remain private.

They MAY be used for:

- OAuth client provisioning;
- client rotation;
- client lifecycle;
- consent/login integration where required;
- workload OAuth configuration;
- migration operations;
- controlled operational support.

They SHALL not be exposed directly to Digital Estates.

---

# 11. Login and Consent Architecture

Hydra SHALL NOT itself become Baobab's human identity database.

Where OAuth/OIDC authorization requires determining whether a person is authenticated:

```text
Hydra
   │
   ▼
Baobab login/consent integration
   │
   ▼
Kratos session
   │
   ▼
authenticated external subject
```

The implementation SHALL preserve the distinction:

```text
Kratos answers:
"Who authenticated?"

Hydra answers:
"What OAuth/OIDC authorization/token is being issued?"

CP answers:
"What Baobab identity/context does this represent?"

Domain engine answers:
"May this actor perform this business operation?"
```

---

# 12. Authentication Flow

Conceptually:

```text
Browser
   │
   ▼
Digital Estate
   │
   ▼
Hydra authorization request
   │
   ▼
Login integration
   │
   ▼
Kratos authentication/session
   │
   ▼
authenticated subject
   │
   ▼
Hydra authorization continues
   │
   ▼
authorization code
   │
   ▼
token exchange
   │
   ▼
access / ID tokens
```

Implementation details SHALL be finalized under the Digital Estate Authentication Boundary ADR, but this runtime architecture SHALL support that flow.

---

# 13. Persistence Decision

Kratos and Hydra SHALL use PostgreSQL for durable production persistence.

PostgreSQL 17 is the Baobab target database generation for this deployment unless compatibility testing of the pinned Ory release requires a different supported version.

Production deployment SHALL verify the actual supported database versions of the pinned Kratos/Hydra release before promotion.

---

# 14. Database Isolation

Preferred topology:

```text
PostgreSQL HA Cluster
│
├── kratos
│   └── kratos_runtime_user
│
└── hydra
    └── hydra_runtime_user
```

Not:

```text
one_database
├── kratos tables
├── hydra tables
├── CP tables
├── Trade tables
└── ERP tables
```

Logical isolation is mandatory even where physical infrastructure is shared.

---

# 15. No Cross-Database Joins

Kratos SHALL NOT join directly against Hydra tables.

Hydra SHALL NOT join directly against Kratos tables.

Neither SHALL join directly against:

```text
baobab-cp
baobab-trade
baobab-erp
baobab-cms
```

Integration occurs through:

- supported APIs;
- protocols;
- canonical contracts;
- events;
- explicit mappings.

---

# 16. Database Users

Each runtime SHALL use its own least-privileged PostgreSQL role.

Conceptually:

```text
kratos_runtime
kratos_migrator

hydra_runtime
hydra_migrator
```

Migration roles SHOULD be separated from normal runtime privileges where operationally practical.

---

# 17. Database Credentials

Database credentials SHALL:

- originate from the production secrets system;
- never be committed;
- never appear in container images;
- never appear in repository `.env` examples as actual credentials;
- be independently rotatable;
- differ across environments.

---

# 18. Database Encryption

Production identity persistence SHALL use encryption:

```text
in transit → TLS
at rest    → infrastructure/storage encryption
backup     → encrypted
```

Sensitive credential material SHALL receive protections appropriate to its security impact.

---

# 19. Database High Availability

Production PostgreSQL supporting IAM SHALL NOT be a single unmanaged database process.

The production architecture SHALL support:

```text
primary
   │
   ├── synchronous or suitably durable HA replica
   │
   └── additional replica/backup strategy as required
```

The exact cloud-native or Kubernetes PostgreSQL topology belongs to infrastructure implementation, but SHALL satisfy ADR-IAM-0018 availability and recovery objectives.

---

# 20. Database Is Not Identity API

No Baobab component SHALL read Kratos/Hydra databases directly to obtain identity information.

Prohibited:

```text
baobab-cp
   │
   └──── SQL ───► Kratos DB
```

Required:

```text
CP
 │
 ├── verified OIDC evidence
 ├── Baobab mappings
 └── supported integration paths
```

---

# 21. Schema Migration Ownership

Kratos SHALL own Kratos database schema migrations.

Hydra SHALL own Hydra database schema migrations.

Baobab SHALL NOT manually recreate Ory database schemas.

---

# 22. Migration Execution

Production schema migration SHALL be an explicit deployment stage.

Conceptually:

```text
new image selected
       │
       ▼
compatibility checks
       │
       ▼
database backup/checkpoint
       │
       ▼
migration job
       │
       ▼
migration verification
       │
       ▼
runtime rollout
       │
       ▼
health/security checks
```

Runtime startup SHALL NOT rely casually on uncontrolled auto-migration.

---

# 23. Migration Concurrency

Only one migration execution SHALL modify a given Ory database at a time.

Kubernetes scaling SHALL not cause every application replica to race database migrations.

---

# 24. Migration Failure

If a database migration fails:

```text
migration failure
      │
      ▼
stop rollout
      │
      ├── preserve evidence/logs
      ├── evaluate database state
      ├── execute supported recovery
      └── do not start incompatible runtime
```

Production deployment SHALL fail closed.

---

# 25. Rollback Caveat

Container rollback does not automatically imply database rollback.

Before upgrading:

```text
Old runtime
    │
    ▼
New DB schema
```

Baobab SHALL determine whether:

```text
Old runtime
```

remains compatible with:

```text
New DB schema
```

If not, restoration/recovery procedures SHALL account for the database transition.

---

# 26. Container Images

Production SHALL use exact or digest-pinned Ory images.

Avoid:

```text
oryd/kratos:latest
oryd/hydra:latest
```

Prefer a controlled immutable version/digest.

Container provenance SHALL be recorded.

---

# 27. No Unnecessary Ory Fork

Baobab SHALL run supported upstream Ory software wherever possible.

Preference order:

```text
native capability
      ↓
configuration
      ↓
Baobab integration
      ↓
supported extension
      ↓
fork only via separate ADR
```

---

# 28. Runtime User

Containers SHALL run without unnecessary root privileges.

Security context SHOULD enforce:

```text
runAsNonRoot
readOnlyRootFilesystem where supported
drop unnecessary Linux capabilities
no privilege escalation
```

unless an explicitly documented requirement prevents it.

---

# 29. Immutable Runtime

Runtime containers SHALL be treated as disposable.

Persistent identity state belongs in approved persistence/secrets systems, not container filesystems.

---

# 30. Kubernetes Deployment Model

Production SHOULD deploy Kratos and Hydra as independent Kubernetes Deployments or equivalent independently managed workloads.

Conceptually:

```text
iam namespace
│
├── kratos
│   ├── Deployment
│   ├── Service-public
│   ├── Service-admin
│   ├── PDB
│   └── migration Job
│
├── hydra
│   ├── Deployment
│   ├── Service-public
│   ├── Service-admin
│   ├── PDB
│   └── migration Job
│
└── baobab-iam-adapter
    ├── Deployment
    ├── Service
    └── PDB
```

Exact manifests MAY be Helm, Kustomize or infrastructure-controlled equivalents.

---

# 31. Namespace Isolation

IAM SHOULD run in a dedicated security boundary such as:

```text
namespace: baobab-iam
```

or an equivalent workload isolation mechanism.

IAM SHALL not simply share unrestricted networking with all application workloads.

---

# 32. Network Policies

Default network policy SHOULD approximate:

```text
DENY
│
├── Internet → Kratos Admin
├── Internet → Hydra Admin
├── Trade → Kratos Admin
├── ERP → Kratos Admin
├── CMS → Hydra Admin
└── arbitrary workload → IAM DB

ALLOW
│
├── Gateway → Kratos Public
├── Gateway → Hydra Public
├── baobab-iam → Kratos Admin
├── baobab-iam → Hydra Admin
├── Kratos → Kratos DB
└── Hydra → Hydra DB
```

Additional login/consent interactions SHALL be explicitly allowed.

---

# 33. East-West Security

Private network placement SHALL not be treated as authentication.

Administrative operations SHOULD use appropriate workload identity and/or mTLS according to the broader infrastructure security architecture.

---

# 34. Gateway Responsibility

APISIX or the selected ingress/gateway MAY provide:

- TLS termination;
- routing;
- rate limiting;
- request size limits;
- WAF integration;
- infrastructure observability.

It SHALL NOT redefine Ory security semantics or CP authorization.

---

# 35. Public Endpoint Rate Limiting

Identity endpoints are security-sensitive.

Rate limiting SHALL protect at least:

```text
login
registration
verification
recovery
password operations
MFA challenge
token endpoint
```

without introducing denial-of-service behavior against legitimate high-volume workflows.

Controls SHOULD be risk-aware where possible.

---

# 36. Enumeration Resistance

Infrastructure and UI behavior SHALL preserve identity enumeration protections.

Responses SHOULD NOT reveal unnecessarily whether a particular email, telephone number or identity exists.

---

# 37. Kratos Identity Schemas

Kratos identity schemas SHALL be configuration-as-code.

Schemas SHALL contain only identity-profile information appropriate to the identity provider.

Suitable examples:

```text
name
email
telephone where required
profile attributes
```

Unsuitable examples:

```text
tenant
legal_entity
buyer_purchase_limit
supplier_approval
market_authority
ERP_role
```

Those remain Baobab/domain state.

---

# 38. Multiple Identity Schemas

Baobab MAY use multiple Kratos identity schemas when materially different identity populations require different profile characteristics.

Schema proliferation SHALL be avoided.

Schema selection SHALL NOT become a substitute for CP context.

---

# 39. Schema Evolution

Identity-schema changes SHALL be version-controlled and tested against existing identities.

A schema change SHALL NOT make production identities unusable without an explicit migration strategy.

---

# 40. Secrets Architecture

IAM secrets include potentially:

```text
database credentials
Hydra system secrets
cookie/session secrets
OAuth client secrets
webhook secrets
provider-management credentials
TLS private keys
migration credentials
```

They SHALL be managed through the approved secret-management infrastructure.

---

# 41. No Secrets in Git

The following are prohibited:

```text
production client secrets
database passwords
cookie secrets
Hydra secrets
private signing material
recovery secrets
```

in Git history.

Secret scanning SHALL cover IAM repositories.

---

# 42. Secret Rotation

Production IAM SHALL support secret rotation.

Where rotation can invalidate sessions/tokens or interrupt service, rotation SHALL use a documented staged procedure.

---

# 43. Signing and Cryptographic Material

Hydra signing/encryption material is Tier-0 security material.

It SHALL receive:

- restricted access;
- encrypted storage;
- controlled rotation;
- backup where required for continuity;
- audit;
- environment isolation.

---

# 44. Key Rotation

Rotation SHALL account for tokens already issued.

Conceptually:

```text
Key A active
     │
     ▼
introduce Key B
     │
     ├── B signs new material
     └── A remains available for required validation window
     │
     ▼
expire A-issued artifacts
     │
     ▼
retire Key A
```

Exact behavior SHALL follow supported Hydra mechanisms.

---

# 45. Cookie Security

Where Kratos or Baobab identity UI uses cookies, production configuration SHALL require appropriate:

```text
Secure
HttpOnly
SameSite
domain/path scoping
```

according to the selected browser architecture.

Cross-estate cookie sharing SHALL NOT be enabled merely for convenience.

---

# 46. Session Boundary

A Kratos session means:

```text
provider-authenticated human session
```

It does not mean:

```text
authorized for every Baobab operation
```

Every sensitive operation still traverses applicable context/domain authorization.

---

# 47. Session Revocation

Session revocation SHALL be possible through provider-supported mechanisms and integrated into Baobab lifecycle handling.

Example:

```text
security compromise
      │
      ▼
CP disable/deny
      │
      ├── immediate platform denial
      │
      ▼
baobab-iam
      │
      ▼
Kratos session revocation
```

---

# 48. Token Lifetimes

Hydra token lifetimes SHALL comply with ADR-IAM-0006 and subsequent assurance/security decisions.

Long-lived bearer access tokens SHOULD be avoided.

Provider defaults SHALL not override Baobab policy.

---

# 49. Refresh Tokens

Where refresh tokens are enabled:

- use SHALL be justified by client type;
- rotation/reuse controls SHOULD be enabled where supported;
- storage SHALL be secure;
- browser exposure SHALL be minimized;
- revocation behavior SHALL be tested.

---

# 50. Browser Token Exposure

The preferred estate architecture SHOULD minimize OAuth token exposure to browser JavaScript.

A BFF/session-based pattern remains preferred where it fits the estate architecture.

The precise decision belongs to ADR-IAM-0023.

---

# 51. Client Types

Hydra clients SHALL distinguish at least:

```text
public browser/mobile client
confidential server/BFF client
machine/workload client
```

Security configuration SHALL correspond to the actual client type.

---

# 52. Redirect URI Isolation

ZuriBeans, Thamani, Nabhold and administrative applications SHALL have explicit callback registrations.

Example:

```text
zuribeans-web
    ≠
thamani-web
```

Cross-estate wildcard callbacks are prohibited by default.

---

# 53. Workload Clients

Hydra workload clients SHALL correspond to Baobab workload identities.

Example:

```text
baobab-trade-worker
baobab-cp-service
baobab-erp-integration
baobab-cms-integration
```

Avoid a shared:

```text
baobab-services
```

credential.

---

# 54. Workload Authentication

The normal M2M pattern is:

```text
Trade Worker
      │
      │ OAuth client credentials
      ▼
Hydra
      │
      ▼
short-lived access token
      │
      ▼
CP/API
      │
      ▼
WorkloadIdentity resolution
      │
      ▼
Capability authorization
```

mTLS MAY additionally authenticate the network/workload channel.

---

# 55. CI Identity Is Not Runtime Identity

GitHub Actions, deployment automation and production workloads SHALL use distinct credentials/identities.

```text
CI identity
   ≠
runtime identity
```

A leaked CI credential SHALL not automatically function as a production service identity.

---

# 56. Health Model

Each runtime SHALL expose appropriate health/readiness information.

Kubernetes SHALL distinguish:

```text
liveness
readiness
startup
```

where supported and meaningful.

---

# 57. Liveness

Liveness SHALL answer approximately:

> Is the process functioning sufficiently that restarting it may help?

It SHALL NOT perform expensive dependency checks on every probe.

---

# 58. Readiness

Readiness SHALL answer approximately:

> Can this replica safely serve its intended requests?

A replica that cannot perform essential operations SHOULD leave the ready set.

---

# 59. Database Failure

If the Kratos database is unavailable:

```text
Kratos
   │
   ▼
not ready / degraded
```

Traffic SHALL not continue to a replica incapable of satisfying requests merely because the process exists.

Equivalent behavior applies to Hydra.

---

# 60. Replica Count

Production Kratos and Hydra SHALL have more than one replica where the runtime supports stateless horizontal scaling around shared durable persistence.

The exact number is determined by capacity planning.

Baseline architecture:

```text
Kratos >= 2 replicas
Hydra  >= 2 replicas
```

for production high availability, subject to actual deployment validation.

---

# 61. Pod Disruption Budgets

Production SHOULD define disruption budgets preventing routine cluster maintenance from simultaneously removing all replicas.

---

# 62. Topology Spread

Replicas SHOULD be distributed across available failure domains where infrastructure permits.

For example:

```text
availability zone A
availability zone B
```

rather than all replicas on one node.

---

# 63. Autoscaling

IAM MAY use horizontal autoscaling where metrics and runtime behavior justify it.

Autoscaling SHALL NOT replace sensible minimum high-availability capacity.

---

# 64. Capacity Planning

Capacity testing SHALL include:

- login bursts;
- registration bursts;
- token issuance;
- client credentials;
- recovery operations;
- session validation;
- database connection pressure;
- Digital Estate launch events;
- automated workload authentication.

---

# 65. Connection Pooling

Kratos and Hydra database connection limits SHALL be coordinated with PostgreSQL capacity.

Scaling replicas without controlling connection counts is prohibited.

---

# 66. Availability Boundary

IAM is Tier-0 infrastructure.

However, not every API request should synchronously depend on Kratos/Hydra.

For resource-server token validation:

```text
access token
    │
    ▼
local cryptographic validation
    │
    ▼
CP/context/domain checks
```

SHOULD be preferred where the token format and security model permit.

---

# 67. IAM Outage Behavior

During a provider outage:

```text
new login              → may fail
new token issuance     → may fail
password recovery      → may fail
registration           → may fail
```

while:

```text
already-issued valid short-lived token
        │
        ▼
local validation
        │
        ▼
CP/domain authorization
```

MAY continue according to ADR-IAM-0018.

No outage SHALL bypass CP/domain security decisions.

---

# 68. JWKS Availability

Resource servers SHALL maintain safe JWKS caching behavior.

They SHALL support key rotation without making every token validation dependent on a live network request.

Unknown signing keys SHALL fail safely.

---

# 69. Introspection

Token introspection MAY be used where required by token format/security design.

It SHALL not be introduced unnecessarily where locally verifiable tokens satisfy the architecture.

The trade-off is:

```text
local JWT validation
   → lower runtime dependency

introspection
   → more immediate provider state
     but higher synchronous dependency
```

The chosen token profile SHALL follow ADR-IAM-0006.

---

# 70. Observability

Kratos, Hydra and the Baobab IAM adapter SHALL integrate with the Baobab observability platform.

Required signals:

```text
metrics
logs
traces where supported
security events
health
alerts
```

---

# 71. Operational Metrics

Monitor at least:

```text
authentication success/failure
registration success/failure
recovery activity
verification activity
token issuance
token errors
client authentication failures
HTTP latency
HTTP error rates
database latency
database connections
replica readiness
administrative API failures
provider adapter failures
```

---

# 72. Security Metrics

Security monitoring SHOULD identify:

```text
credential attacks
recovery abuse
MFA failures
unusual token failures
invalid client attempts
high-volume enumeration attempts
session revocations
privileged administrative actions
```

without treating metrics alone as canonical audit records.

---

# 73. Logs

Logs SHALL:

- be structured where practical;
- include correlation IDs;
- identify component/environment;
- support incident investigation;
- avoid secrets and tokens.

---

# 74. Sensitive Logging

The following SHALL NOT be logged:

```text
passwords
access tokens
refresh tokens
authorization codes
client secrets
private keys
recovery secrets
TOTP secrets
WebAuthn private material
```

---

# 75. Trace Propagation

Baobab correlation/tracing identifiers SHOULD propagate through:

```text
Digital Estate
      │
      ▼
login/consent integration
      │
      ▼
baobab-iam
      │
      ▼
CP/domain
```

where safe and supported.

---

# 76. Canonical Security Events

Provider-native logs/events SHALL be normalized according to ADR-IAM-0017 and ADR-IAM-0020.

Example:

```text
Kratos native event
      │
      ▼
baobab-iam
      │
      ▼
identity.authentication.failed.v1
```

Downstream consumers SHALL not depend directly on an Ory-specific event payload where a canonical event exists.

---

# 77. Backup Scope

IAM backups SHALL cover the state required to recover:

```text
Kratos database
Hydra database
required cryptographic material
configuration-as-code
identity schemas
OAuth client definitions or reproducible source
critical secret metadata/process
migration state
security recovery journal/checkpoints
```

Secrets SHALL be backed up only through approved secure mechanisms.

---

# 78. Configuration Is Not Backup

Git provides reproducible configuration.

Git is not a backup for:

```text
identity records
credentials
sessions where required
OAuth runtime state
cryptographic secrets
```

---

# 79. Backup Encryption

IAM backups SHALL be encrypted.

Backup access SHALL be more restrictive than ordinary application access.

---

# 80. Backup Validation

A backup that has never been restored is not sufficient evidence of recoverability.

IAM SHALL undergo scheduled restoration exercises.

---

# 81. Recovery Objective

ADR-IAM-0018's security principle remains:

> Recovery SHALL preserve security correctness before maximizing superficial availability.

Restoring a database that resurrects revoked identities or privileges is unacceptable.

---

# 82. Recovery Ordering

Conceptually:

```text
Infrastructure
      │
      ▼
PostgreSQL
      │
      ▼
Kratos / Hydra persistence
      │
      ▼
cryptographic trust
      │
      ▼
Kratos / Hydra runtime
      │
      ▼
Baobab IAM adapter
      │
      ▼
CP reconciliation
      │
      ▼
domain reconciliation
      │
      ▼
resume full service
```

---

# 83. Revocation-Safe Recovery

After restore, Baobab SHALL reconcile security-sensitive state newer than the restored snapshot.

Example:

```text
Backup time:      10:00
Identity revoked: 10:20
Disaster:         10:30
Restore backup:   state from 10:00
```

The restored provider MUST NOT leave the identity effectively active simply because the backup predates revocation.

The security-recovery mechanisms established by ADR-IAM-0018 remain applicable.

---

# 84. Recovery Journal

Security-critical post-backup changes SHOULD be recoverable from an independent durable mechanism sufficient to reconcile:

```text
identity disabled
workload revoked
critical membership removed
privilege revoked
provider client disabled
```

The exact implementation belongs to the DR implementation plan.

---

# 85. RPO and RTO

Concrete production RPO/RTO values SHALL be finalized from infrastructure capability and business requirements.

Identity infrastructure SHOULD target stricter recovery objectives than ordinary non-critical content services.

No implementation SHALL claim an RPO/RTO that has not been demonstrated through testing.

---

# 86. Multi-Region

Initial production SHOULD prioritize a well-engineered HA regional deployment over premature globally writable IAM.

Future multi-region design SHALL be addressed by ADR-IAM-0027.

The initial architecture MUST nevertheless avoid assumptions that make future regional expansion impossible.

---

# 87. Region Is Not Market

The following remains invariant:

```text
IAM deployment region
       ≠
Baobab Market
```

For example:

```text
ZA market
```

does not necessarily imply:

```text
ZA IAM cluster
```

unless data residency and deployment policy explicitly establish that relationship.

---

# 88. Data Residency

Identity data residency SHALL follow:

- applicable law;
- contractual requirements;
- Baobab data classification;
- platform residency policy.

Neither Ory nor infrastructure topology SHALL redefine Baobab's Market model.

---

# 89. Development Environment

Development SHALL provide a reproducible local IAM stack.

Conceptually:

```text
DevContainer / Compose
│
├── Kratos
├── Hydra
├── PostgreSQL
├── baobab-iam
└── required login integration
```

Local development configuration SHALL not weaken production security defaults without clearly documented development-only overrides.

---

# 90. GitHub Codespaces

Where Codespaces is used, IAM development configuration SHALL account for:

- forwarded URLs;
- callback URIs;
- secure secret handling;
- ephemeral environments;
- generated hostnames;
- OAuth redirect restrictions.

Production wildcard redirect policies SHALL not be introduced merely to simplify Codespaces.

---

# 91. DevContainer

The `baobab-iam` development container SHOULD make it possible to:

```text
start stack
run migrations
seed test clients
run integration tests
run security tests
destroy/recreate stack
```

with deterministic commands.

---

# 92. CI

CI SHALL validate at minimum:

```text
configuration syntax
identity schemas
provider contract tests
database migration tests
OAuth/OIDC integration tests
security configuration
container vulnerability posture
secret scanning
SBOM
dependency integrity
```

---

# 93. Integration Test Stack

CI SHOULD be capable of launching ephemeral:

```text
Kratos
Hydra
PostgreSQL
baobab-iam
```

for integration tests.

Mocks alone are insufficient for provider contract verification.

---

# 94. Upgrade Testing

Every Ory upgrade SHALL test:

```text
database migration
login
registration
verification
recovery
MFA
passkey flows where applicable
OIDC discovery
authorization code + PKCE
token issuance
client credentials
JWKS
logout/revocation
administrative lifecycle
reconciliation
```

---

# 95. Version Compatibility Matrix

`baobab-iam` SHOULD maintain a compatibility record:

| Component | Version | PostgreSQL | Contract Tests | Status |
|---|---|---|---|---|
| Kratos | pinned | verified | pass | supported |
| Hydra | pinned | verified | pass | supported |
| IAM Adapter | release | n/a | pass | supported |

The actual versions SHALL come from implementation/repository state rather than being invented by this ADR.

---

# 96. Provider Lock File

A provider lock/configuration artifact SHOULD record the approved production provider implementation.

Conceptually:

```yaml
provider: ory

components:
  kratos:
    version: "<pinned>"
  hydra:
    version: "<pinned>"

contract:
  identity: v1
```

Exact format is implementation-specific.

---

# 97. Environment Promotion

IAM changes SHALL progress through controlled environments.

```text
development
     │
     ▼
integration
     │
     ▼
staging
     │
     ▼
production
```

Promotion SHALL use the same immutable artifact where practicable.

---

# 98. Configuration Drift

Production runtime configuration SHALL be continuously or periodically compared against declared configuration.

Unapproved changes to:

```text
OAuth clients
redirect URIs
token lifetimes
identity schemas
security policy
administrative exposure
```

SHALL be detectable.

---

# 99. Break-Glass Administration

Ory operational administration SHALL support controlled emergency access consistent with ADR-IAM-0009.

Break-glass access SHALL be:

- rare;
- strongly authenticated;
- time-bound where practical;
- audited;
- reviewed after use.

---

# 100. Administrative UI

Any provider administration interface SHALL be treated as privileged infrastructure.

It SHALL NOT be exposed as a normal Digital Estate feature.

Baobab SHOULD prefer controlled configuration-as-code/API workflows for repeatable administration.

---

# 101. Client Provisioning

OAuth client provisioning SHOULD be declarative or reconciled from Baobab-owned configuration.

Example:

```text
Desired client registry
        │
        ▼
baobab-iam
        │
        ▼
Hydra Admin API
        │
        ▼
actual client
```

Manual production client creation SHOULD be exceptional.

---

# 102. Client Drift

Reconciliation SHOULD detect:

```text
unexpected redirect URI
unexpected grant type
unexpected scope
unexpected secret change
unexpected client
missing client
disabled expected client
```

---

# 103. Kratos Identity Drift

Reconciliation SHOULD detect security-significant differences such as:

```text
CP disabled / Kratos active
expected identity missing
unexpected identity mapping
verification inconsistency where relevant
```

It SHALL not treat profile differences as equal to security drift.

---

# 104. Runtime Dependency Graph

```text
                 PostgreSQL
                 /        \
                ▼          ▼
             Kratos      Hydra
                │          │
                └────┬─────┘
                     ▼
             Login/Consent Layer
                     │
                     ▼
                 Estates

baobab-iam ─────► Kratos Admin
     │           Hydra Admin
     │
     ▼
baobab-cp
```

Circular runtime dependencies SHALL be avoided.

---

# 105. Bootstrap Problem

IAM bootstrap SHALL not require already-functioning IAM credentials in an impossible circular dependency.

A controlled bootstrap mechanism SHALL exist for:

```text
initial provider configuration
initial OAuth clients
initial platform administrator
initial workload credentials
```

Bootstrap credentials SHALL be rotated/disabled after bootstrap where possible.

---

# 106. Bootstrap Audit

Bootstrap actions SHALL be logged and reviewed.

Initial superuser/bootstrap credentials SHALL not become permanent shared administrative credentials.

---

# 107. Disaster Bootstrap

DR procedures SHALL include recovery of the ability to administer Ory if normal administrative identities depend on unavailable components.

This SHALL be tested rather than assumed.

---

# 108. Degraded Modes

Explicit degraded modes SHALL be documented.

Example:

| Failure | Expected effect |
|---|---|
| Kratos unavailable | new human authentication impaired |
| Hydra unavailable | OAuth/token issuance impaired |
| Kratos DB unavailable | Kratos unavailable/degraded |
| Hydra DB unavailable | Hydra unavailable/degraded |
| `baobab-iam` unavailable | management/reconciliation impaired; ordinary local token validation should not necessarily fail |
| CP unavailable | Baobab contextual authorization fails closed where required |
| event transport unavailable | events queue/retry; security-critical direct denial remains authoritative |

---

# 109. No Authentication Bypass

No failure mode SHALL result in:

```text
IAM unavailable
      ↓
skip authentication
```

or:

```text
CP unavailable
      ↓
trust tenant from browser
```

or:

```text
provider unavailable
      ↓
grant domain role locally
```

---

# 110. Security Headers

Public identity surfaces SHALL use appropriate browser security controls, including where applicable:

```text
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
Referrer-Policy
frame restrictions
```

Configuration SHALL account for passkeys, federation and required redirects without unnecessary broad exceptions.

---

# 111. CORS

CORS SHALL be explicit.

Production SHALL not use unrestricted:

```text
Access-Control-Allow-Origin: *
```

for credential-bearing identity endpoints.

---

# 112. CSRF

Browser-based state-changing identity flows SHALL preserve the CSRF protections expected by Kratos/Hydra and the Baobab integration architecture.

Digital Estates SHALL not disable provider CSRF protections to simplify frontend development.

---

# 113. TLS

All production identity traffic SHALL use TLS.

Administrative and database connections SHOULD additionally use private networking and appropriate mutual/workload authentication according to infrastructure standards.

---

# 114. Domain Names

Identity endpoints SHOULD use stable Baobab-owned DNS names rather than provider implementation names embedded throughout clients.

Conceptually:

```text
identity.baobab.<domain>
auth.baobab.<domain>
```

rather than requiring every client to encode:

```text
kratos-01.internal...
hydra-prod...
```

Exact DNS names are an infrastructure decision.

---

# 115. Provider-Neutral Discovery

Applications SHOULD primarily receive configuration such as:

```text
issuer
discovery URL
client ID
audience
```

rather than requiring knowledge of Hydra administrative topology.

---

# 116. Ory Administrative DNS

Administrative endpoints SHOULD use private service discovery only.

They SHALL not be publicly discoverable merely for convenience.

---

# 117. Deployment Ownership

Responsibility SHALL be divided:

```text
baobab-iam
    → provider configuration
    → identity schemas
    → adapter logic
    → integration tests

infrastructure
    → compute
    → networking
    → PostgreSQL platform
    → secrets platform
    → ingress
    → backup infrastructure
    → observability infrastructure

shared
    → canonical contracts

baobab-cp
    → canonical identity/context
```

---

# 118. Operational Runbooks

Production readiness SHALL include runbooks for at least:

```text
Kratos outage
Hydra outage
database failover
database restore
signing/secret rotation
client-secret compromise
identity compromise
mass session revocation
provider upgrade
failed migration
credential migration incident
Keycloak rollback during transition
```

---

# 119. Alerting

Critical alerts SHOULD include:

```text
all Kratos replicas unavailable
all Hydra replicas unavailable
IAM DB unavailable
sustained authentication failure spike
token endpoint failure spike
migration failure
significant security reconciliation drift
backup failure
restore-test failure
signing-key anomaly
administrative API exposure
```

---

# 120. SLOs

IAM SHALL have explicit service objectives covering:

```text
authentication availability
token issuance availability
latency
recovery capability
backup success
security-event processing
```

Exact targets SHALL be established from measured infrastructure capability and business requirements rather than asserted without evidence.

---

# 121. Security Tier

Kratos, Hydra, their databases, secrets and provider administration plane SHALL be treated as **Tier-0 security infrastructure**.

Access to them SHALL receive stricter control than ordinary application services.

---

# 122. Keycloak Coexistence During Migration

During ADR-IAM-0019 migration:

```text
                ┌── Keycloak
Canonical ID ───┤
                └── Ory
```

may temporarily exist.

Infrastructure SHALL therefore support controlled coexistence without making it permanent.

---

# 123. Dual-Issuer Window

Resource servers MAY temporarily trust:

```text
Keycloak issuer
+
Hydra issuer
```

where required by the migration plan.

This SHALL be:

- explicit;
- monitored;
- time-bound;
- environment-specific;
- removable.

ADR-IAM-0022 SHALL define the detailed cutover.

---

# 124. No Shared Persistence With Keycloak

Ory SHALL NOT attempt to operate directly against Keycloak's database.

Migration occurs through supported extraction/transformation/provisioning processes.

```text
Keycloak DB
    ✕
Kratos runtime
```

---

# 125. Credential Migration

Credential migration SHALL not be improvised at runtime.

Supported credential migration/import capabilities SHALL be validated experimentally against the pinned Ory versions.

Credentials that cannot be securely migrated SHALL use controlled re-enrollment/recovery rather than unsafe transformation.

---

# 126. Migration Does Not Change Canonical Identity

The runtime transition remains:

```text
Keycloak subject
       │
       ▼
ExternalIdentity A
       │
       ▼
CanonicalIdentity
       ▲
       │
ExternalIdentity B
       ▲
       │
Ory subject
```

The runtime architecture SHALL support this without duplicating CanonicalIdentity.

---

# 127. Implementation Gates

Implementation SHOULD proceed through discrete PR-sized gates.

## IAM-R0 — Runtime Discovery

Inspect existing:

```text
baobab-iam
infrastructure
shared
baobab-cp
Trade
ERP
CMS
Digital Estates
```

and identify Keycloak runtime assumptions.

No speculative replacement.

---

## IAM-R1 — Ory Development Runtime

Introduce reproducible:

```text
Kratos
Hydra
PostgreSQL
```

development infrastructure.

No production cutover.

---

## IAM-R2 — Persistence

Establish:

- separate databases;
- separate credentials;
- migration process;
- backup integration;
- restore tests.

---

## IAM-R3 — Network Boundaries

Implement:

```text
public endpoints
admin endpoints
network policies
TLS
ingress
```

---

## IAM-R4 — Secrets and Cryptography

Implement:

- secret management;
- rotation strategy;
- Hydra security material;
- environment isolation.

---

## IAM-R5 — High Availability

Implement:

- multiple replicas;
- readiness/liveness;
- disruption budgets;
- topology spread;
- database HA.

---

## IAM-R6 — Observability

Implement:

- metrics;
- structured logs;
- alerts;
- security monitoring;
- correlation.

---

## IAM-R7 — Backup and Recovery

Implement:

- encrypted backups;
- restore procedures;
- recovery reconciliation;
- DR exercise.

---

## IAM-R8 — CI/CD Hardening

Implement:

- pinned images;
- SBOM;
- vulnerability scanning;
- migration tests;
- provider contract tests;
- immutable promotion.

---

## IAM-R9 — Integration Readiness

Verify:

```text
Kratos identity flows
Hydra OIDC
client credentials
CP token validation
workload identity
Digital Estate integration
```

---

## IAM-R10 — Migration Readiness

Prepare runtime for controlled Keycloak/Ory coexistence under ADR-IAM-0022.

---

# 128. Production Readiness Checklist

Before production use:

### Runtime

- [ ] Kratos version pinned
- [ ] Hydra version pinned
- [ ] image digests/provenance recorded
- [ ] non-root runtime verified
- [ ] immutable deployment verified
- [ ] minimum HA replicas deployed

### Persistence

- [ ] Kratos database isolated
- [ ] Hydra database isolated
- [ ] runtime DB roles isolated
- [ ] migration roles controlled
- [ ] TLS enabled
- [ ] HA verified
- [ ] backup verified
- [ ] restore exercised

### Network

- [ ] public/admin planes separated
- [ ] admin APIs non-public
- [ ] network policies enforced
- [ ] TLS enforced
- [ ] gateway policies tested
- [ ] rate limits tested

### Secrets

- [ ] no production secrets in Git
- [ ] database credentials managed
- [ ] Hydra secrets managed
- [ ] signing material protected
- [ ] rotation procedure tested

### Identity

- [ ] identity schemas version-controlled
- [ ] schemas contain no Baobab business authority
- [ ] registration tested
- [ ] login tested
- [ ] recovery tested
- [ ] verification tested
- [ ] MFA tested
- [ ] passkeys tested where enabled

### OAuth/OIDC

- [ ] discovery verified
- [ ] authorization code + PKCE verified
- [ ] audience enforcement verified
- [ ] JWKS rotation behavior tested
- [ ] workload client credentials tested
- [ ] redirect URIs constrained
- [ ] scopes reconciled

### Availability

- [ ] replica failure tested
- [ ] database failover tested
- [ ] provider outage behavior tested
- [ ] CP outage fails safely
- [ ] disruption budget verified

### Observability

- [ ] IAM dashboards exist
- [ ] critical alerts configured
- [ ] sensitive values absent from logs
- [ ] security-event pipeline tested
- [ ] correlation IDs verified

### Recovery

- [ ] DR runbook exists
- [ ] restore completed successfully
- [ ] post-restore security reconciliation tested
- [ ] revoked identity resurrection test passes
- [ ] workload revocation resurrection test passes

### Migration

- [ ] Keycloak coexistence tested
- [ ] dual issuer is time-bound
- [ ] CanonicalIdentity continuity tested
- [ ] credential migration strategy tested
- [ ] rollback path tested

---

# 129. Architectural Invariants

The following SHALL remain true:

```text
Kratos ≠ Control Plane

Hydra ≠ Control Plane

Kratos Identity ≠ CanonicalIdentity

Hydra Client ≠ Baobab WorkloadIdentity

Kratos Session ≠ Baobab Authorization

Hydra Token ≠ Domain Permission

Ory Organization ≠ Tenant

Ory Organization ≠ LegalEntity

IAM Region ≠ Market

Kratos DB ≠ CP DB

Hydra DB ≠ CP DB

Kratos DB ≠ Hydra DB

Public Endpoint ≠ Administrative Endpoint

Private Network ≠ Authentication

Provider Availability ≠ Authorization Authority
```

---

# 130. Final Target Runtime

```text
                         ┌──────────────────────────────┐
                         │         INTERNET             │
                         └──────────────┬───────────────┘
                                        │
                                 TLS / WAF / APISIX
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 │                                             │
                 ▼                                             ▼
        ┌────────────────┐                           ┌────────────────┐
        │ Kratos Public  │                           │ Hydra Public   │
        │ replicas >= 2  │                           │ replicas >= 2  │
        └───────┬────────┘                           └───────┬────────┘
                │                                            │
                │                                            │
       ┌────────▼────────┐                          ┌────────▼────────┐
       │  Kratos DB      │                          │  Hydra DB       │
       │ PostgreSQL HA   │                          │ PostgreSQL HA   │
       └─────────────────┘                          └─────────────────┘

                ▲                                            ▲
                │ ADMIN                                      │ ADMIN
                │                                            │
                └──────────────────┬─────────────────────────┘
                                   │
                         PRIVATE IAM NETWORK
                                   │
                                   ▼
                         ┌────────────────────┐
                         │    baobab-iam      │
                         │ Identity Adapter   │
                         │                    │
                         │ provisioning       │
                         │ lifecycle          │
                         │ reconciliation     │
                         │ events             │
                         │ migration          │
                         └─────────┬──────────┘
                                   │
                          canonical contracts
                                   │
                                   ▼
                         ┌────────────────────┐
                         │     baobab-cp      │
                         │                    │
                         │ CanonicalIdentity  │
                         │ ExternalIdentity   │
                         │ Context            │
                         │ Capabilities       │
                         └─────────┬──────────┘
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
               Trade             ERP              CMS
                  │                │                │
                  └──────── domain authorization ──┘
```

---

# 131. Final Decision Principle

Baobab SHALL operate Ory Kratos and Ory Hydra as **Tier-0, independently deployable, self-hosted identity infrastructure**.

Kratos SHALL provide human identity, credential and authentication-session mechanics.

Hydra SHALL provide OAuth/OIDC and machine authorization/token mechanics.

`baobab-iam` SHALL integrate and operate those capabilities through the provider-neutral boundary established by ADR-IAM-0020.

`baobab-cp` SHALL continue to own canonical identity resolution and platform context.

Domain engines SHALL continue to own domain authorization.

The deployment architecture SHALL provide:

```text
separate persistence
+
separate public/admin planes
+
least privilege
+
high availability
+
controlled migrations
+
cryptographic key protection
+
observability
+
backup and tested recovery
+
security-state reconciliation
+
provider-neutral integration
```

The migration from Keycloak therefore changes the identity runtime without discarding the substantial canonical identity, context, authorization, lifecycle and security architecture Baobab has already implemented.

> **Ory becomes the identity runtime. It does not become the Baobab domain model.**