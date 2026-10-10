# Baobab Identity and Access Management

## Consolidated Technical Specification

**Document Type:** Technical Architecture and Implementation Specification
**System:** Baobab Platform IAM
**Primary Repository:** `baobab-platform/baobab-iam`
**Related Repositories:**
`baobab-platform/baobab-cp`
`baobab-platform/shared`
`baobab-platform/baobab-trade`
`baobab-platform/baobab-erp`
`baobab-platform/baobab-cms`
`baobab-platform/baobab-pulse`
`baobab-platform/infrastructure`
Zuribeans Digital Estate
Thamani Digital Estate
Nabhold Corporate Digital Estate
Future Baobab Digital Estates

**Status:** Implementation Specification
**Version:** 1.0
**Date:** 2026-09-09
**Derived From:** ADR-0001 through ADR-0018
**Identity Provider:** Keycloak
**Control Plane:** Baobab Control Plane
**Commerce Engine:** MedusaJS v2
**ERP Engine:** iDempiere
**CMS Engine:** Payload CMS
**Intelligence Engine:** Deepset Haystack / Baobab Pulse
**Primary Platform Database:** PostgreSQL 17 where applicable
**Target Runtime Model:** Containerized, cloud-portable, multi-tenant, multi-market, multi-region capable

---

# 1. Purpose

This specification defines the technical architecture and implementation requirements for Baobab Identity and Access Management.

The IAM subsystem SHALL provide a common identity and authentication foundation for:

* Nabhold workforce;
* executives;
* platform administrators;
* ERP users;
* commerce administrators;
* CMS users;
* Baobab Pulse users;
* Zuribeans B2B buyer representatives;
* Zuribeans suppliers;
* Thamani B2C customers;
* Thamani suppliers;
* future Digital Estate users;
* machine-to-machine workloads;
* external enterprise identities.

The specification consolidates the decisions established in ADR-0001 through ADR-0018 into one implementable system design.

---

# 2. Normative Language

The terms:

```text
MUST
MUST NOT
SHALL
SHALL NOT
SHOULD
SHOULD NOT
MAY
```

are normative.

`SHALL` and `MUST` indicate requirements.

`SHOULD` indicates a recommended default that may only be deviated from with documented justification.

---

# 3. Core Security Principle

The foundational Baobab security rule is:

> **Baobab IAM proves identity. Baobab Control Plane determines platform context and entitlement. Domain engines determine business authorization.**

This SHALL remain true for all Digital Estates and all engine integrations.

---

# 4. Security Responsibility Model

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        BAOBAB IAM                                   │
│                                                                     │
│   Authentication                                                    │
│   Credentials                                                       │
│   MFA / Passkeys                                                    │
│   Sessions                                                          │
│   Federation                                                        │
│   OIDC / OAuth                                                      │
│   Workload authentication                                           │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    BAOBAB CONTROL PLANE                             │
│                                                                     │
│   CanonicalIdentity                                                 │
│   Tenant membership                                                 │
│   Legal-entity relationships                                        │
│   Digital Estate context                                            │
│   Market context                                                    │
│   Capability entitlement                                            │
│   EngineInstance resolution                                         │
│   Platform authorization                                            │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
          ┌─────────────────────┼──────────────────────────────┐
          ▼                     ▼                              ▼
┌─────────────────┐   ┌─────────────────────┐       ┌─────────────────┐
│ BAOBAB TRADE    │   │ BAOBAB ERP          │       │ BAOBAB CMS     │
│                 │   │                     │       │                 │
│ Buyer roles     │   │ AD_User             │       │ Editorial roles│
│ Customer access │   │ AD_Role             │       │ Workflow auth  │
│ Supplier rules  │   │ AD_Client           │       │ Publishing     │
│ Purchase auth   │   │ AD_Org              │       │                 │
│ Order ownership │   │ Finance controls    │       │                 │
└─────────────────┘   └─────────────────────┘       └─────────────────┘
                                │
                                ▼
                      ┌─────────────────────┐
                      │ BAOBAB PULSE        │
                      │                     │
                      │ Workspace access    │
                      │ Report access       │
                      │ Dataset policies    │
                      └─────────────────────┘
```

---

# 5. Non-Negotiable Architectural Invariants

The implementation SHALL preserve the following distinctions:

```text
Authentication ≠ Authorization

Identity ≠ Credential

CanonicalIdentity ≠ Keycloak User

CanonicalIdentity ≠ Medusa Customer

CanonicalIdentity ≠ iDempiere AD_User

Tenant ≠ LegalEntity

Tenant ≠ Keycloak Organization

Tenant ≠ AD_Client by definition

LegalEntity ≠ AD_Org by definition

DigitalEstate ≠ Tenant

DigitalEstate ≠ Market

IAM Organization ≠ Buyer Organization

IAM Organization ≠ Supplier Organization

Buyer Organization ≠ Tenant by default

Supplier Organization ≠ Tenant by default

Valid Token ≠ Valid Platform Context

Valid Platform Context ≠ Domain Permission

IAM Role ≠ Trade Role

IAM Role ≠ AD_Role

Scope ≠ Tenant Membership

MFA ≠ Business Permission

Workload Identity ≠ Human Identity

Email ≠ Canonical Identity

Phone Number ≠ Canonical Identity

Mapping Exists ≠ Access Allowed

Credential Recovery ≠ Authorization Recovery

Account Closure ≠ Canonical Identity Deletion

Backup Restore ≠ Permission Resurrection
```

---

# 6. System Context

Baobab IAM sits between human/workload actors and all platform services.

```text
                         ┌──────────────────────┐
                         │    HUMAN ACTORS      │
                         │                      │
                         │ Workforce            │
                         │ Buyers               │
                         │ Suppliers            │
                         │ Customers            │
                         │ Executives           │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   DIGITAL ESTATES    │
                         │                      │
                         │ Zuribeans            │
                         │ Thamani              │
                         │ Nabhold              │
                         │ Future Estates       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     BAOBAB IAM       │
                         │      Keycloak        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    BAOBAB CP         │
                         │ Context + Entitlement│
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
          Trade                  ERP                    CMS
          Medusa              iDempiere              Payload
              │
              └─────────────────────┬─────────────────────┘
                                    ▼
                                  Pulse
```

---

# 7. Target Repository Architecture

## 7.1 `baobab-platform/baobab-iam`

```text
baobab-iam/
├── config/
│   ├── realm/
│   │   ├── baobab/
│   │   └── environments/
│   ├── clients/
│   ├── scopes/
│   ├── organizations/
│   ├── authentication-flows/
│   ├── identity-providers/
│   ├── webauthn/
│   └── policies/
│
├── providers/
│   ├── src/
│   ├── tests/
│   └── pom.xml
│
├── themes/
│   ├── baobab/
│   ├── thamani/
│   └── zuribeans/
│
├── bootstrap/
│   ├── realm/
│   ├── clients/
│   ├── organizations/
│   └── scripts/
│
├── contracts/
│   └── compatibility/
│
├── migrations/
│   ├── identity/
│   └── credentials/
│
├── runtime/
│   ├── container/
│   ├── kubernetes/
│   └── local/
│
├── tests/
│   ├── contract/
│   ├── integration/
│   ├── security/
│   ├── federation/
│   └── disaster-recovery/
│
├── docs/
│   ├── architecture/
│   ├── runbooks/
│   ├── onboarding/
│   └── threat-model/
│
├── upstream.lock.yaml
├── contracts.lock.yaml
├── compose.yaml
├── Dockerfile
└── README.md
```

Keycloak SHALL NOT be forked.

Extension preference SHALL be:

```text
Keycloak native capability
        >
standards configuration
        >
external adapter
        >
minimal custom SPI
        >
Keycloak fork
```

A Keycloak fork requires a separate ADR.

---

# 8. Shared IAM Contracts

`baobab-platform/shared` SHALL contain cross-repository IAM contracts.

Recommended structure:

```text
shared/
└── contracts/
    ├── identity/
    │   └── v1/
    │       ├── principal.schema.json
    │       ├── human-identity.schema.json
    │       ├── workload-identity.schema.json
    │       ├── external-identity.schema.json
    │       ├── claims.schema.json
    │       ├── membership.schema.json
    │       ├── session.schema.json
    │       └── identity-events.schema.json
    │
    ├── authz/
    │   └── v1/
    │       ├── context.schema.json
    │       ├── decision.schema.json
    │       ├── entitlement.schema.json
    │       ├── actor.schema.json
    │       └── scopes.yaml
    │
    └── events/
        └── security/
            └── v1/
                ├── envelope.schema.json
                ├── identity-lifecycle.schema.json
                ├── membership-lifecycle.schema.json
                ├── session-revoked.schema.json
                └── credential-revoked.schema.json
```

Shared SHALL contain contracts only.

It SHALL NOT become an IAM runtime.

---

# 9. Core Identity Model

## 9.1 Principal Types

Baobab SHALL distinguish:

```text
human
workload
```

External buyer/customer/supplier status SHOULD be represented as relationships rather than a fundamentally separate human identity type.

For backward compatibility, an existing `external` actor value MAY remain temporarily until contracts are migrated.

---

# 10. Canonical Identity

The Control Plane SHALL own `CanonicalIdentity`.

Conceptually:

```text
CanonicalIdentity
────────────────────────────────
id
actor_type
lifecycle_state
created_at
updated_at
version
```

`id` SHALL be:

* opaque;
* immutable;
* non-semantic;
* globally unique within Baobab.

Example:

```text
cid_01JZ5Q6PH5AC65NDP30XQAFN8G
```

Do not encode:

```text
tenant
market
email
employee number
organization
```

inside the ID.

---

# 11. External Identity

External authentication identities SHALL map into the canonical identity.

Logical key:

```text
issuer + subject
```

Example:

```json
{
  "issuer": "https://iam.baobab.example/realms/baobab",
  "subject": "8726e38e-96ed-440d-8c58-33173af28264",
  "canonical_identity_id": "cid_01JZ5Q6PH5AC65NDP30XQAFN8G"
}
```

Uniqueness:

```text
UNIQUE (issuer, subject)
```

Email SHALL NOT be used as this key.

---

# 12. External Identity Resolution

```text
JWT
 │
 ▼
Validate signature
 │
 ▼
Validate issuer
 │
 ▼
Validate audience
 │
 ▼
Read iss + sub
 │
 ▼
ExternalIdentity
 │
 ▼
CanonicalIdentity
 │
 ▼
Lifecycle checks
 │
 ▼
Context resolution
```

---

# 13. Realm Architecture

Production SHALL use one principal Keycloak realm:

```text
baobab
```

The realm provides the common authentication boundary for the platform.

---

# 14. Realm ≠ Tenant

Baobab SHALL NOT implement:

```text
realm-per-tenant
```

as its standard tenancy architecture.

Reasons include:

* excessive operational duplication;
* fragmented user identity;
* difficult cross-tenant workforce access;
* harder federation;
* more complex future SaaS operations.

---

# 15. Tenant Architecture

## 15.1 Definition

A Tenant is a Baobab platform consumption and isolation boundary.

A Tenant is not intrinsically identical to a legal company.

---

# 16. Default Tenant Boundary

The current default rule is:

> **Legal Entity is the default Tenant boundary, but Tenant and Legal Entity remain separate concepts.**

Current expected examples:

```text
Nabhold Group Africa
      │
      ▼
Nabhold Tenant

Zuribeans legal entity
      │
      ▼
Zuribeans Tenant

Thamani legal entity
      │
      ▼
Thamani Tenant
```

Future exceptions SHALL remain possible.

---

# 17. Multi-Tenant Relationship Model

```text
                    CanonicalIdentity
                           │
            ┌──────────────┼──────────────┐
            │              │              │
            ▼              ▼              ▼
       Membership A   Membership B   Membership C
            │              │              │
            ▼              ▼              ▼
         Tenant A       Tenant B       Tenant C
            │              │              │
            ▼              ▼              ▼
       LegalEntity A  LegalEntity B  LegalEntity C
```

A user MAY belong to multiple tenants.

---

# 18. Multi-Tenant Isolation Rule

Every protected request SHALL resolve tenant context server-side.

The following SHALL NOT be trusted as authority:

```http
X-Tenant-ID: tenant-zuribeans
```

or:

```json
{
  "tenant_id": "tenant-zuribeans"
}
```

These values represent requested context only.

---

# 19. Context Resolution

The authoritative flow SHALL be:

```text
Incoming Request
      │
      ▼
Validate Token
      │
      ▼
Resolve Canonical Identity
      │
      ▼
Read Requested Context
      │
      ▼
Verify Tenant Membership
      │
      ▼
Verify LegalEntity Relationship
      │
      ▼
Verify DigitalEstate
      │
      ▼
Verify Market
      │
      ▼
Verify Capability Entitlement
      │
      ▼
Resolve CapabilityBinding
      │
      ▼
Resolve EngineInstance
      │
      ▼
Return Authorized Context
```

---

# 20. Control Plane Context Contract

Example:

```json
{
  "canonical_identity_id": "cid_01JZ5Q6PH5AC65NDP30XQAFN8G",
  "actor_type": "human",
  "tenant_id": "ten_zuribeans",
  "legal_entity_id": "le_zuribeans_ug",
  "digital_estate_id": "de_zuribeans",
  "market_id": "mkt_ug",
  "capability_id": "cap_trade",
  "engine_instance_id": "eng_trade_africa_01"
}
```

Generic `organization_id` SHALL be avoided where semantics matter.

---

# 21. Proposed Context API

Conceptual internal endpoint:

```http
POST /internal/v1/context/resolve
Authorization: Bearer <access-token>
Content-Type: application/json
```

Request:

```json
{
  "tenant_id": "ten_zuribeans",
  "digital_estate_id": "de_zuribeans",
  "market_id": "mkt_ug",
  "capability": "trade"
}
```

Response:

```json
{
  "decision_id": "dec_01JZ63VJS0KX74H47B7SVR93MB",
  "result": "ALLOW",
  "context": {
    "canonical_identity_id": "cid_01JZ5Q6PH5AC65NDP30XQAFN8G",
    "tenant_id": "ten_zuribeans",
    "legal_entity_id": "le_zuribeans_ug",
    "digital_estate_id": "de_zuribeans",
    "market_id": "mkt_ug",
    "capability_id": "cap_trade",
    "engine_instance_id": "eng_trade_africa_01"
  }
}
```

Denial:

```json
{
  "decision_id": "dec_01JZ63W4YAEH0QKW3M8CZ3KPN1",
  "result": "DENY",
  "reason_code": "MEMBERSHIP_REVOKED"
}
```

---

# 22. Multi-Market Model

Market SHALL be modeled independently from Tenant.

Example:

```text
Zuribeans Tenant
     │
     ├── Uganda Market
     │
     └── South Africa Market
```

A valid tenant relationship SHALL NOT imply access to all markets.

---

# 23. Multi-Region Model

Region SHALL represent runtime/data locality, not business authorization.

The following concepts SHALL remain separate:

```text
Market
Region
Tenant
LegalEntity
```

Example:

```text
Market:
South Africa

Region:
af-south-1

Tenant:
Thamani

LegalEntity:
Thamani South Africa entity
```

---

# 24. Region Data Model

A region registry SHOULD exist in the Control Plane or infrastructure control model.

Conceptually:

```text
Region
────────────────────────
id
code
jurisdiction
status
primary
data_residency_class
```

Example:

```json
{
  "id": "reg_za_01",
  "code": "ZA-CPT-01",
  "jurisdiction": "ZA",
  "status": "ACTIVE",
  "data_residency_class": "SOUTH_AFRICA"
}
```

---

# 25. EngineInstance Is Region-Aware

Example:

```json
{
  "engine_instance_id": "eng_trade_za_01",
  "engine_id": "trade",
  "region_id": "reg_za_01",
  "status": "ACTIVE"
}
```

Another:

```json
{
  "engine_instance_id": "eng_trade_ug_01",
  "engine_id": "trade",
  "region_id": "reg_ug_01",
  "status": "ACTIVE"
}
```

---

# 26. Multi-Region Resolution

```text
Tenant
  │
  ▼
Market
  │
  ▼
Residency / Routing Policy
  │
  ▼
CapabilityBinding
  │
  ▼
Regional EngineInstance
```

---

# 27. Multi-Region Routing Example

```text
THAMANI CUSTOMER
      │
      ▼
Market = ZA
      │
      ▼
CP Resolution
      │
      ▼
Trade Capability
      │
      ▼
EngineInstance = trade-za
      │
      ▼
South Africa regional infrastructure
```

while:

```text
ZURIBEANS OPERATOR
      │
      ▼
Market = UG
      │
      ▼
CP Resolution
      │
      ▼
ERP Capability
      │
      ▼
EngineInstance = erp-ug
```

---

# 28. Cross-Region Identity

A Canonical Identity SHALL be global at the Baobab logical level.

Regional runtime systems SHALL NOT create independent global identities simply because deployment locality differs.

---

# 29. Data Residency

Identity data SHALL be classified by:

* legal requirements;
* jurisdiction;
* security sensitivity;
* platform operational requirements.

Replication of identity data between regions SHALL be explicit.

Multi-region SHALL NOT mean:

```text
replicate all personal data everywhere
```

---

# 30. Keycloak Organizations

Keycloak Organizations MAY provide:

* B2B identity affiliation;
* invitations;
* organization-oriented login;
* enterprise federation;
* organization membership.

They SHALL NOT become the source of:

* Tenant authority;
* supplier approval;
* buyer purchase authority;
* ERP role;
* legal-entity verification.

---

# 31. Organization Relationship

Conceptually:

```text
Keycloak Organization
        │
        ▼
CanonicalEntity mapping
        │
        ├────────► BuyerOrganization
        │
        └────────► SupplierOrganization
```

These relationships SHALL be explicit.

---

# 32. OIDC Clients

Minimum expected clients:

```text
baobab-control-plane
baobab-trade
baobab-erp
baobab-cms
baobab-pulse

zuribeans-web
thamani-web
nabhold-web
```

Additional admin/BFF clients MAY be created.

---

# 33. Client Isolation

Separate clients SHOULD exist for separate security boundaries.

Avoid:

```text
baobab-everything
```

as a universal OAuth client.

---

# 34. Browser Authentication

Public browser clients SHALL use:

```text
Authorization Code
+
PKCE S256
```

Implicit flow SHALL NOT be used.

Resource Owner Password Credentials SHALL NOT be used.

---

# 35. Browser Authentication Flow

```text
Browser
   │
   ▼
Digital Estate
   │
   ▼
Keycloak /authorize
   │
 authenticate
   ▼
Authorization Code
   │
   ▼
Digital Estate callback
   │
   ▼
PKCE verification
   │
   ▼
Tokens / BFF session
```

---

# 36. BFF Architecture

For higher-security Digital Estates, a Backend-for-Frontend is preferred.

```text
Browser
   │
 secure HttpOnly cookie
   ▼
BFF
   │
 OAuth tokens
   ▼
Baobab APIs
```

The browser SHOULD NOT persist long-lived access/refresh tokens in local storage.

---

# 37. Human Access Token Profile

Minimum desired claims:

```json
{
  "iss": "https://iam.example/realms/baobab",
  "sub": "provider-subject",
  "aud": ["baobab-control-plane"],
  "azp": "zuribeans-web",
  "actor_type": "human",
  "scope": "openid profile context:resolve",
  "iat": 1788930000,
  "exp": 1788930900
}
```

---

# 38. Token Lifetime

Access tokens SHALL be short-lived.

Current CP target:

```text
maximum ≈ 15 minutes
```

A stricter duration MAY be configured for privileged applications.

---

# 39. Token Validation

Every resource server SHALL validate:

```text
signature
issuer
audience
expiry
not-before
algorithm
actor type
required scope
authorized client where applicable
```

Gateway validation is defense in depth.

It SHALL NOT replace resource-server validation.

---

# 40. JWT Algorithms

Only explicitly approved asymmetric algorithms SHALL be accepted.

Current CP compatibility includes:

```text
RS256
ES256
```

No:

```text
alg = none
```

No universal symmetric platform signing secret.

---

# 41. Clock Skew

Initial validation tolerance:

```text
30 seconds
```

subject to operational measurement.

---

# 42. OAuth Scopes

Scopes SHALL represent coarse API/delegation capability.

Examples:

```text
context:resolve
identity:read
identity:manage
trade:invoke
erp:invoke
cms:invoke
pulse:invoke
```

Scopes SHALL NOT encode the entire business permission graph.

---

# 43. Authorization Pipeline

```text
1. Token valid?
        │
       NO ───────────► DENY
        │
       YES
        ▼
2. Required scope/client?
        │
       NO ───────────► DENY
        │
       YES
        ▼
3. Resolve CanonicalIdentity
        │
       FAIL ─────────► DENY
        │
        ▼
4. Resolve CP context
        │
       DENY ─────────► DENY
        │
       ALLOW
        ▼
5. Domain authorization
        │
       DENY ─────────► DENY
        │
       ALLOW
        ▼
      EXECUTE
```

Any required denial SHALL be final.

---

# 44. Deny Precedence

```text
IAM ALLOW
CP DENY
=
DENY
```

```text
IAM ALLOW
CP ALLOW
ENGINE DENY
=
DENY
```

There SHALL be no downstream override of upstream denial.

---

# 45. Workload Identity

Each independently revocable deployed workload SHALL have its own identity.

Examples:

```text
trade-api
trade-order-worker
erp-sync
pulse-ingestion-worker
cms-publisher
thamani-bff
zuribeans-bff
```

---

# 46. Workload Token Flow

```text
Workload
   │
 client authentication
   ▼
Keycloak
   │
 client_credentials
   ▼
Short-lived token
   │
   ▼
Baobab CP
   │
 context resolution
   ▼
Target service
```

---

# 47. Workload Claims

Example:

```json
{
  "iss": "https://iam.example/realms/baobab",
  "sub": "service-account-trade-order-worker",
  "aud": ["baobab-control-plane"],
  "azp": "trade-order-worker",
  "actor_type": "workload",
  "scope": "context:resolve erp:invoke",
  "iat": 1788930000,
  "exp": 1788930600
}
```

---

# 48. No Shared Workload Account

Prohibited:

```text
baobab-services
```

used by every backend.

---

# 49. Workload Registry

The platform SHALL maintain a machine-readable workload registry.

Example:

```yaml
workloads:
  - id: trade-order-worker
    repo: baobab-platform/baobab-trade
    runtime: worker
    environment: production
    audience:
      - baobab-control-plane
      - baobab-erp
    scopes:
      - context:resolve
      - erp:invoke
    credential_type: client_secret
    owner: trade-platform
```

---

# 50. Runtime vs CI Identity

GitHub Actions identity SHALL NOT equal runtime identity.

```text
CI/CD identity
     ≠
application runtime identity
```

---

# 51. mTLS

mTLS SHOULD protect high-trust service paths.

Expected path:

```text
Workload
   │
   ├── mTLS
   │
   └── OAuth access token
         │
         ▼
      APISIX
         │
         ▼
      Service
```

mTLS proves connection/workload identity.

It SHALL NOT establish Tenant or business authority.

---

# 52. Gateway Security

APISIX or equivalent edge infrastructure MAY perform:

* TLS termination;
* mTLS;
* routing;
* rate limiting;
* coarse JWT validation;
* request-size limits;
* security-header enforcement.

It SHALL NOT determine canonical business authorization.

---

# 53. Reserved Headers

Incoming external requests SHALL have internal identity headers stripped.

Examples:

```text
X-Baobab-Canonical-Identity
X-Baobab-Tenant
X-Baobab-Legal-Entity
X-Baobab-Actor
```

If these are used internally, they SHALL be regenerated by trusted infrastructure and SHALL not be the sole authority.

---

# 54. Workforce SSO

Workforce SHALL authenticate through Baobab IAM.

```text
Workforce
   │
   ▼
Keycloak
   │
   ▼
CanonicalIdentity
   │
   ▼
CP
   │
   ├── Trade Admin
   ├── ERP
   ├── CMS
   └── Pulse
```

---

# 55. Workforce Privilege Domains

Separate privilege domains:

```text
IAM
Control Plane
Trade
ERP
CMS
Infrastructure
Security
```

No universal platform administrator SHALL be the routine default.

---

# 56. Executive Access

Nabhold executives MAY have cross-tenant visibility.

This SHALL be explicit.

Preferred:

```text
cross-tenant read/reporting
```

rather than:

```text
universal superuser
```

---

# 57. Joiner / Mover / Leaver

```text
JOINER
 │
 ▼
Identity
 │
 ▼
Membership
 │
 ▼
Entitlement
 │
 ▼
Engine role


MOVER
 │
 ▼
Review old access
 │
 ▼
Revoke obsolete
 │
 ▼
Grant approved new access


LEAVER
 │
 ▼
Suspend/disable workforce access
 │
 ▼
Revoke sessions
 │
 ▼
Revoke memberships
 │
 ▼
Revoke entitlements
 │
 ▼
Deprovision engines
 │
 ▼
Preserve history
```

---

# 58. Zuribeans B2B Identity

Zuribeans is strictly B2B.

The model SHALL distinguish:

```text
Person
  ≠
Buyer Company
```

---

# 59. Buyer Architecture

```text
Buyer Representative
       │
       ▼
Baobab IAM
       │
       ▼
CanonicalIdentity
       │
       ▼
CP Context
       │
       ▼
Trade Buyer Organization
       │
       ▼
BuyerMembership
       │
       ▼
Buyer Role
       │
       ▼
Commercial / Procurement Rules
```

---

# 60. Buyer Organization Model

Potential domain model:

```text
BuyerOrganization
────────────────────────
id
canonical_entity_id
status
market_eligibility
commercial_status
created_at
```

---

# 61. Buyer Membership

Example:

```json
{
  "id": "bm_001",
  "buyer_organization_id": "buyer_hotel_001",
  "canonical_identity_id": "cid_123",
  "role": "purchaser",
  "status": "ACTIVE"
}
```

---

# 62. Buyer Roles

Example domain roles:

```text
buyer_admin
purchaser
approver
finance
viewer
```

These belong to Trade.

They SHALL NOT be treated as authoritative Keycloak roles.

---

# 63. Purchase Authority

Purchase authority MAY depend on:

```text
role
order amount
product category
market
commercial terms
approval policy
credit standing
```

Example:

```text
purchaser
   │
   ▼
Order = USD 40,000
   │
   ▼
Approval threshold = USD 20,000
   │
   ▼
Approver required
```

---

# 64. Multi-Buyer Membership

One person MAY represent several buyer organizations.

```text
Person
 ├── Buyer Org A
 ├── Buyer Org B
 └── Buyer Org C
```

Organization context SHALL be explicit.

---

# 65. Thamani B2C Identity

Thamani SHALL prioritize low-friction customer authentication.

```text
Customer
   │
   ▼
Thamani
   │
   ▼
Baobab IAM
   │
   ▼
CanonicalIdentity
   │
   ▼
CP
   │
   ▼
Medusa Customer
```

---

# 66. Guest Checkout

Guest shopping MAY occur without a Canonical Identity.

```text
Guest Session ≠ CanonicalIdentity
```

Guest records SHALL remain commerce-domain records.

---

# 67. Guest-to-Account Conversion

Historical guest orders SHALL NOT attach to a new account merely because email addresses match.

Proof of ownership SHALL be required.

---

# 68. Social Login

Thamani MAY support social login through Keycloak identity brokering.

```text
Google / Apple / Other
         │
         ▼
      Keycloak
         │
         ▼
ExternalIdentity
         │
         ▼
CanonicalIdentity
```

The Digital Estate SHALL NOT maintain a separate social identity authority.

---

# 69. Supplier Identity

Suppliers SHALL be modeled canonically across estates.

```text
Supplier Representative
        │
        ▼
Baobab IAM
        │
        ▼
CanonicalIdentity
        │
        ▼
Supplier Organization
        │
        ├── Verification
        ├── Documents
        ├── Products
        ├── Markets
        └── Sourcing Relationships
```

---

# 70. Supplier ≠ Tenant

Suppliers SHALL NOT become Baobab Tenants by default.

A supplier becomes a Tenant only if it separately consumes Baobab as a SaaS tenant.

---

# 71. Supplier Lifecycle

Recommended:

```text
DRAFT
  │
  ▼
SUBMITTED
  │
  ▼
PENDING_VERIFICATION
  │
  ▼
IN_REVIEW
  │
  ├────► MORE_INFORMATION_REQUIRED
  │
  ├────► REJECTED
  │
  ├────► CONDITIONALLY_APPROVED
  │
  └────► APPROVED
             │
             ├────► SUSPENDED
             ├────► BLOCKED
             └────► ARCHIVED
```

---

# 72. Supplier Approval Granularity

Do NOT use only:

```text
approved = true
```

The meaningful decision is closer to:

```text
May Supplier S
supply Product P
to Digital Estate E
in Market M
at this time?
```

---

# 73. Sourcing Relationship

Recommended model:

```text
SourcingRelationship
────────────────────────────────
id
supplier_organization_id
digital_estate_id
market_id
product_id?
category_id?
status
effective_from
effective_until?
commercial_conditions
```

---

# 74. Local Supplier Preference

Local supplier preference SHALL be a sourcing/ranking policy.

It SHALL NOT be an IAM authorization rule.

---

# 75. Medusa Authentication Integration

Medusa SHALL use a supported Auth Module Provider.

Suggested identifier:

```text
baobab-oidc
```

---

# 76. Medusa Configuration Example

```typescript
import { defineConfig } from "@medusajs/framework/utils"

export default defineConfig({
  projectConfig: {
    http: {
      authMethodsPerActor: {
        customer: ["baobab-oidc"],
        user: ["baobab-oidc"],
      },
    },
  },
})
```

During controlled migration:

```typescript
authMethodsPerActor: {
  customer: ["baobab-oidc", "emailpass"],
  user: ["baobab-oidc"],
}
```

Legacy authentication SHALL be time-bounded.

---

# 77. Medusa Provider Skeleton

Illustrative implementation:

```typescript
import {
  AbstractAuthModuleProvider,
  AuthenticationInput,
  AuthenticationResponse,
} from "@medusajs/framework/utils"

export class BaobabOidcProviderService
  extends AbstractAuthModuleProvider {

  static identifier = "baobab-oidc"

  async authenticate(
    input: AuthenticationInput
  ): Promise<AuthenticationResponse> {
    /*
     * 1. Validate OIDC callback / token
     * 2. Extract issuer + subject
     * 3. Resolve CanonicalIdentity
     * 4. Resolve/create Medusa AuthIdentity
     * 5. Link to correct Medusa actor
     * 6. Return authentication result
     */

    return {
      success: true,
      authIdentity: {
        provider_identities: [
          {
            provider: "baobab-oidc",
            entity_id: "issuer|subject",
          },
        ],
      },
    }
  }
}
```

Exact signatures SHALL follow the pinned Medusa release.

No Medusa fork SHALL be introduced.

---

# 78. Medusa Identity Relationship

```text
Keycloak User
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity
      │
      ▼
Medusa AuthIdentity
      │
      ├── customer_id
      └── user_id
```

---

# 79. No Email Auto-Linking

This is prohibited:

```typescript
const customer = await findCustomerByEmail(email)
linkIdentity(customer)
```

unless an independently verified secure account-linking flow has established ownership.

---

# 80. iDempiere SSO

iDempiere SHALL authenticate workforce users through OIDC SSO with Baobab IAM.

Target:

```text
Workforce
   │
   ▼
Keycloak
   │
   ▼
OIDC
   │
   ▼
CanonicalIdentity
   │
   ▼
CP ERP entitlement/context
   │
   ▼
AD_User
   │
   ▼
AD_Role
   │
   ▼
AD_Client / AD_Org
```

---

# 81. ERP Mapping

Recommended CP mapping:

```json
{
  "canonical_identity_id": "cid_123",
  "engine_instance_id": "erp_za_01",
  "external_type": "IDEMPIERE_AD_USER",
  "external_id": "1000024"
}
```

---

# 82. ERP Context Mapping

```json
{
  "tenant_id": "ten_nabhold",
  "legal_entity_id": "le_nabhold_za",
  "engine_instance_id": "erp_za_01",
  "ad_client_id": 1000000,
  "ad_org_id": 1000001
}
```

This is explicit mapping.

Do not hard-code:

```text
TenantID == AD_Client_ID
```

---

# 83. ERP Authorization

iDempiere remains authoritative for:

```text
AD_User
AD_Role
AD_Client
AD_Org
window access
process access
form access
workflow access
document permissions
accounting permissions
```

---

# 84. ERP Suppliers and Customers

Business partners MAY map to:

```text
C_BPartner
```

but:

```text
C_BPartner ≠ AD_User
```

A supplier/customer business entity does not automatically receive ERP login.

---

# 85. ERP Machine Integration

Trade-to-ERP integration SHALL use workload identity.

```text
Trade
 │
 ▼
Trade domain authorization
 │
 ▼
Trade workload identity
 │
 ▼
CP
 │
 ▼
ERP adapter/API
 │
 ▼
iDempiere
```

Do not use an employee's `AD_User` for background integrations.

---

# 86. Credential Architecture

Keycloak SHALL be authoritative for normal human credentials.

Supported mechanisms MAY include:

```text
password
passkey
WebAuthn security key
TOTP
recovery codes
enterprise federation
social federation
```

---

# 87. Credential Risk Tiers

| Tier       | Typical Actors                 | Baseline                                 |
| ---------- | ------------------------------ | ---------------------------------------- |
| Standard   | Thamani customer               | Password or passkey                      |
| Enhanced   | Buyer/supplier representatives | Passkey or password + MFA depending role |
| Privileged | ERP finance, admins            | MFA required                             |
| Critical   | IAM/security/break-glass       | Phishing-resistant preferred/required    |

---

# 88. Password Requirements

Passwords SHALL:

* support long passphrases;
* reject common/compromised passwords;
* avoid arbitrary composition rules;
* avoid calendar-based forced rotation;
* support password managers.

---

# 89. Passkey Strategy

Evolution:

```text
Phase 1
Password + MFA
     │
     ▼
Phase 2
Passkey enrollment
     │
     ▼
Phase 3
Passkey preferred
     │
     ▼
Phase 4
Passwordless for appropriate populations
```

---

# 90. MFA Requirements

MFA SHALL be mandatory for:

```text
IAM administrators
CP administrators
ERP finance users
ERP administrators
Trade administrators
CMS administrators with sensitive roles
production infrastructure administrators
security administrators
```

---

# 91. Step-Up Authentication

High-risk operations SHALL be capable of requiring recent stronger authentication.

Examples:

```text
supplier bank change
payment approval
journal posting
tenant suspension
privileged role grant
MFA reset
identity linking
high-value B2B purchase approval
```

---

# 92. Assurance Contract

Example:

```json
{
  "actor_type": "human",
  "acr": "urn:baobab:assurance:privileged",
  "amr": [
    "pwd",
    "webauthn"
  ],
  "authenticated_at": "2026-09-09T08:15:00Z",
  "step_up_at": "2026-09-09T08:20:00Z"
}
```

---

# 93. Step-Up Rule

Example policy:

```yaml
operation: supplier.bank-account.update
minimum_assurance: privileged
phishing_resistant_required: true
max_authentication_age_seconds: 300
```

---

# 94. Account Recovery

Recovery restores authentication control.

It SHALL NOT restore domain authorization.

```text
Recover IAM account
        │
        ▼
Identity can authenticate
        │
        X
        ▼
Old buyer/supplier/ERP privileges do NOT automatically return
```

---

# 95. Recovery Token Properties

Recovery tokens SHALL be:

```text
cryptographically random
single-purpose
single-use
short-lived
non-loggable
```

---

# 96. Security Questions

Prohibited.

Examples:

```text
mother's maiden name
first pet
school name
```

---

# 97. Identity Lifecycle

Recommended Canonical Identity lifecycle:

```text
PROVISIONAL
    │
    ▼
ACTIVE
    │
    ├────► SUSPENDED
    │         │
    │         └────► ACTIVE
    │
    ▼
DISABLED
    │
    ▼
ARCHIVED
```

---

# 98. Credential Lifecycle

```text
ENROLLED
   │
   ▼
ACTIVE
   │
   ├────► COMPROMISED
   ├────► REVOKED
   └────► REPLACED
```

---

# 99. Membership Lifecycle

Recommended:

```text
INVITED
   │
   ▼
PENDING
   │
   ▼
ACTIVE
   │
   ├────► SUSPENDED
   ├────► REVOKED
   └────► EXPIRED
```

---

# 100. Workload Lifecycle

```text
PROVISIONED
    │
    ▼
ACTIVE
    │
    ├────► SUSPENDED
    ├────► REVOKED
    └────► RETIRED
```

---

# 101. Layered Revocation

```text
                  SECURITY CHANGE
                        │
                        ▼
              What authority changed?
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   Credential       Membership        Identity
       │                │                │
       ▼                ▼                ▼
 revoke factor    revoke relation    suspend globally
       │                │                │
       └────────────────┼────────────────┘
                        ▼
                publish lifecycle event
                        │
                        ▼
                 downstream updates
                        │
                        ▼
                  reconciliation
```

---

# 102. Deprovisioning Saga

```text
Leaver
 │
 ▼
Disable workforce IAM access
 │
 ▼
Revoke sessions
 │
 ▼
Revoke CP memberships
 │
 ▼
Revoke capability entitlements
 │
 ├────────► Trade
 │
 ├────────► ERP
 │
 ├────────► CMS
 │
 └────────► Pulse
 │
 ▼
Reconcile
 │
 ├── complete
 │
 └── retry / alert
```

---

# 103. Event-Driven Lifecycle

Baobab SHALL use canonical security events for cross-system lifecycle propagation.

Suggested events:

```text
identity.suspended.v1
identity.disabled.v1
identity.reactivated.v1

membership.granted.v1
membership.revoked.v1

entitlement.granted.v1
entitlement.revoked.v1

credential.revoked.v1
credential.compromised.v1

session.revoked.v1

workload.revoked.v1
workload.retired.v1
```

---

# 104. Security Event Envelope

Example:

```json
{
  "event_id": "evt_01JZ64JZ99W52YHMJK6DZJV10B",
  "event_type": "membership.revoked.v1",
  "schema_version": "1.0",
  "occurred_at": "2026-09-09T09:00:00Z",
  "producer": {
    "service": "baobab-control-plane"
  },
  "actor": {
    "actor_type": "human",
    "canonical_identity_id": "cid_admin_001"
  },
  "subject": {
    "canonical_identity_id": "cid_user_501"
  },
  "context": {
    "tenant_id": "ten_zuribeans"
  },
  "reason_code": "WORKFORCE_TERMINATION",
  "correlation_id": "corr_01JZ64K7"
}
```

---

# 105. Event Idempotency

Consumers SHALL track event IDs.

Conceptual consumer:

```go
func HandleMembershipRevoked(
	ctx context.Context,
	event MembershipRevoked,
) error {
	if repository.AlreadyProcessed(ctx, event.EventID) {
		return nil
	}

	if event.Version < repository.CurrentVersion(
		ctx,
		event.MembershipID,
	) {
		return nil
	}

	if err := repository.Revoke(
		ctx,
		event.MembershipID,
		event.EffectiveAt,
	); err != nil {
		return err
	}

	return repository.MarkProcessed(ctx, event.EventID)
}
```

---

# 106. Stale Event Protection

Scenario:

```text
T1 ACTIVE
T2 REVOKED
T3 old ACTIVE event delivered late
```

T3 SHALL NOT restore access.

Entity version or monotonic lifecycle revision SHALL be used.

---

# 107. Events + Reconciliation

Neither mechanism alone is sufficient.

```text
Event propagation
      +
Periodic reconciliation
      =
Lifecycle correctness
```

---

# 108. Orphan Detection

Examples:

```text
Medusa User
but no canonical mapping

AD_User
but workforce relationship no longer exists

active workload client
but no runtime owner

ExternalIdentity
pointing to missing CanonicalIdentity
```

Reconciliation SHALL detect these.

---

# 109. Security Event Reliability

Services SHOULD use:

```text
database transaction
      │
      ▼
outbox record
      │
      ▼
publisher
      │
      ▼
event broker
```

for important lifecycle/security events.

---

# 110. Transactional Outbox Example

Conceptual PostgreSQL:

```sql
CREATE TABLE security_event_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);
```

This is illustrative.

Exact schema SHALL follow repository standards.

---

# 111. Audit Architecture

Baobab SHALL distinguish:

```text
Operational Logs
Security Audit
Domain Audit
Canonical Security Events
Metrics
Distributed Traces
Alerts
```

---

# 112. Audit Correlation

Minimum identifiers:

```text
event_id
request_id
trace_id
correlation_id
decision_id
canonical_identity_id
```

where applicable.

---

# 113. Actor and Subject

Delegated action:

```json
{
  "subject": {
    "canonical_identity_id": "cid_human_001"
  },
  "actor": {
    "workload_id": "trade-order-worker"
  }
}
```

This identifies:

```text
WHO requested it
+
WHAT service executed it
```

---

# 114. Authorization Audit

CP decisions SHOULD expose:

```json
{
  "decision_id": "dec_001",
  "result": "DENY",
  "canonical_identity_id": "cid_001",
  "tenant_id": "ten_001",
  "capability_id": "cap_erp",
  "reason_code": "CAPABILITY_NOT_ENTITLED"
}
```

---

# 115. Audit Redaction

Never log:

```text
password
access token
refresh token
ID token
authorization code
PKCE verifier
client secret
TOTP seed
recovery code
recovery token
private signing key
```

---

# 116. Example Structured Log

```json
{
  "timestamp": "2026-09-09T09:12:03Z",
  "service": "baobab-cp",
  "event": "authorization.denied",
  "decision_id": "dec_001",
  "canonical_identity_id": "cid_001",
  "tenant_id": "ten_zuribeans",
  "reason": "MEMBERSHIP_REVOKED",
  "trace_id": "a1b2c3d4"
}
```

---

# 117. OpenTelemetry

Baobab SHOULD standardize telemetry on OpenTelemetry-compatible instrumentation.

Example span hierarchy:

```text
thamani.checkout
   │
   ├── iam.authenticate
   │
   ├── cp.context.resolve
   │
   ├── trade.cart.authorize
   │
   └── trade.order.create
```

---

# 118. Recommended Span Attributes

```text
baobab.actor_type
baobab.tenant_id
baobab.legal_entity_id
baobab.digital_estate_id
baobab.market_id
baobab.capability_id
baobab.engine_instance_id
baobab.decision_id
```

Do not use raw email as a routine span attribute.

---

# 119. Security Metrics

Examples:

```text
iam_authentication_attempts_total
iam_authentication_failures_total
iam_mfa_challenges_total
iam_passkey_logins_total
iam_sessions_revoked_total

cp_context_resolution_total
cp_context_denied_total
cp_cross_tenant_denied_total

identity_revocations_total
deprovisioning_duration_seconds
deprovisioning_failures_total
orphan_identity_records_total

security_event_lag_seconds
```

---

# 120. Cross-Tenant Security Monitoring

Every privileged cross-tenant operation SHOULD record:

```text
actor
source context
target tenant
capability
decision
reason
```

---

# 121. IAM High Availability

IAM is Tier-0 infrastructure.

Baseline production:

```text
                    Traffic Layer
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
      AZ / Zone A                   AZ / Zone B
          │                             │
     Keycloak A1                    Keycloak B1
     Keycloak A2                    Keycloak B2
          │                             │
          └──────────────┬──────────────┘
                         ▼
                  HA PostgreSQL 17
                         │
                         ▼
                    PITR / Backup
```

---

# 122. Multi-Region IAM Strategy

The platform SHALL distinguish:

## Regional HA

Protection from:

```text
pod
node
availability zone
```

## Disaster Recovery

Protection from:

```text
region/site loss
database corruption
operator error
security incident
```

---

# 123. Initial Production Recommendation

Prefer:

```text
single primary region
+
multi-AZ HA
+
cross-failure-domain backup/DR
```

before introducing active-active cross-region IAM.

---

# 124. Multi-Region Evolution

Potential evolution:

```text
PHASE A
Single region, Multi-AZ

        │
        ▼

PHASE B
Primary region + warm DR region

        │
        ▼

PHASE C
Supported multi-site Keycloak architecture

        │
        ▼

PHASE D
Regional identity strategy
only if residency/scale justify it
```

---

# 125. Split-Brain Rule

Baobab SHALL NOT operate unsafely writable, asynchronously independent IAM clusters without supported conflict handling.

Security consistency takes precedence over dual-site write availability.

---

# 126. PostgreSQL HA

PostgreSQL SHALL provide:

```text
streaming replication
standby
failover
PITR
backup
monitoring
```

where supported by target infrastructure.

For true zero-loss HA failure:

```text
synchronous replication
```

is required.

---

# 127. IAM Database Isolation

Keycloak SHALL have its own database/database boundary.

Do not share application tables with CP or Trade.

---

# 128. IAM RPO / RTO

Initial engineering objectives:

| Scenario                     |                 Target |
| ---------------------------- | ---------------------: |
| Keycloak instance failure    |                  RPO 0 |
| Node failure                 |                  RPO 0 |
| Synchronous DB failure       |                  RPO 0 |
| Catastrophic backup recovery |   Proposed RPO ≤ 5 min |
| Security revocation state    | Effective RPO 0 target |
| Catastrophic IAM recovery    |  Proposed RTO ≤ 60 min |

These SHALL be validated against actual infrastructure.

---

# 129. Backup Scope

IAM recovery requires more than the Keycloak DB.

Back up/recover:

```text
Keycloak PostgreSQL
approved realm/client configuration
custom providers
themes
bootstrap artifacts
deployment manifests
signing-key strategy
secret references
security/revocation recovery data
```

---

# 130. Backup Security

IAM backups SHALL be:

```text
encrypted
access-controlled
protected from routine deletion
kept outside primary failure domain
regularly restore-tested
```

---

# 131. Restore Safety

A restored Keycloak SHALL NOT immediately receive production traffic.

```text
Restore
  │
  ▼
Keycloak starts
  │
  X
  │
  ▼
DO NOT OPEN TRAFFIC YET
```

---

# 132. Recovery Sequence

```text
1. Contain incident

2. Select trusted recovery point

3. Restore infrastructure dependencies

4. Restore PostgreSQL

5. Restore secrets / signing capability

6. Deploy pinned Keycloak version

7. Validate realm/client configuration

8. Validate OIDC discovery

9. Validate JWKS

10. Reapply post-backup security state

11. Reconcile CP/domain revocations

12. Run positive authentication tests

13. Run negative security tests

14. Validate integrations

15. Gradually reopen traffic

16. Monitor

17. Complete incident review
```

---

# 133. Revocation-Safe Restore

Critical scenario:

```text
Backup T0

     │
     ▼

Identity ACTIVE

     │
     ▼

Identity compromised

     │
     ▼

Identity DISABLED at T1

     │
     ▼

Disaster

     │
     ▼

Restore T0

     │
     ▼

Backup says ACTIVE

     │
     ▼

Security journal says DISABLED

     │
     ▼

DENY WINS
```

---

# 134. Security Recovery Journal

Baobab SHOULD retain a durable recoverable record of critical post-backup security changes.

Examples:

```text
identity disabled
credential revoked
session revoked
workload revoked
tenant suspended
privileged membership revoked
```

This does not replace the authoritative systems.

It exists to prevent security resurrection.

---

# 135. Backup Restore Invariant

> **No backup, rollback, migration, failover or DR operation may knowingly resurrect authority that a later trusted security decision revoked.**

---

# 136. Secrets

Production secrets SHALL NOT exist in:

```text
Git
container images
frontend bundles
plain environment files committed to repository
logs
documentation
```

Use the platform secret-management infrastructure.

---

# 137. Signing Keys

OIDC signing keys SHALL receive high-assurance protection.

Prefer managed:

```text
KMS
HSM
```

where feasible.

---

# 138. Signing Key Rotation

Rotation SHALL support verification overlap where necessary for still-valid short-lived tokens.

---

# 139. Environment Separation

At minimum:

```text
development
staging
production
```

SHALL have separate:

* Keycloak clients;
* client credentials;
* issuer configuration;
* workload identities;
* secrets;
* callback URLs;
* runtime data.

---

# 140. Production Issuer

Production services SHALL reject staging/development issuers.

---

# 141. Go Token Validation Example

Illustrative CP implementation:

```go
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	AZP       string   `json:"azp"`
	ActorType string   `json:"actor_type"`
	Scope     string   `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func ValidateClaims(
	claims Claims,
	expectedIssuer string,
	requiredAudience string,
	requiredActor string,
) error {
	if claims.Issuer != expectedIssuer {
		return ErrInvalidIssuer
	}

	if !contains(claims.Audience, requiredAudience) {
		return ErrInvalidAudience
	}

	if claims.ActorType != requiredActor {
		return ErrInvalidActorType
	}

	if time.Now().Unix() >= claims.ExpiresAt {
		return ErrExpiredToken
	}

	return nil
}
```

Cryptographic signature and algorithm validation SHALL occur before claims are trusted.

---

# 142. Context Authorization Example

```go
func ResolveContext(
	ctx context.Context,
	principal Principal,
	req ContextRequest,
) (ResolvedContext, error) {

	identity, err := identities.ResolveExternalIdentity(
		ctx,
		principal.Issuer,
		principal.Subject,
	)
	if err != nil {
		return ResolvedContext{}, ErrIdentityUnknown
	}

	if identity.Status != StatusActive {
		return ResolvedContext{}, ErrIdentityDisabled
	}

	membership, err := memberships.FindActive(
		ctx,
		identity.ID,
		req.TenantID,
	)
	if err != nil {
		return ResolvedContext{}, ErrMembershipDenied
	}

	entitlement, err := entitlements.Resolve(
		ctx,
		req.TenantID,
		req.Capability,
	)
	if err != nil {
		return ResolvedContext{}, ErrCapabilityDenied
	}

	instance, err := engines.ResolveInstance(
		ctx,
		entitlement.BindingID,
		req.MarketID,
	)
	if err != nil {
		return ResolvedContext{}, ErrEngineUnavailable
	}

	return ResolvedContext{
		CanonicalIdentityID: identity.ID,
		TenantID:            membership.TenantID,
		MarketID:            req.MarketID,
		EngineInstanceID:    instance.ID,
	}, nil
}
```

---

# 143. Domain Enforcement Example

CP context SHALL never replace domain checks.

Conceptual Trade request:

```typescript
const context = await cp.resolveContext(request)

const buyerMembership =
  await buyerMembershipService.findActive({
    canonicalIdentityId: context.canonical_identity_id,
    buyerOrganizationId: request.buyerOrganizationId,
  })

if (!buyerMembership) {
  throw new ForbiddenError("BUYER_MEMBERSHIP_REQUIRED")
}

await purchasePolicy.authorize({
  membership: buyerMembership,
  order: order,
})
```

---

# 144. Tenant Isolation Query Rule

All tenant-scoped repositories SHALL require trusted server-resolved tenant context.

Bad:

```python
orders = Order.objects.filter(
    tenant_id=request.query_params["tenant_id"]
)
```

Preferred conceptual pattern:

```python
context = resolve_authorized_context(request)

orders = Order.objects.filter(
    tenant_id=context.tenant_id
)
```

Even where Django is not the implementation language of a given service, the security rule is universal.

---

# 145. B2B Context Switching

```text
Buyer User
    │
    ▼
My Organizations
    │
    ├── Company A
    └── Company B
          │
          ▼
Select Company B
          │
          ▼
Server validates membership
          │
          ▼
Trade context becomes Company B
```

The browser SHALL NOT be able to switch to Company C without membership.

---

# 146. Multi-Region Context Example

```json
{
  "tenant_id": "ten_thamani",
  "legal_entity_id": "le_thamani_za",
  "market_id": "mkt_za",
  "region_id": "reg_za_01",
  "capability": "trade",
  "engine_instance_id": "eng_trade_za_01"
}
```

---

# 147. Failover and Region Context

Failover SHALL NOT silently change regulatory/business context.

Example:

```text
Market = ZA
```

must remain:

```text
Market = ZA
```

even if the runtime service temporarily executes in an approved DR region.

Runtime location and Market remain different dimensions.

---

# 148. Data Sovereignty Rule

A DR region SHALL only process identity data if allowed by:

```text
residency policy
jurisdiction policy
tenant policy
system classification
```

---

# 149. Digital Estate Login UX

Digital Estates own:

* visual login experience;
* account screens;
* supplier onboarding screens;
* buyer organization UX;
* customer UX.

They SHALL NOT own:

* password storage;
* password verification;
* MFA secrets;
* canonical identity authority.

---

# 150. Supplier Frontend Flow

```text
Supplier visits Estate
       │
       ▼
Register representative identity
       │
       ▼
IAM verifies identity
       │
       ▼
Create/resolve CanonicalIdentity
       │
       ▼
Supplier application
       │
       ▼
Company details
       │
       ▼
Products/categories
       │
       ▼
Markets
       │
       ▼
Documents
       │
       ▼
Submit
       │
       ▼
Verification / Vetting
       │
       ├── Need more info
       ├── Reject
       ├── Conditional approve
       └── Approve
```

---

# 151. Supplier Approval Flow

```text
SUBMITTED
    │
    ▼
Identity checks
    │
    ▼
Company checks
    │
    ▼
Tax/legal checks
    │
    ▼
Bank verification
    │
    ▼
Product/category verification
    │
    ▼
Market eligibility
    │
    ▼
Risk / compliance
    │
    ▼
Decision
 ┌──┼────────────┐
 ▼  ▼            ▼
Reject Conditional Approve
```

---

# 152. Bank Detail Change Flow

```text
Supplier Finance User
        │
        ▼
Authenticated
        │
        ▼
Supplier membership valid?
        │
        ▼
Finance role valid?
        │
        ▼
Fresh step-up authentication?
        │
        ▼
Submit bank change
        │
        ▼
Verification workflow
        │
        ▼
Nabhold approval if required
        │
        ▼
Apply
        │
        ▼
Audit + notification
```

---

# 153. Identity Linking Flow

```text
Existing authenticated identity
         │
         ▼
Request new login method
         │
         ▼
Step-up if required
         │
         ▼
Authenticate new external identity
         │
         ▼
Check issuer + subject uniqueness
         │
         ▼
Explicit linking decision
         │
         ▼
Attach ExternalIdentity
```

Never:

```text
same email → auto link
```

---

# 154. Session Strategy

Sessions SHALL have bounded lifetimes.

Privileged sessions SHOULD be shorter than ordinary customer sessions.

High-risk actions SHOULD additionally use `auth_time`, `acr`, or `amr`.

---

# 155. Logout Semantics

Baobab SHALL distinguish:

```text
application logout
IAM SSO logout
global session revocation
```

A Thamani user logging out of one device does not automatically need global account logout unless requested/policy-driven.

---

# 156. Compromised Identity Flow

```text
Suspicious activity
      │
      ▼
Suspend identity
      │
      ▼
Revoke sessions
      │
      ▼
Revoke suspicious credentials
      │
      ▼
CP denies new context
      │
      ▼
Publish security event
      │
      ▼
Trade / ERP / CMS / Pulse restrict
      │
      ▼
Investigate
      │
      ▼
Controlled recovery
```

---

# 157. Tenant Kill Switch

Security/platform operations SHALL be able to suspend a Tenant.

```text
Tenant SUSPENDED
       │
       ▼
CP context resolution
       │
       ▼
DENY
```

even if:

```text
IAM login succeeds
```

---

# 158. Workload Kill Switch

Individual workload identity SHALL be independently revocable.

```text
erp-sync compromised
      │
      ▼
revoke erp-sync
```

shall NOT require revoking:

```text
trade-api
pulse-worker
cms-api
```

---

# 159. Failure Policy

Baobab SHALL generally fail closed for:

```text
invalid token
unknown identity
disabled identity
missing membership
suspended tenant
missing capability
ambiguous context
invalid market
wrong audience
wrong actor type
required step-up absent
domain role missing
```

---

# 160. Failure Matrix

| Layer    | Condition                      | Result |
| -------- | ------------------------------ | ------ |
| IAM      | Invalid token                  | DENY   |
| IAM      | Disabled identity              | DENY   |
| CP       | Missing Tenant membership      | DENY   |
| CP       | Tenant suspended               | DENY   |
| CP       | Capability not entitled        | DENY   |
| CP       | Engine mapping ambiguous       | DENY   |
| Trade    | Buyer membership revoked       | DENY   |
| Trade    | Customer order not owned       | DENY   |
| Supplier | Supplier suspended             | DENY   |
| ERP      | AD_User inactive               | DENY   |
| ERP      | AD_Role absent                 | DENY   |
| CMS      | Publishing role absent         | DENY   |
| Pulse    | Restricted report unauthorized | DENY   |

---

# 161. Required Threat Model

At minimum evaluate:

```text
credential stuffing
brute force
session theft
token replay
JWT algorithm confusion
wrong audience
cross-tenant traversal
context spoofing
buyer organization spoofing
supplier organization takeover
email auto-link takeover
account recovery abuse
MFA reset abuse
privilege escalation
confused deputy
workload credential theft
gateway header spoofing
event forgery
event replay
stale authorization cache
backup resurrection
break-glass abuse
administrator compromise
```

---

# 162. Required Negative Tests

Examples:

```text
valid token + wrong tenant → DENY

valid token + wrong market → DENY

valid token + suspended tenant → DENY

valid user + buyer org B without membership → DENY

same email + different external identity → no auto-link

customer token → Medusa admin → DENY

supplier identity → buyer authority → DENY

workload token used as human session → DENY

human token used as workload credential → DENY

IAM admin without ERP role → ERP business operation DENY

MFA success without payment permission → DENY
```

---

# 163. Cross-Tenant Test Matrix

| Test                                  | Expected                            |
| ------------------------------------- | ----------------------------------- |
| Tenant A user reads Tenant A          | ALLOW if domain allows              |
| Tenant A user reads Tenant B          | DENY                                |
| Executive cross-tenant role reads B   | ALLOW if explicit                   |
| Executive writes B without permission | DENY                                |
| Workload A invokes Tenant B context   | DENY unless explicitly authorized   |
| Spoof `X-Tenant-ID`                   | DENY                                |
| Change tenant in request body         | Server revalidates                  |
| Stale membership cache after revoke   | DENY within bounded security window |

---

# 164. Multi-Region Test Matrix

| Scenario                                   | Expected                            |
| ------------------------------------------ | ----------------------------------- |
| ZA user routed to ZA engine                | Correct                             |
| UG user routed to UG engine                | Correct                             |
| Region failure                             | Approved failover                   |
| Failover violates residency policy         | DENY / remain unavailable           |
| Market ZA with DR runtime                  | Market remains ZA                   |
| Duplicate identity in two regions          | Reconcile to same CanonicalIdentity |
| Revoked account in primary then DR restore | Remains revoked                     |

---

# 165. B2B Test Matrix

```text
registration
company verification
invite
invite expiry
multi-company membership
buyer-admin removal
purchaser vs approver
high-value approval
cross-buyer isolation
company suspension
email-domain takeover
account recovery
supplier/buyer dual relationship
```

---

# 166. B2C Test Matrix

```text
registration
verification
passkey login
guest checkout
guest cart
guest-to-account conversion
order isolation
social login
identity linking
account recovery
email change
account closure
customer suspension
```

---

# 167. Supplier Test Matrix

```text
representative registration
supplier application
company verification
document expiry
product eligibility
market eligibility
estate eligibility
conditional approval
rejection
suspension
bank change
admin invitation
admin removal
multi-estate relationship
buyer/supplier dual identity
```

---

# 168. ERP Test Matrix

```text
OIDC login
unknown CanonicalIdentity
missing AD_User
inactive AD_User
missing AD_Role
wrong AD_Client
wrong AD_Org
cross-entity access
multi-org user
finance MFA
step-up
offboarding
local password disabled
break-glass
```

---

# 169. IAM DR Test Matrix

```text
Keycloak replica failure
node failure
database failover
Keycloak restart
signing-key rotation
TLS renewal
backup restore
PITR
revoked identity restore
revoked workload restore
suspended tenant restore
session invalidation
security journal reconciliation
```

---

# 170. CI/CD Security Gates

Every IAM-related PR SHOULD include relevant checks.

Example:

```text
lint
unit tests
contract validation
container build
dependency scan
secret scan
SBOM generation
integration tests
OIDC tests
negative security tests
migration tests
```

---

# 171. Deployment Promotion

```text
PR
 │
 ▼
CI
 │
 ▼
Development
 │
 ▼
Integration tests
 │
 ▼
Staging
 │
 ▼
Security tests
 │
 ▼
Approval
 │
 ▼
Production
 │
 ▼
Post-deployment smoke tests
```

---

# 172. Configuration Promotion

Keycloak configuration SHOULD follow the same promotion path as code.

Production IAM configuration SHALL not rely on undocumented manual console operations.

---

# 173. Secrets Promotion

Secrets SHALL NOT be copied through Git promotion.

Secrets SHALL be provisioned separately by environment.

---

# 174. Production Keycloak Image

The image SHALL be pinned.

Example:

```yaml
keycloak:
  version: "26.x.y"
  image: "quay.io/keycloak/keycloak@sha256:<approved-digest>"
```

`latest` SHALL NOT be used.

---

# 175. Container Hardening

Production image SHOULD:

```text
run as non-root where supported
minimize added packages
pin dependencies
scan vulnerabilities
publish SBOM
use read-only filesystem where compatible
drop unnecessary capabilities
```

---

# 176. Example Kubernetes Deployment

Illustrative:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: baobab-iam
spec:
  replicas: 4

  selector:
    matchLabels:
      app: baobab-iam

  template:
    metadata:
      labels:
        app: baobab-iam

    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: baobab-iam

      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak@sha256:PINNED_DIGEST

          args:
            - start

          env:
            - name: KC_DB
              value: postgres

            - name: KC_DB_URL
              valueFrom:
                secretKeyRef:
                  name: baobab-iam-db
                  key: url

          readinessProbe:
            httpGet:
              path: /health/ready
              port: 9000

          livenessProbe:
            httpGet:
              path: /health/live
              port: 9000

          resources:
            requests:
              cpu: "1"
              memory: "2Gi"
            limits:
              cpu: "2"
              memory: "4Gi"
```

Exact health ports/settings SHALL follow the pinned Keycloak release.

---

# 177. Pod Disruption

Production SHALL have an appropriate `PodDisruptionBudget`.

Illustrative:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: baobab-iam
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: baobab-iam
```

---

# 178. Multi-Region Infrastructure Example

```text
                            GLOBAL DNS
                                │
                                ▼
                        REGION ROUTING POLICY
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
       SOUTH AFRICA REGION                 UGANDA/DR REGION
              │                                   │
       ┌──────┴──────┐                    ┌───────┴───────┐
       ▼             ▼                    ▼               ▼
      AZ-A           AZ-B                 AZ-A            AZ-B
       │             │                    │               │
    Keycloak      Keycloak             Keycloak?       Keycloak?
       │             │                    │               │
       └──────┬──────┘                    └───────┬───────┘
              ▼                                   ▼
        Primary HA DB                       DR / supported
                                             architecture
```

Whether both regions actively authenticate SHALL depend on the supported Keycloak topology, residency, latency, and consistency guarantees.

---

# 179. Availability Rule

The platform SHALL NOT build:

```text
two independent writable Keycloak clusters
+
async replicated databases
+
no fencing/conflict control
```

as an improvised active-active architecture.

---

# 180. Regional Engine Architecture

IAM architecture and domain-engine regionalization are related but not identical.

Example:

```text
                       GLOBAL CANONICAL IDENTITY

                              BAOBAB CP

         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
      REGION ZA             REGION UG             FUTURE REGION
         │                      │
   ┌─────┼─────┐          ┌─────┼─────┐
   ▼     ▼     ▼          ▼     ▼     ▼
 Trade  ERP   CMS        Trade  ERP   CMS
```

---

# 181. CapabilityBinding

Capability routing SHOULD remain explicit.

Conceptually:

```text
CapabilityBinding
────────────────────────────────
id
tenant_id
market_id
capability_id
engine_instance_id
status
priority
effective_from
effective_until?
```

---

# 182. Regional Capability Resolution

Example:

```text
Tenant = Zuribeans
Market = UG
Capability = ERP
```

may resolve:

```text
EngineInstance = baobab-erp-ug-01
```

while:

```text
Tenant = Zuribeans
Market = ZA
Capability = ERP
```

could resolve:

```text
EngineInstance = baobab-erp-za-01
```

---

# 183. Identity Mapping Across Regional Engines

One CanonicalIdentity may map to:

```text
AD_User 100003
on ERP ZA
```

and:

```text
AD_User 100044
on ERP UG
```

Therefore mapping key SHALL include `EngineInstance`.

---

# 184. API Error Contract

Security errors SHOULD return stable machine-readable codes.

Example:

```json
{
  "error": {
    "code": "BAOBAB_CONTEXT_DENIED",
    "reason": "TENANT_SUSPENDED",
    "decision_id": "dec_123"
  }
}
```

Avoid exposing sensitive internal reasoning.

---

# 185. Reason Code Registry

Suggested common codes:

```text
INVALID_TOKEN
INVALID_ISSUER
INVALID_AUDIENCE
TOKEN_EXPIRED

IDENTITY_UNKNOWN
IDENTITY_SUSPENDED
IDENTITY_DISABLED

MEMBERSHIP_MISSING
MEMBERSHIP_REVOKED
MEMBERSHIP_EXPIRED

TENANT_SUSPENDED
LEGAL_ENTITY_NOT_ALLOWED
MARKET_NOT_ALLOWED

CAPABILITY_NOT_ENTITLED
ENGINE_BINDING_MISSING

MFA_REQUIRED
STEP_UP_REQUIRED

DOMAIN_PERMISSION_DENIED
RESOURCE_OWNERSHIP_DENIED
```

---

# 186. Rate Limiting

Authentication endpoints SHALL have controls for:

```text
login
registration
verification resend
password recovery
MFA challenge
identity linking
organization invitation acceptance
```

---

# 187. Enumeration Resistance

External responses SHOULD avoid revealing whether:

```text
email exists
username exists
administrator exists
supplier account exists
```

when disclosure is unnecessary.

---

# 188. Security Notifications

Notify users for significant events:

```text
password changed
passkey added
passkey removed
MFA reset
new identity provider linked
email changed
account recovered
new privileged login
```

---

# 189. Privacy

Identity profile data SHALL be minimized.

IAM should generally store identity/security attributes.

Commerce profile remains Trade-owned.

ERP profile remains ERP-owned.

Supplier due-diligence data remains supplier-domain-owned.

---

# 190. Profile Ownership Matrix

| Attribute              | Authority                          |
| ---------------------- | ---------------------------------- |
| Authentication subject | IAM                                |
| Authentication email   | IAM                                |
| Passkeys               | IAM                                |
| Password               | IAM                                |
| MFA                    | IAM                                |
| Canonical ID           | CP                                 |
| Tenant membership      | CP                                 |
| Buyer role             | Trade                              |
| Customer addresses     | Trade                              |
| Order history          | Trade                              |
| Supplier approval      | Supplier domain                    |
| Supplier bank data     | Supplier domain/ERP as appropriate |
| AD_Role                | ERP                                |
| ERP finance permission | ERP                                |
| CMS publishing role    | CMS                                |

---

# 191. No Cross-Database Joins

Applications SHALL NOT perform database joins directly between:

```text
Keycloak DB
CP DB
Trade DB
ERP DB
CMS DB
Pulse DB
```

Cross-system relationships SHALL use:

```text
APIs
events
CanonicalEntity
ExternalReference
Mapping
```

---

# 192. Mapping Spine

```text
CanonicalIdentity
       │
       ├── Keycloak ExternalIdentity
       │
       ├── Medusa AuthIdentity
       │
       ├── Medusa Customer/User
       │
       ├── iDempiere AD_User
       │
       ├── Payload User
       │
       └── Pulse Actor
```

---

# 193. Canonical Business Entity Spine

```text
CanonicalEntity
       │
       ├── LegalEntity
       ├── BuyerOrganization
       ├── SupplierOrganization
       ├── Medusa organization/customer references
       ├── iDempiere C_BPartner
       └── CMS references
```

---

# 194. Identity and Business Entity Separation

```text
CanonicalIdentity
       │
       │ represents
       ▼
     Person

CanonicalEntity
       │
       │ represents
       ▼
Company / Organization / Business Entity
```

A membership connects them.

---

# 195. Suggested Membership Model

```json
{
  "membership_id": "mem_001",
  "canonical_identity_id": "cid_001",
  "entity_id": "ce_supplier_001",
  "membership_type": "SUPPLIER_REPRESENTATIVE",
  "status": "ACTIVE",
  "effective_from": "2026-08-01T00:00:00Z",
  "effective_until": null
}
```

---

# 196. Idempotency

Provisioning APIs SHALL accept an idempotency key where duplicate creation risk exists.

Example:

```http
Idempotency-Key: 01JZ6BXAMK7BNF37A7K14T1XFR
```

Particularly for:

```text
CanonicalIdentity creation
Medusa customer creation
supplier onboarding
engine actor provisioning
membership invitation
```

---

# 197. Concurrency Safety

Concurrent first logins SHALL NOT create two:

```text
CanonicalIdentity
Medusa Customer
AD_User mapping
SupplierRepresentative
```

records for the same logical subject.

Use:

```text
database uniqueness
transaction
upsert
idempotency
```

as appropriate.

---

# 198. Migration Strategy

Existing engine-local identities SHALL be migrated without replacing historical domain actors unnecessarily.

---

# 199. Medusa Migration

```text
Existing Customer
      │
      ▼
Verify human identity
      │
      ▼
Create/resolve CanonicalIdentity
      │
      ▼
Link Medusa AuthIdentity
      │
      ▼
Verify OIDC login
      │
      ▼
Disable legacy credential
```

Orders/customer IDs remain intact.

---

# 200. ERP Migration

```text
Existing AD_User
      │
      ▼
Verify workforce identity
      │
      ▼
CanonicalIdentity
      │
      ▼
Explicit mapping
      │
      ▼
Verify OIDC SSO
      │
      ▼
Disable ordinary local password
```

Existing:

```text
AD_Role
AD_Client
AD_Org
transaction history
```

remain preserved.

---

# 201. No Email-Only Migration

Migration MAY use email to discover candidates.

It SHALL NOT finalize identity linkage based only on email equality.

---

# 202. Implementation Programme

The consolidated specification SHOULD be implemented in Gates.

---

# 203. Gate IAM-0 — Architecture Foundation

Deliver:

```text
ADRs committed
technical specification committed
threat model
repository ownership
security principles
dependency map
```

Exit criteria:

```text
architecture approved
no unresolved authority ambiguity
```

---

# 204. Gate IAM-1 — Shared Contracts

Implement in `baobab-platform/shared`:

```text
Principal
ExternalIdentity
CanonicalIdentityReference
AuthenticationAssurance
AuthorizationContext
AuthorizationDecision
Lifecycle events
SecurityEvent envelope
Reason codes
```

Exit:

```text
schemas versioned
contract tests pass
```

---

# 205. Gate IAM-2 — IAM Repository / Keycloak Foundation

Implement:

```text
baobab-iam repo structure
pinned Keycloak
PostgreSQL configuration
realm provisioning
clients
scopes
base authentication flows
configuration tests
```

---

# 206. Gate IAM-3 — Control Plane Identity Spine

Implement:

```text
CanonicalIdentity
ExternalIdentity
issuer+subject resolution
membership lifecycle
context resolution
authorization decision
decision ID
audit
```

---

# 207. Gate IAM-4 — Workload Identity

Implement:

```text
service clients
client credentials
actor_type=workload
workload registry
scopes
audiences
CP workload context
mTLS integration
```

---

# 208. Gate IAM-5 — Workforce SSO

Integrate:

```text
Nabhold digital estate
CP administration
CMS admin
Pulse admin
Trade admin
```

with central workforce authentication.

---

# 209. Gate IAM-6 — Zuribeans B2B

Implement:

```text
buyer identity
buyer company
company onboarding
invitation
buyer membership
role separation
purchase authority
multi-company context
cross-buyer tests
```

---

# 210. Gate IAM-7 — Thamani B2C

Implement:

```text
customer OIDC
guest flow
Medusa customer mapping
social login readiness
guest-to-account conversion
recovery
customer isolation
```

---

# 211. Gate IAM-8 — Supplier Identity

Implement cross-estate:

```text
supplier representative
supplier organization
registration
vetting
approval
product capability
market eligibility
estate sourcing relationships
supplier roles
supplier lifecycle
```

---

# 212. Gate IAM-9 — Medusa Integration

Implement:

```text
baobab-oidc provider
AuthIdentity mapping
customer actor
admin user actor
migration
negative tests
legacy credential retirement
```

---

# 213. Gate IAM-10 — ERP Integration

Implement:

```text
iDempiere OIDC
CanonicalIdentity → AD_User
CP → AD_Client/AD_Org mappings
SSO
MFA assurance
role preservation
local password migration
```

---

# 214. Gate IAM-11 — Credential Security

Implement:

```text
password baseline
passkeys
WebAuthn
TOTP
recovery codes
MFA policies
step-up policies
account recovery
security notifications
```

---

# 215. Gate IAM-12 — Lifecycle / Deprovisioning

Implement:

```text
identity lifecycle
membership lifecycle
workload lifecycle
session revocation
deprovisioning saga
events
reconciliation
orphan detection
```

---

# 216. Gate IAM-13 — Audit / Observability

Implement:

```text
security events
structured audit
OpenTelemetry
decision IDs
correlation
redaction
metrics
alerts
SIEM export
```

---

# 217. Gate IAM-14 — HA / DR

Implement:

```text
multi-AZ Keycloak
HA PostgreSQL
backup
PITR
restore tests
revocation-safe restore
security journal
DR runbooks
RPO/RTO measurement
```

---

# 218. Gate IAM-15 — Multi-Region Readiness

Implement:

```text
Region model
residency constraints
regional EngineInstance mapping
regional CapabilityBinding
approved DR routing
cross-region security tests
```

Do not necessarily enable multi-region active-active IAM at this Gate.

The goal is architectural readiness.

---

# 219. Gate IAM-16 — Production Hardening

Validate:

```text
penetration tests
cross-tenant isolation
credential attack controls
rate limiting
secret scanning
container hardening
SBOM
dependency scanning
DR exercise
load testing
login storm testing
incident runbooks
```

---

# 220. PR Strategy

Use:

```text
one Gate
=
one PR
```

where practical.

Each PR SHALL include:

```text
code
tests
documentation
migration
configuration
rollback notes
operational notes
```

---

# 221. Definition of Done per Gate

A Gate is done only when:

```text
implementation complete
tests passing
contract tests passing
security checks passing
documentation updated
migration tested
observability added
review completed
PR merged
post-merge verification passed
```

---

# 222. Final Production Readiness Checklist

## IAM

* [ ] Dedicated `baobab-iam`
* [ ] Keycloak pinned
* [ ] One principal `baobab` realm
* [ ] Environment isolation
* [ ] Keycloak Organizations used only for identity affiliation
* [ ] Passkeys configured
* [ ] MFA configured
* [ ] Step-up configured
* [ ] Recovery configured
* [ ] Secret management established

## Control Plane

* [ ] CanonicalIdentity implemented
* [ ] ExternalIdentity implemented
* [ ] `issuer + subject` uniqueness enforced
* [ ] Tenant membership explicit
* [ ] LegalEntity separate from Tenant
* [ ] Market explicit
* [ ] Region explicit
* [ ] DigitalEstate explicit
* [ ] CapabilityBinding explicit
* [ ] EngineInstance resolution explicit
* [ ] Cross-tenant denial tested

## Trade

* [ ] Medusa custom OIDC provider
* [ ] Customer actor mapping
* [ ] Admin actor mapping
* [ ] Buyer organization membership
* [ ] Buyer roles domain-owned
* [ ] Supplier identities separated
* [ ] Guest checkout secure
* [ ] Customer isolation tested

## ERP

* [ ] iDempiere OIDC SSO
* [ ] AD_User mapping
* [ ] AD_Role remains ERP-owned
* [ ] AD_Client mapping explicit
* [ ] AD_Org mapping explicit
* [ ] Finance MFA
* [ ] Local password migration
* [ ] ERP cross-entity tests

## Supplier

* [ ] Representative identity
* [ ] Supplier organization
* [ ] Vetting workflow
* [ ] Approval lifecycle
* [ ] Product eligibility
* [ ] Market eligibility
* [ ] Estate eligibility
* [ ] Bank-change security
* [ ] Supplier admin MFA
* [ ] Multi-estate model

## Workloads

* [ ] One identity per workload boundary
* [ ] No shared service credential
* [ ] Client Credentials
* [ ] Audience restriction
* [ ] Scope restriction
* [ ] mTLS where required
* [ ] Rotation
* [ ] Revocation
* [ ] CI/CD identity separation

## Lifecycle

* [ ] Identity lifecycle
* [ ] Credential lifecycle
* [ ] Membership lifecycle
* [ ] Workload lifecycle
* [ ] Revocation events
* [ ] Reconciliation
* [ ] Orphan detection
* [ ] Joiner/mover/leaver
* [ ] Rehire safe
* [ ] Backup resurrection tests

## Audit

* [ ] Structured security audit
* [ ] Actor + subject preserved
* [ ] Decision IDs
* [ ] Correlation IDs
* [ ] Trace IDs
* [ ] OpenTelemetry
* [ ] Secrets redacted
* [ ] Privileged actions auditable
* [ ] Cross-tenant actions auditable
* [ ] SIEM-ready

## Multi-Tenant

* [ ] No realm-per-tenant
* [ ] Tenant context resolved server-side
* [ ] Buyer org ≠ Tenant
* [ ] Supplier org ≠ Tenant
* [ ] Estate ≠ Tenant
* [ ] Tenant suspension supported
* [ ] Cross-tenant privilege explicit
* [ ] tenant spoofing tests pass

## Multi-Market

* [ ] Market independent from Tenant
* [ ] market eligibility explicit
* [ ] supplier market eligibility explicit
* [ ] buyer market policies explicit
* [ ] CapabilityBinding market-aware

## Multi-Region

* [ ] Region independent from Market
* [ ] regional EngineInstance supported
* [ ] residency policy explicit
* [ ] regional routing explicit
* [ ] disaster region approved
* [ ] split-brain architecture prohibited
* [ ] failover does not change market semantics
* [ ] revoked identities survive region recovery

## Resilience

* [ ] Multi-instance Keycloak
* [ ] Multi-AZ
* [ ] HA PostgreSQL
* [ ] PITR
* [ ] Encrypted backup
* [ ] Protected backup copy
* [ ] Restore test
* [ ] Signing-key recovery
* [ ] Secret recovery
* [ ] revocation-safe recovery
* [ ] DR exercise
* [ ] RPO measured
* [ ] RTO measured
* [ ] negative security recovery tests

---

# 223. Final Target Architecture

```text
                                      ┌───────────────────────┐
                                      │    HUMAN ACTORS       │
                                      │                       │
                                      │ Workforce             │
                                      │ Buyers                │
                                      │ Suppliers             │
                                      │ Customers             │
                                      └──────────┬────────────┘
                                                 │
                                                 ▼
                                    ┌────────────────────────┐
                                    │    DIGITAL ESTATES     │
                                    │                        │
                                    │ Zuribeans              │
                                    │ Thamani                │
                                    │ Nabhold                │
                                    │ Future Estates         │
                                    └──────────┬─────────────┘
                                               │
                                               ▼
                                    ┌────────────────────────┐
                                    │       BAOBAB IAM       │
                                    │       KEYCLOAK         │
                                    │                        │
                                    │ OIDC / OAuth           │
                                    │ MFA / Passkeys         │
                                    │ Federation             │
                                    │ Credentials            │
                                    │ Sessions               │
                                    │ Workload Auth          │
                                    └──────────┬─────────────┘
                                               │
                                               ▼
                                  ┌───────────────────────────────┐
                                  │      BAOBAB CONTROL PLANE     │
                                  │                               │
                                  │ CanonicalIdentity             │
                                  │ CanonicalEntity               │
                                  │ Tenant                        │
                                  │ LegalEntity                   │
                                  │ DigitalEstate                 │
                                  │ Market                        │
                                  │ Region                        │
                                  │ Membership                    │
                                  │ Capability                    │
                                  │ CapabilityBinding             │
                                  │ EngineInstance                │
                                  │ Mapping                       │
                                  │ ExternalReference             │
                                  └───────────┬───────────────────┘
                                              │
                ┌─────────────────────────────┼─────────────────────────────┐
                │                             │                             │
                ▼                             ▼                             ▼
      ┌─────────────────┐           ┌────────────────────┐         ┌────────────────┐
      │ BAOBAB TRADE    │           │ BAOBAB ERP         │         │ BAOBAB CMS     │
      │ MedusaJS        │           │ iDempiere          │         │ Payload        │
      │                 │           │                    │         │                │
      │ Customer        │           │ AD_User            │         │ Users          │
      │ Buyer Org       │           │ AD_Role            │         │ Roles          │
      │ Buyer Roles     │           │ AD_Client          │         │ Workflow       │
      │ Orders          │           │ AD_Org             │         │ Publishing     │
      │ Procurement     │           │ Finance            │         │                │
      └────────┬────────┘           └──────────┬─────────┘         └───────┬────────┘
               │                               │                           │
               └───────────────────────────────┼───────────────────────────┘
                                               │
                                               ▼
                                  ┌────────────────────────┐
                                  │      BAOBAB PULSE      │
                                  │                        │
                                  │ Reports                │
                                  │ Intelligence           │
                                  │ Data Workspaces        │
                                  └────────────────────────┘


                         CROSS-CUTTING PLATFORM SERVICES

        ┌───────────────────┬───────────────────┬──────────────────────┐
        ▼                   ▼                   ▼                      ▼
 Infrastructure          PostgreSQL          Event Bus          Observability
 APISIX / mTLS           HA / PITR           Security Events    OTel / SIEM
 Secrets / PKI           Regional DBs        Lifecycle          Audit
 Backups / DR            Isolation           Outbox             Metrics
```

---

# 224. Final Authorization Hierarchy

Every protected action SHALL answer the following questions in order:

```text
1. WHO OR WHAT IS CALLING?
        │
        ▼
     Baobab IAM

2. IS THE TOKEN TRUSTWORTHY?
        │
        ▼
OIDC / OAuth validation

3. WHO IS THIS ACROSS BAOBAB?
        │
        ▼
CanonicalIdentity

4. IN WHICH TENANT?
        │
        ▼
Tenant Membership

5. WHICH LEGAL ENTITY?
        │
        ▼
Control Plane

6. WHICH DIGITAL ESTATE?
        │
        ▼
Control Plane

7. WHICH MARKET?
        │
        ▼
Control Plane

8. WHICH REGION / ENGINE INSTANCE?
        │
        ▼
CapabilityBinding

9. IS THIS CAPABILITY ENTITLED?
        │
        ▼
Control Plane

10. WHAT BUSINESS RESOURCE / ROLE?
        │
        ▼
Domain Engine

11. IS CURRENT AUTHENTICATION STRONG ENOUGH?
        │
        ▼
MFA / Step-Up where required

12. MAY THE ACTION EXECUTE?
        │
        ▼
ALLOW / DENY

13. CAN WE EXPLAIN WHO DID IT AND WHY?
        │
        ▼
Audit + Trace + Decision ID
```

---

# 225. Final Security Rule

The IAM implementation SHALL never collapse the platform into one universal authorization database.

Instead Baobab SHALL preserve clear authority boundaries:

```text
Identity                 → IAM

Canonical identity       → Control Plane

Tenant context           → Control Plane

Legal-entity context     → Control Plane

Market context           → Control Plane

Region routing           → Control Plane / Infrastructure

Platform entitlement     → Control Plane

Commerce authorization   → Trade

Buyer authorization      → Trade

Supplier approval        → Supplier domain

ERP authorization        → iDempiere

CMS authorization        → Payload

Pulse authorization      → Pulse

Runtime connectivity     → Infrastructure
```

The resulting architecture is intentionally:

```text
multi-tenant
multi-legal-entity
multi-estate
multi-market
multi-currency compatible
multi-engine
multi-region capable
event-driven
standards-based
zero-assumption
fail-closed
auditable
disaster-resilient
```

---

# 226. Governing Technical Principle

> **Baobab IAM authenticates identities once; the Control Plane resolves them into explicit tenant, legal-entity, estate, market, region and capability contexts; every engine retains authority over its own business permissions; all cross-system relationships use explicit canonical mappings; and no infrastructure failure, stale token, client-supplied context, duplicated credential or restored backup may silently expand an actor's authority.**

---

# 227. Implementation Outcome

When this specification is fully implemented, Baobab will have an identity architecture capable of supporting:

```text
Nabhold Group Africa
        │
        ├── Zuribeans B2B
        ├── Thamani B2C
        ├── Equator & Estate
        ├── Nabhold corporate operations
        └── future Digital Estates

across:

multiple tenants
multiple companies
multiple countries
multiple markets
multiple currencies
multiple regulatory environments
multiple cloud regions
multiple engine instances
multiple workforce/business relationships
```

without requiring identity duplication, shared credentials, realm-per-tenant proliferation, direct cross-engine database coupling, or a universal authorization super-system.

This shall be the technical foundation for Baobab's transition from an internal multi-company platform to a future externally consumable multi-tenant SaaS platform.
