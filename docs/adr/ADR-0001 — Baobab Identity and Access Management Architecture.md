# ADR-0001: Baobab Identity and Access Management Architecture

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Scope:** Baobab Platform  
**Supersedes:** None  
**Superseded by:** None  

---

## 1. Context

The Baobab Platform is evolving into a polyrepo, polyglot platform composed of independently deployable headless engines, a central Control Plane, shared canonical contracts, infrastructure services, and multiple Digital Estates.

Principal platform components include:

- `baobab-platform/baobab-cp` — Baobab Control Plane;
- `baobab-platform/baobab-trade` — MedusaJS-based commerce engine;
- `baobab-platform/baobab-erp` — iDempiere-based ERP engine;
- `baobab-platform/baobab-cms` — Payload CMS;
- `baobab-platform/baobab-pulse` — Haystack-based intelligence platform;
- `baobab-platform/shared` — canonical cross-platform contracts;
- `baobab-platform/infrastructure` — production infrastructure and platform networking;
- Zuribeans — B2B Digital Estate;
- Thamani — B2C Digital Estate;
- Nabhold — corporate Digital Estate;
- Equator & Estate — real-estate Digital Estate;
- future Baobab Digital Estates and external tenants.

As integration progresses, authentication can no longer be treated as an implementation detail of each engine.

Zuribeans requires authenticated B2B buyers, buyer-organisation representatives, suppliers and internal operators.

Thamani requires consumer identities, supplier representatives and administrative users.

Baobab ERP requires workforce authentication while retaining iDempiere's native ERP authorization model.

Baobab Trade requires authenticated customer and organisational identities while retaining commerce-domain authorization.

Baobab Control Plane already consumes and verifies OIDC identities for protected platform operations and resolves canonical tenant and platform context.

Allowing each application to establish an independent identity system would produce duplicated credentials, inconsistent lifecycle management, fragmented MFA, incompatible identities, poor revocation behaviour and substantial cross-tenant security risk.

Baobab therefore requires a dedicated platform identity capability.

---

# 2. Problem Statement

Baobab needs to answer three fundamentally different questions:

```text
1. WHO is this actor?

2. IN WHICH Baobab context may the actor operate?

3. WHAT may the actor do inside that context?
```

These questions must not be answered by the same component merely for implementation convenience.

Authentication, platform context and business authorization have different ownership and lifecycle requirements.

A successful login must not automatically imply:

- tenant membership;
- legal-entity membership;
- Digital Estate access;
- Trade entitlement;
- supplier approval;
- purchase authority;
- ERP privileges;
- CMS publishing privileges;
- administrative authority.

Similarly, losing access to one Baobab business domain must not necessarily destroy the person's global identity.

---

# 3. Decision

Baobab SHALL establish a dedicated platform capability and repository:

```text
baobab-platform/baobab-iam
```

Baobab IAM SHALL provide the common authentication and credential-management foundation for the Baobab ecosystem.

The platform SHALL adopt the following fundamental authority model:

> **Baobab IAM proves identity. Baobab Control Plane determines canonical platform context and entitlement. Each authoritative engine determines business-domain authorization.**

The architecture SHALL therefore separate:

```text
Authentication
       │
       ▼
Baobab IAM

Platform Identity / Context
       │
       ▼
Baobab Control Plane

Business Authorization
       │
       ▼
Authoritative Domain Engine
```

No individual Digital Estate or domain engine SHALL become the master identity authority for the Baobab Platform.

---

# 4. Target Identity Plane

```text
                         BAOBAB IDENTITY PLANE

                    ┌─────────────────────────┐
                    │       Baobab IAM        │
                    │                         │
                    │ Authentication          │
                    │ OIDC / OAuth            │
                    │ Credentials             │
                    │ MFA / Passkeys          │
                    │ Sessions                │
                    │ Federation              │
                    │ Recovery                │
                    └────────────┬────────────┘
                                 │
                          signed identity
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       baobab-cp         │
                    │                         │
                    │ Canonical Identity      │
                    │ Tenant Context          │
                    │ Legal Entity            │
                    │ Membership              │
                    │ Market                  │
                    │ Entitlements            │
                    │ Platform Policy         │
                    └────────────┬────────────┘
                                 │
                       authoritative context
               ┌─────────────────┼─────────────────┐
               │                 │                 │
               ▼                 ▼                 ▼
        baobab-trade        baobab-erp        baobab-cms
           Medusa             iDempiere          Payload
               │                 │                 │
               │                 │                 │
        Commerce AuthZ        ERP AuthZ       Content AuthZ
               │                 │                 │
               └─────────────────┼─────────────────┘
                                 │
                        Digital Estates
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
               Zuribeans                    Thamani
                  B2B                          B2C
```

---

# 5. Authentication Authority

Baobab IAM SHALL be authoritative for:

- authentication;
- credential management;
- password authentication where enabled;
- passkeys/WebAuthn;
- MFA;
- authentication sessions;
- account recovery;
- identity federation;
- OIDC token issuance;
- OAuth authorization;
- workload authentication credentials;
- authentication-level security controls.

It SHALL NOT become authoritative for business-domain permissions.

---

# 6. Control Plane Authority

`baobab-cp` SHALL remain authoritative for platform-level context including:

- canonical identity association;
- tenants;
- tenant lifecycle;
- legal entities;
- Digital Estates;
- markets;
- engine instances;
- capabilities;
- capability bindings;
- platform memberships;
- product/engine entitlements;
- canonical context resolution;
- platform-level authorization.

The Control Plane SHALL consume authenticated identity evidence from Baobab IAM.

The Control Plane SHALL NOT store or validate passwords.

The Control Plane SHALL NOT implement a competing OAuth/OIDC identity provider.

---

# 7. Domain Authorization Authority

Domain engines SHALL retain authority over domain-specific permissions.

Examples include:

| Domain | Authorization examples |
|---|---|
| Trade | Buyer membership, PO approval, commercial terms |
| ERP | `AD_Role`, `AD_Client`, `AD_Org`, accounting permissions |
| CMS | Editorial and publishing permissions |
| Supplier domain | Supplier approval, product eligibility, compliance status |
| Pulse | Intelligence-resource access where domain-specific |

Authentication success alone SHALL never grant these permissions.

---

# 8. Shared Contract Authority

`baobab-platform/shared` SHALL remain the source of truth for portable identity and authorization contracts.

These contracts SHOULD include:

- principal shape;
- actor types;
- identity claims;
- OIDC scope definitions;
- workload identity;
- membership representation;
- canonical authorization context;
- identity-related events;
- audit structures.

`shared` SHALL remain a contract repository rather than becoming an IAM runtime service.

---

# 9. Identity Classes

The architecture SHALL distinguish at least three broad actor classes:

```text
                     IDENTITY ACTORS

                          Actor
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
           HUMAN         WORKLOAD       EXTERNAL
             │              │              │
        employees          Trade          buyer
        executives         ERP            customer
        operators          CMS            supplier
        administrators     Pulse          partner
                           estates
```

Actor type SHALL be explicit rather than inferred from naming conventions.

---

# 10. Canonical Identity

An IAM-provider identity SHALL NOT itself become the permanent Baobab canonical identifier.

Baobab SHALL maintain explicit mapping between:

```text
IAM Subject
     │
     ▼
Canonical Baobab Identity
     │
     ├────────────► Membership
     │
     ├────────────► Tenant
     │
     ├────────────► Legal Entity
     │
     ├────────────► Digital Estate
     │
     └────────────► ExternalReference
                         │
              ┌──────────┼───────────┐
              ▼          ▼           ▼
            Trade       ERP         CMS
```

This allows Baobab to change or federate identity providers without changing every domain identifier.

---

# 11. Multi-Context Identity

One authenticated human may legitimately participate in several Baobab contexts.

For example:

```text
                      Person
                        │
                 Canonical Identity
                        │
          ┌─────────────┼──────────────┐
          │             │              │
          ▼             ▼              ▼
       Nabhold      Zuribeans       Thamani
       employee        buyer         consumer
          │             │              │
          ▼             ▼              ▼
      ERP access    Buyer Org      Customer
```

Separate accounts SHALL NOT be required solely because one person has multiple business relationships.

---

# 12. Tenant and Organisation Separation

The following concepts SHALL remain semantically distinct:

```text
Identity
Tenant
Legal Entity
Organisation
Digital Estate
Customer
Buyer Organisation
Supplier Organisation
Engine User
```

In particular:

> An IAM organisation does not automatically constitute a Baobab Tenant.

Likewise:

> A Baobab Tenant does not necessarily correspond one-to-one with a legal entity in every future deployment.

Explicit mappings SHALL be used.

---

# 13. Human Authentication Flow

```text
Human
  │
  ▼
Digital Estate / Admin Application
  │
  ▼
Baobab IAM
  │
  │ authenticate
  ▼
OIDC Identity
  │
  ▼
Baobab Control Plane
  │
  │ canonical resolution
  ▼
Tenant / Entity / Entitlement Context
  │
  ▼
Domain Engine
  │
  │ domain authorization
  ▼
Requested Business Operation
```

Each stage SHALL be independently enforceable.

---

# 14. Workload Authentication Flow

Service-to-service communication SHALL use workload identity rather than universal shared API credentials.

```text
Baobab Service
      │
      ├──────── mTLS where required
      │
      ▼
Baobab IAM
      │
      │ OAuth workload authentication
      ▼
Short-Lived Access Token
      │
      ▼
baobab-cp
      │
      │ context resolution
      ▼
Target Baobab Capability
```

Each workload SHALL have an independent identity and least-privilege scope.

---

# 15. B2B Authentication

For Zuribeans, authentication and commercial authority SHALL remain separate.

```text
Buyer Representative
       │
       ▼
Baobab IAM
       │
       ▼
Canonical Identity
       │
       ▼
Control Plane Context
       │
       ▼
Trade Buyer Organisation
       │
       ▼
Trade Role / Approval Authority
```

IAM SHALL NOT determine purchase limits, commercial terms or PO approval authority.

Those remain Trade concerns.

---

# 16. B2C Authentication

Thamani SHALL consume Baobab IAM for customer authentication.

```text
Consumer
   │
   ▼
Thamani
   │
   ▼
Baobab IAM
   │
   ▼
Canonical Identity
   │
   ▼
Trade Customer Mapping
   │
   ▼
Commerce Operations
```

Thamani SHALL own the customer-facing authentication experience without becoming the credential authority.

---

# 17. Supplier Identity

Supplier authentication SHALL remain separate from supplier approval.

```text
Supplier Representative
          │
          ▼
      Baobab IAM
          │
          ▼
   Verified Identity
          │
          ▼
Supplier Organisation Application
          │
          ▼
      Business Vetting
       ┌───┴────┐
       ▼        ▼
    APPROVE   REJECT
       │
       ▼
Membership / Entitlement
```

A valid authenticated identity SHALL NOT imply supplier approval.

---

# 18. Fail-Closed Principle

Baobab IAM integrations SHALL fail closed for protected operations.

The following SHALL NOT result in authorization:

- IAM unavailable;
- invalid signature;
- unknown issuer;
- wrong audience;
- expired token;
- unresolved canonical identity;
- inactive tenant;
- revoked membership;
- missing product entitlement;
- insufficient domain permission.

A cryptographically valid token SHALL never override a failed Control Plane context decision.

---

# 19. Security Principle

IAM SHALL be treated as **Tier-0 security infrastructure**.

Compromise of IAM can potentially compromise every relying application.

The implementation SHALL therefore emphasise:

- least privilege;
- short-lived credentials;
- MFA for privileged identities;
- strong administrative separation;
- key rotation;
- credential rotation;
- auditability;
- immutable infrastructure where practical;
- secure backups;
- tested recovery;
- strict token verification;
- minimal identity data;
- negative authorization testing.

---

# 20. Rejected Alternative — Authentication Inside baobab-cp

This alternative would implement credentials, sessions and OAuth/OIDC issuance directly in the Control Plane.

### Advantages

- fewer deployable components;
- complete internal control.

### Disadvantages

- significant custom security implementation;
- increased Control Plane attack surface;
- credential-management responsibility;
- OAuth/OIDC protocol maintenance;
- MFA implementation burden;
- recovery implementation burden;
- federation implementation burden;
- unnecessary coupling.

### Decision

Rejected.

The Control Plane is a platform governance and context authority, not a credential provider.

---

# 21. Rejected Alternative — Independent Authentication Per Engine

Under this model:

```text
Medusa     → users/passwords
iDempiere  → users/passwords
Payload    → users/passwords
Zuribeans  → users/passwords
Thamani    → users/passwords
```

### Advantages

Initial implementation simplicity.

### Disadvantages

- credential duplication;
- poor SSO;
- fragmented MFA;
- inconsistent deprovisioning;
- difficult auditing;
- identity ambiguity;
- increased attack surface;
- poor user experience.

### Decision

Rejected.

---

# 22. Rejected Alternative — Digital Estate as Identity Authority

Zuribeans and Thamani could independently own authentication.

This would tightly couple platform identity to presentation applications and make cross-estate identity increasingly difficult.

### Decision

Rejected.

Digital Estates are authentication clients, not platform identity authorities.

---

# 23. Deferred Decision — Fine-Grained Authorization Engine

Systems such as:

- OpenFGA;
- SpiceDB;
- OPA;
- Cerbos;

are not adopted by this ADR.

The current architecture already provides:

```text
IAM       → authentication
CP        → platform authorization
Engines   → domain authorization
```

An additional authorization engine SHALL require a separate ADR supported by demonstrated policy complexity.

---

# 24. Consequences

## Positive

The decision provides:

- centralized authentication;
- consistent MFA;
- SSO potential;
- workload identity;
- common account recovery;
- centralized credential security;
- consistent authentication audit;
- reduced credential duplication;
- identity-provider portability through canonical mapping;
- clearer authorization boundaries;
- scalable support for future Digital Estates.

## Negative

The platform gains:

- another Tier-0 service;
- additional operational complexity;
- additional database requirements;
- key-management responsibilities;
- migration/integration work across engines;
- increased need for disaster recovery.

These costs are accepted because distributed authentication would create materially greater long-term risk.

---

# 25. Operational Consequences

An IAM outage can affect most authenticated Baobab capabilities.

Production IAM SHALL therefore require:

```text
monitoring
backups
restore testing
key recovery
database recovery
disaster-recovery procedures
administrative recovery
incident response
```

Availability SHALL never be improved by silently bypassing authentication.

---

# 26. Implementation Direction

Implementation SHALL proceed incrementally.

```text
Architecture
     │
     ▼
Shared Identity Contracts
     │
     ▼
IAM Runtime
     │
     ▼
Control Plane Integration
     │
     ▼
Workload Identity
     │
     ▼
Workforce SSO
     │
     ├─────────────┐
     ▼             ▼
Zuribeans        Thamani
B2B Identity     B2C Identity
     │             │
     └──────┬──────┘
            ▼
      Supplier Identity
            │
            ▼
    Security Hardening
```

Customer-facing authentication SHALL not precede the canonical identity and Control Plane foundations.

---

# 27. Decision Drivers

This decision prioritises:

1. security;
2. clear authority boundaries;
3. multi-tenancy;
4. identity portability;
5. engine independence;
6. standards-based integration;
7. least privilege;
8. auditability;
9. operational recoverability;
10. future Digital Estate extensibility.

Convenience of a particular engine SHALL not override these principles.

---

# 28. Invariants

The following architectural invariants are established by this ADR:

```text
Identity Provider Subject ≠ Canonical Identity

Authentication ≠ Authorization

Authentication ≠ Tenant Membership

IAM Organisation ≠ Baobab Tenant

Tenant ≠ Legal Entity by definition

Valid Token ≠ Valid Platform Context

Valid Platform Context ≠ Domain Permission

Supplier Identity ≠ Approved Supplier

Buyer Identity ≠ Purchase Authority

ERP User ≠ Canonical Identity Authority
```

Future implementations SHALL preserve these invariants unless explicitly superseded by another accepted ADR.

---

# 29. Follow-on ADRs

This parent ADR SHALL be elaborated through dedicated decisions covering:

```text
ADR-0002  Keycloak as the Baobab Identity Provider
ADR-0003  Identity Authority and Trust Boundaries
ADR-0004  Canonical Identity and External Identity Mapping
ADR-0005  Realm, Organization, Tenant and Legal-Entity Model
ADR-0006  OIDC, OAuth and Token Profile
ADR-0007  Workload Identity and Service-to-Service Authentication
ADR-0008  Platform Authorization Architecture
ADR-0009  Workforce SSO and Privileged Access
ADR-0010  Zuribeans B2B Identity and Organization Access
ADR-0011  Thamani B2C Customer Identity
ADR-0012  Supplier Identity and Representative Access
ADR-0013  MedusaJS Authentication Integration
ADR-0014  iDempiere SSO and ERP Identity Mapping
ADR-0015  Credential Security, MFA, Passkeys and Account Recovery
ADR-0016  Identity Lifecycle, Revocation and Deprovisioning
ADR-0017  IAM Audit, Security Events and Observability
ADR-0018  IAM Availability, Backup, Recovery and Disaster Resilience
```

These ADRs may refine implementation details but SHALL remain consistent with the authority boundaries established here unless this ADR is formally superseded.

---

# 30. Decision Summary

NABHOLD adopts a dedicated Baobab IAM capability as the common authentication foundation for the Baobab Platform.

The architectural responsibility chain is:

```text
             WHO ARE YOU?
                  │
                  ▼
             BAOBAB IAM
                  │
                  ▼
        WHERE MAY YOU OPERATE?
                  │
                  ▼
             BAOBAB CP
                  │
                  ▼
         WHAT MAY YOU DO HERE?
                  │
                  ▼
        AUTHORITATIVE ENGINE
```

This separation is the foundation of Baobab's identity security model.

**Baobab IAM authenticates.**

**Baobab Control Plane establishes canonical platform context and entitlement.**

**Baobab domain engines authorize business operations.**

No engine, Digital Estate, tenant, legal entity or external identity-provider identifier becomes the master identity authority for the entire Baobab Platform.