# ADR-0003: Identity Authority and Trust Boundaries

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Scope:** Baobab Identity Plane, Control Plane, Infrastructure, Digital Estates, and Domain Engines  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  

---

# 1. Context

The Baobab Platform is composed of independently deployable services and Digital Estates communicating across multiple trust boundaries.

Authentication will be centralized through Baobab IAM, implemented using Keycloak, while `baobab-cp` remains authoritative for canonical identity mapping, tenant context, legal-entity context, product entitlement and platform-level authorization.

Domain engines such as Trade, ERP and CMS remain authoritative for their own business permissions.

This architecture creates several distinct trust zones:

```text
Browser / Human
      │
      ▼
Digital Estate
      │
      ▼
Gateway / Infrastructure
      │
      ▼
Baobab IAM
      │
      ▼
Baobab Control Plane
      │
      ▼
Domain Engine
```

It also creates separate machine-to-machine trust flows:

```text
Workload
   │
   ▼
Gateway / mTLS
   │
   ▼
Baobab IAM
   │
   ▼
Control Plane
   │
   ▼
Target Engine
```

Unless these boundaries are explicitly defined, implementations may accidentally trust:

- browser-supplied tenant IDs;
- unsigned headers;
- upstream proxy headers;
- self-declared roles;
- email addresses;
- local engine identity;
- stale JWT claims;
- gateway-injected metadata;
- client-supplied organisation IDs;
- internal network location.

This ADR therefore defines the **identity authority and trust boundaries** for Baobab IAM and all relying services.

---

# 2. Decision

Baobab SHALL implement a **zero-assumption trust model** across identity boundaries.

No component SHALL trust identity, tenancy, entitlement or authorization information solely because it originates:

- from an internal network;
- from a reverse proxy;
- from a frontend;
- from another engine;
- from an HTTP header;
- from a client request body;
- from a query parameter;
- from a Digital Estate;
- from a browser cookie;
- from a previous local session.

Trust SHALL be established explicitly through:

```text
cryptographically verifiable identity
        +
canonical platform resolution
        +
domain authorization
```

The architectural chain SHALL be:

```text
Authentication evidence
        │
        ▼
Baobab IAM
        │
        ▼
Canonical identity/context
        │
        ▼
baobab-cp
        │
        ▼
Business authorization
        │
        ▼
Domain engine
```

---

# 3. Core Trust Principle

The following principle SHALL govern all identity-sensitive interactions:

> **No downstream component may infer more authority than the upstream evidence proves.**

Examples:

```text
Valid JWT
    ≠
Valid tenant access
```

```text
Valid tenant access
    ≠
Domain permission
```

```text
Organization membership
    ≠
Purchase approval authority
```

```text
Successful login
    ≠
Supplier approval
```

```text
Internal network origin
    ≠
Trusted identity
```

---

# 4. Trust Zones

Baobab SHALL explicitly model the following trust zones.

```text
┌──────────────────────────────────────────────┐
│ ZONE 0 — UNTRUSTED EXTERNAL                 │
│                                              │
│ Browsers                                     │
│ Customer devices                            │
│ Supplier devices                            │
│ External partners                           │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ ZONE 1 — EDGE / DIGITAL ESTATE              │
│                                              │
│ Zuribeans                                    │
│ Thamani                                      │
│ Nabhold                                      │
│ Other estates                               │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ ZONE 2 — PLATFORM EDGE                      │
│                                              │
│ API gateway                                  │
│ ingress                                      │
│ TLS termination                             │
│ mTLS termination where applicable           │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ ZONE 3 — IDENTITY PLANE                     │
│                                              │
│ Baobab IAM / Keycloak                       │
│ OIDC / OAuth                                │
│ sessions                                     │
│ credentials                                  │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ ZONE 4 — CONTROL PLANE                      │
│                                              │
│ canonical identity                          │
│ tenancy                                      │
│ entity context                              │
│ entitlement                                 │
│ platform policy                             │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ ZONE 5 — DOMAIN ENGINES                     │
│                                              │
│ Trade                                        │
│ ERP                                          │
│ CMS                                          │
│ Pulse                                        │
│ future engines                              │
└──────────────────────────────────────────────┘
```

Trust SHALL be re-established as requests cross these boundaries.

---

# 5. External Client Trust

All browser and external-client inputs SHALL be considered untrusted.

This includes:

```text
tenant_id
organization_id
entity_id
user_id
role
scope
market
supplier_id
buyer_id
customer_id
engine_instance_id
```

Client-supplied identifiers MAY be treated as **requested context**, but SHALL NOT become authoritative context without server-side verification.

Example:

```text
Client requests:
tenant_id = T-123
        │
        ▼
Server
        │
        ▼
baobab-cp
        │
        ▼
"Is subject S allowed in T-123?"
```

The request SHALL be denied if context resolution fails.

---

# 6. Identity Provider Trust Boundary

Baobab IAM is trusted to assert authenticated identity only after token validation succeeds.

IAM may assert:

```text
subject
issuer
client
actor_type
authentication_time
authentication_method
approved identity claims
scopes
```

IAM SHALL NOT be trusted as the authoritative source for:

```text
tenant lifecycle
legal-entity lifecycle
Trade business roles
ERP permissions
supplier approval
commerce entitlement
purchase limits
business workflow status
```

---

# 7. Control Plane Trust Boundary

`baobab-cp` SHALL trust IAM only for authentication evidence that passes full token validation.

It SHALL independently determine:

```text
canonical identity
tenant
legal entity
Digital Estate
market
capability
engine instance
entitlement
membership
platform authorization
```

The Control Plane SHALL NOT infer platform authority merely from Keycloak roles or organisation membership.

---

# 8. Domain Engine Trust Boundary

Domain engines SHALL trust Control Plane context only where that context has been obtained through an authenticated and authorized server-side interaction.

Domain engines SHALL retain authority over their own domain permissions.

Example:

```text
IAM:
"Jane authenticated"

CP:
"Jane may operate in Zuribeans / Uganda / Trade"

Trade:
"Jane is Buyer Manager for Acme Hotels"

Trade:
"Jane may approve PO-1024"
```

Each layer answers only its own question.

---

# 9. Gateway Trust Boundary

The API gateway and ingress layer MAY perform:

- TLS termination;
- mTLS enforcement;
- routing;
- rate limiting;
- header normalization;
- request-size limits;
- WAF-style controls;
- coarse authentication rejection.

However, gateway headers SHALL NOT become an independent identity authority.

This means:

```text
X-User-ID
X-Tenant-ID
X-Role
X-Organization-ID
X-Authenticated-User
```

MUST NOT be trusted merely because APISIX or another proxy forwarded them.

Downstream services SHALL rely on cryptographically verified tokens and canonical context.

---

# 10. Identity Headers

Any identity-related headers arriving from external clients SHALL be stripped or overwritten at the gateway.

Examples include:

```text
X-Baobab-Subject
X-Baobab-Tenant
X-Baobab-Entity
X-Baobab-Role
X-Baobab-Actor-Type
```

If such headers are used internally for tracing or propagated context, they SHALL:

- be created only by trusted infrastructure;
- not replace token validation;
- not replace Control Plane context resolution;
- be treated as convenience metadata;
- be validated against authoritative context where security-sensitive.

---

# 11. JWT Trust Requirements

A token SHALL be trusted only after verifying at least:

```text
signature
issuer
audience
expiration
not-before
allowed algorithm
token type where applicable
required scopes
client identity
actor type
```

Services SHALL reject tokens that:

- use unsupported algorithms;
- have invalid signatures;
- use unknown issuers;
- target the wrong audience;
- are expired;
- are not yet valid;
- are missing required claims;
- come from unauthorized clients.

---

# 12. No Algorithm Downgrade

Baobab SHALL NOT permit:

```text
alg=none
```

or permissive algorithm fallback.

Each relying service SHALL maintain an explicit allow-list of acceptable signing algorithms.

Algorithm selection SHALL not be trusted solely from the incoming token header.

---

# 13. JWKS Trust

Relying services MAY obtain signing keys through IAM JWKS endpoints.

JWKS retrieval SHALL:

- use trusted HTTPS;
- validate the issuer relationship;
- cache safely;
- refresh on key rotation;
- reject unknown keys;
- avoid arbitrary attacker-controlled JWKS URLs.

The token SHALL NOT be permitted to dictate an arbitrary key location.

---

# 14. Audience Isolation

Baobab clients SHALL use explicit audiences.

Example:

```text
baobab-control-plane
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
```

A token issued solely for:

```text
baobab-trade
```

SHALL NOT automatically be valid for:

```text
baobab-control-plane
```

unless the token profile and authorization policy explicitly permit it.

---

# 15. Actor-Type Trust

Actor type SHALL be explicit.

Typical values include:

```text
human
workload
external
```

Protected endpoints SHALL validate actor type where relevant.

Example:

```text
POST /internal/context/resolve
```

may require:

```text
actor_type = workload
```

while administrative APIs may require:

```text
actor_type = human
```

plus privileged authorization.

A workload token SHALL not silently become a human identity.

---

# 16. Workload Trust Boundary

Service-to-service trust SHALL require explicit workload identity.

Internal services SHALL NOT trust each other solely because they share:

```text
VPC
cluster
namespace
Docker network
private subnet
```

Network location MAY reduce exposure but SHALL not constitute identity.

---

# 17. Workload Authentication

Target pattern:

```text
Workload
   │
   ├── mTLS where required
   │
   └── OAuth client authentication
          │
          ▼
      Baobab IAM
          │
          ▼
Short-lived workload token
          │
          ▼
Target service / CP
```

The combination may provide:

```text
transport identity
        +
application identity
```

where justified.

---

# 18. mTLS Boundary

mTLS, where enabled, proves transport-level client identity.

It SHALL NOT replace:

- OAuth authorization;
- token validation;
- tenant-context resolution;
- business authorization.

Conceptually:

```text
mTLS
 │
 └── "Which workload opened this connection?"

OAuth
 │
 └── "What application identity and scopes does it have?"

CP
 │
 └── "Which Baobab context may it use?"

Domain Engine
 │
 └── "Which business action is allowed?"
```

---

# 19. Digital Estate Trust Boundary

Digital Estates SHALL be treated as IAM clients and business presentation layers.

They SHALL NOT be authoritative for:

- identity;
- canonical tenant context;
- engine entitlement;
- buyer authority;
- supplier approval;
- ERP roles.

They MAY collect requested context from users, but backend services SHALL verify it.

---

# 20. Browser-to-Estate Authentication

Public browser flows SHALL use:

```text
Authorization Code
+
PKCE
```

where direct OIDC browser authentication is employed.

Browser applications SHALL NOT store confidential client secrets.

Access tokens SHALL not be intentionally exposed through:

```text
URLs
analytics payloads
error messages
console logs
browser telemetry
```

---

# 21. BFF Trust Model

Where a Backend-for-Frontend is used:

```text
Browser
   │
   ▼
BFF
   │
   ▼
IAM / APIs
```

the BFF may become the protected holder of server-side credentials.

The browser SHALL still be treated as untrusted.

The BFF SHALL:

- validate sessions;
- apply CSRF protection;
- protect cookies;
- avoid returning backend secrets;
- enforce context server-side.

---

# 22. Session Trust

An IAM session proves that an authentication session exists.

It SHALL NOT permanently cache authorization state.

For example:

```text
User logs in at 09:00
Buyer membership revoked at 09:15
```

The user SHALL not retain buyer authority indefinitely merely because the IAM session remains valid.

Mutable authorization SHALL remain resolvable through appropriate platform/domain checks.

---

# 23. Token Staleness

JWTs inherently contain claims that may become stale before expiration.

Therefore, rapidly changing business permissions SHALL NOT be embedded extensively in access tokens.

Examples include:

```text
supplier approval
buyer purchase limit
tenant lifecycle
commercial authority
ERP posting privilege
```

These SHALL be resolved from authoritative systems when necessary.

---

# 24. Email Trust Boundary

Email addresses SHALL NOT be treated as durable identity proof after authentication.

This is unsafe:

```text
if token.email == database.email:
    grant access
```

Durable mapping SHALL use:

```text
issuer + subject
```

mapped to a canonical Baobab identity.

Email may remain an attribute.

---

# 25. Organisation Trust Boundary

A Keycloak organisation membership MAY establish identity-side association.

It SHALL NOT independently establish platform or domain authorization.

Example:

```text
Keycloak:
Jane belongs to Acme Hotels

        │
        ▼

CP:
Does Acme map to an active Baobab context?

        │
        ▼

Trade:
Is Jane an active buyer member?

        │
        ▼

Trade:
May Jane perform this operation?
```

---

# 26. Tenant Context

Tenant context SHALL be resolved server-side.

A request such as:

```json
{
  "tenant_id": "abc"
}
```

means:

> The caller requests to act in tenant `abc`.

It SHALL NOT mean:

> The caller is authorized for tenant `abc`.

The distinction MUST be maintained in implementation and documentation.

---

# 27. Legal-Entity Context

The same rule applies to legal-entity identifiers.

A legal entity supplied by a client SHALL be treated as requested context until matched against:

- canonical entity mapping;
- membership;
- lifecycle;
- capability;
- market;
- applicable platform policy.

---

# 28. Market Context

Market selection may influence:

- currency;
- tax;
- commerce configuration;
- ERP organization;
- catalog;
- pricing;
- regulatory behaviour.

Therefore market context SHALL not be trusted solely because the client submits:

```text
ZA
UG
KE
```

The requested market SHALL be checked against authoritative context.

---

# 29. Engine-to-Engine Calls

Direct engine-to-engine communication SHALL remain authenticated and authorized.

Example:

```text
Trade
  │
  ▼
ERP
```

shall not mean:

```text
"Trade is internal, therefore trust everything."
```

Instead:

```text
Trade workload identity
        │
        ▼
verified token / transport identity
        │
        ▼
authorized integration scope
        │
        ▼
ERP integration endpoint
```

---

# 30. No Shared Database Trust

No engine SHALL derive trust by reading another engine's database.

This includes identity data.

Prohibited:

```text
Trade querying Keycloak DB
ERP querying CP identity tables
CP querying Medusa user tables directly
```

Trust and identity mapping SHALL cross explicit APIs/contracts.

---

# 31. Canonical Context Object

The Control Plane SHOULD return a canonical context object containing only verified platform context.

Conceptually:

```json
{
  "subject_id": "canonical-subject",
  "actor_type": "human",
  "tenant_id": "tenant-123",
  "entity_id": "entity-456",
  "digital_estate": "zuribeans",
  "market": "UG",
  "capabilities": [
    "baobab-trade"
  ]
}
```

Exact fields SHALL be defined in Shared contracts.

Domain permissions SHOULD NOT be inserted here unless they are genuinely platform-level concerns.

---

# 32. Context Provenance

Downstream services SHOULD be able to determine:

```text
who requested context
which subject was resolved
which client requested it
which tenant/entity was requested
when it was resolved
which policy decision was applied
```

This improves auditing and incident investigation.

---

# 33. Delegation

Delegation SHALL be explicit.

Examples include:

- executive acting across entities;
- procurement manager acting for buyer organisation;
- supplier administrator managing representatives;
- service acting on behalf of a user.

Delegation SHALL NOT be inferred merely from role names.

Future delegated-access mechanisms SHALL preserve:

```text
actor
subject
delegated context
reason
scope
expiry
```

where applicable.

---

# 34. Impersonation

Administrative impersonation, if enabled at all, SHALL be highly restricted.

It SHALL require:

- privileged authorization;
- audit event;
- explicit target identity;
- limited duration;
- reason;
- clear UI indication;
- no silent impersonation.

Impersonation SHALL never be used as a normal support shortcut.

---

# 35. Administrative Boundary

IAM administrative functions SHALL not be exposed to ordinary Digital Estate users.

Administrative access SHALL use separate privilege controls.

Examples include:

```text
realm administration
client creation
secret rotation
identity disablement
MFA reset
federation configuration
```

These operations SHALL require stronger controls than ordinary login.

---

# 36. Recovery Trust Boundary

Account recovery SHALL restore authentication capability only.

Recovery SHALL NOT automatically reinstate:

```text
tenant membership
buyer authority
supplier approval
ERP role
commerce entitlement
```

Those remain separate business states.

---

# 37. Revocation

Baobab SHALL distinguish:

```text
credential revocation
session revocation
identity disablement
platform membership revocation
domain membership revocation
service credential revocation
```

Each SHALL affect only its intended trust layer.

---

# 38. Failure Behaviour

Identity-sensitive operations SHALL fail closed.

Examples:

| Failure | Required result |
|---|---|
| IAM token invalid | deny |
| IAM unavailable during new login | deny login |
| JWKS unverifiable | deny |
| CP context unavailable | deny protected context operation |
| Tenant inactive | deny |
| Entitlement absent | deny |
| Domain role absent | deny |
| Gateway identity header missing | do not infer identity |
| mTLS failure where required | deny |
| Workload token expired | deny |

No security-sensitive component SHALL silently downgrade to anonymous trust.

---

# 39. Availability Versus Trust

High availability SHALL not be implemented through authentication bypass.

This is prohibited:

```text
if IAM unavailable:
    trust internal requests
```

Likewise:

```text
if CP unavailable:
    use tenant_id from request
```

is prohibited.

---

# 40. Trust Boundary Diagram

```text
                      UNTRUSTED
                          │
                          ▼
                ┌───────────────────┐
                │ Browser / Client  │
                └─────────┬─────────┘
                          │
                          │ requested context
                          ▼
                ┌───────────────────┐
                │ Digital Estate    │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Gateway / Edge    │
                │ TLS / rate limit  │
                └─────────┬─────────┘
                          │
                    TRUST BOUNDARY 1
                          │
                          ▼
                ┌───────────────────┐
                │ Baobab IAM        │
                │ authenticate      │
                └─────────┬─────────┘
                          │
                    TRUST BOUNDARY 2
                          │
                          ▼
                ┌───────────────────┐
                │ baobab-cp         │
                │ canonical context │
                └─────────┬─────────┘
                          │
                    TRUST BOUNDARY 3
                          │
                          ▼
                ┌───────────────────┐
                │ Domain Engine     │
                │ business authz    │
                └─────────┬─────────┘
                          │
                          ▼
                   Business Action
```

Every boundary SHALL perform the checks appropriate to its authority.

---

# 41. Trust Decision Matrix

| Input | May be accepted as evidence? | Authoritative? |
|---|---:|---:|
| Browser tenant ID | yes, as requested context | no |
| Browser role | no | no |
| Email claim | yes, as attribute | no |
| OIDC `sub` | yes, after validation | external identity only |
| Keycloak organisation | yes | identity relationship only |
| Gateway identity header | metadata only | no |
| CP context response | yes | platform context |
| Trade buyer role | yes | Trade domain only |
| iDempiere role | yes | ERP domain only |
| mTLS client cert | yes | transport identity |
| Workload access token | yes | application identity/scopes |
| Internal IP address | network signal only | no |

---

# 42. Audit Requirements

Trust-boundary decisions SHOULD generate sufficient audit evidence to answer:

```text
WHO
authenticated?

WHICH
client?

WHAT
context was requested?

WHICH
context was granted?

WHICH
authority made the decision?

WHY
was it allowed or denied?
```

Sensitive tokens SHALL not be written to logs.

---

# 43. Logging

Logs MAY include:

```text
canonical subject ID
client ID
tenant ID
entity ID
request ID
trace ID
decision
reason code
```

Logs SHALL NOT include:

```text
access tokens
refresh tokens
passwords
client secrets
MFA secrets
recovery codes
private keys
```

---

# 44. Error Responses

Authorization failures SHALL not disclose unnecessary security-sensitive information.

For example, externally visible responses should not reveal:

```text
tenant exists but you are not a member
specific role required internally
which internal policy failed
whether an email is registered
```

Internal audit systems MAY retain more detailed reason codes.

---

# 45. Threats Addressed

This ADR primarily mitigates:

- identity spoofing;
- tenant confusion;
- organisation confusion;
- cross-tenant access;
- header spoofing;
- internal-network trust abuse;
- stale-role abuse;
- token replay;
- service impersonation;
- excessive gateway trust;
- engine-local identity drift;
- privilege escalation.

---

# 46. Rejected Alternative — Gateway as Identity Authority

Under this model, the gateway would authenticate users and inject trusted identity headers.

### Advantages

- simple downstream services;
- centralized edge authentication.

### Disadvantages

- header spoofing risk;
- excessive gateway authority;
- brittle trust;
- difficult service-to-service flows;
- hidden coupling;
- weak end-to-end verification.

### Decision

Rejected.

Gateway identity metadata may be useful, but SHALL not replace token/context verification.

---

# 47. Rejected Alternative — Internal Network as Trust Boundary

This model assumes:

```text
inside cluster = trusted
```

### Advantages

Operational simplicity.

### Disadvantages

- lateral movement after compromise;
- poor workload identity;
- weak auditability;
- no least privilege;
- dangerous assumptions.

### Decision

Rejected.

Internal network location is not identity.

---

# 48. Rejected Alternative — JWT Contains All Authorization

This approach would encode:

```text
tenants
roles
supplier status
buyer permissions
ERP permissions
commercial limits
```

inside the token.

### Advantages

- fewer runtime lookups.

### Disadvantages

- stale authorization;
- oversized tokens;
- difficult revocation;
- tight IAM-domain coupling;
- domain-model leakage;
- privilege drift.

### Decision

Rejected.

JWTs SHALL remain compact identity/authentication artifacts.

---

# 49. Rejected Alternative — Trust Email as Identity

Email-based linking is convenient.

It is also unsafe as a durable identity key because email may change, be reused, be federated differently, or be compromised.

### Decision

Rejected.

Use:

```text
issuer + subject
```

mapped to canonical identity.

---

# 50. Consequences

## Positive

This decision provides:

- explicit trust boundaries;
- reduced cross-tenant risk;
- clearer component responsibility;
- stronger workload security;
- reduced header spoofing risk;
- better auditability;
- consistent fail-closed behaviour;
- lower coupling between engines.

## Negative

It requires:

- more explicit context resolution;
- more negative-path testing;
- disciplined token validation;
- workload credential management;
- careful gateway configuration;
- more architecture documentation.

These costs are accepted.

---

# 51. Implementation Requirements

Repositories SHALL eventually enforce this ADR through:

```text
shared:
    canonical identity/context schemas

baobab-iam:
    token issuance and authentication

baobab-cp:
    verified canonical context

infrastructure:
    TLS/mTLS/gateway controls

baobab-trade:
    domain authorization

baobab-erp:
    ERP-native authorization

baobab-cms:
    CMS authorization

Digital Estates:
    authentication UX and requested-context handling
```

---

# 52. Required Negative Tests

At minimum, automated tests SHALL include:

```text
forged tenant header
forged role header
wrong issuer
wrong audience
expired token
wrong actor type
missing scope
cross-tenant context
inactive tenant
revoked membership
invalid workload client
service impersonation
email changed
organization mismatch
gateway header spoof
stale authorization claim
```

Negative security tests SHALL be considered first-class acceptance criteria.

---

# 53. Architectural Invariants

The following invariants become binding:

```text
Internal ≠ Trusted

Gateway Header ≠ Identity

Valid JWT ≠ Valid Tenant Context

Valid Context ≠ Business Permission

mTLS ≠ Business Authorization

Organization Membership ≠ Tenant Membership

Email ≠ Identity

Client Input ≠ Authoritative Context

Network Location ≠ Workload Identity

Successful Login ≠ Access Grant
```

---

# 54. Follow-On Decisions

This ADR establishes trust boundaries but intentionally does not fully define:

- canonical identity persistence;
- external-reference schema;
- token lifetime;
- refresh-token policy;
- workload credential rotation;
- domain-specific authorization models.

These are handled in subsequent ADRs.

The immediate next decision is:

```text
ADR-0004
Canonical Identity and External Identity Mapping
```

---

# 55. Decision Summary

Baobab adopts an explicit layered trust model:

```text
UNTRUSTED INPUT
      │
      ▼
AUTHENTICATE
Baobab IAM
      │
      ▼
RESOLVE PLATFORM CONTEXT
baobab-cp
      │
      ▼
AUTHORIZE BUSINESS ACTION
Domain Engine
```

Every layer SHALL trust only what the previous layer can legitimately prove.

Baobab SHALL not rely on implicit internal trust, unsigned identity headers, email matching, client-declared tenancy or engine-local assumptions.

The governing security rule is:

> **Trust is established explicitly at each architectural boundary and is never inherited merely because a request came from inside the platform.**