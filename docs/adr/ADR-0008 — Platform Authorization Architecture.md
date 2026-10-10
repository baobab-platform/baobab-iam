# ADR-0008: Platform Authorization Architecture

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-cp`, `baobab-platform/baobab-iam`, domain engines  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Platform authorization, context resolution, entitlements, policy composition, deny precedence, authorization decisions, caching, revocation, cross-tenant enforcement, domain authorization boundaries and future policy-engine extensibility  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  
- ADR-0005 — Realm, Organization, Tenant and Legal-Entity Model  
- ADR-0006 — OIDC, OAuth and Token Profile  
- ADR-0007 — Workload Identity and Service-to-Service Authentication  

---

# 1. Context

Authentication answers:

```text
Who is this actor?
```

It does not answer:

```text
In which tenant may the actor operate?

Which legal entity may the actor represent?

Which Digital Estate may the actor access?

Which market is permitted?

Which Baobab capability is enabled?

Which engine instance should serve the request?

May a buyer submit this purchase order?

May an accountant post this journal?

May an editor publish this page?
```

Baobab therefore requires a layered authorization architecture.

The platform already has several distinct authorities:

- Baobab IAM / Keycloak;
- Baobab Control Plane;
- Trade / Medusa;
- ERP / iDempiere;
- CMS / Payload;
- future domain engines.

If authorization concerns are not deliberately separated, Baobab risks creating:

- thousands of Keycloak roles;
- hard-coded authorization inside Digital Estates;
- duplicate policies across services;
- cross-tenant privilege leaks;
- stale JWT business roles;
- gateway-specific security semantics;
- inconsistent domain authorization;
- a monolithic central policy service that must understand every business rule.

This ADR defines the authorization architecture and ownership boundaries.

---

# 2. Decision

Baobab SHALL implement authorization as a layered decision model.

The canonical architecture SHALL be:

```text
Authentication
    │
    ▼
BAOBAB IAM
identity + authentication assurance + coarse scopes
    │
    ▼
BAOBAB CONTROL PLANE
canonical identity + tenant + legal entity + market
+ Digital Estate + capability + engine entitlement
    │
    ▼
DOMAIN ENGINE
business role + resource relationship
+ workflow rules + business constraints
    │
    ▼
BUSINESS ACTION
```

The governing rule SHALL be:

> **IAM establishes identity and coarse delegated capability. The Control Plane establishes platform context and entitlement. The domain engine establishes business authorization.**

---

# 3. Three-Layer Authorization Model

Baobab SHALL distinguish three authorization layers.

| Layer | Primary authority | Question |
|---|---|---|
| Authentication / coarse access | Baobab IAM | Who is this and may this token invoke this API class? |
| Platform authorization | `baobab-cp` | In which Baobab context and capabilities may this actor operate? |
| Domain authorization | Domain engine | May this actor perform this business action on this resource? |

No layer SHALL silently absorb the responsibility of the others.

---

# 4. Layer 1 — IAM Authorization

IAM SHALL govern coarse authentication-side authorization including:

- valid authenticated subject;
- client identity;
- workload identity;
- OAuth scopes;
- authentication method;
- authentication assurance;
- session state;
- selected privileged IAM roles.

Example:

```text
scope = context:resolve
```

means:

> The client is permitted to call the Control Plane context resolver.

It does not mean:

> The client is authorized for every tenant.

---

# 5. IAM SHALL NOT Own Business Authorization

Keycloak SHALL NOT become authoritative for:

```text
purchase approval limit
buyer commercial terms
supplier approval
inventory authority
ERP accounting permission
CMS publishing permission
customer refund authority
```

These are domain permissions.

---

# 6. Layer 2 — Control Plane Authorization

`baobab-cp` SHALL own platform-level authorization.

This includes determining whether an actor is permitted to operate in a requested combination of:

```text
CanonicalIdentity
Tenant
LegalEntity
DigitalEstate
Market
Capability
EngineInstance
```

where those dimensions apply.

---

# 7. Platform Authorization Question

A Control Plane decision conceptually answers:

```text
Is actor A permitted to use capability C
in tenant T,
for entity E,
through Digital Estate D,
in market M?
```

If the answer is no, the downstream business request SHALL not proceed.

---

# 8. Layer 3 — Domain Authorization

Once platform context has been resolved, the authoritative domain engine determines whether the requested business operation is permitted.

Examples:

```text
Trade:
May Jane submit PO-1001?

ERP:
May Peter post journal J-202?

CMS:
May Maria publish article A-55?
```

The Control Plane SHALL not attempt to duplicate such domain rules.

---

# 9. Authorization Pipeline

The target flow SHALL be:

```text
Request
   │
   ▼
Token validation
   │
   ├── invalid ─────────────► DENY
   │
   ▼
IAM scope/client checks
   │
   ├── insufficient ────────► DENY
   │
   ▼
Canonical identity resolution
   │
   ├── invalid/disabled ─────► DENY
   │
   ▼
Control Plane context resolution
   │
   ├── unauthorized ─────────► DENY
   │
   ▼
Domain authorization
   │
   ├── unauthorized ─────────► DENY
   │
   ▼
ALLOW BUSINESS ACTION
```

Every stage SHALL be fail-closed.

---

# 10. Deny Precedence

An explicit deny at any authoritative layer SHALL stop the request.

Conceptually:

```text
IAM allow
+
CP deny
=
DENY
```

and:

```text
IAM allow
+
CP allow
+
Domain deny
=
DENY
```

No downstream system SHALL override an upstream platform-level denial.

---

# 11. No Accumulated Privilege

Authorization SHALL not use:

```text
"one component allowed it,
therefore globally allowed"
```

semantics.

Every required authority must independently approve the part of the decision it owns.

---

# 12. Authentication Is Necessary but Insufficient

This invariant remains fundamental:

```text
authenticated = true
```

does not imply:

```text
authorized = true
```

---

# 13. Token Scope Is Necessary but Insufficient

Likewise:

```text
scope = context:resolve
```

allows invocation of the resolver.

It does not establish the requested tenant, entity, or market.

---

# 14. Platform Context

A resolved platform context SHOULD be represented explicitly.

Conceptually:

```json
{
  "canonical_identity_id": "CI-...",
  "actor_type": "human",
  "tenant_id": "TEN-...",
  "legal_entity_id": "ENT-...",
  "digital_estate_id": "EST-...",
  "market_id": "UG",
  "capability_id": "baobab-trade",
  "engine_instance_id": "ENG-..."
}
```

The exact schema SHALL be owned by `baobab-platform/shared`.

---

# 15. Context Resolution

The typical context-resolution flow SHALL be:

```text
Authenticated actor
      │
      ▼
requested context
      │
      ▼
Control Plane
      │
      ├── canonical identity valid?
      ├── membership valid?
      ├── tenant active?
      ├── legal entity permitted?
      ├── estate active?
      ├── market enabled?
      ├── capability bound?
      ├── engine instance available?
      │
      ▼
resolved context or denial
```

---

# 16. Requested Context Is Not Granted Context

Client-supplied identifiers SHALL represent requested context only.

Example:

```json
{
  "tenant_id": "TEN-123"
}
```

means:

> Please resolve whether I may operate in TEN-123.

It does not mean:

> I am authorized for TEN-123.

---

# 17. Membership

Control Plane membership SHALL establish platform relationships such as:

```text
identity → tenant
identity → legal entity
identity → Digital Estate
```

where required.

It SHALL NOT substitute for domain membership.

---

# 18. Platform Membership Versus Trade Membership

Example:

```text
CP:
Jane may operate in Zuribeans tenant.

Trade:
Jane belongs to Acme Hotels buyer organization.
```

These are related but separate authorization facts.

---

# 19. Platform Membership Versus ERP Role

Example:

```text
CP:
Peter may operate in Nabhold ERP context.

ERP:
Peter has AD_Role allowing financial posting.
```

The first does not imply the second.

---

# 20. Tenant Lifecycle

Tenant lifecycle SHALL be a platform-level authorization condition.

If:

```text
tenant.status = SUSPENDED
```

then protected tenant operations SHALL be denied even if:

- token remains valid;
- IAM session remains active;
- domain roles remain assigned.

---

# 21. Legal Entity Lifecycle

Where legal-entity status is part of platform policy, an inactive or invalid legal-entity relationship SHALL cause denial for operations requiring that entity.

---

# 22. Digital Estate Lifecycle

A Digital Estate MAY independently be disabled.

Example:

```text
tenant = ACTIVE
estate = DISABLED
```

Requests requiring that estate SHALL be denied.

---

# 23. Market Authorization

A tenant may operate only in enabled markets.

Example:

```text
Tenant: Zuribeans
Allowed markets:
- UG
- ZA
```

A request for:

```text
KE
```

SHALL be denied until the market is explicitly enabled.

---

# 24. Capability Entitlement

A tenant SHALL not automatically have access to every Baobab engine.

Example:

```text
Tenant A
   ├── baobab-trade       ENABLED
   ├── baobab-cms         ENABLED
   └── baobab-erp         DISABLED
```

Attempting ERP access SHALL be denied at the Control Plane entitlement layer.

---

# 25. CapabilityBinding

`CapabilityBinding` SHALL remain the canonical mechanism for associating platform capability with the permitted tenant/context and engine instance.

Conceptually:

```text
Tenant
  │
  ▼
Capability
  │
  ▼
CapabilityBinding
  │
  ▼
EngineInstance
```

Authorization and routing MAY both derive from the binding, but those semantics SHALL remain explicit.

---

# 26. Engine Instance Resolution

The Control Plane MAY resolve a request to:

```text
EngineInstance
```

only after authorization context has succeeded.

Routing SHALL not precede authorization in a way that exposes unauthorized engine instances.

---

# 27. Context Resolution Is an Authorization Decision

The resolver SHALL not be treated merely as a lookup API.

It is a security decision.

Therefore its output SHALL be subject to:

- authentication;
- scope enforcement;
- policy evaluation;
- audit;
- lifecycle validation;
- fail-closed behavior.

---

# 28. Human Versus Workload Context Resolution

Context resolution SHALL support both:

```text
human actors
```

and:

```text
workload actors
```

with distinct policies.

Example:

```text
Human:
may operate in tenant because of membership.

Workload:
may resolve tenant because its service is entitled to process that tenant.
```

---

# 29. Workload Authorization

A workload identity SHALL not receive universal platform authority merely because it is a core Baobab service.

Example:

```text
baobab-trade
```

may require access to multiple Trade-enabled tenants.

It SHALL not automatically receive:

```text
all ERP administration
all IAM administration
all CMS administration
```

---

# 30. Digital Estate Authorization

Digital Estate backends SHALL receive only the platform capabilities they require.

For example:

```text
zuribeans-backend
```

may access:

```text
Trade-facing APIs
approved CP context endpoints
```

but should not receive general IAM administration or ERP financial permissions.

---

# 31. Keycloak Roles

Keycloak roles MAY be used for:

- IAM administration;
- limited workforce classifications;
- coarse client permissions.

They SHOULD NOT become:

```text
Baobab universal roles
```

such as attempting to model every buyer, supplier, ERP and CMS permission centrally.

---

# 32. OAuth Scopes

OAuth scopes SHALL authorize API classes or delegated capability.

Example:

```text
context:resolve
identity:self
tenant:read
```

Scopes SHALL be evaluated alongside:

```text
audience
actor type
client
platform context
```

where appropriate.

---

# 33. Scope Does Not Equal Role

This relationship SHALL be rejected:

```text
scope = buyer:approve
```

as a substitute for actual buyer authorization where approval depends on:

- organisation;
- purchase amount;
- approval level;
- commercial policy;
- order state.

Such authorization belongs in Trade.

---

# 34. Domain Authorization — Trade

`baobab-trade` SHALL own commerce-specific authorization.

Examples include:

```text
buyer organization membership
buyer administrator
buyer purchaser
buyer approver
purchase-order approval limits
commercial terms
delivery-site authority
refund authority
customer-specific workflows
```

---

# 35. Zuribeans B2B Example

```text
Buyer representative logs in
        │
        ▼
IAM authenticates
        │
        ▼
CP resolves:
tenant = Zuribeans
market = UG
capability = Trade
        │
        ▼
Trade resolves:
buyer organization = Acme Hotels
role = purchase approver
        │
        ▼
Trade evaluates:
PO amount
approval limit
order state
commercial rules
        │
        ▼
ALLOW / DENY
```

IAM SHALL not decide the purchase approval.

---

# 36. Domain Authorization — Thamani

Thamani consumer operations may require comparatively simple authorization.

Example:

```text
IAM:
authenticated customer

CP:
valid Thamani Trade context

Trade:
customer owns order
```

An authenticated customer SHALL not be authorized to read another customer's order.

---

# 37. Domain Authorization — Supplier

Supplier-specific authorization may include:

- supplier representative membership;
- supplier administrator rights;
- document submission rights;
- bank-data modification rights;
- product submission rights.

Supplier approval remains a domain/business status.

---

# 38. Supplier Example

```text
Supplier representative
       │
       ▼
IAM authenticated
       │
       ▼
CP valid supplier-portal context
       │
       ▼
Supplier domain:
representative active?
supplier approved?
operation permitted?
       │
       ▼
ALLOW / DENY
```

---

# 39. Domain Authorization — ERP

`baobab-erp` SHALL retain iDempiere-native authorization.

Examples:

```text
AD_User
AD_Role
AD_Client
AD_Org
window access
process access
document access
accounting access
workflow permissions
```

The Control Plane provides canonical context, not ERP permission replacement.

---

# 40. ERP Authorization Example

```text
IAM:
Peter authenticated

CP:
Peter permitted in:
Tenant = Nabhold
Entity = Nabhold legal entity
Capability = ERP

ERP:
AD_User = 100020
AD_Role = Finance_Manager
AD_Org = ZA Operations

ERP:
May Finance_Manager post this journal?
```

The final business decision belongs to ERP.

---

# 41. Domain Authorization — CMS

Payload CMS SHALL remain authoritative for editorial permissions such as:

```text
create
edit
review
publish
unpublish
archive
```

CP may determine tenant/estate context, but CMS controls content-specific authorization.

---

# 42. Domain Authorization — Pulse

Pulse SHALL own authorization around intelligence-domain resources if such permissions emerge.

For example:

```text
private report access
research workspace access
paid intelligence product entitlement
```

where these are domain-specific rather than general platform capabilities.

---

# 43. Cross-Engine Operations

A workflow crossing multiple engines SHALL require each participating authority to validate its own boundary.

Example:

```text
Trade order
    │
    ▼
ERP invoice creation
```

shall involve:

```text
Trade authorization
+
workload identity
+
CP context
+
ERP integration authorization
```

not one blanket approval.

---

# 44. Authorization Decision Model

`baobab-cp` SHOULD expose a versioned authorization/context decision contract.

Conceptually:

```json
{
  "decision": "allow",
  "subject_id": "CI-123",
  "tenant_id": "TEN-10",
  "capability": "baobab-trade",
  "engine_instance_id": "ENG-5",
  "reason_code": "CONTEXT_AUTHORIZED"
}
```

Exact fields SHALL be specified in Shared contracts.

---

# 45. Denial Model

A denied decision SHOULD use machine-readable reason codes.

Examples:

```text
IDENTITY_DISABLED
TENANT_SUSPENDED
MEMBERSHIP_MISSING
MARKET_DISABLED
CAPABILITY_NOT_BOUND
ESTATE_DISABLED
ENGINE_INSTANCE_UNAVAILABLE
POLICY_DENIED
```

These codes SHALL not expose sensitive information indiscriminately to external clients.

---

# 46. Decision Provenance

Authorization decisions SHOULD retain enough provenance to answer:

```text
which actor?
which client?
which requested context?
which policy?
which capability binding?
which decision?
which time?
```

This is critical for forensic audit and cross-tenant investigations.

---

# 47. Authorization Decision ID

Sensitive platform decisions SHOULD receive a correlation/decision identifier.

Example:

```text
authorization_decision_id
```

may be propagated to downstream audit records.

This allows:

```text
Trade audit
   │
   ▼
CP decision
```

to be correlated.

---

# 48. Decision Objects SHALL Not Become Credentials

A context/authorization decision object SHALL NOT automatically become a bearer credential.

If Baobab later adopts signed capability tokens or context tokens, that SHALL require a specific ADR.

For now, authorization decisions remain API responses or trusted server-side context.

---

# 49. Authorization Caching

Authorization results MAY be cached only where correctness and revocation requirements permit.

Caching SHALL distinguish:

```text
stable reference data
```

from:

```text
security-sensitive mutable state
```

---

# 50. Safe Cache Candidates

Potentially cacheable data may include:

- immutable canonical IDs;
- static mapping metadata;
- engine-instance descriptors;
- capability definitions.

Even these SHALL have invalidation strategy where required.

---

# 51. Sensitive Cache Candidates

Short-lived caching MAY be acceptable for:

```text
tenant status
membership
capability binding
market enablement
```

only with:

- bounded TTL;
- explicit invalidation where feasible;
- fail-safe behavior;
- documented stale-access risk.

---

# 52. Authorization Cache TTL

Authorization cache lifetime SHALL not exceed the tolerated revocation delay for the relevant permission.

A high-value administrative permission may require:

```text
near-immediate validation
```

while a low-risk read entitlement may tolerate a short cache.

---

# 53. No Unbounded Authorization Cache

This is prohibited:

```text
resolve once
cache forever
```

for mutable permissions.

---

# 54. Revocation Semantics

Baobab SHALL distinguish:

```text
IAM revocation
CP membership revocation
tenant suspension
capability removal
domain role revocation
```

Each authorization layer SHALL respond appropriately to the state it owns.

---

# 55. Membership Revocation

If Control Plane membership is revoked:

```text
IAM session may remain active
```

but:

```text
future CP context resolution must deny
```

subject to bounded cache behavior.

---

# 56. Domain Role Revocation

If a Trade buyer role is revoked:

```text
CP context may remain valid
```

but:

```text
Trade operation must deny
```

This distinction is intentional.

---

# 57. Tenant Suspension

Tenant suspension SHOULD invalidate or supersede previously cached positive context as quickly as operationally feasible.

Tenant suspension is a high-level platform security action.

---

# 58. Capability Revocation

Removing:

```text
baobab-erp
```

from a tenant's capability bindings SHALL prevent new authorized ERP context.

The tenant's IAM users do not need to be deleted.

---

# 59. Cross-Tenant Safeguards

Cross-tenant authorization SHALL be treated as a first-class risk.

Every tenant-scoped request SHALL ensure that:

```text
requested tenant
```

matches:

```text
resolved authorized tenant
```

before resource access.

---

# 60. Cross-Tenant Query Protection

Domain repositories SHALL not rely solely on user-supplied tenant filters.

Example prohibited pattern:

```text
SELECT *
FROM orders
WHERE tenant_id = request.tenant_id
```

without verified server-side context.

---

# 61. Context Injection

Once context is resolved, server-side middleware MAY make verified context available to domain handlers.

Example:

```text
request_context.tenant_id
```

SHALL be derived from authoritative resolution, not copied blindly from the incoming request.

---

# 62. Tenant Context and Database Queries

Tenant-scoped database operations SHOULD use resolved server-side context consistently.

Where practical, repository abstractions SHOULD require tenant context explicitly rather than allowing ambiguous unscoped queries.

---

# 63. Cross-Tenant Administrative Access

Platform administrators or Nabhold executives MAY legitimately operate across tenants.

Such access SHALL be explicit.

It SHALL not be implemented by omitting tenant filters.

---

# 64. Cross-Tenant Access Model

A privileged cross-tenant identity SHOULD still operate with a resolved target context:

```text
Executive
   │
   ▼
select Zuribeans
   │
   ▼
CP authorizes target context
   │
   ▼
operation runs within Zuribeans
```

rather than:

```text
Executive
   │
   ▼
unscoped global database access
```

for normal application paths.

---

# 65. Platform Administrator

A platform administrator may possess privileged Control Plane authority.

This SHALL remain separate from domain superuser rights.

Example:

```text
CP platform admin
```

does not automatically imply:

```text
iDempiere System Administrator
```

---

# 66. Break-Glass Access

If emergency/break-glass authorization is introduced, it SHALL be:

- explicit;
- time-bounded;
- strongly authenticated;
- highly audited;
- alert-generating;
- separately governed.

Break-glass SHALL not be an undocumented hidden role.

---

# 67. Superuser Policy

The platform SHOULD minimize universal superuser concepts.

Where engines require native superusers, those accounts SHALL be tightly controlled and not used for ordinary integrations.

---

# 68. Default Deny

Baobab authorization SHALL be based on:

```text
deny by default
```

A capability or action is unavailable unless positively authorized by the responsible layer.

---

# 69. Missing Policy Means Deny

If the system cannot determine whether an actor is authorized, it SHALL deny.

This includes:

```text
unknown tenant
unknown capability
ambiguous mapping
missing membership
unresolved engine instance
```

---

# 70. Policy Error Means Deny

Authorization subsystem exceptions SHALL not convert into allow.

Example:

```text
policy evaluation failed
```

must not become:

```text
fallback to allow
```

---

# 71. Gateway Authorization

APISIX MAY perform coarse route-level authorization such as:

- valid authentication required;
- client allow-list;
- rate limits;
- mTLS;
- route exposure.

It SHALL NOT become the authoritative place for dynamic tenant or business authorization.

---

# 72. Digital Estate Authorization

Digital Estates MAY hide or disable UI based on permissions for user experience.

Such UI behavior SHALL NOT constitute the security boundary.

The server SHALL independently enforce authorization.

---

# 73. Frontend Permission Checks

Example:

```text
Hide "Approve PO" button
```

is useful UX.

Trade SHALL still verify purchase approval authorization when the request is submitted.

---

# 74. Authorization and Authentication Assurance

Some operations may require:

```text
authorization
+
sufficient authentication assurance
```

Example:

```text
high-value PO approval
```

may require:

- Trade approval role;
- current platform context;
- recent MFA/step-up.

The relevant domain may request or validate authentication assurance according to ADR-0015.

---

# 75. Attribute-Based Authorization

Baobab MAY use attributes in authorization decisions.

Examples:

```text
tenant status
market
organisation relationship
purchase amount
resource owner
document state
```

However attributes SHALL be evaluated by the authority that owns them.

---

# 76. Relationship-Based Authorization

Baobab may naturally develop relationship-oriented rules such as:

```text
Jane
is member of
Acme Hotels
which owns
Purchase Order 123
```

For now, these relationships SHALL remain within the authoritative domain or Control Plane model.

No separate global relationship authorization engine is adopted by this ADR.

---

# 77. Policy Placement Principle

Policy SHALL be placed as close as possible to the authoritative data required to evaluate it.

For example:

```text
tenant active?
```

belongs in CP.

```text
purchase order approval limit?
```

belongs in Trade.

```text
journal posting permission?
```

belongs in ERP.

---

# 78. Avoid Policy Duplication

A rule SHALL NOT intentionally be implemented in:

```text
Keycloak
+
CP
+
Trade
+
Frontend
```

as four separate authoritative policies.

Defence-in-depth checks may exist, but one system SHALL own the rule.

---

# 79. Policy Authority Matrix

| Question | Authority |
|---|---|
| Token authentic? | IAM / token validator |
| Actor human/workload? | IAM claims |
| Scope granted? | IAM |
| Canonical subject exists? | CP |
| Identity active at platform level? | CP |
| Tenant exists and active? | CP |
| Actor permitted in tenant? | CP |
| Market enabled? | CP |
| Digital Estate active? | CP |
| Capability enabled? | CP |
| Engine instance permitted? | CP |
| Buyer belongs to organization? | Trade |
| Buyer may submit PO? | Trade |
| Buyer may approve PO? | Trade |
| Supplier approved? | Supplier domain |
| ERP user may post journal? | ERP |
| CMS editor may publish? | CMS |

---

# 80. Authorization Context Flow

```text
                  ACCESS TOKEN
                       │
                       ▼
               Authentication Layer
                       │
                       ▼
              CanonicalIdentity
                       │
                       ▼
               Requested Context
                       │
                       ▼
                  baobab-cp
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
      Tenant         Market       Capability
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                  EngineInstance
                       │
                       ▼
                 Domain Engine
                       │
                       ▼
              Resource Authorization
```

---

# 81. Authorization Event Model

Security-relevant authorization changes SHOULD emit canonical events where appropriate.

Examples:

```text
membership.granted.v1
membership.revoked.v1
tenant.suspended.v1
capability.granted.v1
capability.revoked.v1
```

Exact events SHALL align with Shared event conventions.

---

# 82. Decision Logging

Authorization decisions SHOULD be logged selectively.

High-value decisions SHOULD include:

```text
decision ID
canonical actor
client/workload
tenant
entity
capability
action category
result
reason code
timestamp
```

---

# 83. Sensitive Data in Authorization Logs

Authorization logs SHALL not unnecessarily include:

```text
passwords
tokens
supplier bank accounts
full customer PII
commercially sensitive payloads
```

Identifiers and reason codes SHOULD generally suffice.

---

# 84. Denial Observability

Repeated denials across:

```text
tenant boundaries
privileged routes
IAM administrative routes
ERP financial operations
```

SHOULD generate observable metrics and potentially security alerts.

---

# 85. Policy Metrics

The platform SHOULD expose metrics such as:

```text
authorization allow count
authorization deny count
context resolution failure count
cross-tenant denial count
capability denial count
membership denial count
```

with suitable labels that do not create excessive cardinality or reveal secrets.

---

# 86. Decision Latency

Authorization is on critical request paths.

Implementations SHALL measure authorization latency and avoid unnecessary policy fan-out.

This performance requirement SHALL NOT justify bypassing authoritative checks.

---

# 87. CP Context API

The Control Plane SHOULD maintain a well-defined context-resolution API.

Conceptually:

```text
POST /internal/context/resolve
```

The exact endpoint SHALL respect existing CP architecture rather than being introduced redundantly if equivalent capability already exists.

---

# 88. Context Request

Conceptually:

```json
{
  "tenant_id": "TEN-123",
  "legal_entity_id": "ENT-22",
  "digital_estate_id": "EST-ZURI",
  "market_id": "UG",
  "capability": "baobab-trade"
}
```

The authenticated caller SHALL be derived from the token.

---

# 89. Context Response

Conceptually:

```json
{
  "decision": "allow",
  "canonical_identity_id": "CI-100",
  "tenant_id": "TEN-123",
  "legal_entity_id": "ENT-22",
  "digital_estate_id": "EST-ZURI",
  "market_id": "UG",
  "capability": "baobab-trade",
  "engine_instance_id": "ENG-TRD-UG",
  "decision_id": "..."
}
```

Exact schemas SHALL be versioned in Shared.

---

# 90. Never Accept Canonical Identity from Untrusted Caller

The public caller SHALL not declare:

```text
canonical_identity_id
```

and expect the Control Plane to trust it.

The canonical actor SHALL be derived from validated authentication evidence.

---

# 91. Subject Versus Actor in Delegation

For delegated requests, context may need both:

```text
subject
```

and:

```text
actor
```

The authorization model SHALL preserve both where needed.

Example:

```text
subject = Jane
actor = baobab-trade
```

---

# 92. Confused Deputy Protection

The platform SHALL prevent a trusted service from being tricked into exercising its own broad privileges on behalf of an unauthorized caller.

Example threat:

```text
User lacks ERP access
      │
      ▼
calls Trade
      │
      ▼
Trade uses powerful ERP workload identity
      │
      ▼
ERP action succeeds
```

This SHALL be prevented through:

- explicit actor/subject separation;
- context validation;
- business authorization;
- least-privilege workload credentials.

---

# 93. Service Privilege SHALL Not Elevate User Privilege

A service's workload permission SHALL not automatically elevate the human caller.

If Trade may technically call ERP, that does not mean every Trade customer may initiate every ERP action.

---

# 94. Background Operations

For genuine service-owned tasks:

```text
inventory sync
event replay
data reconciliation
```

authorization MAY be based solely on the workload actor and platform context.

The audit record SHALL indicate that no human subject initiated the action.

---

# 95. Authorization Policy Versioning

Material Control Plane authorization policy changes SHOULD be versioned or otherwise traceable.

An audit investigation SHOULD be able to determine which policy generation produced a decision where feasible.

---

# 96. Configuration as Code

Static authorization configuration SHOULD be managed as code where appropriate.

Examples:

```text
scope registry
capability definitions
client permission templates
policy schema
```

Dynamic business memberships SHALL remain runtime data.

---

# 97. Policy Testing

Authorization rules SHALL receive direct automated tests.

Tests SHALL cover:

```text
positive cases
negative cases
cross-tenant cases
revocation
disabled tenant
missing capability
wrong actor type
wrong market
wrong estate
```

---

# 98. Property-Based Security Testing

For critical context-resolution code, Baobab SHOULD consider property-based tests establishing invariants such as:

```text
changing tenant without matching authorization
must never produce allow
```

and:

```text
removing capability binding
must never leave capability authorized
```

---

# 99. Authorization Matrix Tests

Repository integration tests SHOULD codify expected authorization matrices.

Example:

| Actor | Tenant | Capability | Expected |
|---|---|---|---|
| Trade workload | Zuribeans | Trade | allow |
| Trade workload | Zuribeans | ERP | deny unless explicit |
| Thamani backend | Thamani | Trade | allow |
| Thamani backend | Zuribeans | Trade | deny unless explicit |
| Consumer | Thamani | Trade | contextual |
| Consumer | Nabhold | ERP | deny |

---

# 100. Cross-Tenant Negative Tests

At minimum test:

```text
valid token + wrong tenant
valid token + forged tenant header
valid token + unauthorized legal entity
valid tenant + unauthorized market
valid tenant + missing capability
valid capability + wrong engine instance
```

---

# 101. Domain Negative Tests

Trade SHALL test:

```text
buyer in wrong organization
PO owned by another buyer
insufficient approval level
inactive buyer membership
```

ERP SHALL test:

```text
valid platform context
+
missing AD_Role
=
deny
```

CMS SHALL test equivalent content authorization failures.

---

# 102. No Authorization Through URL Shape

The existence of:

```text
/tenants/{tenant_id}/...
```

does not itself establish tenant authority.

Server-side context verification remains mandatory.

---

# 103. No Authorization Through Hidden UI

Likewise:

```text
button hidden
```

does not equal:

```text
operation inaccessible
```

Server-side enforcement remains authoritative.

---

# 104. No Authorization Through Database Presence

A user being present in an engine database SHALL not automatically imply current authorization.

Example:

```text
AD_User exists
```

does not mean:

```text
current ERP access allowed
```

without current role/context evaluation.

---

# 105. No Authorization Through IAM Organization Alone

Keycloak Organization membership does not establish:

```text
buyer approval authority
supplier approval
tenant entitlement
```

unless a separately authoritative relationship explicitly maps it.

---

# 106. Fine-Grained Authorization Engine

Baobab SHALL NOT introduce a dedicated global fine-grained authorization engine at this stage.

Specifically, ADR-0008 does not adopt:

```text
OpenFGA
SpiceDB
OPA
Cerbos
```

as mandatory platform infrastructure.

---

# 107. Reason for Deferral

Current authorization can be expressed naturally through:

```text
IAM
+
Control Plane
+
domain-engine policy
```

Introducing another policy service now would add:

- new runtime dependency;
- new policy language/model;
- synchronization complexity;
- new HA requirements;
- another security-critical system;
- risk of duplicate source-of-truth semantics.

The added complexity is not yet justified.

---

# 108. Future Trigger for Relationship Authorization Engine

A dedicated relationship-based authorization engine MAY be reconsidered when Baobab develops substantial cross-domain rules such as:

```text
user X
may act for organization Y
because Y owns entity Z
which participates in venture V
whose portfolio resource R
is shared with tenant T
```

at scale.

---

# 109. Future Trigger for General Policy Engine

A general policy engine MAY be reconsidered if Baobab accumulates significant portable policies involving:

```text
environmental context
regulatory rules
infrastructure policy
cross-service ABAC
```

that cannot be reasonably owned by CP or domain engines.

---

# 110. Adoption Criteria for New Authorization Engine

Before adopting one, a future ADR SHALL demonstrate:

- concrete unmet authorization requirements;
- clear source-of-truth model;
- operational ownership;
- latency impact;
- HA requirements;
- policy lifecycle;
- migration strategy;
- integration cost;
- failure behavior;
- auditability.

Technology SHALL not be adopted merely because relationship authorization is fashionable.

---

# 111. Rejected Alternative — Keycloak as Universal Authorization Engine

### Advantages

Centralized configuration.

### Disadvantages

- business-domain coupling;
- role explosion;
- stale claims;
- poor engine autonomy;
- difficult commerce/ERP workflows.

### Decision

Rejected.

---

# 112. Rejected Alternative — Control Plane Owns All Authorization

### Advantages

One policy authority.

### Disadvantages

- Control Plane must understand every business rule;
- strong domain coupling;
- reduced engine autonomy;
- large central blast radius;
- difficult evolution.

### Decision

Rejected.

CP owns platform authorization only.

---

# 113. Rejected Alternative — Engines Own Everything

### Advantages

Maximum domain autonomy.

### Disadvantages

- duplicated tenancy logic;
- inconsistent market resolution;
- inconsistent entitlement;
- cross-tenant risk;
- loss of canonical control.

### Decision

Rejected.

---

# 114. Rejected Alternative — Gateway Owns Authorization

### Advantages

Central edge enforcement.

### Disadvantages

- insufficient business context;
- hidden coupling to gateway;
- difficult service-to-service policy;
- weak domain semantics.

### Decision

Rejected.

---

# 115. Rejected Alternative — JWT Contains Full Authorization

### Advantages

Fast local evaluation.

### Disadvantages

- stale authorization;
- token bloat;
- poor revocation;
- domain leakage into IAM;
- large security blast radius.

### Decision

Rejected.

---

# 116. Rejected Alternative — Dedicated Fine-Grained Authorization Engine Now

### Advantages

Powerful policy/relationship model.

### Disadvantages

- premature complexity;
- another Tier-0 dependency;
- synchronization problems;
- unclear ownership boundary.

### Decision

Deferred.

---

# 117. Consequences

## Positive

This decision provides:

- clear policy ownership;
- strong tenant isolation;
- engine autonomy;
- reduced IAM role explosion;
- reduced JWT complexity;
- auditable platform decisions;
- explicit deny precedence;
- scalable multi-engine authorization;
- clean future extension point.

## Negative

The model requires:

- multiple authorization checks;
- careful context propagation;
- disciplined domain boundaries;
- cache invalidation;
- explicit service integration;
- stronger test coverage.

These costs are accepted.

---

# 118. Implementation Ownership

| Concern | Owner |
|---|---|
| Authentication | `baobab-iam` |
| OAuth scopes | `baobab-iam` + `shared` |
| Authentication assurance | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| Tenant authorization | `baobab-cp` |
| Legal-entity context | `baobab-cp` |
| Market context | `baobab-cp` |
| Digital Estate context | `baobab-cp` |
| Capability entitlement | `baobab-cp` |
| Engine-instance resolution | `baobab-cp` |
| Buyer authorization | `baobab-trade` |
| Consumer ownership authorization | `baobab-trade` |
| Supplier workflow authorization | supplier domain |
| ERP permission | `baobab-erp` |
| CMS permission | `baobab-cms` |
| Gateway coarse enforcement | `infrastructure` |

---

# 119. Shared Contract Requirements

`baobab-platform/shared` SHOULD define versioned contracts for:

```text
authorization context
authorization decision
denial reason
scope registry
actor type
entitlement
membership
delegation metadata
decision provenance
```

The contracts SHALL preserve distinction between:

```text
authentication
platform authorization
domain authorization
```

---

# 120. Recommended Authorization Contract

Conceptually:

```text
AuthorizationContext
────────────────────────
canonical_identity_id
actor_type
tenant_id
legal_entity_id
digital_estate_id
market_id
capability_id
engine_instance_id
decision_id
```

No field SHALL be included merely because it exists somewhere in the platform.

---

# 121. Production-Readiness Requirements

Authorization SHALL not be considered production-ready until:

- token validation is enforced;
- context resolution fails closed;
- tenant lifecycle is enforced;
- capability bindings are enforced;
- market context is enforced;
- engine-instance routing is authorized;
- domain engines independently enforce domain roles;
- cross-tenant negative tests pass;
- audit correlation exists;
- cache behavior is bounded;
- revocation behavior is tested;
- no frontend-only security controls remain;
- no engine relies solely on client-supplied tenant IDs.

---

# 122. Architectural Invariants

The following become binding:

```text
Authentication ≠ Authorization

Scope ≠ Tenant Membership

Tenant Membership ≠ Domain Permission

IAM Role ≠ Trade Role

IAM Role ≠ ERP Role

IAM Organization ≠ Business Authorization

Valid Token ≠ Valid Context

Valid Context ≠ Business Permission

Gateway Allow ≠ Domain Allow

Frontend Allow ≠ Server Allow

Workload Permission ≠ User Permission

Cross-Tenant Access Requires Explicit Authorization

Missing Policy = Deny

Policy Failure = Deny

Any Required Denial = Final Denial
```

---

# 123. Target Authorization Architecture

```text
                        ┌──────────────────────┐
                        │     BAOBAB IAM       │
                        │                      │
                        │ Identity             │
                        │ OAuth scopes         │
                        │ Auth assurance       │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │     BAOBAB CP        │
                        │                      │
                        │ Canonical identity   │
                        │ Tenant               │
                        │ Legal entity         │
                        │ Digital Estate       │
                        │ Market               │
                        │ CapabilityBinding    │
                        │ EngineInstance       │
                        └──────────┬───────────┘
                                   │
                ┌──────────────────┼──────────────────┐
                ▼                  ▼                  ▼
       ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
       │     TRADE      │ │      ERP       │ │      CMS       │
       │                │ │                │ │                │
       │ Buyer roles    │ │ AD_Role        │ │ Editor roles   │
       │ PO approval    │ │ AD_Org         │ │ Publish        │
       │ Customer own.  │ │ Accounting     │ │ Content ACLs   │
       └────────────────┘ └────────────────┘ └────────────────┘
```

Authorization is distributed by **authority**, not fragmented arbitrarily.

---

# 124. Decision Flowchart

```text
REQUEST
   │
   ▼
Is authentication valid?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
Does IAM allow this API class/scope?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
Can canonical identity be resolved?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
Is requested platform context allowed?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
Is capability enabled and routable?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
Does domain engine authorize action?
   │
   ├── NO ───────────────► DENY
   │
   ▼ YES
ALLOW
```

---

# 125. Decision Summary

Baobab SHALL implement authorization as a deliberate hierarchy:

```text
WHO?
 │
 ▼
BAOBAB IAM

WHERE / IN WHAT PLATFORM CONTEXT?
 │
 ▼
BAOBAB CONTROL PLANE

WHAT BUSINESS ACTION?
 │
 ▼
DOMAIN ENGINE
```

No one component SHALL attempt to answer all three questions.

Explicit deny SHALL take precedence.

Tenant, legal-entity, market, Digital Estate, capability and engine context SHALL be resolved through the Control Plane.

Business-resource permissions SHALL remain with the engines that own the underlying data and workflow.

A dedicated global fine-grained authorization engine SHALL remain deferred until the platform demonstrates a concrete requirement that cannot be handled cleanly by this layered model.

The governing principle is:

> **Centralize what must be globally consistent, keep business authorization with the domain that owns it, and require every security boundary to prove its own part of the decision.**