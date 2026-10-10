# ADR-0014: iDempiere SSO and ERP Identity Mapping

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-erp`  
**Primary Runtime Owners:** `baobab-platform/baobab-erp`, `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** iDempiere OIDC SSO, canonical identity mapping, AD_User provisioning, AD_Role preservation, AD_Client and AD_Org context, workforce ERP access, service identities, deprovisioning, role lifecycle, local account migration, privileged finance access, break-glass, audit and identity synchronization  
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
- ADR-0008 — Platform Authorization Architecture  
- ADR-0009 — Workforce SSO and Privileged Access  
- ADR-0010 — Zuribeans B2B Identity and Organization Access  
- ADR-0011 — Thamani B2C Customer Identity  
- ADR-0012 — Supplier Identity and Representative Access  
- ADR-0013 — MedusaJS Authentication Integration  

---

# 1. Context

Baobab ERP runs iDempiere.

iDempiere has its own mature authorization model centered around constructs such as:

```text
AD_User
AD_Role
AD_Client
AD_Org
Window access
Process access
Form access
Workflow access
Document access
Accounting access
```

Baobab IAM, meanwhile, has established Keycloak as the platform authentication authority.

The platform therefore requires a deliberate mapping between:

```text
Baobab identity
```

and:

```text
iDempiere ERP user
```

without replacing iDempiere's domain authorization model.

The target architecture must support:

- workforce SSO;
- multiple legal entities;
- multiple ERP organizations;
- multi-tenant Baobab context;
- finance users;
- ERP administrators;
- external integration identities;
- employee joiner/mover/leaver workflows;
- local account migration;
- emergency access;
- strict separation between platform authorization and ERP authorization.

---

# 2. Decision

Baobab SHALL use Baobab IAM for human authentication into iDempiere.

The canonical relationship SHALL be:

```text
Keycloak Identity
      │
      ▼
CanonicalIdentity
      │
      ▼
Baobab CP Context
      │
      ▼
iDempiere AD_User
      │
      ▼
AD_Role
      │
      ▼
AD_Client / AD_Org
      │
      ▼
ERP Authorization
```

Baobab IAM SHALL authenticate the user.

Baobab CP SHALL establish platform context.

iDempiere SHALL remain authoritative for ERP permissions.

---

# 3. Governing Principle

> **Baobab IAM proves who the ERP user is; the Control Plane determines the authorized Baobab context; iDempiere determines what that user may do inside ERP.**

---

# 4. Canonical Identity to AD_User Mapping

Each human ERP user SHALL map explicitly from:

```text
CanonicalIdentity
```

to:

```text
AD_User
```

The mapping SHALL use immutable identifiers.

Conceptually:

```text
CanonicalIdentity
      │
      ▼
ExternalReference / Mapping
      │
      ▼
iDempiere AD_User_ID
```

---

# 5. AD_User Is Not Canonical Identity

The following invariant SHALL remain binding:

```text
AD_User ≠ CanonicalIdentity
```

`AD_User` is the ERP-local representation of the person.

Canonical Identity remains Baobab's cross-system identity.

---

# 6. OIDC SSO

iDempiere SHALL use OIDC-based authentication through Baobab IAM where supported by the deployed iDempiere version and extension model.

The integration SHALL avoid introducing a parallel password authority for ordinary ERP users.

Target:

```text
ERP User
   │
   ▼
iDempiere
   │
   ▼
Baobab IAM
   │
   ▼
OIDC authentication
   │
   ▼
AD_User resolution
```

---

# 7. No IAM Password Duplication

For normal workforce ERP access:

```text
Keycloak password
```

SHALL remain the authoritative credential.

iDempiere SHALL NOT maintain a second independent password for the same user's routine login.

---

# 8. Login Flow

The target human login flow SHALL be:

```text
User
  │
  ▼
Open iDempiere
  │
  ▼
Redirect to Baobab IAM
  │
  ▼
Authenticate + MFA if required
  │
  ▼
OIDC callback
  │
  ▼
Canonical identity mapping
  │
  ▼
Resolve AD_User
  │
  ▼
ERP role/org selection
  │
  ▼
ERP session
```

---

# 9. OIDC Subject Mapping

The primary identity mapping SHALL derive from:

```text
issuer + subject
```

through Baobab's canonical identity layer.

It SHALL NOT rely on:

```text
email
username
display name
```

as durable identity keys.

---

# 10. Email Is an Attribute

Email MAY be used for:

- display;
- contact;
- initial migration assistance;
- account discovery.

It SHALL NOT be the authoritative cross-system identity mapping key.

---

# 11. JIT ERP Provisioning

Automatic ERP user creation MAY be supported selectively.

It SHALL NOT be universal.

For privileged ERP users, provisioning SHOULD normally require explicit workforce authorization.

---

# 12. JIT Provisioning Preconditions

Before creating a new `AD_User`, Baobab SHOULD verify:

```text
CanonicalIdentity exists
      │
      ▼
Workforce relationship active
      │
      ▼
ERP capability entitled
      │
      ▼
Appropriate legal-entity context
      │
      ▼
Provision AD_User
```

---

# 13. No Authentication-Equals-Provisioning

This SHALL be prohibited:

```text
valid Keycloak user
     =
new ERP user automatically
```

unless a narrowly scoped, approved JIT policy exists.

---

# 14. AD_User Provisioning

Provisioning MAY populate:

- name;
- email/contact data;
- active status;
- linked Business Partner where appropriate;
- language/locale defaults;
- other safe profile metadata.

It SHALL NOT automatically assign unrestricted ERP roles.

---

# 15. AD_Role Preservation

`AD_Role` SHALL remain authoritative for ERP role authorization.

Baobab SHALL NOT reproduce the full iDempiere role graph inside Keycloak.

---

# 16. No AD_Role Mirroring in IAM

The following pattern SHOULD be avoided:

```text
Keycloak role:
idempiere_post_journal
idempiere_access_window_143
idempiere_run_process_220
...
```

iDempiere already owns these permissions.

---

# 17. ERP Role Assignment

ERP role assignment SHALL be managed through:

- iDempiere native authorization;
- approved provisioning automation;
- governed ERP administration workflows.

IAM SHALL not be the sole authority for role assignment.

---

# 18. AD_Client

`AD_Client` represents an iDempiere client/accounting boundary.

Baobab SHALL not assume:

```text
Tenant = AD_Client
```

as a universal equivalence.

Explicit mapping SHALL be required.

---

# 19. Tenant to AD_Client Mapping

Where a Baobab Tenant maps to an ERP client:

```text
Tenant
  │
  ▼
Mapping
  │
  ▼
AD_Client
```

the relationship SHALL be maintained explicitly through Control Plane mappings.

---

# 20. Legal Entity to AD_Client / AD_Org

A Baobab Legal Entity MAY map to:

```text
AD_Client
```

and/or:

```text
AD_Org
```

depending on iDempiere organizational design.

No global hard-coded assumption SHALL be made.

---

# 21. AD_Org

`AD_Org` SHALL remain iDempiere's organization-level authorization and transaction context.

The Control Plane SHALL not replace it.

---

# 22. Platform Context vs ERP Context

Baobab context may be:

```text
Tenant = Nabhold
LegalEntity = Nabhold Pty Ltd
Market = ZA
Capability = ERP
```

while iDempiere context may be:

```text
AD_Client = Nabhold
AD_Org = South Africa Operations
AD_Role = Finance Manager
```

These layers are related but not identical.

---

# 23. Context Resolution

Before initiating sensitive ERP operations, Baobab SHOULD resolve:

```text
CanonicalIdentity
Tenant
LegalEntity
Market
ERP Capability
EngineInstance
```

and then allow iDempiere to resolve:

```text
AD_User
AD_Role
AD_Client
AD_Org
```

---

# 24. Context Selection

Users with access to multiple ERP contexts SHALL explicitly select or be assigned the intended context.

Example:

```text
User
  │
  ├── Nabhold ZA
  ├── Zuribeans UG
  └── Thamani ZA
```

The current context SHALL not be inferred solely from a browser parameter.

---

# 25. No AD_Client From Client Input Alone

The following SHALL NOT establish authority:

```text
ad_client_id = 1000000
```

provided by the frontend.

Server-side authorization SHALL verify the mapping.

---

# 26. No AD_Org From Client Input Alone

Likewise:

```text
ad_org_id = 1000012
```

must be validated against the user's ERP roles and Baobab context.

---

# 27. Multi-Organization Users

A single Canonical Identity MAY legitimately map to one `AD_User` with access to multiple organizations through iDempiere roles.

This is preferred over duplicate ERP users where iDempiere's authorization model supports the requirement.

---

# 28. Duplicate AD_User Avoidance

Baobab SHOULD avoid:

```text
Peter-Nabhold
Peter-Zuribeans
Peter-Thamani
```

as separate users solely because business context differs.

Prefer one ERP identity with explicit ERP role/context mappings where appropriate.

---

# 29. Exceptions

Separate ERP users MAY be justified where:

- regulatory segregation requires it;
- deployment boundaries require it;
- engine instances are completely separate;
- local ERP architecture requires isolated identities.

Such cases SHALL be explicit.

---

# 30. Multiple Engine Instances

Baobab may operate more than one iDempiere EngineInstance.

Therefore mapping SHALL include engine context.

Conceptually:

```text
CanonicalIdentity
      │
      ▼
EngineInstance
      │
      ▼
AD_User
```

---

# 31. AD_User Identity Scope

An `AD_User_ID` SHALL not be assumed globally unique across independent iDempiere instances.

Mappings SHALL therefore include the engine instance identity.

---

# 32. Role Selection

Where iDempiere requires role selection after login, the user SHALL only be offered roles authorized by the ERP instance.

Baobab IAM SHALL not fabricate role choices.

---

# 33. Role Default

A default role MAY be configured for convenience.

It SHALL not override or expand iDempiere authorization.

---

# 34. Finance Users

Finance users SHALL be treated as privileged workforce.

They SHOULD require:

- MFA;
- explicit ERP entitlement;
- explicit AD_Role;
- appropriate AD_Client/AD_Org access;
- auditable role assignment.

---

# 35. High-Risk Finance Operations

Sensitive ERP operations MAY require step-up authentication.

Examples:

```text
journal posting
payment approval
bank account change
supplier payment instruction change
role assignment
financial close
```

---

# 36. Step-Up Flow

```text
Finance User
     │
     ▼
ERP sensitive action
     │
     ▼
authentication assurance check
     │
     ├── insufficient
     │       │
     │       ▼
     │   Baobab IAM step-up
     │
     ▼
ERP authorization
     │
     ▼
action
```

---

# 37. Step-Up Does Not Replace AD_Role

Strong authentication SHALL not grant ERP authority.

This remains false:

```text
MFA successful
      =
may post journal
```

`AD_Role` and ERP policy remain authoritative.

---

# 38. ERP Administrators

ERP administrative users SHALL be distinct from:

- IAM administrators;
- CP administrators;
- Trade administrators;
- infrastructure administrators.

---

# 39. System Administrator

iDempiere System Administrator-level privileges SHALL be tightly restricted.

They SHALL not be granted as a convenience role.

---

# 40. ERP Superuser

If iDempiere requires highly privileged local administrative identities, those identities SHALL:

- be named;
- be minimally used;
- be audited;
- be protected by strong authentication where possible;
- not become generic shared accounts.

---

# 41. Break-Glass

A controlled break-glass path SHALL exist for ERP administrative recovery.

Examples:

- IAM unavailable;
- OIDC misconfiguration;
- mapping failure;
- ERP lockout;
- disaster recovery.

---

# 42. Break-Glass Requirements

Emergency ERP access SHALL be:

- separate from normal workforce login;
- strongly protected;
- monitored;
- tested;
- auditable;
- rotated/resealed after use where appropriate.

---

# 43. Break-Glass Is Not Routine Login

The existence of emergency local credentials SHALL not justify maintaining normal local-password login for all ERP users.

---

# 44. Local Account Migration

Existing iDempiere local users SHALL be migrated toward Baobab IAM SSO.

Migration SHALL preserve:

```text
AD_User
AD_Role
AD_Client
AD_Org
historical transactions
audit attribution
```

where possible.

---

# 45. User Mapping During Migration

Migration SHOULD establish:

```text
existing AD_User
      │
      ▼
verified CanonicalIdentity
      │
      ▼
OIDC identity mapping
```

rather than creating duplicate ERP users.

---

# 46. Same-Email Auto-Link Prohibited

Migration SHALL NOT auto-link:

```text
iDempiere user
+
Keycloak identity
```

solely because email matches.

Identity ownership SHALL be verified.

---

# 47. Migration State

A useful state model MAY include:

```text
UNMAPPED
IDENTIFIED
LINKED
SSO_VERIFIED
LOCAL_LOGIN_DISABLED
COMPLETE
```

---

# 48. Dual Authentication Window

Temporary coexistence of:

```text
local login
+
OIDC SSO
```

MAY exist during migration.

It SHALL be:

- temporary;
- monitored;
- documented;
- removed after successful migration.

---

# 49. Legacy Password Retirement

Migration is incomplete while obsolete local credentials remain usable indefinitely.

---

# 50. Workforce Joiner

For new ERP users:

```text
employment approved
      │
      ▼
CanonicalIdentity
      │
      ▼
workforce membership
      │
      ▼
ERP entitlement approved
      │
      ▼
AD_User provisioned
      │
      ▼
AD_Role assigned
      │
      ▼
SSO enabled
```

---

# 51. Workforce Mover

Role changes SHALL include ERP privilege review.

Example:

```text
Procurement
    │
    ▼
moves to Finance
```

SHALL not automatically leave all prior procurement roles active.

---

# 52. Workforce Leaver

ERP offboarding SHALL include:

```text
workforce terminated
      │
      ▼
IAM access disabled/revoked
      │
      ▼
CP ERP entitlement removed
      │
      ▼
AD_User disabled or access revoked
      │
      ▼
AD_Role assignments reviewed
```

---

# 53. AD_User Deactivation

Offboarding SHOULD generally deactivate ERP access rather than hard-delete ERP user records where historical transaction attribution must be preserved.

---

# 54. Historical Attribution

A terminated user's prior transactions SHALL remain attributable to the original `AD_User`.

The system SHALL not reassign historical actions to a generic user.

---

# 55. Supplier Representatives

External supplier representatives SHALL NOT receive direct broad iDempiere login by default.

Supplier ERP information SHOULD generally be exposed through Baobab APIs and supplier-facing portals.

---

# 56. Buyer Representatives

Zuribeans buyer representatives SHALL likewise not receive ERP access simply because they transact through Trade.

---

# 57. Customer Identities

Thamani consumers SHALL never be mapped to `AD_User` merely because orders flow into ERP.

Commerce customers remain Trade actors.

---

# 58. ERP Users Are Workforce or Explicit External Roles

Direct ERP login SHOULD be limited to:

- workforce users;
- explicitly approved external professional roles;
- exceptional controlled support users.

---

# 59. Service Identities

System integrations into iDempiere SHALL use workload/service identities, not human accounts.

Example:

```text
baobab-trade-sync
baobab-erp-reconciliation
baobab-cp-integration
```

---

# 60. Human Account ≠ Integration Account

This SHALL remain binding:

```text
Peter's AD_User
      ≠
Trade service integration identity
```

---

# 61. Workload Authentication

Machine-to-machine integration SHALL follow ADR-0007.

Where iDempiere cannot directly consume Baobab workload tokens for a given integration surface, the Baobab ERP adapter layer SHALL provide a controlled translation boundary.

---

# 62. Integration Credential Scope

Service credentials SHALL be:

- unique per workload;
- environment-specific;
- narrowly scoped;
- rotatable;
- audited.

---

# 63. No Shared ERP Integration User

The platform SHOULD avoid one universal:

```text
baobab_integration
```

account with unrestricted ERP authority.

---

# 64. Separate Service Identities

Prefer:

```text
trade-order-sync
trade-inventory-sync
supplier-sync
financial-reconciliation
```

or equivalent security boundaries where operationally justified.

---

# 65. Service-Owned vs Human-Initiated Operations

ERP SHALL distinguish where possible:

```text
service-owned action
```

from:

```text
human-initiated action through service
```

---

# 66. Delegated Provenance

Where Trade triggers ERP activity on behalf of a person:

```text
subject = human
actor = Trade workload
```

SHOULD be preserved in audit metadata where practical.

---

# 67. Service Identity Does Not Grant Human Authority

A powerful ERP integration identity SHALL not permit an unauthorized end user to indirectly trigger arbitrary ERP actions.

Confused-deputy protection is mandatory.

---

# 68. Trade-to-ERP Integration

A typical flow SHALL be:

```text
Trade Action
    │
    ▼
Trade domain authorization
    │
    ▼
Workload identity
    │
    ▼
CP context resolution
    │
    ▼
ERP integration
    │
    ▼
ERP authorization
```

---

# 69. Supplier-to-ERP Integration

Supplier onboarding may create or update ERP Business Partner mappings after supplier approval.

This integration SHALL be workload-driven.

Supplier representatives SHALL not directly manipulate ERP master data.

---

# 70. Business Partner Mapping

Supplier organizations MAY map to iDempiere Business Partners.

Buyer organizations MAY also map to Business Partners.

These mappings SHALL remain distinct from `AD_User`.

---

# 71. Business Partner ≠ Login Identity

This SHALL be explicit:

```text
C_BPartner ≠ AD_User
```

A business entity record does not automatically imply a direct ERP user.

---

# 72. Customer ≠ AD_User

Likewise:

```text
Medusa Customer ≠ AD_User
```

unless a separate, explicit workforce or ERP relationship justifies it.

---

# 73. Canonical Entity Mapping

Baobab SHOULD map:

```text
CanonicalEntity
      │
      ▼
ERP Business Partner / Organization
```

using the Control Plane mapping spine.

---

# 74. No Direct Database Coupling

Baobab IAM or CP SHALL NOT read/write iDempiere ERP tables directly as an authentication shortcut.

Integration SHALL use supported APIs, services, extensions or controlled adapters.

---

# 75. No Keycloak DB Coupling

Similarly, iDempiere SHALL NOT read the Keycloak database directly.

OIDC remains the authentication interface.

---

# 76. Identity Synchronization

Minimal identity attributes MAY be synchronized into `AD_User`.

Examples:

```text
display name
email
locale
active status
```

where appropriate.

---

# 77. Attribute Source of Truth

The source of truth SHALL be explicit.

Example:

```text
authentication email → IAM
ERP role → iDempiere
legal entity relationship → CP
```

---

# 78. ERP-Specific Attributes

ERP-specific attributes SHALL remain in ERP.

Examples:

- default warehouse;
- default organization;
- accounting settings;
- role preferences.

---

# 79. User Rename

A user's display-name change SHALL not create a new ERP identity.

The immutable mapping remains authoritative.

---

# 80. Email Change

An email change SHALL not break the Canonical Identity to `AD_User` mapping.

---

# 81. AD_User Lifecycle

ERP user state SHOULD support:

```text
ACTIVE
INACTIVE
```

and other native state required by iDempiere.

Baobab SHALL not invent parallel ERP-user lifecycle semantics unnecessarily.

---

# 82. Platform Identity State

A disabled Canonical Identity SHALL prevent new ERP SSO access even if `AD_User` remains technically active.

---

# 83. ERP State

An inactive `AD_User` SHALL prevent ERP access even if IAM authentication succeeds.

---

# 84. Multi-Layer Deny

The final decision remains:

```text
IAM allow
+
CP allow
+
AD_User inactive
=
DENY
```

---

# 85. Role Revocation

If `AD_Role` is revoked:

```text
IAM session may remain valid
```

but ERP permissions SHALL immediately or within documented cache bounds reflect the revocation.

---

# 86. Client/Org Revocation

Removing access to an `AD_Client` or `AD_Org` SHALL not require deleting the person's identity.

---

# 87. CP Tenant Suspension

If the Baobab Tenant becomes suspended:

```text
valid IAM login
+
valid AD_User
+
valid AD_Role
```

SHALL not bypass the platform-level suspension where access flows through Baobab-controlled context.

---

# 88. Context Spoofing

The platform SHALL test attempts to modify:

```text
tenant
legal_entity
AD_Client
AD_Org
```

through request parameters.

Unauthorized context-switch attempts SHALL fail.

---

# 89. Multiple Legal Entities

Nabhold executives or shared-services finance personnel MAY legitimately access more than one legal entity.

Such access SHALL be explicit.

---

# 90. Cross-Entity Access

Cross-entity visibility SHALL not imply cross-entity mutation authority.

Example:

```text
Executive:
read financial reports across entities

Finance user:
post transactions only in assigned entity
```

---

# 91. Executive ERP Access

Executive users SHOULD preferably receive:

```text
reporting/read-oriented ERP roles
```

rather than broad System Administrator authority.

---

# 92. Reporting Access

Where possible, executive reporting SHOULD be surfaced through:

```text
Baobab Pulse
analytics/reporting APIs
read-oriented ERP interfaces
```

instead of unrestricted ERP administration.

---

# 93. Role Explosion Avoidance

Baobab SHALL not duplicate iDempiere's detailed security model into CP.

CP SHALL know only enough to decide:

```text
Is this person entitled to ERP in this platform context?
```

iDempiere SHALL answer:

```text
What can this person do inside ERP?
```

---

# 94. CP Authorization Decision

A CP decision MAY contain:

```text
canonical_identity_id
tenant_id
legal_entity_id
market_id
capability = ERP
engine_instance_id
```

It SHOULD NOT contain the full `AD_Role` permission graph.

---

# 95. ERP Context Adapter

Where required, an ERP integration component MAY translate Baobab context into the corresponding:

```text
AD_Client
AD_Org
```

selection.

This mapping SHALL be explicit and auditable.

---

# 96. Mapping Cache

ERP identity/context mappings MAY be cached only with bounded TTL and invalidation appropriate to security risk.

---

# 97. No Permanent Authorization Cache

This SHALL be prohibited:

```text
user had Finance role once
      │
      ▼
cache forever
```

---

# 98. Role Change Invalidation

High-risk role changes SHOULD invalidate relevant authorization/session caches as quickly as feasible.

---

# 99. Audit

ERP access audit SHOULD capture:

```text
CanonicalIdentity
AD_User
AD_Role
AD_Client
AD_Org
action
timestamp
correlation ID
```

where appropriate.

---

# 100. Authentication Audit

IAM SHALL separately record:

- login success/failure;
- MFA;
- session revocation;
- account recovery.

---

# 101. Cross-System Correlation

Where feasible:

```text
IAM login
    │
    ▼
CP authorization decision
    │
    ▼
iDempiere session/action
```

SHOULD be correlatable.

---

# 102. Financial Audit

Financial transactions SHALL retain native iDempiere audit provenance.

Baobab identity metadata MAY complement this but SHALL not replace it.

---

# 103. Sensitive Audit Data

Audit SHALL not record:

```text
passwords
access tokens
refresh tokens
client secrets
full payment credentials
```

---

# 104. Session Timeout

ERP privileged sessions SHOULD use stricter timeouts than low-risk customer-facing applications.

Exact timeout values SHALL be security-policy driven.

---

# 105. MFA Requirement

At minimum, MFA SHALL be mandatory for:

```text
ERP finance users
ERP administrators
high-privilege procurement users
```

where access is interactive.

---

# 106. Step-Up Candidates

Candidate actions include:

```text
payment approval
bank-account modification
role assignment
journal posting
financial close
sensitive master-data change
```

---

# 107. Recovery

Human ERP users SHALL recover credentials through Baobab IAM.

iDempiere SHALL not maintain a parallel normal password-recovery process after migration.

---

# 108. Recovery Does Not Restore ERP Roles

This SHALL remain binding:

```text
IAM account recovered
      ≠
AD_Role restored
```

if ERP access had been revoked separately.

---

# 109. Compromised ERP User

Incident response SHOULD include:

```text
revoke IAM sessions
      │
      ▼
disable/restrict identity
      │
      ▼
review AD_User
      │
      ▼
review AD_Role assignments
      │
      ▼
review recent ERP activity
```

---

# 110. Compromised Integration Identity

For a compromised workload:

```text
revoke workload credential
      │
      ▼
rotate secret/certificate
      │
      ▼
disable integration access
      │
      ▼
review ERP changes
```

without affecting unrelated service identities.

---

# 111. ERP API Access

Machine-accessible ERP APIs SHALL require explicit workload authentication.

Internal network location alone SHALL not be sufficient.

---

# 112. mTLS

mTLS MAY protect internal ERP integration paths.

It SHALL remain complementary to application-level authorization.

---

# 113. Gateway Headers

Gateway-provided identity headers SHALL not become the sole ERP identity authority.

---

# 114. Environment Isolation

Production ERP SHALL accept only production IAM configuration and production workload identities.

Development identities SHALL not authenticate to production.

---

# 115. Client Configuration

OIDC client configuration SHALL be managed as code where appropriate.

At minimum define:

```text
issuer
client ID
redirect URI
allowed scopes
signing algorithms
session policy
```

---

# 116. Secret Management

Confidential client secrets SHALL be:

- unique;
- runtime-injected;
- rotatable;
- excluded from Git;
- excluded from images;
- excluded from logs.

---

# 117. Key Rotation

iDempiere or its OIDC integration layer SHALL support trusted signing-key rotation through standard discovery/JWKS behavior.

---

# 118. Fail Closed

If identity validation, mapping or ERP context resolution fails:

```text
access SHALL be denied
```

There SHALL be no email-based or local-password silent fallback.

---

# 119. IAM Outage

During IAM outage:

- new SSO authentication cannot complete;
- existing valid ERP sessions MAY continue until their configured expiration;
- emergency break-glass MAY be invoked under controlled procedure;
- unrestricted password fallback SHALL not activate automatically.

---

# 120. CP Outage

If CP is required for new platform context resolution and is unavailable, new Baobab-governed ERP context establishment SHALL fail closed.

Existing ERP sessions MAY continue according to explicitly documented resilience policy.

---

# 121. Mapping Failure

If Canonical Identity resolves but no valid `AD_User` mapping exists:

```text
login denied
```

unless approved JIT provisioning applies.

---

# 122. Role Mapping Failure

If `AD_User` exists but no valid ERP role exists:

```text
authentication success
+
ERP authorization failure
=
DENY
```

---

# 123. Integration Testing

At minimum test:

```text
valid OIDC workforce login
invalid issuer
wrong audience
expired token
disabled IAM identity
valid identity + missing AD_User
valid identity + inactive AD_User
valid AD_User + no AD_Role
valid role + wrong AD_Org
valid role + wrong AD_Client
```

---

# 124. Multi-Entity Tests

Test one workforce identity accessing:

```text
Nabhold
Zuribeans
Thamani
```

with distinct valid ERP contexts.

Ensure unauthorized entity switching fails.

---

# 125. Finance Tests

Test:

```text
viewer cannot post journal
finance user can according to AD_Role
finance user wrong org denied
MFA missing for sensitive action
step-up succeeds then ERP policy evaluated
```

---

# 126. Migration Tests

Test:

```text
existing AD_User preserved
existing roles preserved
new CanonicalIdentity mapping
same-email auto-link rejected
OIDC login succeeds
legacy local login disabled
historical audit remains intact
```

---

# 127. Offboarding Tests

Test:

```text
IAM disabled
CP ERP entitlement revoked
AD_User inactive
AD_Role removed
existing session revoked/expired
historical transaction attribution preserved
```

---

# 128. Workload Tests

Test:

```text
Trade workload accepted only for authorized ERP operation
wrong workload denied
wrong tenant denied
wrong audience denied
human token used as service credential denied
shared service identity not required
```

---

# 129. Break-Glass Tests

Staging SHALL periodically validate:

```text
SSO unavailable
      │
      ▼
approved emergency procedure
      │
      ▼
ERP access restored
      │
      ▼
event audited
      │
      ▼
credential resealed/rotated
```

without exposing production emergency credentials.

---

# 130. Rejected Alternative — Rebuild ERP Authorization in Keycloak

### Advantages

Centralized permissions.

### Disadvantages

- massive role duplication;
- loss of iDempiere semantics;
- synchronization complexity;
- stale claims;
- upgrade risk.

### Decision

Rejected.

---

# 131. Rejected Alternative — Rebuild ERP Authorization in CP

### Advantages

Single Baobab policy authority.

### Disadvantages

- CP would need detailed ERP knowledge;
- duplicate AD_Role semantics;
- tight coupling;
- large blast radius.

### Decision

Rejected.

---

# 132. Rejected Alternative — Local iDempiere Passwords for Everyone

### Advantages

Native simplicity.

### Disadvantages

- fragmented identity;
- duplicate password recovery;
- duplicate MFA;
- weak workforce offboarding.

### Decision

Rejected.

---

# 133. Rejected Alternative — Email as Identity Mapping

### Advantages

Simple.

### Disadvantages

- mutable;
- non-unique;
- takeover risk.

### Decision

Rejected.

---

# 134. Rejected Alternative — Every Customer Gets AD_User

### Advantages

Uniform ERP visibility.

### Disadvantages

- enormous ERP user proliferation;
- incorrect business semantics;
- security risk.

### Decision

Rejected.

---

# 135. Rejected Alternative — One Shared ERP Integration User

### Advantages

Operational simplicity.

### Disadvantages

- large blast radius;
- weak audit attribution;
- no per-service revocation.

### Decision

Rejected.

---

# 136. Rejected Alternative — CP Allow Equals ERP Allow

### Decision

Rejected.

CP authorizes platform context.

iDempiere authorizes ERP operations.

---

# 137. Consequences

## Positive

This decision provides:

- unified workforce authentication;
- preserved iDempiere authorization;
- clean CanonicalIdentity-to-AD_User mapping;
- multi-entity support;
- reduced password duplication;
- stronger finance security;
- explicit workload identity;
- safer migration;
- better cross-system audit.

## Negative

It requires:

- OIDC integration;
- mapping infrastructure;
- ERP provisioning/deprovisioning;
- role governance;
- migration tooling;
- context translation;
- comprehensive integration testing.

These costs are accepted.

---

# 138. Implementation Ownership

| Concern | Owner |
|---|---|
| Workforce authentication | `baobab-iam` |
| MFA / step-up | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| Tenant/legal-entity context | `baobab-cp` |
| ERP engine resolution | `baobab-cp` |
| AD_User | `baobab-erp` |
| AD_Role | `baobab-erp` |
| AD_Client | `baobab-erp` |
| AD_Org | `baobab-erp` |
| ERP domain authorization | `baobab-erp` |
| Workload identity | `baobab-iam` + infrastructure |
| Identity contracts | `baobab-platform/shared` |

---

# 139. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend versioned contracts for:

```text
canonical identity reference
ERP user reference
engine instance reference
ERP context mapping
workforce entitlement
delegated actor metadata
identity lifecycle events
ERP mapping events
```

Detailed iDempiere authorization structures SHALL remain inside `baobab-erp`.

---

# 140. Recommended Mapping Model

Conceptually:

```text
ERPIdentityMapping
────────────────────────
canonical_identity_id
engine_instance_id
ad_user_id
status
created_at
updated_at
```

and:

```text
ERPContextMapping
────────────────────────
tenant_id
legal_entity_id
market_id
engine_instance_id
ad_client_id
ad_org_id
status
```

Exact persistence SHOULD reuse existing Control Plane Mapping / ExternalReference constructs where appropriate.

---

# 141. Production-Readiness Checklist

iDempiere IAM integration SHALL not be considered production-ready until:

- OIDC SSO is functional;
- CanonicalIdentity maps explicitly to AD_User;
- no email-only identity matching is authoritative;
- ERP roles remain iDempiere-owned;
- AD_Client mappings are explicit;
- AD_Org mappings are explicit;
- multi-entity access is tested;
- MFA is enforced for finance/admin users;
- step-up is available for sensitive operations where required;
- joiner/mover/leaver workflows include ERP;
- local passwords have a migration/retirement plan;
- existing AD_User records are preserved where possible;
- historical audit remains attributable;
- direct customer/supplier ERP access is not granted by default;
- machine integrations use workload identities;
- no universal shared ERP service account is required;
- tenant/entity spoofing tests pass;
- disabled identities fail closed;
- AD_Role revocation is enforced;
- break-glass procedure exists and is tested;
- IAM/CP outage behavior is documented;
- identity and ERP audits are correlatable.

---

# 142. Architectural Invariants

The following become binding:

```text
CanonicalIdentity ≠ AD_User

AD_User ≠ AD_Role

Tenant ≠ AD_Client automatically

LegalEntity ≠ AD_Org automatically

Platform Context ≠ ERP Permission

IAM Role ≠ AD_Role

Valid IAM Login ≠ ERP Access

Valid CP Context ≠ ERP Business Authorization

MFA ≠ ERP Permission

Medusa Customer ≠ AD_User

Supplier Organization ≠ AD_User

C_BPartner ≠ AD_User

Human Identity ≠ Workload Identity

AD_User Exists ≠ AD_User Authorized

Email Match ≠ Identity Match

Break-Glass ≠ Routine Login

CP Allow ≠ ERP Allow
```

---

# 143. Target Architecture

```text
                        BAOBAB IAM
                           │
                          OIDC
                           │
                           ▼
                    CanonicalIdentity
                           │
                           ▼
                      BAOBAB CP
             Tenant / Entity / Market / ERP
                           │
                           ▼
                    EngineInstance
                           │
                           ▼
                     iDempiere
                           │
                           ▼
                        AD_User
                           │
                           ▼
                        AD_Role
                           │
                   ┌───────┴───────┐
                   ▼               ▼
               AD_Client         AD_Org
                   │               │
                   └───────┬───────┘
                           ▼
                ERP Domain Authorization
```

---

# 144. Human ERP Login Flow

```text
ERP USER
   │
   ▼
iDempiere
   │
   ▼
Baobab IAM
   │
 authenticate + MFA
   │
   ▼
OIDC response
   │
   ▼
Resolve CanonicalIdentity
   │
   ▼
Resolve CP ERP context
   │
   ├── DENY ─────────────► STOP
   │
   ▼
Resolve AD_User
   │
   ├── MISSING ──────────► JIT if approved / DENY
   │
   ▼
Is AD_User active?
   │
   ├── NO ───────────────► DENY
   │
   ▼
Resolve AD_Role / AD_Client / AD_Org
   │
   ▼
iDempiere authorization
   │
   ├── DENY ─────────────► STOP
   │
   ▼
ERP SESSION
```

---

# 145. ERP Integration Flow

```text
BAOBAB TRADE
     │
     ▼
Trade domain authorization
     │
     ▼
Trade workload identity
     │
     ▼
Baobab CP
context + ERP entitlement
     │
     ▼
ERP integration boundary
     │
     ▼
iDempiere
     │
     ▼
authorized ERP operation
```

Human and workload authority SHALL remain distinguishable.

---

# 146. Offboarding Flow

```text
WORKFORCE LEAVER
      │
      ▼
Workforce membership revoked
      │
      ▼
IAM sessions revoked
      │
      ▼
CP ERP entitlement revoked
      │
      ▼
AD_User disabled
      │
      ▼
AD_Role assignments reviewed
      │
      ▼
Historical ERP records retained
```

---

# 147. Decision Summary

Baobab SHALL integrate iDempiere into the common IAM architecture through standards-based SSO while preserving iDempiere as the authoritative ERP authorization engine.

The decision hierarchy SHALL be:

```text
WHO IS THIS PERSON?
        │
        ▼
Baobab IAM

WHO ARE THEY ACROSS BAOBAB?
        │
        ▼
CanonicalIdentity

IN WHICH PLATFORM / LEGAL-ENTITY CONTEXT?
        │
        ▼
Baobab Control Plane

WHO ARE THEY INSIDE ERP?
        │
        ▼
AD_User

WHAT MAY THEY DO?
        │
        ▼
AD_Role + AD_Client + AD_Org + iDempiere permissions
```

Baobab SHALL not reproduce iDempiere's authorization graph inside IAM or the Control Plane.

Local ERP credentials SHALL become migration/emergency artifacts rather than normal workforce authentication.

Workload integrations SHALL use distinct service identities and shall not impersonate human ERP users.

The governing principle is:

> **Use Baobab IAM to establish ERP identity, use the Control Plane to establish business context, and let iDempiere remain the final authority over ERP permissions, organizations, roles and financial actions.**