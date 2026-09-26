# ADR-IAM-0031 — IAM Administration, Delegated Administration, Privileged Access and Break-Glass Governance

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture / IAM Operations  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0030  
**Extends:** ADR-IAM-0003, 0005, 0008, 0009, 0016, 0017, 0018, 0020, 0021, 0024, 0025, 0026, 0027, 0028, 0029, 0030  
**Decision Type:** Privileged Access / IAM Administration / Delegated Administration / Emergency Access  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Business Authorization Authority:** Respective authoritative domain engines

---

# 1. Decision

Baobab SHALL implement IAM administration as a **separate, explicitly authorized privileged plane**.

Administrative capability SHALL be:

```text
IDENTIFIED
    ↓
AUTHENTICATED
    ↓
CONTEXTUALISED
    ↓
AUTHORIZED
    ↓
STEP-UP VERIFIED
    ↓
SCOPE LIMITED
    ↓
EXECUTED
    ↓
AUDITED
    ↓
REVIEWED
```

Baobab SHALL NOT create a single ordinary:

```text
SUPER_ADMIN
```

role possessing unrestricted authority over:

```text
identity
tenants
organizations
credentials
business permissions
ERP
Trade
suppliers
security
infrastructure
cryptography
privacy
```

Instead, privileged authority SHALL be decomposed by:

```text
CAPABILITY
+
SCOPE
+
CONTEXT
+
ASSURANCE
+
TIME
+
PURPOSE
```

The governing principle is:

> **Administration is authority to perform a bounded administrative operation; it is not ownership of the user's identity, business authority or unrestricted access to the platform.**

---

# 2. Administrative Authority Is Not One Thing

Baobab SHALL distinguish:

```text
Platform Administration

IAM Administration

Security Administration

Tenant Administration

Organization Administration

Domain Administration

Infrastructure Administration

Privacy Administration

Support Operations

Emergency / Break-Glass Administration
```

These SHALL NOT be collapsed merely because one person performs several functions in a small initial operations team.

---

# 3. Foundational Separation

The following invariants apply:

```text
Authentication
      ≠
Administration

Administration
      ≠
Impersonation

Administration
      ≠
Business Authorization

IAM Administration
      ≠
Tenant Ownership

Tenant Administration
      ≠
Platform Administration

Organization Administration
      ≠
Tenant Administration

Security Response
      ≠
Permanent Administration

Support Access
      ≠
Administrative Authority

Infrastructure Root
      ≠
Business Authority

Database Access
      ≠
Application Authorization
```

---

# 4. Administrative Planes

Baobab recognizes at least five administrative planes:

```text
┌───────────────────────────────────────┐
│ 1. PLATFORM GOVERNANCE                │
│    CP / tenants / capabilities        │
├───────────────────────────────────────┤
│ 2. IDENTITY ADMINISTRATION            │
│    Ory / identities / credentials     │
├───────────────────────────────────────┤
│ 3. DOMAIN ADMINISTRATION              │
│    Trade / ERP / Supplier / CMS       │
├───────────────────────────────────────┤
│ 4. SECURITY & PRIVACY OPERATIONS      │
│    containment / investigation        │
├───────────────────────────────────────┤
│ 5. INFRASTRUCTURE ADMINISTRATION      │
│    Kubernetes / DB / secrets / keys   │
└───────────────────────────────────────┘
```

Authority in one plane SHALL NOT automatically grant authority in another.

---

# 5. Platform Administration

Platform administrators MAY manage appropriately authorized:

```text
Tenant lifecycle
DigitalEstate registration
Engine registration
EngineInstance
Capability
CapabilityBinding
IsolationProfile
Market registration
platform-level Context policy
```

through the Control Plane.

They SHALL NOT automatically gain:

```text
buyer purchase approval
ERP finance roles
supplier approval
customer impersonation
user credentials
```

---

# 6. IAM Administration

IAM administrators MAY administer identity-runtime functions such as:

```text
identity lifecycle
provider identity mapping
credential lifecycle operations
federation configuration
OAuth clients
authentication policies
identity reconciliation
```

within assigned capability boundaries.

IAM administrators SHALL NOT automatically possess business-domain permissions.

---

# 7. Security Administration

Security operators MAY possess narrowly scoped capabilities such as:

```text
iam.security.observe
iam.security.investigate
iam.session.revoke
iam.identity.suspend
iam.workload.suspend
iam.oauth_client.suspend
iam.federation.suspend
```

as established by ADR-IAM-0029.

Security responders SHALL NOT automatically become IAM configuration administrators.

---

# 8. Privacy Administration

Privacy administrators MAY coordinate:

```text
access requests
correction
restriction
erasure
legal holds
privacy exports
```

under ADR-IAM-0030.

They SHALL NOT automatically gain:

```text
credential administration
business approval
security configuration
infrastructure root
```

---

# 9. Infrastructure Administration

Infrastructure operators MAY administer:

```text
Kubernetes
PostgreSQL
networking
APISIX
secret infrastructure
backups
runtime configuration
```

within their assigned responsibilities.

Infrastructure privilege SHALL NOT be interpreted as legitimate business authorization.

---

# 10. Technical Power vs Legitimate Authority

A database administrator might technically be capable of modifying database rows.

That does not mean the administrator is authorized to grant:

```text
buyer approval
supplier approval
finance authority
tenant ownership
```

Baobab SHALL distinguish:

```text
technical capability
        ≠
legitimate application authority
```

---

# 11. Administrative Principal

Every administrative action SHALL resolve to a known principal.

Conceptually:

```text
AdministrativePrincipal
├── CanonicalIdentity
├── authentication assurance
├── administrative capabilities
├── administrative scope
├── context
├── session
└── delegation state
```

---

# 12. No Shared Administrator Accounts

Human administrators SHALL use individual identities.

Prohibited:

```text
admin@baobab
root-team
shared-security
shared-support
```

as normal interactive human accounts.

---

# 13. Accountability

Every privileged action SHALL be attributable to:

```text
WHO
WHAT
WHEN
WHERE
WHICH CONTEXT
WHY
WHICH ASSURANCE
WHICH AUTHORIZATION
```

where applicable.

---

# 14. Administrative Capability Model

Administrative authorization SHOULD be capability-oriented.

Examples:

```text
iam.identity.read
iam.identity.suspend
iam.identity.reactivate

iam.session.read
iam.session.revoke

iam.credential.reset
iam.credential.revoke

iam.federation.read
iam.federation.configure
iam.federation.activate
iam.federation.suspend

iam.oauth_client.read
iam.oauth_client.configure
iam.oauth_client.revoke

iam.security.investigate

iam.privacy.request.read
iam.privacy.erasure.approve

cp.tenant.read
cp.tenant.configure

cp.capability.bind

platform.breakglass.activate
```

---

# 15. Capability ≠ Role

Roles MAY bundle capabilities.

The canonical authorization semantics SHALL remain capability-based where practical.

---

# 16. Administrative Scope

Every capability SHOULD have an explicit scope.

Examples:

```text
GLOBAL

REGION

TENANT

LEGAL_ENTITY

ORGANIZATION

DIGITAL_ESTATE

ENGINE

ENGINE_INSTANCE

FEDERATION

IDENTITY

WORKLOAD
```

---

# 17. Scope Example

```text
Capability:
iam.identity.read

Scope:
Tenant A
```

does not authorize:

```text
Tenant B
```

---

# 18. Administrative Context

Administrative requests SHALL resolve context through authoritative Baobab mechanisms.

Client-supplied:

```text
tenant_id
organization_id
legal_entity_id
```

remain requested context, not authority.

---

# 19. No Global-by-Default Administration

A newly created administrative capability SHALL NOT default to:

```text
scope = *
```

Global authority must be explicit.

---

# 20. Administrative Role Classes

Baobab MAY define logical role bundles such as:

| Role | Typical Scope |
|---|---|
| Platform Operator | Platform |
| IAM Operator | IAM |
| IAM Security Analyst | Security telemetry |
| IAM Security Responder | Containment |
| Federation Administrator | Federation |
| Privacy Operator | Privacy workflows |
| Tenant Administrator | One tenant |
| Organization Administrator | One business organization |
| Support Operator | Narrow support |
| Infrastructure Operator | Runtime |
| Break-Glass Operator | Emergency only |

These are convenience bundles, not universal superuser roles.

---

# 21. Delegated Administration

Baobab SHALL support controlled delegation.

This is essential for external B2B customers.

Example:

```text
Baobab Platform
       │
       ▼
Customer Tenant
       │
       ▼
Customer Administrator
       │
       ▼
Customer Organization
       │
       ├── Users
       ├── Memberships
       └── Allowed customer-level configuration
```

---

# 22. Delegation Does Not Transfer Platform Ownership

A tenant/customer administrator SHALL NOT gain authority over:

```text
another tenant
Baobab infrastructure
Ory global configuration
issuer signing keys
platform OAuth clients
other organizations
```

---

# 23. Organization Administrator

An organization administrator MAY manage approved organizational functions such as:

```text
invite members
remove members
assign permitted organization roles
manage selected organization configuration
```

within the organization's scope.

---

# 24. Organization Admin ≠ Tenant Admin

An organization administrator SHALL NOT automatically become:

```text
tenant administrator
legal-entity administrator
platform administrator
```

---

# 25. Tenant Admin ≠ Domain Superuser

A tenant administrator SHALL NOT automatically gain every domain permission.

Example:

```text
Tenant Admin
   ≠
ZuriBeans Purchase Approver
```

---

# 26. Business Authority Remains Domain-Owned

ZuriBeans Trade continues to own:

```text
purchaser
approver
purchase authority
commercial limits
```

iDempiere continues to own:

```text
AD_Role
document permissions
process permissions
accounting permissions
```

Supplier domain continues to own:

```text
supplier approval
supplier representative authority
bank-detail approval
```

---

# 27. Delegation Ceiling

An administrator SHALL NOT delegate authority they do not possess.

Formally:

```text
DelegatedAuthority
⊆
DelegatorAuthority
```

---

# 28. Delegation Cannot Expand Scope

If Jane administers:

```text
Organization A
```

Jane cannot create an administrator for:

```text
Organization B
```

unless independently authorized there.

---

# 29. Delegation Cannot Lower Mandatory Assurance

If a capability requires:

```text
BAOBAB-A3
```

delegating that capability does not permit A1 execution.

---

# 30. Delegation Record

Conceptually:

```text
AdministrativeDelegation
├── delegation_id
├── delegator
├── delegate
├── capabilities[]
├── scope
├── valid_from
├── expires_at?
├── constraints
├── reason
├── status
└── audit_reference
```

---

# 31. Delegation Lifecycle

```text
PROPOSED
   ↓
AUTHORIZED
   ↓
ACTIVE
   ↓
SUSPENDED
   ↓
REVOKED / EXPIRED
```

---

# 32. Time-Bounded Delegation

Temporary administration SHOULD use expiry rather than relying on humans to remember removal.

---

# 33. Just-In-Time Privilege

High-risk administrative capability SHOULD increasingly use:

```text
eligible
   ↓
request
   ↓
step-up
   ↓
approval where required
   ↓
temporary activation
   ↓
automatic expiry
```

rather than permanently active privilege.

---

# 34. Standing Privilege

Standing privileged access SHALL be minimized.

---

# 35. Privileged Access State

Baobab SHOULD distinguish:

```text
ASSIGNED
ELIGIBLE
ACTIVE
EXPIRED
SUSPENDED
REVOKED
```

---

# 36. Privileged Session

A privileged session SHALL be distinguishable from an ordinary user session.

---

# 37. Authentication Assurance

Privileged administrative operations SHALL use ADR-IAM-0024 assurance requirements.

At minimum:

```text
ordinary low-impact admin
    → strong MFA

high-risk privileged admin
    → phishing-resistant authentication

Tier-0 / emergency operations
    → phishing-resistant + recent authentication
```

according to policy.

---

# 38. BAOBAB-A4

A4 SHALL represent a privileged/high-assurance session meeting the required policy conditions.

It SHALL NOT simply mean:

```text
user has admin role
```

---

# 39. A4 Is Session State

A4 SHALL be:

```text
time-bound
authentication-bound
policy-bound
```

rather than a permanent user attribute.

---

# 40. Privilege Does Not Raise Assurance

Being an administrator does not itself increase authentication assurance.

---

# 41. Step-Up

Sensitive actions SHALL trigger step-up where current assurance or authentication age is insufficient.

Examples:

```text
grant privileged capability
remove MFA
reset privileged credential
activate federation
change issuer trust
rotate signing key
activate break-glass
bulk export identities
approve privacy erasure exception
```

---

# 42. Recent Authentication

A valid long-running session SHALL not automatically authorize a high-risk administrative operation.

---

# 43. Phishing Resistance

High-impact administrative operations SHOULD require phishing-resistant authenticators.

Passkeys/security keys are preferred according to ADR-IAM-0024.

---

# 44. Administrative Session Duration

Privileged sessions SHOULD have shorter:

```text
idle timeout
absolute lifetime
step-up freshness
```

than ordinary low-risk user sessions.

---

# 45. Administrative Browser Security

Administrative UIs SHALL follow ADR-IAM-0023:

```text
BFF preferred
secure HttpOnly cookies
server-side token handling
CSRF protection
CSP
strict origins
no localStorage bearer tokens
```

---

# 46. Dedicated Administrative Interfaces

High-risk platform administration SHOULD use clearly distinguishable administrative interfaces.

This reduces accidental execution in the wrong context.

---

# 47. Context Visibility

Administrative UX SHALL prominently display:

```text
current tenant
current organization
current environment
current region
current privilege state
```

where relevant.

---

# 48. Production Visibility

Production administrative sessions SHALL be visually and operationally distinguishable from:

```text
development
staging
test
```

---

# 49. Environment Isolation

Privilege in:

```text
staging
```

SHALL NOT imply privilege in:

```text
production
```

---

# 50. Production Access

Production privileged access SHALL be explicitly granted.

---

# 51. Support Personnel

Support SHALL use narrowly scoped support capabilities.

---

# 52. Support Is Not Admin

A support agent able to view:

```text
account status
```

SHALL NOT automatically be able to:

```text
reset MFA
change email
grant organization membership
change business authority
impersonate user
```

---

# 53. Support-Assisted Recovery

Support-assisted recovery SHALL follow ADR-IAM-0025 proofing and recovery rules.

A support operator SHALL NOT bypass proofing merely because the caller sounds convincing.

---

# 54. No Knowledge-Question Backdoor

Support SHALL NOT use weak security questions as a privileged bypass.

---

# 55. Administrative Impersonation

Baobab SHALL NOT treat unrestricted user impersonation as a normal support feature.

---

# 56. Default Rule

```text
NO GENERAL "LOGIN AS USER"
```

---

# 57. Why Impersonation Is Dangerous

Unrestricted impersonation can collapse:

```text
authentication provenance
user intent
non-repudiation
business approval
privacy boundaries
audit interpretation
```

---

# 58. Preferred Support Model

Prefer:

```text
read-only diagnostic view
+
explicit support tooling
+
safe administrative actions
```

over impersonation.

---

# 59. Exceptional Impersonation

If a future domain demonstrates a legitimate need, impersonation SHALL require a separate architectural/security decision.

At minimum it would need:

```text
explicit capability
reason
approval
time limit
prominent banner
separate audit actor
subject identity preservation
prohibited high-risk operations
```

---

# 60. Actor vs Subject

Any delegated or assisted action SHALL preserve:

```text
Actor
```

separately from:

```text
Subject
```

---

# 61. Never Rewrite Actor

If Administrator Jane acts concerning Customer Bob:

```text
actor   = Jane
subject = Bob
```

Audit SHALL NOT claim:

```text
actor = Bob
```

---

# 62. Service Accounts

Human administrators SHALL NOT normally use workload/service identities interactively.

---

# 63. Workload Administration

Workload administration SHALL use dedicated administrative capabilities and machine identity governance.

---

# 64. CI/CD Administration

GitHub Actions or deployment automation SHALL receive only deployment/runtime capabilities necessary for the workflow.

CI SHALL NOT receive universal IAM administration merely because it deploys `baobab-iam`.

---

# 65. Secrets

Administrative applications SHALL not expose:

```text
Hydra system secrets
private signing keys
database passwords
SCIM secrets
OAuth client secrets
```

unless the specific operation requires controlled secret handling.

---

# 66. Secret Read vs Secret Rotate

Baobab SHOULD distinguish:

```text
secret metadata read
secret rotate
secret material read
```

where infrastructure permits.

---

# 67. Ory Administrative APIs

Ory administrative interfaces SHALL remain on restricted administrative networks/services.

They SHALL NOT be exposed as public Digital Estate APIs.

---

# 68. Ory Admin Access

Access to Kratos/Hydra administrative APIs SHALL require:

```text
trusted network path
service authentication
authorization
audit
```

through Baobab infrastructure controls.

---

# 69. No Browser-to-Ory-Admin

Digital Estate browsers SHALL NOT directly call privileged Ory administrative APIs.

---

# 70. Administrative Service Layer

Where business/admin semantics are required:

```text
Admin UI
   ↓
Baobab administrative service
   ↓
authorization
   ↓
provider-neutral adapter
   ↓
Ory Admin API
```

is preferred.

---

# 71. Provider Neutrality

Administrative contracts SHALL use Baobab concepts.

Do not expose permanent cross-repository contracts such as:

```text
ory_identity_admin_role
hydra_super_admin
```

---

# 72. Federation Administration

Federation administration SHALL distinguish:

```text
create configuration
edit draft
verify
test
activate
suspend
revoke
```

---

# 73. Federation Activation

Activation of a new enterprise trust SHOULD require stronger authority than editing a draft.

---

# 74. Federation Separation of Duties

For higher-risk customers or deployments, Baobab MAY require:

```text
Administrator A configures
Administrator B approves activation
```

---

# 75. SCIM Administration

SCIM credential creation/rotation SHALL be privileged and auditable.

---

# 76. OAuth Client Administration

OAuth client administration SHALL distinguish:

```text
create
configure
rotate secret
change redirect URI
change scopes
suspend
delete
```

---

# 77. Redirect URI Changes

Changing a confidential/public client redirect URI is security-sensitive and SHALL be auditable.

---

# 78. Scope Expansion

Expanding OAuth scopes SHALL be treated differently from metadata-only changes.

---

# 79. Privileged Identity Lifecycle

Privileged capability SHALL be removed promptly when:

```text
employment ends
contract ends
administrative duty ends
organization relationship ends
security incident requires suspension
```

---

# 80. Offboarding

Administrative offboarding SHALL include:

```text
revoke privileged sessions
remove privileged capability
revoke temporary delegation
rotate shared technical secrets if exposure possible
review owned automation
review break-glass eligibility
```

---

# 81. Mover Events

Changing job/organizational responsibility SHALL trigger administrative access review.

---

# 82. Rehire

Rehire SHALL NOT automatically restore historical privilege.

---

# 83. Privileged Access Review

Privileged access SHALL undergo periodic review.

Review SHALL answer:

```text
Does this person still need this capability?

Is the scope still correct?

Is standing access necessary?

Can this become JIT?

Is assurance adequate?

Has the relationship changed?
```

---

# 84. Review Frequency

Higher-risk privilege SHOULD receive more frequent review.

Exact periods belong in operational policy rather than this ADR.

---

# 85. Orphaned Privilege

Baobab SHALL detect:

```text
privilege with no valid relationship
expired contractor still privileged
disabled identity with active admin binding
deleted organization with active delegation
```

---

# 86. Separation of Duties

Baobab SHALL support separation-of-duty policies for high-risk operations.

---

# 87. SoD Example

A person SHOULD NOT normally both:

```text
request own privilege elevation
+
approve own privilege elevation
```

---

# 88. Other SoD Examples

Potentially separate:

```text
federation configure / federation approve

key rotation request / key rotation approval

privacy exception request / approval

supplier bank change / approval

financial role assignment / approval

break-glass request / review
```

depending on risk.

---

# 89. Self-Administration

An administrator MAY perform low-risk self-service operations such as:

```text
register own passkey
view own sessions
```

under normal identity rules.

They SHALL NOT use administrative authority to approve their own privileged elevation.

---

# 90. Four-Eyes Control

High-impact actions MAY require two independent authorized humans.

---

# 91. Approval Is Not Authentication

The second approver SHALL independently authenticate and authorize.

A checkbox entered by the first administrator is not dual control.

---

# 92. Administrative Request

Conceptually:

```text
PrivilegedOperation
├── operation_id
├── actor
├── requested_capability
├── target
├── scope
├── reason
├── authentication_assurance
├── requested_at
├── approval_policy
├── approvals[]
├── expires_at?
├── execution_state
└── audit_reference
```

---

# 93. Privileged Operation States

```text
REQUESTED
    ↓
AUTHORIZED
    ↓
STEP_UP_REQUIRED
    ↓
READY
    ↓
EXECUTING
    ↓
COMPLETED
```

Alternative states:

```text
DENIED
EXPIRED
CANCELLED
FAILED
```

---

# 94. Reason Capture

High-risk administrative actions SHOULD require structured reason codes and, where appropriate, explanatory text.

---

# 95. Ticket References

Operations MAY reference:

```text
incident
change request
support case
privacy request
customer request
```

but an external ticket number SHALL NOT itself constitute authorization.

---

# 96. Break-Glass Purpose

Break-glass exists only for situations where ordinary privileged-access mechanisms cannot safely satisfy urgent operational need.

---

# 97. Break-Glass Is Not Convenience

Break-glass SHALL NOT be used because:

```text
approval takes too long
operator forgot access
ordinary account misconfigured
normal process is inconvenient
```

unless the situation has become a genuine qualifying emergency.

---

# 98. Break-Glass Conditions

Examples MAY include:

```text
IAM administrative plane unavailable

ordinary privileged identities inaccessible

critical security incident requiring immediate containment

federation failure blocking all administrators

regional disaster

severe CP failure

critical recovery operation
```

---

# 99. Break-Glass Account Design

Break-glass capability SHALL be:

```text
separate
minimal
strongly protected
rarely used
monitored
tested
audited
```

---

# 100. Break-Glass Identity

Where possible, break-glass SHALL still resolve to an accountable individual.

Avoid anonymous:

```text
root
```

as the only evidence of who acted.

---

# 101. Break-Glass Authentication

Break-glass SHALL use the strongest practical independent authentication mechanism.

It SHALL NOT depend solely on the failed system it exists to recover.

---

# 102. Independent Recovery Path

Example:

```text
Normal Ory Admin Authentication
             X
          unavailable
             │
             ▼
Independent emergency credential
             │
             ▼
restricted emergency interface
```

---

# 103. Break-Glass Credentials

Emergency credentials SHALL be:

```text
protected separately
periodically verified
rotated when exposed/used as policy requires
unavailable to ordinary applications
```

---

# 104. Break-Glass Scope

Emergency authority SHALL be limited to recovery-critical capabilities where technically practical.

---

# 105. Break-Glass Does Not Mean Universal Root

Preferred:

```text
restore IAM control
suspend issuer
revoke compromised client
recover administrative plane
```

rather than:

```text
access every customer record
approve every transaction
alter every ERP ledger
```

---

# 106. Break-Glass Activation

Conceptually:

```text
Emergency
   ↓
Declare Break-Glass Need
   ↓
Authenticate Strongly
   ↓
Record Reason
   ↓
Activate Restricted Capability
   ↓
Alert Security
   ↓
Execute
   ↓
Terminate
   ↓
Rotate/Seal
   ↓
Independent Review
```

---

# 107. Break-Glass Alert

Activation SHALL generate an immediate high-severity security event under ADR-IAM-0029.

---

# 108. Break-Glass Audit

Every action performed during emergency access SHALL be attributable to the break-glass session.

---

# 109. Break-Glass Session

Break-glass sessions SHALL have short:

```text
idle timeout
absolute lifetime
```

and SHALL not become ordinary reusable sessions.

---

# 110. Break-Glass Automatic Expiry

Emergency privilege SHOULD expire automatically.

---

# 111. Break-Glass Review

Every activation SHALL receive independent post-use review.

---

# 112. Review Questions

At minimum:

```text
Was the emergency legitimate?

Who activated access?

Was authentication adequate?

What was changed?

Was scope appropriate?

Did any customer/personal data become exposed?

Were credentials rotated?

Was normal authority restored?

What prevented normal administration?

What should be fixed?
```

---

# 113. Break-Glass Testing

Emergency access that is never tested cannot be assumed to work.

Controlled exercises SHALL verify it.

---

# 114. Testing Without Routine Use

Break-glass SHALL be tested periodically without normalizing its use.

---

# 115. Break-Glass Monitoring

Security operations SHALL detect:

```text
unexpected access to emergency credential
failed break-glass authentication
activation
privileged operations
session extension
credential rotation
```

---

# 116. Break-Glass and DR

ADR-IAM-0027 disaster recovery SHALL include break-glass procedures for:

```text
region failure
control-plane failure
Ory failure
database recovery
issuer recovery
```

---

# 117. Break-Glass and Cryptography

ADR-IAM-0028 cryptographic emergencies SHALL define which break-glass capability can:

```text
suspend issuer trust
initiate emergency key rotation
revoke compromised trust
```

---

# 118. Break-Glass and Privacy

Emergency access SHALL NOT suspend privacy obligations.

Access to personal information remains limited to what the emergency requires.

---

# 119. Customer Delegated Administration

External customers MAY administer their own users and organization relationships where the relevant product supports it.

---

# 120. Customer Admin Bootstrap

Initial customer administrator establishment SHALL require stronger evidence than ordinary user self-registration.

Potential methods include:

```text
verified organization onboarding
verified representative
contractual provisioning
controlled invitation
enterprise federation
```

---

# 121. First Administrator Problem

The first registrant for an organization SHALL NOT automatically become organization administrator merely by claiming the company.

---

# 122. Organization Verification

ADR-IAM-0025/0026 organization verification SHALL precede high-impact organization administration.

---

# 123. Customer Admin Lifecycle

```text
CANDIDATE
   ↓
VERIFIED
   ↓
ADMIN_ACTIVE
   ↓
SUSPENDED
   ↓
REMOVED
```

---

# 124. Multiple Customer Administrators

Business organizations SHOULD support more than one administrator to avoid dependence on a single human.

---

# 125. Last Administrator Protection

Removing the final organization administrator SHOULD trigger additional safeguards.

---

# 126. Ownership Transfer

Transferring organization administration SHALL be treated as high-risk.

---

# 127. Organization Takeover Defense

High-risk signals include:

```text
all admins removed
new admin added immediately after recovery
domain/federation changed
organization owner transferred
MFA changed before admin change
```

These SHALL integrate with ADR-IAM-0029 detection.

---

# 128. ZuriBeans Administration

ZuriBeans SHALL distinguish:

```text
Buyer Organization Administrator

Purchaser

Approver

Buyer Finance Contact

Supplier Representative

ZuriBeans Staff
```

---

# 129. ZuriBeans Admin Boundary

Buyer organization administration SHALL NOT automatically confer:

```text
purchase authority
credit authority
quotation approval
ZuriBeans staff authority
```

Trade remains authoritative.

---

# 130. ZuriBeans Staff

ZuriBeans staff administrative access SHALL be scoped by staff responsibility.

Customer administration and internal staff administration SHALL remain distinct.

---

# 131. Thamani Administration

Thamani SHALL distinguish:

```text
Individual Customer

Business Account Administrator

Shipping Operator

Finance/Approver

Agent/Partner

Carrier Representative

Thamani Staff
```

---

# 132. Thamani Business Admin

A Thamani business-account administrator MAY manage organization membership.

They SHALL NOT automatically gain authority over:

```text
all shipments
financial approvals
carrier administration
another business account
```

unless domain policy grants it.

---

# 133. Same Human, Multiple Administrative Contexts

Jane may be:

```text
ACME Thamani Admin
+
Beta Ltd ZuriBeans Buyer User
+
personal Thamani Customer
```

These authorities SHALL remain independently resolved.

---

# 134. Supplier Administration

Supplier administrators SHALL manage only permitted supplier organization functions.

---

# 135. Supplier Admin ≠ Supplier Approval

An administrator of a supplier's own account cannot approve that supplier as an accepted Baobab/ZuriBeans supplier.

---

# 136. Supplier Banking

Bank-detail administration SHALL use stronger controls from the supplier and security ADRs.

---

# 137. ERP Administration

ERP administration SHALL respect iDempiere's native authorization model.

---

# 138. ERP Boundary

Baobab IAM administrator:

```text
≠
iDempiere System Administrator
```

unless separately authorized.

---

# 139. ERP Role Assignment

Assignment of:

```text
AD_Role
AD_Client
AD_Org
```

shall remain under governed ERP/CP integration rather than arbitrary IdP role manipulation.

---

# 140. CMS Administration

CMS administrative roles SHALL remain separate from IAM platform administration.

A content editor does not become an identity administrator.

---

# 141. Pulse Administration

Pulse administrators SHALL not automatically receive raw identity/security data.

---

# 142. Infrastructure Privilege

Infrastructure privilege SHALL be minimized using:

```text
RBAC
namespaces
service accounts
network policy
secret policy
database roles
environment separation
```

---

# 143. Kubernetes Administration

Routine application deployment SHALL NOT require cluster-admin where narrower privileges suffice.

---

# 144. PostgreSQL Administration

Application administration SHALL NOT require PostgreSQL superuser.

---

# 145. Database Emergency Access

Emergency database access SHALL be treated as privileged infrastructure access and audited independently of application authorization.

---

# 146. GitHub Administration

Repository administration SHALL remain distinct from production IAM administration.

---

# 147. CI Trust

Ability to merge code does not automatically mean ability to:

```text
read production secrets
administer Ory
change signing keys
grant tenant privilege
```

Deployment pipelines SHALL preserve these separations where practical.

---

# 148. Administrative API Security

Administrative endpoints SHALL be:

```text
separate where appropriate
authenticated
authorized
rate-limited
audited
network-restricted where appropriate
```

---

# 149. Administrative APIs Are Not Public APIs

Documentation and routing SHALL clearly distinguish them.

---

# 150. Administrative Mutation Idempotency

Where feasible, privileged mutations SHOULD be idempotent and safe to retry.

---

# 151. Bulk Administrative Operations

Bulk operations require additional controls.

Examples:

```text
bulk identity disable
bulk session revoke
bulk organization membership update
bulk federation change
```

---

# 152. Bulk Operation Preview

Before high-impact bulk execution, the administrator SHOULD see:

```text
target count
scope
expected action
potential impact
```

---

# 153. Bulk Approval

Very high-impact bulk operations MAY require dual control.

---

# 154. Administrative Audit Event

Conceptually:

```text
AdministrativeAuditEvent
├── event_id
├── actor
├── actor_context
├── capability
├── target
├── target_context
├── operation
├── reason
├── assurance
├── approvals[]
├── occurred_at
├── result
├── correlation_id
└── incident/change_reference?
```

---

# 155. Before/After State

For important configuration changes, audit SHOULD preserve appropriate:

```text
before
after
```

information without logging secrets.

---

# 156. Secret Redaction

Audit SHALL never store raw:

```text
password
private key
client secret
recovery code
TOTP seed
session token
```

---

# 157. Failed Administrative Attempts

Denied privileged operations SHALL also be observable.

---

# 158. Audit Immutability

Administrative actors SHALL NOT normally be able to erase their own privileged audit trail.

---

# 159. Security Correlation

Administrative events SHALL integrate with ADR-IAM-0029.

Examples:

```text
unexpected admin activation
repeated denied privilege
new global delegation
break-glass activation
federation change
mass revocation
```

---

# 160. Administrative Anomaly Detection

High-risk anomalies SHOULD include:

```text
privileged action from new environment
unusual bulk change
self-elevation attempt
cross-tenant administration attempt
privilege change after recovery
unexpected after-hours emergency activation
```

as signals, not automatic proof of malicious intent.

---

# 161. Notifications

Material administrative changes MAY notify:

```text
affected administrator
organization administrators
security operations
customer owner
```

according to policy.

---

# 162. Administrative Change Reconciliation

Baobab SHALL periodically reconcile:

```text
assigned capabilities
active delegations
organization administrators
provider administrative state
CP authorization state
domain administrative state
```

---

# 163. Provider State Is Not Canonical Authority

If Ory contains an administrative identity but CP says:

```text
privilege revoked
```

the restrictive state wins.

---

# 164. External Enterprise Administrators

A customer's Microsoft Entra/Okta/other administrator SHALL NOT automatically become a Baobab administrator.

---

# 165. Federation Group Mapping

An enterprise group MAY establish eligibility for bounded organization administration only through explicit trusted mapping.

It SHALL NOT directly create:

```text
Baobab platform administrator
IAM administrator
security administrator
```

---

# 166. Enterprise Offboarding

SCIM or federation deprovisioning SHALL remove corresponding delegated administrative relationships where policy maps them.

---

# 167. Administrative Invitations

Privileged invitations SHALL be:

```text
single-purpose
time-limited
recipient-bound where possible
audited
```

---

# 168. Invitation Acceptance

Accepting an administrative invitation SHALL require authentication and required assurance.

---

# 169. Invitation Forwarding

Possession of an invitation URL alone SHALL not establish privileged identity.

---

# 170. Admin Email Change

Changing the email of a privileged identity SHALL NOT transfer administrative authority to a different person.

CanonicalIdentity continuity and proofing controls apply.

---

# 171. Privileged Recovery

Recovery of privileged administrator accounts SHALL follow stronger ADR-IAM-0025 recovery classes.

---

# 172. Recovery Does Not Restore Everything

Following high-risk recovery, Baobab MAY require:

```text
reauthentication
new passkey
new MFA
session revocation
privilege review
temporary restriction
```

before privileged capability is restored.

---

# 173. Administrator Compromise

A compromised administrator SHALL enter ADR-IAM-0029 incident response.

Containment MAY independently suspend:

```text
privileged session
privileged delegation
identity
credential
```

depending on scope.

---

# 174. Privilege Suspension

Security operations SHALL be capable of suspending administrative capability without necessarily deleting the CanonicalIdentity.

---

# 175. Least-Blast-Radius Response

Compromise of:

```text
ACME organization administrator
```

SHOULD not automatically disable:

```text
all Baobab platform administrators
```

---

# 176. Administrative Availability

Administrative controls SHALL not create a single-human dependency.

---

# 177. Minimum Resilience

Tier-0 administration SHOULD have sufficient independently authenticated authorized operators to recover from:

```text
one unavailable administrator
one lost authenticator
one compromised administrative identity
```

without falling immediately to uncontrolled root access.

---

# 178. Small-Team Reality

During Baobab's early stage, one human MAY hold multiple administrative responsibilities.

The architecture SHALL still record those responsibilities as distinct capabilities.

---

# 179. No Architecture Shortcut for Small Team

Do not encode:

```text
founder = universal superuser forever
```

into the domain model.

---

# 180. Capability Bundles Can Evolve

Initially:

```text
Person A
 ├── IAM Operator
 ├── Platform Operator
 └── Infrastructure Operator
```

may be necessary.

Later these can be separated without redesigning authorization semantics.

---

# 181. Administrative Policy

Administrative policy SHALL be configuration/policy driven where appropriate.

---

# 182. Policy Versioning

Privileged decisions SHOULD be traceable to:

```text
policy version
capability version
scope
```

where practical.

---

# 183. Fail Closed

If Baobab cannot determine whether an administrator has a high-risk capability:

```text
DENY
```

is the default.

---

# 184. CP Failure

If CP authorization is required and unavailable, privileged mutation SHALL normally fail closed.

---

# 185. Read-Only Emergency Visibility

A carefully bounded read-only diagnostic mode MAY remain available under explicitly designed emergency procedures.

It SHALL not silently permit mutation.

---

# 186. No Cached Eternal Admin

Administrative authority SHALL not survive indefinitely merely because an old token contains an admin claim.

---

# 187. Short-Lived Privileged Claims

Privileged authorization SHOULD rely on short-lived, current state and/or authoritative checks according to operation risk.

---

# 188. Revocation

High-risk administrative privilege revocation SHALL propagate rapidly.

---

# 189. Token Claims

Tokens SHOULD NOT contain huge mutable administrative role sets.

Prefer identifiers/context plus authoritative resolution where needed.

---

# 190. Business Roles in Tokens

Provider-issued tokens SHALL NOT become canonical stores of:

```text
ERP roles
buyer approval limits
supplier approval
```

---

# 191. Administrative UI Does Not Authorize

Hiding a button is UX.

Backend authorization SHALL independently enforce every privileged operation.

---

# 192. Direct API Calls

An administrator unable to see a UI control SHALL also be unable to invoke its API without required capability.

---

# 193. Multi-Tenant Administrative Invariant

Every tenant-scoped privileged operation SHALL resolve:

```text
Actor
   ↓
CanonicalIdentity
   ↓
Administrative Capability
   ↓
Authorized Scope
   ↓
Requested Context
   ↓
Target
```

before mutation.

---

# 194. Cross-Tenant Administration

Global operators requiring cross-tenant support SHALL use explicitly global or multi-scope capability.

Cross-tenant access SHALL never emerge accidentally from missing filters.

---

# 195. Customer Data Access

Platform administrator capability SHALL not imply unrestricted browsing of customer business data.

---

# 196. Need-to-Know

Administrative interfaces SHOULD expose only data necessary to perform the administrative function.

---

# 197. Privacy Integration

ADR-IAM-0030 applies to all administrative access to personal information.

---

# 198. Production Safeguards

High-risk production administration SHOULD support controls such as:

```text
step-up
JIT elevation
approval
change reference
restricted network path
short session
audit
notification
```

depending on risk.

---

# 199. Administrative Workstation

Baobab MAY later require hardened administrative workstations for Tier-0 operations.

This is not required for every ordinary organization administrator.

---

# 200. Privileged Network Access

Tier-0 provider/database/cryptographic administration MAY require private network paths rather than Internet-public management endpoints.

---

# 201. Administrative Security Invariants

The following SHALL remain true:

```text
Administrator ≠ Superuser

IAM Admin ≠ Business Admin

Tenant Admin ≠ Platform Admin

Organization Admin ≠ Tenant Admin

Platform Admin ≠ Customer Data Owner

Infrastructure Admin ≠ Business Authority

Database Admin ≠ Application Authority

Support Agent ≠ Identity Owner

Security Analyst ≠ Security Mutator

Security Responder ≠ Permanent IAM Admin

Federation Admin ≠ Enterprise Business Approver

Enterprise IdP Admin ≠ Baobab Admin

SCIM Group ≠ Platform Admin Role

Authentication ≠ Authorization

Privilege ≠ Assurance

A4 ≠ Permanent Identity Attribute

Delegation ≠ Authority Expansion

Invitation ≠ Privilege

Impersonation ≠ Administration

Break-Glass ≠ Convenience

Break-Glass ≠ Universal Root

Technical Capability ≠ Legitimate Authority

Shared Account ≠ Accountability

UI Visibility ≠ Authorization

Repository Admin ≠ Production Admin

Production Admin ≠ Cryptographic Custodian
```

---

# 202. Prohibited Shortcuts

Baobab SHALL NOT:

```text
create one permanent universal admin role

trust an email domain as administrative authority

make first organization registrant admin automatically

grant platform admin through enterprise SCIM group

store admin privilege solely in IdP profile attributes

authorize privileged mutation only in frontend

use shared administrator accounts routinely

permit support to reset privileged identity without proofing

expose Ory admin APIs publicly

allow browser clients to hold provider admin credentials

use break-glass for ordinary operations

allow break-glass without audit

permit self-approval of high-risk elevation

treat database root as application authorization

restore old admin authority from stale backup
```

---

# 203. Implementation Gates

## IAM-ADM0 — Privileged Authority Inventory

Inventory all current privileged operations across:

```text
baobab-iam
baobab-cp
infrastructure
Trade
ERP
CMS
Pulse
ZuriBeans
Thamani
supplier systems
CI/CD
```

Identify implicit superuser behavior.

---

## IAM-ADM1 — Administrative Capability Contract

Define provider-neutral:

```text
AdministrativeCapability
AdministrativeScope
AdministrativeDelegation
PrivilegedOperation
PrivilegedSession
```

where genuinely shared.

---

## IAM-ADM2 — Role Decomposition

Replace broad administrator semantics with bounded capability bundles.

---

## IAM-ADM3 — CP Administrative Authorization

Implement canonical scope/context enforcement for platform and tenant administration.

---

## IAM-ADM4 — Ory Administrative Boundary

Secure:

```text
Kratos Admin API
Hydra Admin API
identity lifecycle adapters
OAuth client administration
```

behind private/authorized service boundaries.

---

## IAM-ADM5 — Privileged Authentication

Implement:

```text
A3/A4 requirements
passkey/security-key preference
recent-authentication requirements
step-up
short privileged sessions
```

---

## IAM-ADM6 — Delegated Customer Administration

Implement:

```text
tenant administration
organization administration
delegation ceilings
expiry
organization verification
last-admin safeguards
```

---

## IAM-ADM7 — ZuriBeans Administration

Separate:

```text
buyer admin
buyer purchasing authority
supplier admin
ZuriBeans staff administration
```

---

## IAM-ADM8 — Thamani Administration

Separate:

```text
personal customer
business admin
shipping roles
finance/approver
partner/carrier
staff administration
```

---

## IAM-ADM9 — ERP / CMS / Domain Administration

Integrate domain-native administrative authority without leaking IdP roles into domain authorization.

---

## IAM-ADM10 — Privileged Access Lifecycle

Implement:

```text
eligible
activate
expire
suspend
revoke
review
reconcile
```

---

## IAM-ADM11 — Separation of Duties

Implement configurable:

```text
approval
dual control
self-elevation prevention
high-risk operation policies
```

---

## IAM-ADM12 — Support Boundary

Implement narrow support tooling without unrestricted impersonation.

---

## IAM-ADM13 — Break-Glass

Implement independent emergency access with:

```text
strong authentication
restricted scope
automatic expiry
immediate alert
full audit
post-use review
```

---

## IAM-ADM14 — Privileged Observability

Integrate administrative events with ADR-IAM-0017 and ADR-IAM-0029.

---

## IAM-ADM15 — Reconciliation

Detect:

```text
orphan privilege
expired delegation
disabled privileged identity
provider/CP disagreement
stale organization admin
stale break-glass state
```

---

## IAM-ADM16 — Production Certification

Production approval requires:

```text
no uncontrolled superuser path
admin APIs protected
A3/A4 tested
delegation tested
cross-tenant isolation tested
break-glass tested
privileged audit tested
revocation tested
SoD tested
runbooks approved
```

---

# 204. Required Test Matrix

| Scenario | Expected Result |
|---|---|
| Ordinary user calls IAM admin endpoint | Denied |
| Org A admin modifies Org B | Denied |
| Tenant A admin modifies Tenant B | Denied |
| Organization admin grants platform role | Denied |
| Buyer admin self-grants purchase approval | Denied unless Trade independently authorizes |
| Supplier admin self-approves supplier | Denied |
| IAM admin attempts ERP finance action | Denied absent ERP authority |
| Support operator attempts MFA bypass | Denied |
| Shared/anonymous admin account attempted | Policy violation |
| A1 session performs privileged action | Step-up/deny |
| A3 required action with stale auth | Reauthentication |
| Admin grants privilege beyond own ceiling | Denied |
| Temporary delegation expires | Authority removed |
| Disabled identity has old admin token | Denied |
| Enterprise SCIM group maps to platform admin | Denied |
| Ory admin endpoint from public Internet | Denied |
| Browser directly invokes Ory admin API | Denied |
| Admin removes final org admin | Additional safeguard |
| Admin approves own high-risk elevation | Denied |
| Break-glass activates | Immediate security event |
| Break-glass expires | Emergency authority removed |
| Break-glass action lacks actor attribution | Test fails |
| Break-glass modifies unrelated domain data | Denied where outside emergency scope |
| Restored backup contains old admin binding | Current restrictive state wins |
| Admin UI hides action but direct API invoked | Backend denies |
| Cross-tenant bulk operation without global scope | Denied |
| Privileged account recovery completes | Privilege review/controls applied |

---

# 205. Production Readiness Checklist

### Administrative Model

- [ ] privileged operations inventoried
- [ ] capabilities defined
- [ ] scopes defined
- [ ] global privilege explicit
- [ ] role bundles documented
- [ ] no universal implicit superuser
- [ ] technical power distinguished from legitimate authority

### Authentication

- [ ] privileged MFA
- [ ] phishing-resistant authentication for high-risk operations
- [ ] step-up
- [ ] recent-authentication enforcement
- [ ] privileged session timeout
- [ ] privileged session audit

### Delegation

- [ ] tenant administration
- [ ] organization administration
- [ ] delegation ceiling
- [ ] time-bound delegation
- [ ] organization verification
- [ ] last-admin protection
- [ ] delegated-access review

### Separation of Duties

- [ ] self-elevation prevented
- [ ] dual control supported
- [ ] high-risk approval policies
- [ ] security observe/mutate separation
- [ ] privacy exception separation
- [ ] cryptographic administration separation

### Support

- [ ] narrow support permissions
- [ ] no routine impersonation
- [ ] support recovery proofing
- [ ] personal data minimization
- [ ] support audit

### Ory

- [ ] admin APIs private
- [ ] no public browser admin access
- [ ] provider-neutral admin adapter
- [ ] OAuth client administration controlled
- [ ] federation administration controlled

### Break-Glass

- [ ] independent emergency path
- [ ] strong authentication
- [ ] restricted capabilities
- [ ] automatic expiry
- [ ] immediate security alert
- [ ] complete audit
- [ ] post-use review
- [ ] credential rotation/sealing
- [ ] periodic exercise

### Lifecycle

- [ ] privileged onboarding
- [ ] mover review
- [ ] offboarding
- [ ] suspension
- [ ] revocation
- [ ] periodic access review
- [ ] orphan privilege reconciliation

### Testing

- [ ] cross-tenant admin isolation
- [ ] stale-token revocation
- [ ] direct API authorization
- [ ] delegation ceiling
- [ ] self-approval prevention
- [ ] break-glass
- [ ] DR privilege reconciliation
- [ ] admin compromise containment

---

# 206. Final Administrative Architecture

```text
                       HUMAN
                         │
                         ▼
                  CanonicalIdentity
                         │
                         ▼
                   Authentication
                         │
                         ▼
               Authentication Assurance
                         │
                         ▼
                Administrative Context
                         │
                         ▼
               Administrative Capability
                         │
                         ▼
                 Authorized Scope
                         │
                         ▼
              ┌──────────┼───────────┐
              │          │           │
              ▼          ▼           ▼
             IAM         CP        Domain
              │          │           │
              ▼          ▼           ▼
          Identity    Platform     Business
          Operation   Operation    Operation
              │          │           │
              └──────────┼───────────┘
                         ▼
                       Audit
                         │
                         ▼
                 Security Monitoring
                         │
                         ▼
                   Access Review
```

Emergency administration follows a separate path:

```text
                NORMAL ADMINISTRATION
                         │
                         X
                    unavailable
                         │
                         ▼
                Qualifying Emergency
                         │
                         ▼
               Break-Glass Declaration
                         │
                         ▼
            Independent Strong Authentication
                         │
                         ▼
              Restricted Emergency Scope
                         │
                         ▼
                     Operation
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
             Audit      Alert      Timer
                                    │
                                    ▼
                                  Expiry
                                    │
                                    ▼
                             Independent Review
```

---

# 207. Consequences

## Positive

This architecture provides:

- no permanent universal administrative model;
- strong separation between IAM and business authority;
- tenant-safe delegated administration;
- organization-level customer self-service;
- capability and scope-based privilege;
- stronger privileged authentication;
- just-in-time privilege;
- separation of duties;
- support without unrestricted impersonation;
- governed emergency access;
- auditable privileged activity;
- safer Ory administrative integration;
- better privilege revocation;
- architecture that can scale from Baobab's initial small team to larger operations.

## Costs

Baobab must implement and operate:

```text
capability registry
administrative scope
delegation lifecycle
privileged session policy
step-up
approval workflows
access reviews
reconciliation
break-glass
privileged auditing
administrative runbooks
```

This additional complexity is justified because administrative authority controls the systems that establish trust for every other user and workload.

---

# 208. Explicitly Deferred

This ADR does not mandate:

```text
a commercial PAM product
a particular privileged workstation product
one SIEM
one ticketing system
one approval application
one secrets-management vendor
one enterprise PIM/PAM vendor
```

Baobab MAY integrate such systems later without changing the authority model established here.

---

# 209. Final Decision Principle

Baobab administration SHALL follow:

```text
Identity
   ↓
Strong Authentication
   ↓
Current Assurance
   ↓
Administrative Capability
   ↓
Scope
   ↓
Context
   ↓
Purpose
   ↓
Operation
   ↓
Audit
```

Never:

```text
"User is an admin"
        ↓
"User can do everything"
```

Delegation SHALL obey:

```text
delegate
    only
what you possess
    within
your authorized scope
    for
the permitted duration
```

Emergency access SHALL obey:

```text
exceptional
+
independent
+
minimal
+
temporary
+
observable
+
reviewable
```

The architecture must remain valid even while Baobab is operated by a small team in which one person temporarily performs several functions.

The model therefore records the **capabilities**, not organizational shortcuts.

As Baobab grows:

```text
one person
holding several bounded capabilities
            ↓
several people
holding separated capabilities
```

requires organizational reassignment—not architectural redesign.

Therefore:

> **No administrator is powerful merely because they are called an administrator. Authority exists only as an explicit capability exercised within an authorized scope, context, assurance level and lifetime.**

And the emergency rule is:

> **Break glass only when normal control cannot safely meet the emergency; grant the smallest sufficient authority, make every action visible, expire it automatically, and independently review what happened afterward.**

Finally:

> **The people who operate Baobab's identity system must themselves be governed by the same principles the identity system exists to enforce: explicit identity, strong authentication, least privilege, separation of authority, rapid revocation and complete accountability.**