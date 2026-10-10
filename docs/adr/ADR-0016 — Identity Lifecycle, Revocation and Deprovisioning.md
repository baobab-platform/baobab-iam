# ADR-0016: Identity Lifecycle, Revocation and Deprovisioning

**Status:** Proposed  
**Date:** 2026-09-09  
**Decision Owners:** NABHOLD / Baobab Platform Architecture and Security  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Related Repositories:** `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/shared`, `baobab-platform/infrastructure`, Digital Estate repositories  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Identity creation, activation, suspension, disablement, archival, membership lifecycle, entitlement lifecycle, credential lifecycle, session and token revocation, workforce joiner/mover/leaver, buyer and supplier representative lifecycle, customer closure, workload lifecycle, engine deprovisioning, revocation propagation, eventual consistency, orphan detection, reconciliation and identity-related security events  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:** ADR-0001 through ADR-0015

---

# 1. Context

Baobab identity is distributed across several deliberately separated authorities.

A human may simultaneously have:

```text
Keycloak User
CanonicalIdentity
Tenant Membership
Legal-Entity Relationship
Digital-Estate Access
Capability Entitlement
Medusa Customer/User
iDempiere AD_User
Payload User
Pulse User/Profile
Buyer Organization Membership
Supplier Organization Membership
Active Sessions
Refresh Tokens
External Identity Links
```

These objects do not have identical lifecycle semantics.

For example:

```text
Employee leaves Nabhold
```

does not mean:

```text
delete CanonicalIdentity
```

because historical audit attribution must remain.

Similarly:

```text
Supplier suspended
```

does not necessarily mean:

```text
disable representative's Keycloak account
```

because the person may legitimately represent another organization.

Baobab therefore requires a lifecycle architecture that can revoke the correct authority at the correct layer without destroying historical identity, corrupting audit records, or accidentally affecting unrelated relationships.

---

# 2. Decision

Baobab SHALL model identity lifecycle, credential lifecycle, relationship lifecycle, platform entitlement lifecycle, domain actor lifecycle, and session lifecycle as separate but coordinated state machines.

The architecture SHALL follow:

```text
Identity
   │
   ├── Credentials
   ├── Sessions
   ├── Memberships
   ├── Entitlements
   ├── External Identities
   └── Engine Actors
```

Revocation SHALL target the narrowest authority necessary while supporting broader emergency revocation when risk requires it.

---

# 3. Governing Principle

> **Revoke the authority that is no longer valid, preserve the identity and history that remain valid, propagate security changes quickly, and never rely on deletion as the primary lifecycle mechanism.**

---

# 4. Lifecycle Domains

Baobab SHALL distinguish at least:

| Lifecycle | Authority |
|---|---|
| Authentication identity | Baobab IAM |
| Credential | Baobab IAM |
| Session | Baobab IAM/application |
| Canonical identity | Control Plane |
| Tenant membership | Control Plane |
| Legal-entity relationship | Control Plane |
| Capability entitlement | Control Plane |
| Buyer membership | Trade |
| Supplier membership | Supplier domain |
| Customer actor | Trade |
| ERP user | iDempiere |
| ERP role | iDempiere |
| CMS user/role | Payload |
| Pulse access | Pulse |
| Workload identity | IAM + Infrastructure |

No lifecycle SHALL silently substitute for another.

---

# 5. Identity Lifecycle

The Canonical Identity SHOULD support a lifecycle concept similar to:

```text
PROVISIONAL
    │
    ▼
ACTIVE
    │
    ├────────► SUSPENDED
    │              │
    │              ▼
    │            ACTIVE
    │
    ▼
DISABLED
    │
    ▼
ARCHIVED
```

Exact persistence SHALL align with the existing Control Plane model.

---

# 6. PROVISIONAL

`PROVISIONAL` represents an identity that has been created but is not yet fully eligible for ordinary platform access.

Examples:

- invitation accepted but verification incomplete;
- controlled JIT provisioning in progress;
- migration record awaiting verification;
- supplier representative awaiting relationship confirmation.

---

# 7. ACTIVE

`ACTIVE` means the Canonical Identity itself is permitted to participate in platform authorization.

It does NOT mean that every tenant, estate, capability or domain action is authorized.

---

# 8. SUSPENDED

`SUSPENDED` SHALL represent temporary restriction.

Examples:

- security investigation;
- suspected compromise;
- temporary workforce suspension;
- compliance hold.

Suspension SHOULD be reversible.

---

# 9. DISABLED

`DISABLED` represents an identity that is no longer permitted to establish ordinary Baobab access.

The record SHALL normally remain for:

- audit;
- mappings;
- historical attribution;
- legal/compliance records.

---

# 10. ARCHIVED

`ARCHIVED` SHALL represent a terminal or long-term historical state where the identity remains retained but is no longer operational.

Archival SHALL NOT imply physical deletion.

---

# 11. Identity State Is Not Membership State

This SHALL remain binding:

```text
CanonicalIdentity = ACTIVE

does not imply

TenantMembership = ACTIVE
```

and:

```text
TenantMembership = REVOKED

does not imply

CanonicalIdentity = DISABLED
```

---

# 12. Credential Lifecycle

Credentials SHALL have their own lifecycle.

Conceptually:

```text
ENROLLED
   │
   ▼
ACTIVE
   │
   ├────► COMPROMISED
   │
   ├────► REVOKED
   │
   └────► REPLACED
```

Credential state SHALL not be inferred solely from Canonical Identity state.

---

# 13. Credential Revocation

Revoking one credential SHOULD invalidate only that credential unless broader compromise is suspected.

Example:

```text
lost security key
      │
      ▼
revoke that WebAuthn credential
```

The Canonical Identity may remain active.

---

# 14. Identity Disablement

Disabling the IAM/Canonical Identity SHOULD invalidate all ordinary authentication paths associated with that identity.

---

# 15. Relationship Lifecycle

A person may have multiple simultaneous relationships.

Example:

```text
CanonicalIdentity: Person A
        │
        ├── Nabhold employee
        ├── Zuribeans buyer representative
        └── Supplier representative
```

Each relationship SHALL be independently revocable.

---

# 16. Relationship State

A common relationship lifecycle SHOULD support concepts such as:

```text
INVITED
PENDING
ACTIVE
SUSPENDED
REVOKED
EXPIRED
```

where appropriate.

Domain-specific states MAY extend this model.

---

# 17. Membership Revocation

Revoking a membership SHALL remove authority derived from that membership.

It SHALL NOT automatically disable the person's identity.

---

# 18. Multi-Relationship Safety

This is prohibited:

```text
remove supplier membership
        │
        ▼
delete Keycloak user
```

if that person has other valid Baobab relationships.

---

# 19. Tenant Membership

Tenant membership SHALL remain a Control Plane relationship.

Its lifecycle SHALL be independently governed.

---

# 20. Tenant Membership Removal

When membership is revoked:

```text
CanonicalIdentity
       │
       X
       │
    Tenant A
```

future CP context resolution for Tenant A SHALL deny access.

---

# 21. Other Tenant Memberships

If the same identity retains:

```text
Tenant B membership
```

Tenant B access SHALL remain unaffected.

---

# 22. Tenant Suspension

Tenant suspension is distinct from member suspension.

If:

```text
Tenant = SUSPENDED
```

all ordinary access dependent on that tenant SHALL be denied regardless of individual membership state.

---

# 23. Capability Entitlement

Capability entitlement SHALL have an independent lifecycle.

Example:

```text
Tenant active
User active
ERP entitlement revoked
```

SHALL produce:

```text
ERP access = DENY
```

while other entitled capabilities may remain available.

---

# 24. Capability Revocation

Revoking:

```text
ERP capability
```

SHALL not necessarily revoke:

```text
Trade
CMS
Pulse
```

unless policy explicitly couples them.

---

# 25. Digital Estate Access

Digital Estate access SHALL likewise be separately revocable where explicit estate entitlement exists.

---

# 26. Market Access

Market-specific authority MAY be revoked without disabling the entire identity.

Example:

```text
ZA market access = ACTIVE
UG market access = REVOKED
```

---

# 27. Authentication Session Lifecycle

Sessions SHALL be treated as independently revocable security objects.

Conceptually:

```text
CREATED
   │
   ▼
ACTIVE
   │
   ├────► EXPIRED
   ├────► REVOKED
   └────► TERMINATED
```

---

# 28. Access Token Lifecycle

Self-contained access tokens may remain cryptographically valid until expiry.

Therefore Baobab SHALL combine:

- short access-token lifetime;
- current-state authorization;
- session revocation;
- downstream revocation mechanisms where needed.

---

# 29. Token Expiry Is Not Sufficient Revocation

For high-risk access:

```text
wait 15 minutes
```

SHALL NOT always be considered sufficient incident response.

Current authorization state SHALL be able to deny sensitive actions before token expiry.

---

# 30. Refresh Token Revocation

Revocation of an IAM session SHALL prevent continued refresh-token use according to Keycloak semantics and Baobab configuration.

---

# 31. Session Revocation Levels

Baobab SHOULD support:

```text
revoke current session
revoke selected sessions
revoke all user sessions
```

where technically supported.

---

# 32. Global Security Revocation

For suspected identity compromise:

```text
disable/restrict identity
        │
        ▼
revoke sessions
        │
        ▼
revoke suspicious credentials
        │
        ▼
propagate security event
```

SHALL be supported.

---

# 33. Domain Revocation Does Not Require Global Logout

If only a Trade buyer role is removed, global Keycloak logout MAY be unnecessary.

Trade SHALL deny the removed authority using current domain state.

---

# 34. Revocation Granularity

Baobab SHALL prefer the narrowest effective revocation.

Examples:

| Event | Preferred Revocation |
|---|---|
| Lost passkey | Credential |
| Buyer employee leaves buyer company | Buyer membership |
| Supplier suspended | Supplier organization/domain authority |
| Employee leaves Nabhold | Workforce relationship + relevant entitlements |
| Account takeover | Identity + credentials + sessions |
| ERP role removed | AD_Role |
| Tenant terminated | Tenant |
| Service secret compromised | Workload credential/identity |

---

# 35. Workforce Joiner

Workforce onboarding SHALL be explicit.

```text
Person approved
     │
     ▼
CanonicalIdentity
     │
     ▼
IAM authentication established
     │
     ▼
Workforce relationship
     │
     ▼
Tenant/context memberships
     │
     ▼
Capability entitlements
     │
     ▼
Engine mappings
     │
     ▼
Domain roles
```

---

# 36. Joiner Least Privilege

A new employee SHALL receive only the access required for the approved role.

---

# 37. Joiner Does Not Equal Admin

This is prohibited:

```text
new Nabhold employee
      =
platform administrator
```

---

# 38. Joiner MFA

Required authenticators SHALL be enrolled before privileged access becomes effective.

---

# 39. Workforce Mover

A role or organizational change SHALL trigger access reevaluation.

The preferred model is:

```text
Current access
      │
      ▼
Determine obsolete privileges
      │
      ▼
Revoke obsolete privileges
      │
      ▼
Approve new privileges
      │
      ▼
Provision new privileges
```

---

# 40. Revoke Before Grant Where Risk Warrants

For sensitive moves, obsolete authority SHOULD be removed before or atomically with new authority.

---

# 41. Privilege Accumulation

Baobab SHALL guard against:

```text
Role A
  +
Role B
  +
Role C
  +
Role D
```

accumulating indefinitely through successive job changes.

---

# 42. Separation-of-Duties Review

Mover workflows SHALL check for incompatible privilege combinations where SoD policy applies.

---

# 43. Workforce Leaver

Leaver processing SHALL prioritize rapid removal of active authority.

Target:

```text
Leaver confirmed
      │
      ▼
Disable workforce authentication/access
      │
      ▼
Revoke IAM sessions
      │
      ▼
Revoke workforce memberships
      │
      ▼
Revoke platform entitlements
      │
      ▼
Revoke domain roles
      │
      ▼
Deactivate engine actors where appropriate
      │
      ▼
Preserve audit/history
```

---

# 44. Leaver Identity Preservation

A leaver's Canonical Identity SHALL normally remain retained.

Historical transactions MUST remain attributable.

---

# 45. Rehire

A future rehire SHOULD normally reuse the verified Canonical Identity rather than creating an unrelated identity solely because employment was interrupted.

New employment relationships and privileges SHALL be explicitly granted.

---

# 46. Rehire Does Not Restore Old Privileges

This is binding:

```text
Rehire
  ≠
restore previous access graph
```

Access SHALL be reprovisioned according to the new role.

---

# 47. Contractor Expiry

Time-bound workforce/contractor relationships SHOULD support explicit expiry.

Expired relationships SHALL not rely solely on manual cleanup.

---

# 48. Scheduled Expiry

Where a relationship has:

```text
valid_until
```

authorization SHALL cease when that validity expires.

---

# 49. Buyer Representative Onboarding

Zuribeans buyer representatives SHALL follow:

```text
Identity
   │
   ▼
Buyer Organization invitation
   │
   ▼
Membership verification
   │
   ▼
Buyer role
   │
   ▼
Trade authorization
```

---

# 50. Buyer Representative Removal

When a representative leaves the buyer organization:

```text
buyer membership revoked
```

SHALL immediately remove authority derived from that membership.

---

# 51. Buyer Removal Does Not Delete Customer Identity

If the person has another legitimate Baobab relationship, their Canonical Identity and IAM account SHALL remain.

---

# 52. Buyer Approval Authority

Purchase approval authority SHALL be independently revocable from ordinary buyer membership.

---

# 53. Supplier Representative Onboarding

Supplier representatives SHALL follow ADR-0012.

Identity activation SHALL remain separate from supplier approval.

---

# 54. Supplier Representative Removal

Removing a supplier representative SHALL revoke:

- supplier membership;
- supplier portal authority;
- domain roles associated with that supplier.

It SHALL NOT automatically alter the supplier organization's commercial status.

---

# 55. Supplier Suspension

Suspending the supplier organization SHALL restrict supplier-domain actions for all representatives as policy requires.

Individual identities may remain valid elsewhere.

---

# 56. Supplier Rejection

If supplier onboarding is rejected:

```text
Supplier Application = REJECTED
```

the representatives' identities SHALL NOT automatically be deleted.

---

# 57. Supplier Approval ≠ Permanent Approval

Supplier status SHALL remain independently revocable/suspendable.

---

# 58. Supplier Finance Role Revocation

Financial-data modification authority SHALL be independently removable without removing ordinary supplier portal access.

---

# 59. Thamani Customer Lifecycle

B2C customer identity lifecycle SHALL support:

```text
registered
verified
active
restricted
closed
```

using IAM and Trade states appropriately.

---

# 60. Customer Closure

A customer requesting account closure SHALL not require destructive deletion of commerce records that must be retained for:

- accounting;
- taxation;
- fraud prevention;
- legal obligations;
- transaction history.

---

# 61. Closure vs Erasure

Baobab SHALL distinguish:

```text
account closure
```

from:

```text
personal-data erasure/anonymization
```

Privacy-retention policy SHALL govern the latter.

---

# 62. Customer Authentication Closure

Closing a customer account SHOULD prevent future normal authentication/use of that customer relationship.

---

# 63. Customer Commerce History

Orders, invoices and legally required records SHALL remain governed by Trade/ERP retention rules.

---

# 64. Customer Reopening

If reopening is permitted, it SHALL use controlled identity verification.

A closed account SHALL not silently reactivate merely because the same email registers again.

---

# 65. Email Reuse

Email reuse SHALL NOT cause historical identity takeover.

---

# 66. External Identity Unlinking

Removing an external IdP relationship SHALL revoke only that authentication path unless the entire identity is being disabled.

---

# 67. Last Authentication Path

Baobab SHOULD prevent accidental removal of the final usable authentication path unless:

- account closure is intended; or
- a recovery process is available.

---

# 68. External Identity Compromise

A compromised federated identity MAY be unlinked while preserving other valid authentication mechanisms.

---

# 69. Engine Actor Lifecycle

Engine-local actors SHALL retain their native lifecycle semantics.

Examples:

```text
Medusa Customer
Medusa User
iDempiere AD_User
Payload User
Pulse Profile
```

---

# 70. Engine Actor Disablement

An engine actor MAY be disabled independently of Canonical Identity.

Example:

```text
CanonicalIdentity = ACTIVE
AD_User = INACTIVE
```

Result:

```text
ERP access = DENY
```

---

# 71. Medusa Customer Deactivation

Trade MAY restrict or deactivate a customer actor while IAM remains active.

Authentication success SHALL not override Trade suspension.

---

# 72. Medusa Admin Deprovisioning

When Trade admin access is removed:

```text
Medusa User administrative authority
```

SHALL be revoked even if workforce SSO remains active.

---

# 73. ERP Deprovisioning

For ERP leavers or role changes:

```text
AD_User
AD_Role
AD_Client
AD_Org
```

access SHALL be reviewed according to ADR-0014.

Historical `AD_User` attribution SHALL remain.

---

# 74. CMS Deprovisioning

Removing CMS access SHALL revoke Payload-specific editorial/publishing authority without necessarily disabling workforce identity.

---

# 75. Pulse Deprovisioning

Pulse workspace/report/data privileges SHALL be independently revocable.

---

# 76. Engine Mapping Preservation

Mappings MAY remain historically retained after engine access is disabled.

A mapping's existence SHALL not itself authorize access.

---

# 77. Mapping State

Where useful, mappings SHOULD carry lifecycle metadata such as:

```text
ACTIVE
INACTIVE
REVOKED
HISTORICAL
```

rather than requiring physical deletion.

---

# 78. Mapping ≠ Authorization

This remains binding:

```text
CanonicalIdentity → AD_User mapping exists
```

does not mean:

```text
ERP access allowed
```

---

# 79. Workload Lifecycle

Workload identities SHALL have their own lifecycle.

Recommended:

```text
PROVISIONED
    │
    ▼
ACTIVE
    │
    ├────► SUSPENDED
    │
    ├────► REVOKED
    │
    └────► RETIRED
```

---

# 80. Workload Provisioning

A workload identity SHALL be created only for an identified deployment/security boundary with:

- owner;
- repository;
- runtime;
- environment;
- required audience;
- required scopes.

---

# 81. Workload Retirement

When a service is retired:

```text
runtime removed
     │
     ▼
credential revoked
     │
     ▼
client/workload disabled
     │
     ▼
downstream grants removed
```

---

# 82. Deployment Removal Is Not Credential Revocation

Deleting a container or deployment SHALL NOT be assumed to revoke its credentials.

Explicit credential retirement remains necessary.

---

# 83. Credential Rotation Is Not Workload Retirement

Rotating a client secret SHALL preserve the workload identity while replacing its credential.

---

# 84. Compromised Workload

Compromise response SHALL permit revoking one workload without disabling unrelated Baobab services.

---

# 85. Runtime vs Deployment Identity

Runtime identities and CI/CD deployment identities SHALL remain separate.

---

# 86. GitHub Offboarding

Removing a developer's GitHub access SHALL be governed by GitHub/provider authorization and workforce offboarding.

It SHALL not be assumed to occur merely because Keycloak access was disabled unless explicit federation/provisioning guarantees it.

---

# 87. Cloud Access

Cloud IAM and infrastructure access SHALL likewise have explicit deprovisioning steps.

---

# 88. Cross-System Deprovisioning

Baobab SHALL implement coordinated deprovisioning through events and reconciliation rather than distributed database writes.

---

# 89. Deprovisioning Event Model

Conceptually:

```text
Authoritative lifecycle change
          │
          ▼
Canonical security event
          │
    ┌─────┼─────┬─────┐
    ▼     ▼     ▼     ▼
 Trade   ERP   CMS   Pulse
```

---

# 90. Event Examples

`baobab-platform/shared` SHOULD define versioned events such as:

```text
identity.suspended
identity.disabled
identity.reactivated
membership.revoked
entitlement.revoked
credential.compromised
session.revoked
workload.revoked
```

Exact naming SHALL follow the platform's canonical event conventions.

---

# 91. Events Are Notifications, Not Sole Authority

Consumers SHALL use events to update local state.

However:

```text
event received once
```

SHALL NOT become the only guarantee of correct revocation.

Reconciliation is also required.

---

# 92. Event Idempotency

Lifecycle consumers SHALL process revocation events idempotently.

Duplicate events SHALL not recreate access or corrupt state.

---

# 93. Event Ordering

Consumers SHALL tolerate delayed and potentially out-of-order lifecycle events.

---

# 94. Lifecycle Versioning

Security-sensitive entities SHOULD carry a version, revision, timestamp or equivalent ordering mechanism sufficient to reject stale state transitions.

---

# 95. Stale Activation Protection

This scenario SHALL be prevented:

```text
T1: membership ACTIVE
T2: membership REVOKED
T3: delayed ACTIVE event arrives
```

The T3 event SHALL NOT reactivate the membership.

---

# 96. Event Provenance

Lifecycle events SHALL identify the authoritative producer.

Consumers SHALL not trust arbitrary event publishers to revoke or activate identities.

---

# 97. Event Security

Lifecycle event transport SHALL require authenticated workload identities and platform security controls.

---

# 98. Event Audit

Security-sensitive lifecycle events SHOULD contain or correlate to:

```text
event_id
event_type
subject/reference
effective_at
actor
reason
decision/change ID
correlation ID
schema version
```

without embedding secrets.

---

# 99. Eventual Consistency

Cross-engine deprovisioning is inherently distributed.

Baobab accepts bounded eventual consistency but SHALL explicitly define maximum acceptable revocation windows by risk.

---

# 100. Risk-Based Revocation Objectives

Illustrative classes:

| Change | Expected Behaviour |
|---|---|
| Compromised privileged identity | Near-immediate |
| Workforce termination | Near-immediate |
| Tenant suspension | Near-immediate |
| Privileged role removal | Near-immediate |
| Ordinary membership expiry | Short bounded propagation |
| Historical archival | Asynchronous |
| Non-security profile update | Normal eventual consistency |

Exact SLOs SHALL be defined operationally.

---

# 101. High-Risk Revocation

High-risk revocation SHALL NOT depend solely on asynchronous engine synchronization.

Authoritative online checks SHOULD deny access as early as possible.

---

# 102. CP as Immediate Platform Gate

If a tenant membership or capability entitlement has been revoked in CP:

```text
new context resolution
```

SHALL deny immediately even if an engine has not yet processed its local cleanup event.

---

# 103. Domain as Immediate Domain Gate

If a Trade or ERP role has been revoked:

```text
domain authorization
```

SHALL deny according to current domain state even if IAM session remains valid.

---

# 104. Cache Invalidation

Security-relevant lifecycle changes SHALL trigger appropriate cache invalidation.

---

# 105. Authorization Cache TTL

Authorization caches SHALL use bounded TTLs proportional to risk.

No indefinite membership/entitlement cache is permitted.

---

# 106. Negative Cache Safety

Caching a previous `ALLOW` SHALL never override a newer authoritative `DENY`.

---

# 107. Token Claims and Revocation

Because JWT claims can become stale, mutable authorization SHALL not depend exclusively on long-lived token claims.

---

# 108. Short-Lived Access Tokens

ADR-0006's short-lived token policy remains a defense against stale identity/session state.

---

# 109. Token Refresh

Refresh SHALL re-evaluate IAM eligibility according to Keycloak/session policy.

---

# 110. Revoked Platform Membership Despite Valid Token

This SHALL produce:

```text
Valid token
+
revoked tenant membership
=
DENY
```

---

# 111. Revoked Domain Role Despite Valid Token

Likewise:

```text
Valid token
+
valid CP context
+
revoked AD_Role
=
DENY
```

---

# 112. Orphan Definition

An orphan is an identity-related record whose expected authoritative relationship no longer exists or cannot be resolved.

Examples:

```text
Medusa User without CanonicalIdentity mapping

AD_User expected to be workforce-linked but mapping missing

ExternalIdentity pointing to missing CanonicalIdentity

active domain membership for disabled/deleted organization

active workload client with no registered runtime owner
```

---

# 113. Orphan Detection

Baobab SHALL implement scheduled reconciliation capable of detecting orphaned identity/access records.

---

# 114. Orphan Handling

Security-sensitive orphans SHOULD default toward restriction rather than implicit access.

---

# 115. No Auto-Delete of Orphans

Reconciliation SHALL not blindly delete records.

It SHOULD classify them for:

```text
automatic safe repair
automatic disablement
manual investigation
```

---

# 116. Reconciliation

Lifecycle correctness SHALL use both:

```text
events
+
periodic reconciliation
```

---

# 117. Reconciliation Direction

The authoritative owner of each property SHALL determine repair direction.

Example:

```text
AD_Role
```

is iDempiere-owned.

CP SHALL not overwrite it merely because CP lacks an equivalent role.

---

# 118. Source-of-Truth Matrix

| Data | Authority |
|---|---|
| Keycloak account/session | IAM |
| CanonicalIdentity | CP |
| Tenant membership | CP |
| Capability entitlement | CP |
| Buyer membership | Trade |
| Supplier approval/membership | Supplier domain |
| Medusa actor status | Trade |
| AD_User/AD_Role | ERP |
| CMS role | CMS |
| Pulse domain access | Pulse |
| Runtime workload ownership | IAM/Infrastructure registry |

---

# 119. Reconciliation Shall Respect Authority

A mismatch SHALL not automatically mean CP wins.

The owner defined above wins for its property.

---

# 120. Deprovisioning Saga

Complex offboarding MAY be implemented as a saga/workflow.

Example:

```text
Disable IAM
    │
    ▼
Revoke sessions
    │
    ▼
Revoke CP memberships
    │
    ▼
Revoke capabilities
    │
    ▼
Notify Trade
    │
    ▼
Notify ERP
    │
    ▼
Notify CMS
    │
    ▼
Notify Pulse
    │
    ▼
Verify reconciliation
```

---

# 121. Saga Partial Failure

If ERP deprovisioning fails while IAM/CP revocation succeeds:

```text
overall workflow
```

SHALL remain in an incomplete/error state requiring retry or intervention.

The platform SHALL NOT reactivate IAM merely to obtain symmetry.

---

# 122. Security Bias During Partial Failure

Partial deprovisioning SHALL bias toward denying access.

---

# 123. Retry

Deprovisioning steps SHALL be retryable and idempotent.

---

# 124. Dead-Letter Handling

Repeatedly failing lifecycle events SHALL enter an operational failure path such as:

```text
dead-letter / quarantine
```

with alerting and remediation.

---

# 125. Completion State

High-risk offboarding SHALL not be marked `COMPLETE` until required downstream revocation steps are confirmed or explicitly waived by authorized security personnel.

---

# 126. Deprovisioning Status

A workflow MAY expose:

```text
PENDING
IN_PROGRESS
PARTIAL
COMPLETE
FAILED
```

without making the workflow status itself an authorization authority.

---

# 127. Idempotency Keys

Lifecycle commands and events SHOULD carry stable identifiers sufficient to prevent duplicate provisioning or deprovisioning.

---

# 128. Reactivation

Reactivation SHALL be explicit.

A previously disabled identity SHALL not reactivate merely because a downstream engine still contains an active actor.

---

# 129. Reactivation Review

Reactivation SHOULD verify:

- identity status;
- credential security;
- relationships;
- memberships;
- entitlements;
- engine access.

---

# 130. Reactivation Does Not Restore Everything

This remains binding:

```text
Identity reactivated
      ≠
all old memberships restored
```

---

# 131. Suspended-to-Active

Temporary suspension MAY preserve relationships for later restoration according to policy.

However, high-risk roles SHOULD still be revalidated.

---

# 132. Archived Identity Reactivation

Reactivating an archived identity SHOULD be treated as exceptional and may require identity re-verification.

---

# 133. Deletion

Hard deletion SHALL be exceptional.

It SHALL only occur when:

- legally appropriate;
- retention obligations permit it;
- referential integrity is understood;
- audit requirements are preserved.

---

# 134. Pseudonymization

Where privacy requirements demand reduction of retained personal data while historical business records must remain, pseudonymization/anonymization SHOULD be considered instead of destructive transaction deletion.

---

# 135. Legal Holds

Lifecycle cleanup SHALL respect legal or regulatory retention holds.

---

# 136. Privacy Deletion Is Not Security Deprovisioning

These are separate workflows:

```text
SECURITY:
stop access now

PRIVACY:
determine which personal data may/must be erased
```

---

# 137. Deprovisioning Before Privacy Processing

Account access SHOULD be disabled promptly even if privacy/retention evaluation takes longer.

---

# 138. Audit Preservation

Lifecycle changes SHALL preserve enough historical identity information to answer:

```text
Who had access?

When?

To what context?

Who revoked it?

Why?

Was downstream revocation completed?
```

---

# 139. Audit Events

At minimum, audit:

```text
identity created
identity activated
identity suspended
identity disabled
identity reactivated
membership created
membership revoked
entitlement granted
entitlement revoked
credential revoked
sessions revoked
engine actor disabled
workload revoked
deprovisioning completed/failed
```

---

# 140. Lifecycle Actor

Every administrative lifecycle change SHOULD identify the initiating actor.

Examples:

```text
self-service
administrator
security automation
HR integration
supplier administrator
buyer administrator
system policy
```

---

# 141. Reason Codes

Security-sensitive revocations SHOULD carry structured reason codes where practical.

Examples:

```text
WORKFORCE_TERMINATION
MEMBERSHIP_EXPIRED
SECURITY_COMPROMISE
ROLE_CHANGE
TENANT_SUSPENSION
CONTRACT_END
USER_REQUEST
ADMINISTRATIVE_ACTION
```

---

# 142. Free-Text Reason

Optional human explanation MAY supplement reason codes.

Sensitive personal information SHOULD not be unnecessarily embedded in lifecycle events.

---

# 143. Effective Time

Lifecycle actions MAY support:

```text
effective_at
```

for scheduled starts/expiry.

Security revocation commands requiring immediate effect SHALL not be delayed by scheduled processing.

---

# 144. Future-Dated Revocation

Known contract termination MAY be scheduled in advance.

The system SHALL execute the revocation reliably at the effective time.

---

# 145. Manual Override

Manual security intervention MAY accelerate a scheduled revocation.

---

# 146. Approval Workflow

High-risk privilege grants MAY require approval.

Revocation SHOULD generally not require approval where delay would increase security risk.

---

# 147. Self-Revocation

Users SHOULD be able to perform safe actions such as:

```text
terminate own session
remove own authenticator
leave optional relationship
```

subject to business/audit requirements.

---

# 148. Self-Service Cannot Evade Obligations

A supplier representative SHALL not be able to delete audit history by leaving an organization.

---

# 149. Administrative Deprovisioning APIs

Lifecycle APIs SHALL require explicit:

- audience;
- scope;
- authorization;
- context;
- audit.

---

# 150. No Public Lifecycle Trust

A Digital Estate SHALL not be able to send:

```text
identity_disabled = true
```

and have CP/IAM trust it without authorization.

---

# 151. Workload Authorization

Automation performing lifecycle actions SHALL use workload identity under ADR-0007.

---

# 152. Delegated Administration

Buyer/supplier administrators MAY revoke representatives only within organizations they are explicitly authorized to administer.

---

# 153. Tenant Administrators

Tenant administrators SHALL not receive realm-wide identity deletion powers merely because they manage a tenant.

---

# 154. IAM Administrators

IAM administrators manage authentication identities.

They SHALL not automatically control:

```text
AD_Role
buyer approval
supplier approval
commerce refund authority
```

---

# 155. Control Plane Administrators

CP administrators manage platform relationships and entitlements.

They SHALL not automatically possess domain engine privileges.

---

# 156. Domain Administrators

Domain administrators manage domain access.

They SHALL not automatically disable the global identity.

---

# 157. Security Administrator

A dedicated security authority MAY receive emergency cross-layer suspension powers.

Such authority SHALL be exceptional and heavily audited.

---

# 158. Kill Switch

Baobab SHOULD provide a controlled security operation capable of rapidly suspending a compromised Canonical Identity across platform entry points.

---

# 159. Kill Switch Semantics

The operation SHOULD:

```text
suspend identity
revoke IAM sessions
prevent CP context resolution
publish security event
trigger downstream restriction
```

without destroying historical records.

---

# 160. Tenant Kill Switch

Similarly, platform operations SHOULD support emergency tenant suspension.

---

# 161. Workload Kill Switch

Security operations SHOULD be able to revoke an individual compromised workload identity rapidly.

---

# 162. Revocation SLO Monitoring

The platform SHOULD measure:

```text
revocation requested
        │
        ▼
authoritative state changed
        │
        ▼
downstream enforcement observed
```

---

# 163. Useful Metrics

Metrics MAY include:

```text
identity_revocations_total
session_revocations_total
membership_revocations_total
deprovisioning_duration
deprovisioning_failures_total
orphan_identities_total
stale_mappings_total
revocation_event_lag
```

---

# 164. Alerting

Alerts SHOULD exist for:

- failed privileged-user deprovisioning;
- failed tenant suspension propagation;
- orphan privileged accounts;
- stale active workload identities;
- repeated lifecycle event failures;
- unexpectedly long revocation lag.

---

# 165. Reconciliation Metrics

Track:

```text
records scanned
mismatches found
automatic repairs
automatic restrictions
manual investigations
```

---

# 166. Dormant Identities

Dormancy SHALL not automatically equal termination.

However, dormant privileged identities SHOULD trigger review.

---

# 167. Dormant Privileged Accounts

Privileged accounts unused for a configured period SHOULD be:

```text
reviewed
```

and potentially:

```text
suspended
```

according to policy.

---

# 168. Dormant External Users

Long-unused customer/buyer/supplier identities MAY follow product-specific retention and security policy.

---

# 169. Access Certification

Periodic access review SHOULD complement event-driven lifecycle management.

Review populations SHOULD include:

```text
privileged users
cross-tenant users
finance users
supplier administrators
buyer administrators
workloads
```

---

# 170. Certification Outcomes

Access review MAY produce:

```text
RETAIN
MODIFY
REVOKE
INVESTIGATE
```

---

# 171. Access Certification Is Not Source of Truth

Certification workflows trigger changes.

Authoritative state remains in the owning system.

---

# 172. Production vs Non-Production

Environment access SHALL have independent lifecycle.

Removing production access SHALL not necessarily remove development access and vice versa.

---

# 173. Non-Production Does Not Imply Production

This remains binding:

```text
dev membership
    ≠
prod membership
```

---

# 174. Production Offboarding

Production privileges SHOULD receive priority during urgent offboarding.

---

# 175. Engine Instance Retirement

When an EngineInstance is retired:

```text
CapabilityBindings
Mappings
Workload credentials
Identity mappings
```

SHALL be reviewed and retired appropriately.

---

# 176. Engine Replacement

Replacing an engine SHALL not create a new Canonical Identity for every user.

New engine-local mappings SHALL reference existing canonical identities.

---

# 177. Migration Lifecycle

During engine migration, old and new mappings MAY temporarily coexist.

The migration SHALL define:

```text
OLD_ACTIVE
DUAL
NEW_ACTIVE
OLD_RETIRED
```

or equivalent operational state.

---

# 178. Migration Rollback

Rollback SHALL not accidentally reactivate credentials or roles intentionally revoked during migration.

---

# 179. No Identity Resurrection

This scenario SHALL be prevented:

```text
user revoked in new system
       │
       ▼
migration rollback
       │
       ▼
old active user restores access
```

---

# 180. Security State Dominates Migration State

Revocation SHALL survive migrations, rollbacks and disaster recovery.

---

# 181. Backup Restoration

Restoring an old backup SHALL not silently resurrect:

- disabled identities;
- revoked credentials;
- terminated memberships;
- revoked workload identities.

---

# 182. Revocation Ledger/Checkpoint

Disaster recovery design SHOULD maintain sufficient post-backup lifecycle information or reconciliation capability to reapply security changes made after the restored snapshot.

---

# 183. DR Reconciliation

After significant restoration:

```text
restore
  │
  ▼
reconcile security state
  │
  ▼
verify privileged identities
  │
  ▼
verify tenant/workload revocations
  │
  ▼
resume normal service
```

---

# 184. Lifecycle Contract Versioning

Lifecycle commands/events SHALL use versioned schemas.

Breaking changes SHALL follow Shared contract governance.

---

# 185. Consumer Compatibility

Consumers SHALL reject unsupported security-event versions safely rather than silently interpreting them incorrectly.

---

# 186. Required Shared Contracts

`baobab-platform/shared` SHOULD define:

```text
identity lifecycle event
membership lifecycle event
entitlement lifecycle event
credential revocation event
session revocation event
workload lifecycle event
deprovisioning status
lifecycle reason codes
lifecycle provenance
```

---

# 187. Suggested Identity Event

Conceptually:

```text
IdentityLifecycleEvent
────────────────────────
event_id
schema_version
canonical_identity_id
previous_state
new_state
effective_at
reason_code
actor
correlation_id
occurred_at
```

---

# 188. Suggested Membership Event

Conceptually:

```text
MembershipLifecycleEvent
────────────────────────
event_id
schema_version
membership_id
canonical_identity_id
membership_type
resource_id
previous_state
new_state
effective_at
reason_code
occurred_at
```

---

# 189. Suggested Revocation Event

Conceptually:

```text
AccessRevoked
────────────────────────
revocation_id
subject_type
subject_id
authority
scope
effective_at
reason_code
security_critical
correlation_id
```

---

# 190. Event Payload Minimization

Events SHALL carry identifiers and security-relevant state, not full identity profiles.

---

# 191. Rejected Alternative — Delete User Everywhere

### Advantages

Simple mental model.

### Disadvantages

- destroys historical attribution;
- breaks audit;
- mishandles multi-relationship identities;
- creates referential-integrity problems.

### Decision

Rejected.

---

# 192. Rejected Alternative — Disable Keycloak Only

### Advantages

Fast authentication shutdown.

### Disadvantages

- domain sessions may remain;
- engine actors remain privileged;
- workload/domain authorization may be unaffected;
- platform relationships become stale.

### Decision

Rejected as complete deprovisioning.

---

# 193. Rejected Alternative — Engine Deletion Only

### Decision

Rejected.

It does not revoke IAM or CP authority.

---

# 194. Rejected Alternative — Long-Lived JWT as Authorization State

### Decision

Rejected.

Mutable lifecycle state SHALL remain server-authoritative.

---

# 195. Rejected Alternative — Email-Based Deprovisioning

Example:

```text
disable every account with user@example.com
```

### Decision

Rejected.

Immutable identity mappings SHALL be used.

---

# 196. Rejected Alternative — Events Without Reconciliation

### Decision

Rejected.

Distributed event delivery alone is insufficient for lifecycle correctness.

---

# 197. Rejected Alternative — Reconciliation Without Events

### Decision

Rejected.

Periodic scanning alone cannot meet urgent revocation requirements.

---

# 198. Rejected Alternative — Global Identity Disablement for Every Membership Change

### Decision

Rejected.

It breaks legitimate multi-relationship access.

---

# 199. Rejected Alternative — Automatic Restoration on Rehire

### Decision

Rejected.

Old privileges may no longer be appropriate.

---

# 200. Rejected Alternative — Permanent Authorization Cache

### Decision

Rejected.

---

# 201. Rejected Alternative — One Universal Deprovisioning Owner

### Decision

Rejected.

Each domain retains authority over its own access model while participating in coordinated lifecycle workflows.

---

# 202. Consequences

## Positive

This decision provides:

- precise revocation;
- safer multi-relationship identities;
- rapid incident response;
- historical audit preservation;
- robust workforce offboarding;
- independent domain lifecycle;
- controlled distributed deprovisioning;
- orphan detection;
- disaster-recovery safety;
- scalable SaaS tenancy lifecycle.

## Negative

It requires:

- explicit lifecycle state machines;
- canonical security events;
- reconciliation jobs;
- cross-engine workflows;
- monitoring;
- retry/dead-letter handling;
- careful source-of-truth governance.

These costs are accepted.

---

# 203. Implementation Ownership

| Concern | Owner |
|---|---|
| Authentication identity lifecycle | `baobab-iam` |
| Credentials | `baobab-iam` |
| IAM sessions | `baobab-iam` |
| Canonical Identity | `baobab-cp` |
| Tenant membership | `baobab-cp` |
| Capability entitlement | `baobab-cp` |
| Buyer membership | `baobab-trade` |
| Customer actor | `baobab-trade` |
| Supplier membership/approval | Supplier domain |
| AD_User/AD_Role | `baobab-erp` |
| CMS actor/roles | `baobab-cms` |
| Pulse domain access | `baobab-pulse` |
| Workload identity | IAM + Infrastructure |
| Lifecycle contracts | `baobab-platform/shared` |
| Security-event transport | Infrastructure/platform integration |

---

# 204. Target Lifecycle Architecture

```text
                     BAOBAB IAM
                Credentials / Sessions
                         │
                         ▼
                 CanonicalIdentity
                         │
                         ▼
                     BAOBAB CP
        ┌────────────────┼─────────────────┐
        │                │                 │
    Memberships     Entitlements       Context
        │                │                 │
        └────────────────┼─────────────────┘
                         │
                  Lifecycle Events
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
       ▼                 ▼                 ▼
    TRADE               ERP               CMS
 Buyer/Customer      AD_User/Role       User/Role
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                         ▼
                  RECONCILIATION
                         │
                         ▼
              Detect / Repair / Restrict
```

---

# 205. Layered Revocation Model

```text
              SECURITY EVENT
                    │
                    ▼
        ┌──────────────────────┐
        │ What must be revoked?│
        └──────────┬───────────┘
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
 Credential    Relationship   Identity
       │           │           │
       ▼           ▼           ▼
 revoke key    revoke member   suspend all
                   │           │
                   ▼           ▼
              CP/domain deny  sessions revoke
                   │           │
                   └─────┬─────┘
                         ▼
                downstream events
                         │
                         ▼
                 reconciliation
```

---

# 206. Workforce Leaver Flow

```text
LEAVER CONFIRMED
       │
       ▼
Suspend/disable workforce access
       │
       ▼
Revoke IAM sessions
       │
       ▼
Revoke CP memberships/entitlements
       │
       ├───────────┬───────────┬───────────┐
       ▼           ▼           ▼           ▼
     Trade        ERP         CMS        Pulse
       │           │           │           │
       ▼           ▼           ▼           ▼
remove roles   disable/review remove role revoke access
               AD_User/Role
       │           │           │           │
       └───────────┴─────┬─────┴───────────┘
                         ▼
                    RECONCILE
                         │
                    ┌────┴────┐
                  CLEAN      ERROR
                    │          │
                    ▼          ▼
                 COMPLETE    RETRY/ALERT
```

---

# 207. Multi-Relationship Revocation Flow

```text
                    CANONICAL IDENTITY
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Nabhold Staff    Buyer Member    Supplier Member
          │                │                │
       ACTIVE            ACTIVE           ACTIVE

Supplier membership revoked:

                    CANONICAL IDENTITY
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                X
     Nabhold Staff    Buyer Member    Supplier Member
          │                │
       ACTIVE            ACTIVE

Identity remains valid.
Only supplier-derived authority disappears.
```

---

# 208. High-Risk Revocation Flow

```text
ACCOUNT COMPROMISE
        │
        ▼
Suspend identity
        │
        ▼
Revoke IAM sessions
        │
        ▼
Revoke compromised credentials
        │
        ▼
CP rejects new contexts
        │
        ▼
Publish security event
        │
  ┌─────┼─────┬─────┐
  ▼     ▼     ▼     ▼
Trade  ERP   CMS   Pulse
  │     │     │     │
  └─────┴──┬──┴─────┘
           ▼
      Reconciliation
           │
           ▼
     Incident review
```

---

# 209. Joiner / Mover / Leaver Model

```text
                   WORKFORCE LIFECYCLE

JOINER                    MOVER                    LEAVER
  │                         │                        │
  ▼                         ▼                        ▼
Identity                Review current           Suspend access
  │                     privileges                 │
  ▼                         │                       ▼
Membership                  ▼                  Revoke sessions
  │                     Remove obsolete             │
  ▼                         │                       ▼
Entitlement                  ▼                  Revoke grants
  │                      Add approved                │
  ▼                         │                       ▼
Engine mapping               ▼                  Deprovision engines
  │                     Re-certify                   │
  ▼                                                  ▼
Domain role                                         Reconcile
```

---

# 210. Production-Readiness Checklist

Identity lifecycle SHALL not be considered production-ready until:

- Canonical Identity lifecycle is explicit;
- credential lifecycle is distinct;
- session lifecycle is distinct;
- tenant membership lifecycle is distinct;
- capability entitlement lifecycle is distinct;
- domain actor lifecycle remains domain-owned;
- buyer representative removal is implemented;
- supplier representative removal is implemented;
- customer closure is defined;
- workforce joiner/mover/leaver is implemented;
- workload retirement is implemented;
- session revocation is supported;
- privileged compromise can trigger rapid suspension;
- tenant suspension denies new contexts;
- domain revocation works despite valid IAM session;
- lifecycle events are versioned;
- lifecycle consumers are idempotent;
- stale/out-of-order events cannot restore access;
- event provenance is authenticated;
- reconciliation exists;
- orphan privileged identities are detectable;
- deprovisioning partial failure is visible;
- retries/dead-letter handling exist;
- revocation SLOs are measured;
- authorization caches have bounded TTLs;
- security revocation survives engine migration;
- security revocation survives backup restoration;
- historical audit attribution is preserved;
- hard deletion is exceptional;
- rehire does not restore obsolete privileges;
- multi-relationship revocation tests pass.

---

# 211. Required Tests

At minimum, automated integration/security testing SHALL prove:

```text
ACTIVE identity + ACTIVE membership = eligible for further authorization

ACTIVE identity + REVOKED membership = DENY that membership context

SUSPENDED identity + ACTIVE membership = DENY

DISABLED identity + valid token = DENY

ACTIVE identity + revoked capability = DENY capability

ACTIVE IAM session + revoked Trade role = Trade DENY

ACTIVE IAM session + revoked AD_Role = ERP DENY

supplier membership revoked + buyer membership active
= buyer access remains

leaver disabled + historical ERP records
= history preserved

workload revoked
= only that workload loses access

stale ACTIVE event after REVOKED
= remains REVOKED

deprovisioning consumer failure
= retry/alert, not silent success

restored backup
= revoked identities are not resurrected
```

---

# 212. Architectural Invariants

The following become binding:

```text
Identity ≠ Credential

Identity ≠ Session

Identity ≠ Membership

Identity ≠ Entitlement

Identity ≠ Domain Actor

Credential Revocation ≠ Identity Deletion

Membership Revocation ≠ Identity Disablement

Domain Suspension ≠ IAM Disablement

Tenant Suspension ≠ User Deletion

Session Revocation ≠ Historical Erasure

Mapping Exists ≠ Access Allowed

Valid Token ≠ Active Membership

Valid Token ≠ Active Entitlement

Valid Token ≠ Active Domain Role

Rehire ≠ Old Privilege Restoration

Account Closure ≠ Transaction Deletion

Privacy Erasure ≠ Security Deprovisioning

Event Delivery ≠ Reconciliation

Engine Record ≠ Source of Global Identity Truth

Backup Restore ≠ Permission to Resurrect Access

Deployment Removal ≠ Workload Credential Revocation
```

---

# 213. Decision Summary

Baobab SHALL treat identity lifecycle as a coordinated set of independent state machines rather than a single user `active` flag.

The lifecycle hierarchy SHALL be:

```text
DOES THIS IDENTITY STILL EXIST?
            │
            ▼
     CanonicalIdentity

CAN IT STILL AUTHENTICATE?
            │
            ▼
     IAM + Credentials

DOES THE RELATIONSHIP STILL EXIST?
            │
            ▼
       Membership

IS THIS PLATFORM CAPABILITY STILL GRANTED?
            │
            ▼
       Entitlement

IS THIS CONTEXT STILL VALID?
            │
            ▼
      Control Plane

IS THIS DOMAIN ACTOR STILL AUTHORIZED?
            │
            ▼
       Domain Engine
```

Revocation SHALL therefore occur at the layer that owns the authority being revoked.

For severe compromise, Baobab SHALL be able to suspend the identity, revoke sessions, deny Control Plane context, and propagate downstream restriction rapidly.

For ordinary relationship changes, Baobab SHALL revoke only the affected relationship and preserve unrelated legitimate access.

Events SHALL provide rapid propagation.

Reconciliation SHALL provide eventual correctness.

Short-lived tokens and current-state authorization SHALL bound stale authorization.

Historical identities and engine actors SHALL normally be retained for audit rather than destructively deleted.

The governing principle is:

> **Baobab shall revoke authority without erasing history, isolate lifecycle changes to the relationships they actually affect, and make every security-critical revocation observable, recoverable, reconcilable and resistant to accidental resurrection.**