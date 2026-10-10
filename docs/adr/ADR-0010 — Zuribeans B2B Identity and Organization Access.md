# ADR-0010: Zuribeans B2B Identity and Organization Access

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/zuribeans`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Zuribeans B2B buyer identity, company registration, organization onboarding, invitations, representatives, procurement roles, buyer-company isolation, Trade integration, company verification, buyer lifecycle and account recovery  
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

---

# 1. Context

Zuribeans is the B2B Digital Estate of the Baobab platform.

Its users are not merely individual consumers.

They may represent:

- hotels;
- restaurants;
- distributors;
- wholesalers;
- retailers;
- processors;
- manufacturers;
- institutional buyers;
- exporters;
- hospitality groups;
- other commercial organisations.

The authorization problem therefore involves at least two distinct entities:

```text
person
+
business organization
```

A user may be authorized to act on behalf of one buyer company but not another.

Within the same buyer organization, different representatives may also possess different responsibilities.

Examples include:

```text
administrator
procurement manager
buyer
approver
finance contact
viewer
```

Zuribeans therefore requires a B2B identity and organization-access model that preserves the architectural boundaries already established by the Baobab IAM ADR series.

---

# 2. Decision

Zuribeans SHALL use Baobab IAM for authentication and identity-side organization management.

`baobab-cp` SHALL remain authoritative for canonical identity and platform context.

`baobab-trade` SHALL remain authoritative for buyer organization membership and commercial authorization.

The target model SHALL be:

```text
Human
  │
  ▼
Baobab IAM
  │
  ▼
CanonicalIdentity
  │
  ▼
Baobab CP
  │
  ▼
Zuribeans / Trade context
  │
  ▼
Trade Buyer Organization
  │
  ▼
Buyer Role / Commercial Authority
```

---

# 3. Core Principle

The governing rule SHALL be:

> **Baobab IAM proves who the buyer representative is; Trade determines what that representative may do for the buyer organization.**

---

# 4. Buyer Identity

Every Zuribeans human user SHALL authenticate as an individual identity.

The system SHALL NOT authenticate:

```text
Acme Hotels
```

as though the company itself were a human user.

Instead:

```text
Jane Doe
  │
  ▼
represents
  │
  ▼
Acme Hotels
```

The person's identity and the company's identity SHALL remain separate.

---

# 5. Buyer Company

A buyer company SHALL be represented as a business-domain organization and Canonical Entity where cross-platform representation is required.

Conceptually:

```text
Buyer Company
    │
    ├── CanonicalEntity
    ├── IAM Organization
    └── Trade Buyer Organization
```

These representations SHALL be linked explicitly.

---

# 6. IAM Organization Role

Keycloak Organization MAY be used for:

- identity-side company membership;
- invitation workflows;
- B2B login experience;
- organisation-specific federation;
- representative onboarding.

It SHALL NOT own:

- purchase authority;
- approval limits;
- commercial terms;
- buyer credit;
- order permissions;
- buyer approval status.

---

# 7. Trade Buyer Organization

`baobab-trade` SHALL own the authoritative buyer organization record for commerce behavior.

This MAY include:

- members;
- buyer roles;
- purchase-order settings;
- commercial terms;
- payment terms;
- tax registrations;
- delivery sites;
- purchasing constraints;
- approval chains.

---

# 8. Buyer Organization Is Not Tenant

The following invariant SHALL remain binding:

```text
Buyer Organization ≠ Baobab Tenant by default
```

Most Zuribeans buyers consume the Zuribeans commerce service inside the Zuribeans tenant context.

Conceptually:

```text
Zuribeans Tenant
     │
     ▼
Baobab Trade
     │
     ├── Buyer Company A
     ├── Buyer Company B
     └── Buyer Company C
```

A buyer becomes its own Baobab Tenant only if it later consumes Baobab as an independently isolated SaaS tenant.

---

# 9. Buyer Organization Is Not IAM Organization

This invariant also applies:

```text
IAM Organization ≠ Trade Buyer Organization
```

The two MAY map 1:1 initially, but SHALL remain independently authoritative.

---

# 10. Buyer Organization Is Not Legal Entity by Assumption

Many buyers will be legal entities.

However the platform SHALL not assume every buyer record has already passed legal-entity verification.

During onboarding, a buyer company MAY exist in states such as:

```text
APPLICANT
PENDING_VERIFICATION
APPROVED
REJECTED
SUSPENDED
```

---

# 11. Buyer Registration Modes

Zuribeans SHOULD support at least:

```text
self-service company registration
invitation-based registration
sales-assisted onboarding
admin-created organization
```

All routes SHALL converge on the same canonical business model.

---

# 12. Self-Service Registration

A typical self-service flow SHALL be:

```text
Buyer representative
      │
      ▼
Create identity
      │
      ▼
Verify email
      │
      ▼
Submit company application
      │
      ▼
Company verification
      │
      ▼
Buyer organization created/approved
      │
      ▼
Representative linked
      │
      ▼
Buyer access enabled
```

---

# 13. Identity Registration Before Company Approval

Identity creation MAY occur before buyer-company approval.

This permits:

- email verification;
- application progress;
- document submission;
- communication.

However, pre-approval identity SHALL NOT imply purchasing authority.

---

# 14. Buyer Application

A buyer application MAY collect business data such as:

```text
legal/business name
registration number
country
tax/VAT number
business type
industry
website
business address
primary contact
expected purchase categories
expected volumes
preferred market
```

Exact requirements SHALL be owned by the buyer onboarding/business domain rather than IAM.

---

# 15. IAM SHALL Minimize Business Data

IAM SHALL retain only identity information required for authentication and organization-side identity relationships.

Business verification data SHALL remain outside IAM.

---

# 16. Verification

Buyer-company verification MAY include:

- legal-registration verification;
- tax verification;
- business identity checks;
- sanctions/risk review;
- credit or commercial assessment;
- market eligibility.

The exact business process may evolve.

It SHALL NOT be represented simply as:

```text
Keycloak Organization exists
```

---

# 17. Buyer Approval

Buyer approval is a business-domain decision.

The state:

```text
buyer.status = APPROVED
```

SHALL NOT be inferred from:

```text
user.email_verified = true
```

or:

```text
IAM organization membership = true
```

---

# 18. Company Verification and Authentication Are Separate

The following remain distinct:

```text
person verified
company verified
person authorized for company
company commercially approved
```

Each must have its own lifecycle.

---

# 19. First Representative

The person submitting a new company application MAY become the first candidate administrator.

They SHALL NOT automatically gain permanent buyer-admin authority before verification.

Possible workflow:

```text
Applicant
   │
   ▼
Company approved
   │
   ▼
Representative verified
   │
   ▼
Buyer Admin granted
```

---

# 20. Buyer Administrator

A buyer administrator MAY be permitted to:

- manage representatives;
- invite users;
- revoke user membership;
- manage selected company profile details;
- assign permitted buyer roles.

They SHALL NOT automatically gain every commercial privilege.

---

# 21. Buyer Administrator Versus Approver

This distinction SHALL be supported:

```text
Buyer Admin
   ≠
Purchase Approver
```

A user able to manage team membership does not necessarily have authority to approve high-value purchases.

---

# 22. Buyer Roles

Trade SHOULD support business roles such as:

```text
buyer_admin
purchaser
approver
finance
viewer
```

The exact role taxonomy MAY evolve.

Roles SHALL remain Trade-domain constructs.

---

# 23. Purchase Authority

Purchase authority MAY depend on:

- role;
- organization;
- order value;
- product category;
- market;
- approval level;
- commercial terms.

Therefore it SHALL not be modeled as a simple IAM role.

---

# 24. Purchase Approval Example

```text
Jane logs in
    │
    ▼
IAM proves Jane
    │
    ▼
CP resolves Zuribeans Trade context
    │
    ▼
Trade finds:
Jane → Acme Hotels
role = approver
limit = 100,000
    │
    ▼
PO amount = 80,000
    │
    ▼
ALLOW
```

For:

```text
PO amount = 150,000
```

Trade may require another approver.

---

# 25. Company Membership

A person's ability to act for a buyer SHALL require an active Trade membership.

Conceptually:

```text
CanonicalIdentity
      │
      ▼
Trade BuyerMembership
      │
      ▼
BuyerOrganization
```

---

# 26. IAM Membership

An IAM Organization membership MAY also exist:

```text
CanonicalIdentity
      │
      ▼
IAM Organization membership
```

It is identity-side evidence, not final purchasing authority.

---

# 27. Membership Layers

Zuribeans SHALL distinguish:

| Membership | Authority |
|---|---|
| IAM Organization membership | Baobab IAM |
| platform context membership | `baobab-cp` |
| buyer organization membership | `baobab-trade` |

These relationships may be synchronized operationally but SHALL not be collapsed.

---

# 28. Invitation Flow

A buyer administrator MAY invite a colleague.

Target flow:

```text
Buyer Admin
    │
    ▼
Invite email
    │
    ▼
Recipient authenticates/registers
    │
    ▼
IAM organization relationship
    │
    ▼
Trade buyer membership
    │
    ▼
role assigned
```

---

# 29. Invitation Is Not Authority

Accepting an invitation SHALL not automatically grant arbitrary buyer privileges.

The invitation SHALL specify or result in an allowed role according to Trade policy.

---

# 30. Invitation Expiry

Buyer invitations SHALL:

- expire;
- be single-purpose;
- be revocable;
- avoid embedding sensitive permissions in URLs;
- be bound to intended organization.

---

# 31. Invitation Replay

An invitation SHALL not be reusable indefinitely after acceptance.

---

# 32. Wrong Identity Acceptance

Where risk warrants, invitation acceptance SHOULD validate that the intended recipient identity matches the invitation policy.

This may use verified email or other approved identity proof.

---

# 33. Email Is Not Canonical Identity

Even when invitations are sent by email:

```text
email address
```

remains a delivery/addressing attribute.

Canonical identity remains based on the IAM subject mapping established in ADR-0004.

---

# 34. Multiple Buyer Organizations

A user MAY represent multiple buyer companies where legitimate.

Example:

```text
Jane
  │
  ├── Acme Hotels
  └── Lakeview Resorts
```

The active buyer context SHALL be explicit.

---

# 35. Buyer Context Selection

Where multiple memberships exist:

```text
Jane logs in
     │
     ▼
Available buyer organizations
  ┌────┴────┐
  ▼         ▼
Acme      Lakeview
```

The user may select one.

Trade SHALL verify membership before granting context.

---

# 36. No Buyer Context by Header Alone

The following SHALL NOT establish authority:

```text
X-Buyer-Organization: ACME
```

unless it is verified against authoritative server-side membership.

---

# 37. Buyer Context Switching

Switching between buyer organizations SHALL not require duplicate user accounts.

It MAY require:

- explicit selection;
- fresh context resolution;
- step-up authentication for high-risk operations.

---

# 38. Buyer Isolation

Buyer A SHALL NOT access Buyer B resources merely because both use the same Zuribeans tenant.

This is a domain-isolation requirement inside Trade.

---

# 39. Buyer Isolation Example

```text
Zuribeans Tenant
       │
       ▼
Trade
  ┌────┴────┐
  ▼         ▼
Acme      Lakeview
  │         │
Orders A  Orders B
```

A valid Zuribeans tenant context does not grant access across buyer organizations.

---

# 40. Trade Resource Ownership

Trade SHALL enforce buyer ownership/association for resources such as:

- orders;
- purchase orders;
- delivery addresses;
- procurement records;
- buyer-specific pricing;
- commercial terms.

---

# 41. Cross-Buyer Negative Test

The following must deny:

```text
Jane belongs to Acme

Jane requests Lakeview PO
```

even though:

```text
tenant = Zuribeans
```

is valid.

---

# 42. Buyer Lifecycle

A buyer organization SHOULD support lifecycle states such as:

```text
APPLICATION
PENDING_VERIFICATION
ACTIVE
SUSPENDED
REJECTED
ARCHIVED
```

Exact naming SHALL align with domain implementation.

---

# 43. Suspended Buyer

If buyer status becomes:

```text
SUSPENDED
```

representatives may still authenticate.

But restricted Trade operations SHALL deny.

---

# 44. Rejected Buyer

Rejected buyer applications SHALL not create purchasing rights.

Historical onboarding records MAY be retained according to compliance policy.

---

# 45. Buyer Reactivation

Reactivating a buyer SHOULD restore only approved relationships.

It SHALL not automatically recreate roles that were separately revoked for security reasons.

---

# 46. Buyer Member Lifecycle

Membership states MAY include:

```text
INVITED
ACTIVE
SUSPENDED
REVOKED
```

A member state SHALL remain independent from company state.

---

# 47. Remove Representative

When a representative leaves a buyer company:

```text
BuyerMembership → REVOKED
```

The person's Canonical Identity SHALL remain intact.

The person may retain unrelated Baobab identities and relationships.

---

# 48. Immediate Revocation

Buyer administrators SHALL be able to revoke a representative's buyer access promptly.

Where the user remains authenticated to IAM, the next authoritative Trade authorization SHALL deny buyer operations.

---

# 49. Role Changes

Changing:

```text
approver → viewer
```

SHALL take effect according to defined authorization-cache bounds.

Business role changes SHALL not require a new global identity.

---

# 50. Buyer Admin Departure

A company SHOULD not be left without a viable administrator because its sole admin departed.

Business workflow SHOULD support:

- secondary admins;
- controlled administrator transfer;
- support-assisted recovery.

---

# 51. Organization Recovery

Recovery of company administration SHALL be distinct from personal account recovery.

Example:

```text
lost password
```

is IAM recovery.

```text
all company admins departed
```

is buyer-organization governance recovery.

---

# 52. Personal Account Recovery

Buyer users SHALL use Baobab IAM recovery mechanisms.

Recovery of authentication SHALL not automatically restore revoked buyer memberships.

---

# 53. Compromised Buyer User

On suspected compromise:

```text
revoke IAM sessions
      │
      ▼
secure identity
      │
      ▼
review buyer memberships
      │
      ▼
review recent orders/approvals
```

---

# 54. High-Risk Buyer Actions

Sensitive actions MAY require step-up authentication.

Examples:

```text
large PO approval
change finance contact
change delivery destination for high-value order
change security-sensitive company settings
invite buyer administrator
```

Exact rules belong to Trade/business risk policy.

---

# 55. Buyer MFA

Buyer administrators and high-value approvers SHOULD be candidates for stronger MFA requirements than ordinary viewer roles.

Mandatory requirements may evolve under ADR-0015.

---

# 56. Company Federation

Large enterprise buyers MAY later federate their corporate IdP with Baobab IAM.

Conceptually:

```text
Enterprise IdP
      │
      ▼
Baobab IAM Organization
      │
      ▼
CanonicalIdentity
      │
      ▼
Trade BuyerMembership
```

---

# 57. Federation Does Not Grant Purchasing Authority

Successful enterprise authentication SHALL not automatically create:

```text
approver
buyer_admin
```

roles.

Trade membership remains authoritative.

---

# 58. JIT Buyer Provisioning

For approved federated organizations, Baobab MAY support controlled JIT identity creation.

However buyer membership and roles SHALL remain governed separately.

---

# 59. Email Domain Discovery

Company domains MAY assist B2B login discovery.

Example:

```text
@acmehotels.com
```

may route a user toward Acme's configured identity provider.

It SHALL not automatically establish buyer membership.

---

# 60. Company Domain Is Not Authorization

This SHALL remain false:

```text
email domain matches company
    =
authorized buyer representative
```

---

# 61. Buyer Commercial Terms

Trade SHALL own commercial terms such as:

- payment terms;
- minimum order quantities;
- credit arrangements;
- discount agreements;
- contract pricing.

These SHALL not appear as IAM roles.

---

# 62. Pricing Access

Buyer-specific prices SHALL be returned only after Trade identifies the authoritative buyer context.

A user SHALL not be able to obtain another organization's negotiated prices by changing a buyer identifier.

---

# 63. Delivery Sites

A buyer may maintain multiple delivery sites.

Authorization to use/manage those sites SHALL belong to Trade.

---

# 64. Tax Registrations

Buyer tax registration information SHALL remain business/domain data.

IAM SHALL not become authoritative for tax compliance information.

---

# 65. Purchase Order Reference

Purchase-order references and buyer procurement metadata remain Trade domain state.

---

# 66. Buyer Finance Contact

Finance-contact status MAY represent:

```text
contact relationship
```

rather than broad application permission.

Trade SHALL distinguish business contacts from authorization roles where necessary.

---

# 67. Organization Owner Myth

Baobab SHALL avoid a simplistic:

```text
organization_owner
```

role that implies every possible permission.

Company governance MAY require multiple administrators and separation of duties.

---

# 68. Procurement Separation of Duties

Trade SHOULD support scenarios where:

```text
purchaser
   ≠
approver
```

and potentially:

```text
requester
   ≠
approver
```

for buyer organizations that require it.

---

# 69. Buyer Approval Chains

Trade MAY support approval chains such as:

```text
Buyer
  │
  ▼
Manager
  │
  ▼
Finance
```

depending on purchase amount or buyer configuration.

IAM SHALL remain unaware of this workflow.

---

# 70. Internal Zuribeans Operators

Nabhold/Zuribeans workforce operators SHALL use workforce identity under ADR-0009.

They SHALL not be modeled as buyer representatives merely because they administer buyer records.

---

# 71. Support Access

Zuribeans support personnel MAY need access to buyer information.

Such access SHALL use explicit workforce roles and audited context.

Support SHALL not impersonate buyer administrators silently.

---

# 72. Buyer Impersonation

If buyer impersonation is ever enabled for support:

```text
subject = buyer representative
actor = support user
```

SHALL remain auditable.

---

# 73. Buyer vs Supplier Identity

Zuribeans SHALL preserve a clear distinction between:

```text
buyer organization
```

and:

```text
supplier organization
```

A company MAY theoretically participate as both, but each relationship is separate.

---

# 74. Same Company as Buyer and Supplier

Where one Canonical Entity legitimately acts as both:

```text
CanonicalEntity: Company X
      │
      ├── buyer relationship
      └── supplier relationship
```

the relationships SHALL remain independently approved and authorized.

---

# 75. Buyer Approval Does Not Approve Supplier

This SHALL be binding:

```text
approved buyer
   ≠
approved supplier
```

---

# 76. Supplier Access

Supplier onboarding/access SHALL follow the supplier-domain architecture and ADR-0012.

Zuribeans buyer roles SHALL not grant supplier-portal capabilities.

---

# 77. Buyer Data and Supplier Data Isolation

If one person represents both buyer and supplier relationships:

```text
same CanonicalIdentity
```

does not authorize mixing the two contexts.

The active business relationship SHALL be explicit.

---

# 78. Buyer Context Resolution Flow

```text
User token
   │
   ▼
IAM validates identity
   │
   ▼
CP resolves:
tenant = Zuribeans
estate = Zuribeans
market = requested market
capability = Trade
   │
   ▼
Trade resolves:
buyer organization
membership
role
commercial rules
   │
   ▼
operation
```

---

# 79. Context Examples

A user may have:

```text
Platform Context:
Tenant = Zuribeans
Market = UG
Capability = Trade

Trade Context:
BuyerOrganization = Acme Hotels
Role = Approver
```

These contexts SHALL not be collapsed.

---

# 80. Multi-Market Buyer

A buyer may operate in multiple markets.

Example:

```text
Acme Hotels
  │
  ├── UG procurement
  └── ZA procurement
```

Trade/CP SHALL verify the market independently.

---

# 81. Buyer Market Eligibility

Buyer approval in one market SHALL not automatically imply eligibility in every market if regulatory/business policy differs.

---

# 82. Company Identity Mapping

Buyer mapping MAY conceptually be:

```text
Keycloak Organization ID
       │
       ▼
CanonicalEntity ID
       │
       ▼
Trade BuyerOrganization ID
```

Mappings SHALL use immutable identifiers.

---

# 83. No Mapping by Name

The platform SHALL not use:

```text
company name equality
```

as the authoritative mapping strategy.

Names change and may collide.

---

# 84. No Mapping by Email Domain Alone

Likewise, domain equality SHALL not be treated as canonical buyer mapping.

---

# 85. Organization Binding

A conceptual `IAMOrganizationBinding` MAY record:

```text
iam_organization_id
canonical_entity_id
relationship_type
status
created_at
```

but implementation SHOULD reuse existing CP `ExternalReference`/`Mapping` constructs where possible.

---

# 86. Buyer Creation Idempotency

Buyer onboarding SHALL be idempotent.

Repeated callbacks or retries SHALL not create duplicate:

- Canonical Entities;
- IAM Organizations;
- Trade buyer organizations.

---

# 87. Duplicate Company Detection

Potential duplicate company applications SHOULD be reviewed using business verification data.

Automatic merging solely by company name or email domain SHALL be avoided.

---

# 88. Existing Company Join

If a person attempts to register a company that already exists:

```text
existing buyer organization detected
```

the system SHOULD route toward:

- invitation;
- administrator approval;
- ownership/representation verification;

rather than creating a duplicate company automatically.

---

# 89. Unauthorized Claim Prevention

A malicious user SHALL not be able to claim an existing organization merely by:

- knowing its name;
- possessing a public email domain;
- knowing a registration number.

Representation requires explicit verification or invitation.

---

# 90. Registration Enumeration

Buyer-registration endpoints SHALL avoid revealing excessive information about existing companies or representatives.

Example response SHOULD not expose:

```text
This company has administrators Jane and John
```

to arbitrary applicants.

---

# 91. Rate Limiting

Registration, invitation and recovery endpoints SHOULD be rate-limited and monitored.

---

# 92. Abuse Controls

B2B onboarding SHOULD include controls against:

- fake company registrations;
- invitation spam;
- credential stuffing;
- company-takeover attempts;
- account enumeration.

---

# 93. Invitation Audit

Audit SHOULD capture:

```text
who invited?
which buyer organization?
which recipient?
which intended role?
when?
accepted/rejected/expired?
```

without exposing invitation secrets.

---

# 94. Membership Audit

Buyer membership changes SHOULD record:

```text
member added
member suspended
member revoked
role changed
administrator changed
```

---

# 95. Commercial Authorization Audit

High-value buyer actions SHOULD be auditable.

Examples:

```text
PO submitted
PO approved
PO rejected
approval overridden
commercial term changed
```

Trade owns these audit events.

---

# 96. Identity Audit Correlation

Where possible:

```text
IAM identity event
      │
      ▼
CP authorization decision
      │
      ▼
Trade buyer action
```

SHOULD be correlatable through canonical identity and request/decision identifiers.

---

# 97. Privacy

Buyer representatives are human users and their personal data SHALL be minimized.

Business and identity data SHALL be separated where practical.

---

# 98. Account Deletion

A buyer representative requesting account deletion SHALL not automatically delete:

- company;
- historical orders;
- commercial records;
- legally required audit data.

Identity privacy handling SHALL account for business-record retention obligations.

---

# 99. Buyer Organization Deletion

Hard deletion of buyer organizations SHOULD be exceptional.

Archival/deactivation is generally preferable where historical transaction records exist.

---

# 100. Cross-Company Isolation Tests

Tests SHALL prove:

```text
Buyer A representative cannot:
- read Buyer B orders
- modify Buyer B addresses
- view Buyer B contract pricing
- approve Buyer B purchase orders
- invite users into Buyer B
```

---

# 101. Role Tests

At minimum:

```text
viewer cannot place order
purchaser can submit where allowed
purchaser cannot approve if not permitted
approver obeys approval limit
buyer admin can manage allowed memberships
buyer admin does not automatically gain approval authority
```

---

# 102. Invitation Tests

Test:

```text
valid invitation
expired invitation
revoked invitation
already-used invitation
wrong organization
unauthorized inviter
role escalation attempt
```

---

# 103. Buyer Lifecycle Tests

Test:

```text
pending buyer cannot transact
active buyer can transact according to roles
suspended buyer denied
rejected buyer denied
reactivated buyer obeys current roles
```

---

# 104. Identity Lifecycle Tests

Test:

```text
valid identity + revoked buyer membership = deny
disabled identity + active buyer membership = deny
recovered identity + revoked membership = deny
```

---

# 105. Context Tests

Test:

```text
valid buyer + wrong tenant = deny
valid buyer + unauthorized market = deny
valid Zuribeans context + wrong buyer org = deny
```

---

# 106. Multi-Organization Tests

Test a single identity legitimately representing two buyer organizations and ensure:

- explicit context selection;
- strict resource separation;
- correct pricing;
- correct order ownership;
- correct audit identity.

---

# 107. Supplier Separation Tests

Test:

```text
buyer role does not grant supplier portal access
supplier role does not grant buyer purchasing authority
same canonical identity with both roles resolves correctly by context
```

---

# 108. Rejected Alternative — Shared Company Login

Example:

```text
purchasing@acmehotels.com
shared password
```

### Decision

Rejected.

Every human action SHALL be attributable to an individual.

---

# 109. Rejected Alternative — Keycloak Organization as Commerce Authority

### Advantages

Central organization management.

### Disadvantages

- no procurement semantics;
- no approval limits;
- no commercial terms;
- domain coupling.

### Decision

Rejected.

---

# 110. Rejected Alternative — Every Buyer Is Tenant

### Advantages

Strong conceptual isolation.

### Disadvantages

- excessive tenancy proliferation;
- unnecessary CP configuration;
- wrong business semantics.

### Decision

Rejected.

---

# 111. Rejected Alternative — Buyer Roles in JWT

### Advantages

Fast authorization.

### Disadvantages

- stale permissions;
- role explosion;
- poor purchase-policy modeling;
- large revocation window.

### Decision

Rejected as authoritative domain authorization.

---

# 112. Rejected Alternative — Email Domain Auto-Membership

### Advantages

Simple B2B onboarding.

### Disadvantages

- weak company-ownership proof;
- account-takeover risk;
- email domains may be shared or outsourced.

### Decision

Rejected as default.

---

# 113. Rejected Alternative — First Registrant Automatically Owns Company

### Advantages

Fast onboarding.

### Disadvantages

- organization hijacking;
- weak business verification;
- difficult recovery.

### Decision

Rejected.

---

# 114. Consequences

## Positive

This model provides:

- strong individual accountability;
- explicit buyer-company representation;
- proper B2B procurement roles;
- multi-company identity support;
- cross-buyer isolation;
- clean company invitation workflows;
- future enterprise federation;
- clear separation between buyer and supplier relationships.

## Negative

It requires:

- organization verification;
- mapping between IAM and Trade;
- buyer lifecycle management;
- invitation workflows;
- role administration;
- stronger security tests.

These costs are accepted.

---

# 115. Implementation Ownership

| Concern | Owner |
|---|---|
| Human authentication | `baobab-iam` |
| IAM Organizations | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| Canonical business entity | `baobab-cp` |
| Tenant/market/estate context | `baobab-cp` |
| Buyer organization | `baobab-trade` |
| Buyer membership | `baobab-trade` |
| Procurement roles | `baobab-trade` |
| Commercial terms | `baobab-trade` |
| Buyer frontend UX | `baobab-platform/zuribeans` |
| Shared schemas/events | `baobab-platform/shared` |

---

# 116. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend versioned contracts for:

```text
organization identity reference
buyer onboarding identity reference
membership lifecycle
invitation identity metadata
canonical entity mapping
authorization context
identity events
```

Business-specific Trade contracts SHOULD remain within Trade where appropriate.

---

# 117. Production-Readiness Checklist

Zuribeans B2B identity SHALL not be considered production-ready until:

- individual user login uses Baobab IAM;
- no shared buyer credentials are required;
- canonical identity mapping works;
- company applications are independently verified;
- first registrant does not automatically gain unsafe ownership;
- buyer organization mapping exists;
- buyer membership is Trade-owned;
- IAM organization membership is not treated as purchasing authority;
- invitation workflow is secure and auditable;
- buyer roles are enforced server-side;
- purchase approval limits are enforced in Trade;
- cross-buyer resource isolation tests pass;
- multi-company identities work correctly;
- suspended/rejected buyers are denied;
- member revocation takes effect within documented bounds;
- account recovery does not restore revoked buyer rights;
- buyer and supplier relationships remain separated.

---

# 118. Architectural Invariants

The following become binding:

```text
Person ≠ Buyer Company

IAM Organization ≠ Trade Buyer Organization

Buyer Organization ≠ Tenant by default

Buyer Identity ≠ Purchase Authority

Email Verification ≠ Company Verification

Company Verification ≠ User Authorization

IAM Membership ≠ Buyer Membership

Buyer Admin ≠ Purchase Approver

Buyer Approval ≠ Supplier Approval

Email Domain ≠ Company Ownership

Valid Zuribeans Context ≠ Access to Every Buyer

Account Recovery ≠ Buyer Membership Recovery
```

---

# 119. Target Architecture

```text
                     BAOBAB IAM
                         │
                         ▼
                  Human Identity
                         │
                         ▼
                 CanonicalIdentity
                         │
                         ▼
                   BAOBAB CP
                         │
        Tenant / Estate / Market / Trade
                         │
                         ▼
                   BAOBAB TRADE
                         │
               ┌─────────┴─────────┐
               ▼                   ▼
       Buyer Organization A   Buyer Organization B
               │                   │
          memberships          memberships
               │                   │
          procurement          procurement
             roles               roles
               │                   │
            orders              orders
```

Buyer isolation occurs inside Trade even though both organizations operate within the same Zuribeans platform context.

---

# 120. Registration Flow

```text
NEW BUYER REPRESENTATIVE
          │
          ▼
Create / authenticate IAM identity
          │
          ▼
Verify identity contact
          │
          ▼
Submit company application
          │
          ▼
Does company already exist?
       ┌──┴───┐
       │      │
      YES     NO
       │      │
       ▼      ▼
membership   verify company
workflow         │
       │         ▼
       │    approve/reject
       │         │
       └────┬────┘
            ▼
      establish buyer org
            │
            ▼
      establish membership
            │
            ▼
       assign Trade role
            │
            ▼
      enable buyer access
```

---

# 121. Authorization Flow

```text
BUYER REPRESENTATIVE
       │
       ▼
Authenticate through IAM
       │
       ▼
Resolve Zuribeans platform context
       │
       ├── DENIED ─────────► STOP
       │
       ▼
Resolve buyer membership in Trade
       │
       ├── NONE/INACTIVE ──► DENY
       │
       ▼
Resolve buyer role
       │
       ▼
Evaluate resource ownership
       │
       ▼
Evaluate procurement/commercial policy
       │
       ├── DENIED ─────────► DENY
       │
       ▼
ALLOW
```

---

# 122. Decision Summary

Zuribeans SHALL use a B2B identity architecture in which:

```text
WHO IS THE PERSON?
        │
        ▼
Baobab IAM

WHICH BAOBAB CONTEXT?
        │
        ▼
Baobab Control Plane

WHICH BUYER DO THEY REPRESENT?
        │
        ▼
Baobab Trade

WHAT MAY THEY DO FOR THAT BUYER?
        │
        ▼
Baobab Trade
```

The buyer company and its representatives SHALL remain separate identities.

Keycloak Organizations MAY support invitations, B2B login and identity-side membership, but they SHALL not become the commerce authorization model.

The governing principle is:

> **Zuribeans authenticates people, verifies companies, authorizes representation explicitly, and leaves procurement authority with the Trade domain that owns it.**