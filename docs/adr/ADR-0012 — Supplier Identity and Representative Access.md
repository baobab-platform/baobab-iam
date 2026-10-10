# ADR-0012: Supplier Identity and Representative Access

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, supplier onboarding/domain services, `baobab-platform/zuribeans`, `baobab-platform/thamani`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Supplier identity, supplier-company representation, supplier representatives, onboarding, invitations, vetting, approval, suspension, market eligibility, product/category capability, multi-estate access, sensitive supplier changes, supplier administration, supplier/buyer separation and sourcing authorization  
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

---

# 1. Context

Baobab requires a supplier onboarding and identity model that can serve:

- Zuribeans;
- Thamani;
- future Baobab Digital Estates;
- sourcing and procurement operations;
- potentially multiple markets and legal entities.

Suppliers may include:

- producers;
- farmers;
- cooperatives;
- processors;
- manufacturers;
- exporters;
- distributors;
- wholesalers;
- aggregators;
- importers;
- specialist service providers.

They may be located in:

- markets where Nabhold currently operates;
- markets where Baobab has no active Digital Estate;
- markets from which Nabhold wishes to source strategically.

The architecture must therefore distinguish:

```text
the human representative
the supplier organization
the supplier's identity relationship
supplier vetting
supplier approval
product/category capability
market eligibility
commercial onboarding
sourcing approval
```

These SHALL NOT be collapsed into a single IAM role or account state.

---

# 2. Decision

Baobab SHALL implement supplier identity as a cross-estate business relationship built on:

```text
Baobab IAM
    │
    ▼
CanonicalIdentity
    │
    ▼
Baobab Control Plane
    │
    ▼
Supplier Organization / CanonicalEntity
    │
    ▼
Supplier Domain / Trade / ERP integrations
```

Baobab IAM SHALL authenticate supplier representatives.

The Control Plane SHALL own canonical identity, canonical business entity linkage and platform context.

The supplier onboarding/domain layer SHALL own:

- supplier registration;
- vetting;
- approval;
- rejection;
- suspension;
- market eligibility;
- product/category eligibility;
- representative authority;
- sensitive supplier changes.

Trade and ERP SHALL own their respective supplier-facing operational and accounting mappings.

---

# 3. Governing Principle

> **Supplier identity proves who represents the supplier; supplier approval determines whether Baobab may source from that supplier. These are different decisions and SHALL remain different states.**

---

# 4. Supplier Is an Organization

A supplier SHALL be modeled as an organization/business entity.

A supplier account SHALL NOT be modeled as one shared human credential.

This SHALL be prohibited:

```text
username: acme-coffee
password: ********
```

shared among multiple supplier employees.

Instead:

```text
Alice ─┐
Bob   ─┼──► Supplier Organization: Acme Coffee Ltd
Carol ─┘
```

Each representative SHALL have an individual identity.

---

# 5. Supplier Representative

A supplier representative SHALL authenticate as a human through Baobab IAM.

Conceptually:

```text
IAM Subject
    │
    ▼
CanonicalIdentity
    │
    ▼
SupplierRepresentativeMembership
    │
    ▼
SupplierOrganization
```

---

# 6. Supplier Organization

A supplier organization MAY have representations in several Baobab systems.

Conceptually:

```text
Supplier Organization
      │
      ├── CanonicalEntity
      ├── IAM Organization
      ├── Supplier Domain Record
      ├── Trade Supplier/Vendor Mapping
      └── ERP Business Partner Mapping
```

These representations SHALL be explicitly mapped.

---

# 7. IAM Organization

Keycloak Organization MAY support:

- supplier representative invitations;
- identity-side membership;
- organization-specific login;
- federation;
- B2B identity experience.

It SHALL NOT determine:

- supplier approval;
- procurement eligibility;
- banking verification;
- product eligibility;
- quality compliance;
- sourcing priority.

---

# 8. Supplier Organization Is Not Tenant

A supplier SHALL NOT automatically become a Baobab Tenant.

The default model SHALL be:

```text
Baobab Tenant
   │
   ▼
Supplier/Sourcing Capability
   │
   ├── Supplier A
   ├── Supplier B
   └── Supplier C
```

A supplier becomes a tenant only if it later consumes Baobab as an independently isolated SaaS customer.

---

# 9. Supplier Is Not Automatically a Legal Entity

Some supplier applicants may be:

- companies;
- cooperatives;
- sole traders;
- producer groups;
- informal or partially formalized enterprises where policy permits.

Therefore:

```text
SupplierOrganization ≠ LegalEntity automatically
```

Legal status SHALL be modeled explicitly.

---

# 10. Supplier Registration

Supplier registration SHOULD be available through suitable Digital Estates.

Examples:

```text
Zuribeans Supplier Registration
Thamani Supplier Registration
future centralized Baobab Supplier Portal
```

These SHOULD converge on one canonical supplier onboarding model.

---

# 11. One Supplier Onboarding Spine

Baobab SHALL avoid creating:

```text
Zuribeans supplier database
+
Thamani supplier database
+
future estate supplier database
```

as independent sources of truth.

Instead:

```text
Multiple Digital Estates
        │
        ▼
Canonical Supplier Onboarding
        │
        ▼
Supplier Organization
        │
        ▼
Estate-specific sourcing relationships
```

---

# 12. Registration Flow

A typical supplier registration flow SHALL be:

```text
Representative
    │
    ▼
Create/authenticate identity
    │
    ▼
Verify contact
    │
    ▼
Submit supplier application
    │
    ▼
Create/resolve organization
    │
    ▼
Submit business/product evidence
    │
    ▼
Vetting
    │
    ▼
Approve / Reject / Request Information
    │
    ▼
Establish sourcing eligibility
```

---

# 13. Identity Before Approval

A supplier representative MAY obtain an IAM identity before the supplier is approved.

This allows:

- completing application forms;
- uploading documents;
- responding to vetting questions;
- tracking onboarding status.

It SHALL NOT imply:

```text
supplier approved
```

---

# 14. Supplier Lifecycle

The supplier domain SHOULD support lifecycle states such as:

```text
DRAFT
SUBMITTED
PENDING_VERIFICATION
IN_REVIEW
MORE_INFORMATION_REQUIRED
APPROVED
CONDITIONALLY_APPROVED
REJECTED
SUSPENDED
BLOCKED
ARCHIVED
```

Exact state names MAY evolve.

---

# 15. Identity Lifecycle and Supplier Lifecycle Are Independent

This distinction SHALL remain explicit:

```text
IAM identity ACTIVE
```

may coexist with:

```text
supplier status = PENDING_VERIFICATION
```

or:

```text
supplier status = SUSPENDED
```

Authentication success does not establish supplier eligibility.

---

# 16. Supplier Vetting

Supplier vetting MAY include:

- legal registration verification;
- tax registration;
- ownership/beneficial ownership data;
- sanctions screening;
- banking verification;
- references;
- business reputation;
- quality certifications;
- product certificates;
- export capability;
- import/export licences;
- sustainability information;
- food safety information;
- insurance;
- production capacity;
- logistics capability.

The exact checks SHALL depend on:

```text
market
product category
risk
supplier type
transaction value
```

---

# 17. Risk-Based Vetting

Not every supplier SHALL require identical vetting.

Example:

```text
low-risk local office supplier
       ≠
cross-border food commodity exporter
```

Vetting requirements SHOULD therefore be policy-driven.

---

# 18. Supplier Approval

Supplier approval SHALL be an explicit business decision.

This SHALL remain false:

```text
IAM organization membership
      =
approved supplier
```

---

# 19. Conditional Approval

Baobab MAY support:

```text
CONDITIONALLY_APPROVED
```

for suppliers whose use is restricted.

Examples:

- specific products only;
- one market only;
- limited order value;
- probationary sourcing;
- documentation pending renewal.

---

# 20. Product Capability

A supplier MAY be approved to supply only certain categories or products.

Example:

```text
Supplier: Uganda Highlands Cooperative

Approved:
- green coffee
- roasted coffee
- vanilla pods

Not approved:
- dairy
- packaged cosmetics
```

Product/category eligibility SHALL be explicit.

---

# 21. Product Capability Is Not IAM Role

The system SHALL NOT encode:

```text
role = vanilla_supplier
```

as the authoritative supplier-product permission in IAM.

Such capability belongs to the supplier/procurement domain.

---

# 22. Product Declaration

During onboarding, suppliers MAY declare:

- product categories;
- specific products;
- grades;
- varieties;
- packaging formats;
- minimum order quantities;
- expected volumes;
- lead times;
- certifications.

These declarations SHALL remain:

```text
supplier assertions
```

until verified where verification is required.

---

# 23. Declared Product vs Approved Product

Baobab SHALL distinguish:

```text
declared_product
```

from:

```text
approved_supply_capability
```

---

# 24. Example

```text
Supplier declares:
  Arabica coffee

Vetting:
  certification verified

Procurement review:
  capacity accepted

Result:
  APPROVED to supply Arabica coffee in UG sourcing context
```

---

# 25. Market Eligibility

Supplier eligibility SHALL be market-aware.

A supplier MAY be:

```text
approved for sourcing in UG
```

but:

```text
not approved for import into ZA
```

until additional requirements are met.

---

# 26. Supplier Location ≠ Market Eligibility

This SHALL remain false:

```text
supplier country = Uganda
      =
eligible for every Uganda or South Africa transaction
```

Legal, customs and sourcing policy may impose different requirements.

---

# 27. Source From Non-Operating Markets

Baobab SHALL support suppliers from markets where Nabhold does not yet operate a Digital Estate.

Example:

```text
Supplier Country: Ethiopia
Active Baobab customer estate in Ethiopia: No
Sourcing relationship: Possible
```

Supplier identity SHALL therefore not depend on Digital Estate presence.

---

# 28. Preferred Local Suppliers

Business policy MAY give preference to suppliers located in the same markets as the purchasing legal entity or Digital Estate.

This SHOULD be represented as:

```text
sourcing preference
```

not an IAM permission.

---

# 29. Supplier Ranking

Supplier selection MAY later use factors such as:

- local-market preference;
- price;
- quality;
- reliability;
- sustainability;
- lead time;
- capacity;
- historical performance;
- risk score.

These SHALL remain procurement/business logic.

---

# 30. First Representative

The first person who registers a supplier MAY become:

```text
applicant representative
```

but SHALL not automatically become an unrestricted permanent supplier administrator.

---

# 31. Supplier Administrator

After appropriate verification, a supplier representative MAY receive:

```text
supplier_admin
```

authority within the supplier domain.

They MAY be permitted to:

- manage representatives;
- invite colleagues;
- maintain selected organization profile fields;
- manage product submissions;
- upload documents.

---

# 32. Supplier Admin Is Not Supplier Approval Authority

This SHALL remain binding:

```text
Supplier Admin ≠ Baobab Supplier Approver
```

Supplier representatives SHALL NOT approve their own supplier organization into Nabhold sourcing.

---

# 33. Supplier Representative Roles

Potential supplier-side roles MAY include:

```text
supplier_admin
sales_contact
catalog_manager
finance_contact
compliance_contact
viewer
```

Exact taxonomy belongs to the supplier domain.

---

# 34. Supplier Internal Roles vs Nabhold Roles

Baobab SHALL distinguish:

```text
supplier representative role
```

from:

```text
Nabhold procurement role
```

They belong to different organizations and trust boundaries.

---

# 35. Representative Invitation

A supplier administrator MAY invite another representative.

Flow:

```text
Supplier Admin
    │
    ▼
Invite Representative
    │
    ▼
IAM registration/authentication
    │
    ▼
Supplier membership established
    │
    ▼
Supplier role assigned
```

---

# 36. Invitation Security

Supplier invitations SHALL be:

- expiring;
- revocable;
- scoped to one supplier organization;
- single-purpose;
- resistant to replay.

---

# 37. Invitation Acceptance Is Not Supplier Approval

A representative successfully joining a supplier organization SHALL not alter the organization's sourcing approval.

---

# 38. Multiple Representatives

Suppliers SHOULD be encouraged to maintain multiple authorized representatives where operationally appropriate.

This reduces reliance on one account and improves continuity.

---

# 39. Representative Removal

When a representative leaves:

```text
SupplierMembership → REVOKED
```

The Canonical Identity SHALL remain intact.

---

# 40. Supplier Admin Recovery

If all supplier administrators are lost, a controlled recovery process SHALL exist.

Recovery MAY require:

- business ownership proof;
- registration evidence;
- verified company contact;
- manual procurement/support review.

It SHALL NOT be solved merely by matching an email domain.

---

# 41. Organization Claiming

A person SHALL NOT be able to claim an existing supplier merely because they know:

- company name;
- website;
- registration number;
- tax number;
- email domain.

Representation must be independently verified.

---

# 42. Duplicate Supplier Detection

Supplier onboarding SHOULD detect possible duplicates.

However automatic merging SHALL not occur solely on:

```text
name
email
website
registration number entered by applicant
```

without appropriate verification.

---

# 43. Supplier Canonical Mapping

Conceptually:

```text
Keycloak Organization
      │
      ▼
CanonicalEntity
      │
      ▼
Supplier Domain Record
      │
      ├── Trade Supplier Mapping
      └── ERP Business Partner Mapping
```

---

# 44. Immutable Mapping

Mappings SHALL use immutable identifiers.

Company names, domains and contact emails SHALL not serve as canonical foreign keys.

---

# 45. Trade Integration

Where suppliers participate in Trade operations, `baobab-trade` MAY maintain a supplier/vendor-domain representation.

Examples:

- supplier catalogue;
- product offers;
- purchase orders;
- sourcing requests;
- fulfillment interactions.

---

# 46. ERP Integration

Approved suppliers requiring financial/procurement integration SHALL map to iDempiere business records such as appropriate Business Partner structures.

Conceptually:

```text
Canonical Supplier
       │
       ▼
ERP ExternalReference
       │
       ▼
iDempiere Business Partner
```

---

# 47. ERP Record Does Not Approve Supplier

This remains false:

```text
ERP Business Partner exists
      =
supplier approved
```

ERP representation may exist for administrative reasons before or after sourcing approval.

---

# 48. Trade Record Does Not Approve Supplier

Likewise:

```text
Trade Supplier record exists
      ≠
supplier approved
```

Approval remains supplier/procurement-domain state.

---

# 49. Supplier Approval Authority

Nabhold-side approval SHALL be performed by authorized workforce users.

Examples:

```text
procurement officer
supplier compliance reviewer
procurement manager
```

under ADR-0009.

---

# 50. Separation of Duties

Where risk warrants:

```text
supplier application reviewer
      ≠
final approver
```

SHOULD be supported.

---

# 51. Self-Approval Prohibited

A supplier representative SHALL never approve their own supplier organization.

A workforce user with a personal relationship to the supplier MAY require conflict-of-interest controls under future governance policy.

---

# 52. Sensitive Supplier Changes

Certain supplier changes SHALL be considered high-risk.

Examples:

```text
bank account
beneficiary name
payment details
legal name
ownership
tax number
company registration
authorized signatory
```

---

# 53. Bank Detail Changes

Bank detail changes SHALL NOT be treated as ordinary profile edits.

They SHOULD require:

- authenticated supplier representative;
- suitable supplier role;
- step-up authentication;
- verification workflow;
- Nabhold-side approval where policy requires;
- strong audit.

---

# 54. Supplier Bank Details Are Not IAM Data

IAM SHALL NOT store:

- bank accounts;
- beneficiary information;
- payment instructions.

These belong to the supplier/ERP/procurement domain.

---

# 55. Sensitive Change Flow

```text
Supplier Representative
        │
        ▼
Request sensitive change
        │
        ▼
Step-up authentication
        │
        ▼
Domain authorization
        │
        ▼
Verification
        │
        ▼
Nabhold approval if required
        │
        ▼
Apply change
        │
        ▼
Audit + notification
```

---

# 56. Supplier Security Notifications

Suppliers SHOULD receive notifications for high-risk changes such as:

- bank account change;
- new supplier admin;
- primary contact change;
- identity recovery;
- suspension;
- approval-status change.

---

# 57. Multi-Estate Supplier Access

One supplier MAY supply:

```text
Zuribeans
Thamani
future estates
```

without creating multiple supplier identities.

---

# 58. Canonical Supplier Across Estates

The preferred model SHALL be:

```text
Canonical Supplier
      │
      ├── Zuribeans sourcing relationship
      ├── Thamani sourcing relationship
      └── Future estate relationship
```

---

# 59. Estate Relationship

An estate-specific supplier relationship SHALL be explicit.

Example:

```text
Supplier X

Zuribeans:
approved for coffee

Thamani:
approved for coffee + vanilla

Future Estate:
no relationship
```

---

# 60. Global Supplier Approval SHALL NOT Be Assumed

Baobab SHALL not automatically treat:

```text
approved in one estate
```

as:

```text
approved everywhere
```

unless procurement policy explicitly establishes a global approval.

---

# 61. Shared Vetting Reuse

Where legally and operationally valid, completed supplier vetting MAY be reused across estates.

Example:

```text
company registration verified once
```

may not need re-verification for every estate.

However estate/product/market approval remains separate.

---

# 62. Verification Reuse ≠ Approval Reuse

This distinction SHALL remain:

```text
verified evidence reusable
      ≠
commercial approval universal
```

---

# 63. Supplier Context

A supplier user's platform context MAY be:

```text
Tenant = Zuribeans
Estate = Zuribeans
Capability = Supplier Portal
Market = UG
```

while the domain relationship is:

```text
SupplierOrganization = Supplier X
RepresentativeRole = catalog_manager
```

---

# 64. Thamani Supplier Context

The same person MAY also resolve:

```text
Tenant = Thamani
Estate = Thamani
Capability = Supplier Portal
Market = ZA
```

only if explicitly authorized.

---

# 65. Multi-Supplier Representative

A person MAY legitimately represent more than one supplier.

Example:

```text
Consultant
   │
   ├── Supplier A
   └── Supplier B
```

The active supplier context SHALL be explicit.

---

# 66. No Supplier Context from Client Input Alone

This SHALL not establish authority:

```text
supplier_id = SUPPLIER-A
```

submitted by the browser.

Membership SHALL be resolved server-side.

---

# 67. Supplier Isolation

Supplier A SHALL NOT access:

- Supplier B profile;
- Supplier B bank information;
- Supplier B product submissions;
- Supplier B sourcing requests;
- Supplier B documents.

even if both operate in the same estate.

---

# 68. Supplier Resource Ownership

Supplier-domain services SHALL enforce supplier-scoped access to:

- documents;
- product submissions;
- certifications;
- profile information;
- onboarding responses;
- sourcing interactions.

---

# 69. Supplier vs Buyer

One Canonical Entity MAY legitimately be both:

```text
buyer
+
supplier
```

but these SHALL remain separate business relationships.

---

# 70. Supplier vs Buyer Representative

Likewise a human may be:

```text
BuyerRepresentative
+
SupplierRepresentative
```

where legitimate.

Authorization SHALL depend on active context.

---

# 71. No Cross-Role Leakage

This SHALL remain prohibited:

```text
buyer_admin
      ⇒
supplier_admin
```

or:

```text
supplier_admin
      ⇒
buyer_approver
```

---

# 72. Supplier Approval vs Buyer Approval

These SHALL remain independently governed:

```text
approved supplier
      ≠
approved buyer
```

---

# 73. Supplier Portal

Supplier functionality MAY appear inside:

- Zuribeans;
- Thamani;
- future dedicated Supplier Portal.

The frontend location SHALL not determine the underlying supplier authority.

---

# 74. Digital Estate Owns UX, Not Supplier Authority

Digital Estates MAY own:

- registration forms;
- supplier dashboards;
- onboarding status UX;
- document upload UX.

They SHALL NOT become the supplier approval authority.

---

# 75. Supplier Documents

Supplier onboarding may require documents such as:

- registration certificate;
- tax certificate;
- export licence;
- certification;
- quality documents;
- bank proof;
- identity of authorized representative.

Document storage SHALL follow data-classification and security policy.

IAM SHALL not store these documents.

---

# 76. Document Access

Supplier documents SHALL be protected using:

```text
supplier membership
+
appropriate role
+
platform context
```

for supplier users and separate workforce authorization for reviewers.

---

# 77. Document Status

Documents MAY have states such as:

```text
SUBMITTED
UNDER_REVIEW
VERIFIED
REJECTED
EXPIRED
```

Supplier approval MAY depend on document state.

---

# 78. Expiring Certifications

Certifications and licences SHOULD support expiry tracking.

An expired required document MAY trigger:

```text
review required
conditional restriction
supplier suspension
```

according to policy.

---

# 79. Supplier Monitoring

Supplier approval SHALL not necessarily be permanent.

Baobab SHOULD support ongoing monitoring for:

- certification expiry;
- performance;
- delivery failures;
- quality issues;
- compliance changes;
- sanctions changes;
- financial risk.

---

# 80. Supplier Suspension

Supplier suspension MAY occur while representative identities remain active.

Example:

```text
IAM identity = ACTIVE
Supplier = SUSPENDED
```

Representatives may still be permitted to:

- view suspension status;
- submit corrective evidence;
- communicate with procurement.

They SHALL be denied restricted sourcing operations.

---

# 81. Supplier Blocking

A `BLOCKED` or equivalent status MAY represent higher-risk prohibition than ordinary suspension.

The domain SHALL define exact semantics.

---

# 82. Product Suspension

Baobab SHOULD be able to suspend:

```text
one product capability
```

without suspending the entire supplier.

Example:

```text
Supplier active
Coffee approved
Vanilla suspended
```

---

# 83. Market Suspension

Likewise:

```text
Supplier active globally
UG sourcing active
ZA sourcing suspended
```

SHOULD be possible where required.

---

# 84. Sourcing Relationship

A sourcing relationship SHOULD be explicitly modelled.

Conceptually:

```text
SupplierOrganization
      │
      ▼
SourcingRelationship
      │
      ├── Estate
      ├── Market
      ├── Product/Category
      ├── Status
      └── Commercial conditions
```

---

# 85. Supplier Approval Granularity

A robust supplier model SHOULD avoid a single boolean:

```text
approved = true
```

when actual authorization depends on:

```text
supplier
estate
market
category
product
risk state
```

---

# 86. Procurement Eligibility

The actual question may be:

```text
May Nabhold source product P
from supplier S
for estate E
in market M
at this time?
```

This is a domain authorization decision.

---

# 87. Supplier Authentication Does Not Answer Procurement Eligibility

This SHALL remain binding:

```text
supplier representative logged in
      ≠
supplier may receive purchase order
```

---

# 88. Catalogue Submission

Supplier representatives MAY submit catalog/product information.

Submission SHALL not automatically publish products to customer-facing estates.

---

# 89. Product Publication

A separate workflow MAY require:

```text
supplier submission
      │
      ▼
review
      │
      ▼
commercial approval
      │
      ▼
CMS/Trade publication
```

---

# 90. Supplier Cannot Self-Publish Without Policy

A supplier SHALL NOT automatically gain public catalog publication authority merely because they submitted a product.

---

# 91. Pricing Submission

Supplier price submissions SHALL be treated as procurement-domain data.

They MAY require:

- effective periods;
- currency;
- market;
- MOQ;
- incoterms;
- commercial review.

IAM SHALL not own them.

---

# 92. Currency and Market

Supplier commercial offers MAY vary by:

```text
currency
market
legal entity
estate
```

The supplier identity remains the same.

---

# 93. ERP Procurement Flow

An approved supplier may eventually participate in:

```text
supplier approval
      │
      ▼
ERP Business Partner
      │
      ▼
purchase requisition
      │
      ▼
purchase order
      │
      ▼
receipt
      │
      ▼
invoice
      │
      ▼
payment
```

IAM authenticates representatives but does not manage ERP procurement authority.

---

# 94. Supplier Self-Service ERP Access

Supplier users SHALL NOT receive direct broad iDempiere access by default.

Supplier-facing ERP data SHOULD normally be exposed through governed Baobab APIs/portals.

---

# 95. Least Privilege

Supplier representatives SHALL receive only capabilities needed for external supplier participation.

They SHALL not receive:

- ERP finance roles;
- CP administrative roles;
- internal Trade administration;
- IAM administration.

---

# 96. Supplier Federation

Large suppliers MAY later federate their enterprise IdP into Baobab IAM.

Flow:

```text
Supplier Enterprise IdP
        │
        ▼
Baobab IAM
        │
        ▼
CanonicalIdentity
        │
        ▼
SupplierRepresentativeMembership
```

---

# 97. Federation Does Not Grant Supplier Authority

A successful federated login SHALL not automatically assign:

```text
supplier_admin
```

or sourcing approval.

---

# 98. Email Domain Discovery

Supplier email domains MAY assist organization discovery or federated login.

They SHALL NOT authorize supplier representation automatically.

---

# 99. Recovery

Supplier representatives SHALL use Baobab IAM account recovery.

Authentication recovery SHALL NOT restore:

- revoked supplier memberships;
- revoked supplier-admin rights;
- suspended sourcing status.

---

# 100. Supplier Organization Recovery

Organization-administration recovery is separate from personal account recovery.

It MAY require manual business verification.

---

# 101. MFA

Supplier administrators and representatives able to modify sensitive information SHOULD receive stronger MFA requirements.

At minimum, high-risk actions SHOULD support step-up.

---

# 102. High-Risk Actions

Candidate step-up operations include:

```text
bank detail change
legal entity change
supplier admin invitation
ownership change
identity linking
sensitive compliance submission
```

---

# 103. Auditing

Supplier identity and onboarding audit SHOULD record:

```text
representative identity
supplier organization
action
market
estate
status transition
reviewer
decision
timestamp
```

where relevant.

---

# 104. Approval Audit

Approval records SHOULD answer:

```text
who approved?
what was approved?
which supplier?
which products?
which market?
which estate?
which evidence?
when?
```

---

# 105. Sensitive Change Audit

Bank/payment-related changes SHALL receive enhanced audit.

Audit SHALL preserve:

- old/new metadata where safe;
- requesting supplier representative;
- approving workforce user;
- decision;
- timestamp;
- correlation ID.

Secrets and full sensitive values SHOULD not be sprayed into logs.

---

# 106. Cross-System Correlation

Where feasible:

```text
IAM login
   │
   ▼
CP context
   │
   ▼
Supplier action
   │
   ▼
Trade/ERP consequence
```

SHOULD be correlated through canonical IDs and decision/request identifiers.

---

# 107. Supplier Privacy

Supplier records contain both:

```text
business data
+
human representative data
```

These SHOULD be distinguished for privacy and retention.

---

# 108. Representative Deletion

Deleting or closing a representative account SHALL not delete:

- supplier organization;
- historical purchase orders;
- compliance audit;
- invoices;
- legally required business records.

---

# 109. Supplier Closure

Supplier closure SHOULD generally use:

```text
ARCHIVED
```

or equivalent rather than hard deletion where transactional records exist.

---

# 110. Data Classification

Sensitive supplier information SHOULD receive appropriate classification.

Examples:

```text
Public:
company marketing profile

Business:
product catalogue

Confidential:
contracts
vetting evidence

Highly Sensitive:
bank details
ownership documents
identity evidence
```

Exact classifications SHALL align with Baobab's data-classification standard.

---

# 111. Abuse Controls

Supplier registration endpoints SHOULD defend against:

- mass fake registrations;
- invitation spam;
- company hijacking;
- document-upload abuse;
- enumeration;
- credential stuffing.

---

# 112. Rate Limiting

Rate limits SHOULD apply to:

```text
registration
login
invitation
recovery
document submission
verification resend
```

as risk requires.

---

# 113. Malware and File Safety

Supplier-uploaded documents SHOULD be treated as untrusted input.

The supplier onboarding architecture SHOULD provide for:

- file-type validation;
- size limits;
- malware scanning;
- protected storage;
- controlled rendering/download.

---

# 114. Cross-Supplier Isolation Tests

Tests SHALL prove that Supplier A cannot:

```text
read Supplier B application
modify Supplier B profile
access Supplier B documents
view Supplier B bank details
change Supplier B products
accept Supplier B sourcing request
```

---

# 115. Representative Role Tests

At minimum test:

```text
viewer cannot modify
catalog manager can manage approved catalog fields
finance contact cannot automatically manage users
supplier admin can manage allowed representatives
supplier admin cannot self-approve supplier
```

---

# 116. Supplier Lifecycle Tests

Test:

```text
DRAFT → SUBMITTED
SUBMITTED → REVIEW
REVIEW → APPROVED
REVIEW → MORE_INFORMATION_REQUIRED
REVIEW → REJECTED
APPROVED → SUSPENDED
SUSPENDED → APPROVED
APPROVED → ARCHIVED
```

according to implemented policy.

---

# 117. Identity-vs-Approval Tests

Test:

```text
valid identity + pending supplier = restricted
valid identity + rejected supplier = denied sourcing
valid identity + suspended supplier = denied restricted operations
disabled identity + approved supplier = login denied
```

---

# 118. Product Capability Tests

Test:

```text
supplier approved for coffee
      +
request vanilla
      =
deny unless vanilla capability exists
```

---

# 119. Market Tests

Test:

```text
supplier approved UG
      +
request ZA sourcing
      =
deny unless ZA relationship exists
```

---

# 120. Estate Tests

Test:

```text
supplier approved for Zuribeans
      +
request Thamani supplier action
      =
deny unless Thamani relationship exists
```

---

# 121. Sensitive Change Tests

Test:

```text
bank detail change without step-up
      = deny

bank detail change with supplier role but missing verification
      = pending/deny

supplier self-approves bank change where dual approval required
      = deny
```

---

# 122. Multi-Role Tests

Test one Canonical Identity that legitimately acts as:

```text
buyer representative
+
supplier representative
```

and ensure:

- contexts remain separate;
- buyer permissions do not leak into supplier operations;
- supplier permissions do not leak into buyer operations.

---

# 123. Duplicate Supplier Tests

Test:

```text
same company name
different registration identities

same registration number
conflicting applicant data

existing supplier
new unauthorized claimant
```

to ensure unsafe automatic merging/claiming does not occur.

---

# 124. Rejected Alternative — Shared Supplier Login

### Advantages

Simple for supplier organizations.

### Disadvantages

- no individual accountability;
- weak offboarding;
- insecure credential sharing;
- poor audit.

### Decision

Rejected.

---

# 125. Rejected Alternative — Supplier Approval in IAM

### Advantages

Centralized state.

### Disadvantages

- business-domain leakage;
- no market/product granularity;
- weak compliance model;
- inappropriate source of truth.

### Decision

Rejected.

---

# 126. Rejected Alternative — Every Supplier Is a Tenant

### Advantages

Strong conceptual isolation.

### Disadvantages

- tenancy explosion;
- incorrect business semantics;
- excessive Control Plane configuration.

### Decision

Rejected.

---

# 127. Rejected Alternative — One Supplier Approval Boolean

### Advantages

Simple.

### Disadvantages

Cannot adequately represent:

```text
estate
market
product
conditional approval
suspension
```

### Decision

Rejected as the long-term model.

---

# 128. Rejected Alternative — Email-Domain Auto-Join

### Advantages

Fast onboarding.

### Disadvantages

- weak representation proof;
- domain compromise risk;
- shared domains;
- consultants/outsourced staff.

### Decision

Rejected.

---

# 129. Rejected Alternative — First Registrant Owns Supplier Permanently

### Advantages

Simple onboarding.

### Disadvantages

- supplier hijacking;
- poor organizational recovery;
- weak governance.

### Decision

Rejected.

---

# 130. Rejected Alternative — Separate Supplier Identity Per Estate

### Advantages

Simpler estate-local implementation.

### Disadvantages

- duplicate accounts;
- inconsistent vetting;
- duplicated supplier records;
- poor cross-estate visibility.

### Decision

Rejected.

---

# 131. Consequences

## Positive

This decision provides:

- one supplier identity model across Baobab;
- individual representative accountability;
- reusable company vetting;
- explicit estate/market/product approval;
- cross-estate supplier reuse;
- safer bank and compliance changes;
- clean Trade/ERP mapping;
- strict buyer/supplier separation;
- support for non-operating sourcing markets.

## Negative

It introduces:

- supplier workflow complexity;
- mapping requirements;
- document-management security;
- approval governance;
- market/product granularity;
- more lifecycle states and tests.

These costs are accepted.

---

# 132. Implementation Ownership

| Concern | Owner |
|---|---|
| Supplier representative authentication | `baobab-iam` |
| IAM Organizations | `baobab-iam` |
| Canonical human identity | `baobab-cp` |
| Canonical supplier entity | `baobab-cp` |
| Tenant/estate/market context | `baobab-cp` |
| Supplier onboarding | supplier domain |
| Supplier representative membership | supplier domain |
| Supplier approval/vetting | supplier domain |
| Product/category eligibility | supplier domain |
| Sourcing relationship | supplier domain / Trade |
| Trade supplier mapping | `baobab-trade` |
| ERP Business Partner mapping | `baobab-erp` |
| Supplier UX | Digital Estate |
| Shared contracts | `baobab-platform/shared` |

---

# 133. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend versioned contracts for:

```text
supplier identity reference
supplier organization reference
supplier representative membership
supplier lifecycle
supplier approval event
supplier suspension event
supplier mapping
supplier context
sourcing relationship reference
```

Detailed procurement-domain contracts MAY remain inside the authoritative supplier/Trade domain.

---

# 134. Recommended Domain Model

Conceptually:

```text
CanonicalEntity
     │
     ▼
SupplierOrganization
     │
     ├── SupplierRepresentative
     │
     ├── SupplierDocument
     │
     ├── SupplierCapability
     │
     ├── SupplierMarketEligibility
     │
     └── SourcingRelationship
```

Where:

```text
SupplierCapability
```

may represent product/category approval, and:

```text
SourcingRelationship
```

may represent estate/market-specific commercial eligibility.

---

# 135. Production-Readiness Checklist

Supplier identity SHALL not be considered production-ready until:

- supplier representatives authenticate individually;
- shared supplier passwords are unnecessary;
- supplier identity and approval are separate;
- IAM Organization is not used as supplier approval;
- supplier CanonicalEntity mapping exists;
- existing supplier claiming is protected;
- duplicate supplier prevention exists;
- supplier lifecycle is implemented;
- representative lifecycle is implemented;
- supplier-admin role cannot approve supplier status;
- product/category eligibility exists;
- market eligibility exists;
- estate-specific relationships exist;
- one supplier can participate in multiple estates;
- non-operating-market suppliers are supported;
- Trade mappings are explicit;
- ERP Business Partner mappings are explicit;
- bank/payment changes receive enhanced controls;
- supplier document storage is secured;
- cross-supplier isolation tests pass;
- buyer/supplier role separation tests pass;
- suspension/rejection takes effect correctly;
- recovery does not restore revoked memberships;
- high-risk events are auditable.

---

# 136. Architectural Invariants

The following become binding:

```text
Supplier Representative ≠ Supplier Organization

IAM Organization ≠ Supplier Approval

Supplier Identity ≠ Supplier Approval

Supplier Approval ≠ Product Approval

Product Approval ≠ Market Approval

Market Approval ≠ Estate Approval

Supplier ≠ Tenant by default

Supplier Admin ≠ Nabhold Supplier Approver

Supplier Approval ≠ Buyer Approval

Trade Supplier Record ≠ Supplier Approval

ERP Business Partner ≠ Supplier Approval

Email Domain ≠ Supplier Representation

Identity Recovery ≠ Supplier Membership Recovery

Supplier Authentication ≠ Procurement Eligibility

One Canonical Supplier ≠ One Estate Only
```

---

# 137. Target Supplier Architecture

```text
                         BAOBAB IAM
                             │
                    Supplier Representatives
                             │
                             ▼
                    CanonicalIdentity
                             │
                             ▼
                       BAOBAB CP
                             │
                     CanonicalEntity
                             │
                             ▼
                  Supplier Organization
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
      Zuribeans          Thamani            Future Estate
          │                  │
          ▼                  ▼
   Sourcing Relation   Sourcing Relation
          │                  │
          └──────────┬───────┘
                     ▼
               Supplier Domain
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
      BAOBAB TRADE        BAOBAB ERP
      supplier refs       Business Partner
```

---

# 138. Supplier Registration Flow

```text
SUPPLIER REPRESENTATIVE
          │
          ▼
Authenticate / Register
          │
          ▼
Verify identity
          │
          ▼
Does supplier already exist?
       ┌──┴───┐
      YES     NO
       │       │
       ▼       ▼
representation  create application
verification         │
       │             ▼
       │        submit evidence
       │             │
       └──────┬──────┘
              ▼
            VETTING
              │
       ┌──────┼─────────────┐
       ▼      ▼             ▼
 APPROVED   MORE INFO    REJECTED
       │
       ▼
create sourcing eligibility
       │
       ▼
map Trade / ERP as required
```

---

# 139. Supplier Authorization Flow

```text
SUPPLIER REPRESENTATIVE
        │
        ▼
IAM authentication
        │
        ▼
CP estate/market context
        │
        ├── DENY ─────────────► STOP
        │
        ▼
Supplier membership active?
        │
        ├── NO ───────────────► DENY
        │
        ▼
Supplier organization status valid?
        │
        ├── NO ───────────────► DENY / LIMITED
        │
        ▼
Representative role permits action?
        │
        ├── NO ───────────────► DENY
        │
        ▼
Product / market / estate policy permits?
        │
        ├── NO ───────────────► DENY
        │
        ▼
If sensitive, step-up / verification satisfied?
        │
        ├── NO ───────────────► DENY / CHALLENGE
        │
        ▼
ALLOW
```

---

# 140. Supplier Approval Matrix

A supplier SHOULD be understood through a multidimensional authorization model.

| Dimension | Example |
|---|---|
| Identity | Supplier X |
| Overall status | Active |
| Estate | Zuribeans |
| Market | Uganda |
| Category | Coffee |
| Product | Arabica green coffee |
| Capability | Approved |
| Risk status | Normal |
| Commercial status | Eligible |

Another row may be:

| Dimension | Example |
|---|---|
| Identity | Supplier X |
| Overall status | Active |
| Estate | Thamani |
| Market | South Africa |
| Category | Vanilla |
| Product | Vanilla pods |
| Capability | Pending import verification |
| Risk status | Review |
| Commercial status | Not yet eligible |

Thus:

```text
supplier = ACTIVE
```

alone SHALL never be treated as the complete procurement authorization decision.

---

# 141. Decision Summary

Baobab SHALL establish a unified supplier identity model across Zuribeans, Thamani and future Digital Estates.

The decision hierarchy is:

```text
WHO IS THE PERSON?
        │
        ▼
Baobab IAM

WHICH SUPPLIER DO THEY REPRESENT?
        │
        ▼
Supplier Membership

WHICH PLATFORM / ESTATE / MARKET CONTEXT?
        │
        ▼
Baobab Control Plane

IS THE SUPPLIER VERIFIED AND ELIGIBLE?
        │
        ▼
Supplier / Procurement Domain

WHAT MAY THEY SUPPLY, WHERE, AND TO WHOM?
        │
        ▼
Supplier Capability + Sourcing Relationship

HOW DOES IT FLOW INTO COMMERCE AND ERP?
        │
        ▼
Trade + iDempiere mappings
```

The platform SHALL support suppliers from outside Nabhold's active operating markets while allowing sourcing policy to prefer local suppliers where commercially appropriate.

Supplier authentication SHALL never be mistaken for supplier approval.

Supplier approval SHALL never be mistaken for universal product, market or estate eligibility.

The governing principle is:

> **Baobab shall authenticate supplier representatives once, model supplier organizations canonically, verify sourcing eligibility explicitly, and authorize procurement only at the precise intersection of supplier, product, market, estate and business policy.**