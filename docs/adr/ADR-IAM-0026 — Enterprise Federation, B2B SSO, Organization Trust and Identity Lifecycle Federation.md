# ADR-IAM-0026 — Enterprise Federation, B2B SSO, Organization Trust and Identity Lifecycle Federation

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, ZuriBeans, Thamani, supplier-facing estates, and future B2B Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0025  
**Extends:** ADR-IAM-0004, 0005, 0006, 0008, 0009, 0010, 0011, 0012, 0015–0025  
**Decision Type:** Enterprise Federation / B2B SSO / SCIM / Organization Trust / Identity Lifecycle  
**Identity Runtime:** Ory Kratos + Ory Hydra, with enterprise federation capability integrated through the approved Ory enterprise SSO boundary  
**Canonical Identity Authority:** Baobab Control Plane  
**Organization and Business Authority:** Baobab Control Plane plus respective domain engines

---

# 1. Decision

Baobab SHALL support enterprise identity federation for B2B customers and partners using standards-based:

```text
SAML 2.0
OIDC
SCIM 2.0
```

where appropriate.

Enterprise customers MAY authenticate their personnel through identity providers such as:

```text
Microsoft Entra ID
Okta
Google Workspace
Ping Identity
AD FS
other standards-compatible enterprise IdPs
```

without requiring Baobab to become the credential authority for those enterprise identities.

Ory currently exposes enterprise SSO integration for SAML and OIDC providers and directory synchronization/SCIM capabilities. These capabilities SHALL be consumed behind the provider-neutral architecture established by ADR-IAM-0019 and ADR-IAM-0020 rather than becoming Baobab's canonical organization model.

The fundamental rule is:

> **Enterprise federation may establish authentication and identity evidence. It does not establish Baobab business authority by itself.**

---

# 2. Architectural Principle

```text
Customer Enterprise IdP
        │
        │ SAML / OIDC
        ▼
      Ory
        │
        ▼
Provider Identity
        │
        ▼
ExternalIdentity
        │
        ▼
CanonicalIdentity
        │
        ▼
Baobab Control Plane
        │
        ▼
Organization Relationship
        │
        ▼
Business Context
        │
        ▼
Domain Authorization
```

The external enterprise controls authentication of its workforce.

Baobab controls what those authenticated identities mean inside Baobab.

---

# 3. What Federation Answers

Enterprise federation can answer:

> "Microsoft Entra ID for Company A asserts that this subject authenticated."

It MAY also provide:

```text
name
email
enterprise subject identifier
authentication method
authentication strength
selected organizational attributes
```

subject to trust configuration.

It does not inherently answer:

```text
Is this a Baobab Tenant?

Is this person a ZuriBeans buyer administrator?

May this person approve a USD 100,000 purchase?

May this person change Thamani billing details?

Is this person an approved supplier representative?

May this person access iDempiere finance?

May this person administer Baobab?
```

Those remain Baobab decisions.

---

# 4. Federation Is Not Authorization

This is prohibited:

```text
Entra Group:
"Finance"

      │
      ▼

Baobab ERP Finance Role
```

unless an explicit Baobab-governed mapping has been deliberately configured.

Likewise:

```text
IdP Group
"Admins"
```

SHALL NOT automatically imply:

```text
Baobab Admin
```

---

# 5. Trust Boundary

```text
┌─────────────────────────────┐
│ CUSTOMER ENTERPRISE         │
│                             │
│ Entra / Okta / Google / IdP │
│                             │
│ Employee lifecycle          │
│ Credential policy           │
│ MFA                         │
│ Enterprise groups           │
└─────────────┬───────────────┘
              │
         SAML / OIDC
              │
              ▼
┌─────────────────────────────┐
│ BAOBAB IDENTITY BOUNDARY    │
│                             │
│ Federation validation       │
│ Provider identity           │
│ Assurance mapping           │
│ Lifecycle normalization     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ BAOBAB CONTROL PLANE        │
│                             │
│ CanonicalIdentity           │
│ Organization                │
│ Membership                  │
│ Context                     │
│ Capability                  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ DOMAIN ENGINES              │
│                             │
│ Trade                       │
│ ERP                         │
│ Thamani                     │
│ Supplier Domain             │
└─────────────────────────────┘
```

---

# 6. Federation Trust Is Explicit

Baobab SHALL NOT accept arbitrary external IdPs.

Every enterprise federation SHALL be represented by an explicit trust configuration.

Conceptually:

```text
FederationTrust
├── id
├── canonical_organization_id
├── provider_type
├── issuer/entity_id
├── protocol
├── status
├── verified_domains
├── assurance_mapping
├── provisioning_mode
├── attribute_mapping_version
├── created_at
├── activated_at
└── revoked_at
```

---

# 7. Federation Trust Lifecycle

```text
REQUESTED
    │
    ▼
CONFIGURING
    │
    ▼
VERIFYING
    │
    ▼
ACTIVE
    │
    ├──► SUSPENDED
    │
    ├──► ROTATING
    │
    └──► REVOKED
```

Federation SHALL not become trusted merely because metadata was uploaded.

---

# 8. Organization Verification Precedes Federation Authority

Before an enterprise can establish federation:

```text
Baobab Organization
       │
       ▼
organization verified
       │
       ▼
authorized organization administrator
       │
       ▼
federation configuration
       │
       ▼
technical verification
       │
       ▼
ACTIVE
```

ADR-IAM-0025 controls organization and representative verification.

---

# 9. Domain Ownership Verification

Where email-domain routing is used, the domain SHALL be verified.

Ory's current enterprise SSO implementation supports explicit organization-domain verification using DNS TXT records rather than trusting a domain merely because an organization's owner has an email address at that domain.

Baobab SHALL follow the same architectural principle:

```text
claimed domain
     ≠
trusted domain
```

until ownership/control has been established.

---

# 10. Domain Verification Is Not Organization Verification

Control of:

```text
company-a.com
```

is strong technical evidence concerning the domain.

It does not necessarily prove every legal fact about:

```text
Company A Ltd
```

Therefore:

```text
DNS Domain Verification
       ≠
Legal Entity Verification
```

---

# 11. Supported Federation Protocols

Baobab SHOULD support:

```text
OIDC
SAML 2.0
```

for enterprise SSO.

Preference SHOULD generally be:

```text
OIDC where customer supports it cleanly
```

while SAML remains necessary for broad enterprise interoperability.

---

# 12. Protocol Translation

Where Ory provides:

```text
Enterprise SAML
      │
      ▼
Ory federation boundary
      │
      ▼
Baobab-compatible identity/session
```

downstream Baobab services SHOULD remain unaware of SAML-specific mechanics.

---

# 13. No SAML in Domain Engines

`baobab-trade`, `baobab-erp`, Thamani domain services and other engines SHALL NOT independently implement customer SAML integrations.

Federation belongs at the IAM boundary.

---

# 14. No Customer-Specific OAuth Logic in Estates

Digital Estates SHALL not contain code such as:

```text
if customer == ACME:
    use_entra()
elif customer == XYZ:
    use_okta()
```

Enterprise IdP routing belongs to the IAM/federation layer.

---

# 15. Enterprise Login Discovery

An estate MAY initiate organization-aware login.

Example:

```text
Jane enters
jane@acme.example
       │
       ▼
domain discovery
       │
       ▼
verified ACME federation
       │
       ▼
redirect to ACME IdP
```

But email-domain discovery SHALL be routing assistance, not identity authority.

---

# 16. Login Discovery Does Not Link Identities

Finding:

```text
@acme.example
```

SHALL NOT itself create:

```text
CanonicalIdentity
membership
business authority
```

---

# 17. Enterprise Subject Identity

The stable external identity SHALL use the provider's appropriate stable subject semantics.

Conceptually:

```text
ExternalIdentity
{
    issuer,
    subject
}
```

remains authoritative for external identity mapping.

Email remains an attribute.

---

# 18. Microsoft Identity Considerations

Microsoft enterprise identity identifiers can require provider-specific normalization.

Those details SHALL be isolated inside the federation/provider adapter.

Canonical domain code SHALL still receive:

```text
ExternalSubject
CanonicalIdentity
```

rather than Microsoft-specific identity keys.

---

# 19. Federation and CanonicalIdentity

On successful trusted federation:

```text
Enterprise Subject
       │
       ▼
ExternalIdentity
       │
       ▼
CanonicalIdentity
```

If a mapping already exists, it SHALL be reused.

---

# 20. No Email Auto-Linking

Suppose Jane already has:

```text
Personal Ory Identity
email = jane@acme.example
```

and later authenticates via:

```text
ACME Entra ID
email = jane@acme.example
```

Baobab SHALL NOT automatically conclude that these identities belong to the same CanonicalIdentity solely because the emails match.

ADR-IAM-0004 and ADR-IAM-0025 remain controlling.

---

# 21. Controlled Identity Linking

Linking MAY use:

```text
existing authenticated session
+
enterprise federation authentication
+
explicit linking workflow
```

or another approved identity-proofing mechanism.

---

# 22. Enterprise Federation and Assurance

Enterprise authentication MAY satisfy Baobab authentication assurance requirements when sufficient trustworthy evidence exists.

Ory added support in 2026 for carrying upstream OIDC `acr` and `amr` authentication evidence into Ory sessions and mapping configured upstream MFA evidence to stronger session assurance.

This capability SHALL be used through ADR-IAM-0024's provider-neutral assurance mapping.

---

# 23. Upstream MFA Is Not Assumed

Baobab SHALL NOT assume:

```text
Enterprise SSO
     =
MFA
```

The enterprise federation configuration SHALL specify what upstream evidence is trusted.

---

# 24. Assurance Mapping

Example:

```text
ACME Entra ID
    │
    ├─ password only
    │      ▼
    │   BAOBAB-A1
    │
    └─ phishing-resistant MFA
           ▼
        BAOBAB-A3
```

Exact mapping SHALL be explicit and tested.

---

# 25. Unknown Assurance

If upstream assurance cannot be established:

```text
assurance = UNKNOWN
```

or the configured safe baseline SHALL apply.

Baobab SHALL not infer A3 because the IdP is a well-known vendor.

---

# 26. Local Step-Up

Where upstream authentication does not satisfy the required Baobab assurance:

```text
Enterprise SSO
     │
     ▼
A1/A2
     │
     ▼
Operation requires A3
     │
     ▼
Baobab/Ory step-up
```

MAY be required where technically supported and appropriate.

---

# 27. Enterprise Organization != Baobab Tenant

The following remains a critical invariant:

```text
Enterprise IdP Organization
        ≠
Baobab Tenant
```

Likewise:

```text
Ory Organization
        ≠
CanonicalOrganization
        ≠
LegalEntity
        ≠
BuyerOrganization
        ≠
SupplierOrganization
```

---

# 28. Organization Hierarchy

An external customer may itself contain subsidiaries.

Example:

```text
ACME Holdings
│
├── ACME Uganda
├── ACME Kenya
└── ACME South Africa
```

Their enterprise IdP may represent this structure differently—or not at all.

Baobab's canonical organization hierarchy remains governed by CP and its organization architecture.

---

# 29. Federation Does Not Redefine Hierarchy

An Entra tenant SHALL NOT become the source of truth for:

```text
parent company
subsidiary
legal entity
Baobab tenant
market
```

unless an explicit integration maps verified information into the appropriate canonical model.

---

# 30. One Federation, Multiple Organizations

A large enterprise IdP MAY legitimately authenticate users representing several related Baobab organizations.

Therefore:

```text
one IdP
```

does not necessarily mean:

```text
one Baobab organization
```

---

# 31. Multiple Federations, One Organization

Likewise, a Baobab organization MAY support:

```text
Entra ID
+
acquired subsidiary Okta
+
selected local identities
```

where policy permits.

---

# 32. Federation Trust Scope

Federation SHALL specify its scope.

Conceptually:

```text
FederationTrust
    │
    ├── Organization A
    ├── Organization B
    └── permitted estates
```

rather than becoming globally trusted by default.

---

# 33. Digital Estate Scope

An enterprise federation established for:

```text
ZuriBeans
```

SHALL NOT automatically grant access to:

```text
Thamani
ERP
Nabhold
CP
```

---

# 34. Enterprise User Lifecycle

Enterprise federation introduces:

```text
JOINER
MOVER
LEAVER
```

lifecycle concerns.

Baobab SHALL support lifecycle synchronization without surrendering business authority to the customer's directory.

---

# 35. Joiner

```text
Enterprise Directory
       │
       ▼
new employee
       │
       ▼
SCIM / JIT federation
       │
       ▼
ExternalIdentity
       │
       ▼
CanonicalIdentity mapping
       │
       ▼
eligible relationship workflow
```

Provisioning SHALL NOT automatically create unrestricted business authority.

---

# 36. Mover

Example:

```text
Jane
ACME Procurement
       │
       ▼
moves to
ACME Marketing
```

This may require:

```text
remove purchasing relationships
retain basic company membership
review active approvals
```

depending on mapping policy.

---

# 37. Leaver

```text
ACME disables Jane
       │
       ▼
SCIM deprovision / federation event
       │
       ▼
Baobab enterprise relationship suspended/revoked
       │
       ▼
sessions/relevant authority invalidated
```

Jane's CanonicalIdentity SHALL normally remain.

---

# 38. Leaver Does Not Delete Person

Jane may still be:

```text
Thamani personal customer
Company B representative
supplier representative elsewhere
```

Therefore:

```text
Enterprise Deprovisioning
       ≠
CanonicalIdentity deletion
```

---

# 39. SCIM

Baobab SHALL use SCIM 2.0 where automated enterprise provisioning/deprovisioning is justified.

SCIM is standardized by RFC 7643 and RFC 7644 as a schema and HTTP protocol for cross-domain identity provisioning and lifecycle management.

---

# 40. SCIM Is Provisioning, Not Authentication

```text
SAML/OIDC
    │
    ▼
Authentication
```

versus:

```text
SCIM
    │
    ▼
Provisioning / lifecycle synchronization
```

These SHALL remain distinct.

---

# 41. SCIM Is Not Authorization

A SCIM request creating:

```text
User Jane
```

SHALL NOT inherently create:

```text
BUYER_APPROVER
SUPPLIER_ADMIN
ERP_FINANCE
PLATFORM_ADMIN
```

---

# 42. SCIM User Semantics

SCIM `User` SHALL represent an enterprise-provisioned identity relationship.

It SHALL not replace CanonicalIdentity.

---

# 43. SCIM Group Semantics

SCIM groups MAY be useful inputs for relationship mapping.

But:

```text
SCIM Group
     ≠
Baobab Role
```

by default.

---

# 44. Group Mapping

An explicit mapping MAY state:

```text
ACME SCIM Group:
"Purchasing Users"

       │
       ▼
eligible for
ACME Buyer Membership
```

but domain role assignment SHALL remain governed by Baobab policy.

---

# 45. High-Risk Group Mapping

Groups SHALL NOT directly map to high-risk authority such as:

```text
IAM_ADMIN
CP_ADMIN
ERP_SYSTEM
SUPPLIER_BANK_ADMIN
```

without stronger explicit controls.

---

# 46. Group Renaming

External group display names are mutable.

Mappings SHOULD prefer stable provider identifiers over display names.

---

# 47. SCIM Deactivation

SCIM:

```json
{
  "active": false
}
```

SHOULD trigger appropriate enterprise relationship deactivation.

It SHALL NOT blindly delete CanonicalIdentity.

---

# 48. Deprovisioning Priority

Deprovisioning is security-sensitive.

Lifecycle events indicating loss of enterprise authority SHOULD receive higher operational priority than cosmetic profile changes.

---

# 49. Eventual Consistency

SCIM synchronization is not guaranteed to be instantaneous.

Baobab SHALL therefore design for:

```text
duplicates
retries
delays
out-of-order updates
temporary provider outage
```

---

# 50. Revocation Safety

For high-risk access, Baobab SHALL not depend solely on an infrequent directory sync to discover that a user left an organization.

Use:

```text
SCIM
+
session controls
+
reconciliation
+
Baobab relationship state
```

as appropriate.

---

# 51. SCIM Reconciliation

Periodic reconciliation SHALL compare:

```text
Enterprise Directory State
          │
          ▼
SCIM Projection
          │
          ▼
Baobab Relationship State
```

and detect drift.

---

# 52. Example Drift

```text
Enterprise:
Jane inactive

Baobab:
Jane active buyer approver
```

is a security-significant drift condition.

---

# 53. SCIM Endpoint Architecture

Conceptually:

```text
Enterprise IdP
     │
     │ SCIM 2.0
     ▼
Baobab IAM Federation Boundary
     │
     ▼
normalize
     │
     ▼
Lifecycle Event
     │
     ▼
CP / Relationship Service
```

---

# 54. SCIM SHALL NOT Write Directly to Domain Databases

Prohibited:

```text
Entra SCIM
   │
   ▼
UPDATE medusa_users
```

or:

```text
UPDATE AD_User
```

Baobab lifecycle boundaries SHALL mediate the change.

---

# 55. SCIM Authentication

SCIM endpoints SHALL use strong machine authentication.

RFC 7644 deliberately leaves the exact authentication scheme to deployments while warning that stronger authentication than HTTP Basic is encouraged.

Baobab SHOULD use appropriately scoped secrets/tokens or stronger workload credentials supported by the integration.

---

# 56. SCIM Credential Scope

Each enterprise SCIM integration SHALL receive a distinct credential.

Never:

```text
one global SCIM secret
for every customer
```

---

# 57. SCIM Credential Rotation

SCIM credentials SHALL be:

```text
secret-managed
rotatable
revocable
audited
customer-scoped
```

---

# 58. SCIM Rate Limits

SCIM endpoints SHALL implement bounded rate limits while supporting realistic bulk provisioning.

Microsoft's current App Gallery guidance, for example, requires SCIM applications submitted for automated provisioning to support user/group endpoints and at least 25 requests per second per tenant. This is useful interoperability guidance, not automatically a Baobab production capacity requirement.

---

# 59. Idempotency

SCIM create/update/deactivate processing SHALL be idempotent.

Retries SHALL NOT create duplicate CanonicalIdentity records.

---

# 60. External Identifier

SCIM `externalId` MAY be retained as provider relationship metadata.

It SHALL NOT replace:

```text
CanonicalIdentity ID
```

---

# 61. Attribute Mapping

Enterprise attributes SHALL pass through explicit mapping.

Example:

```text
Entra
givenName
      │
      ▼
SCIM
name.givenName
      │
      ▼
Baobab profile attribute
```

Mappings SHALL be versioned.

---

# 62. Attribute Authority

For each synchronized attribute, define authority.

Example:

| Attribute | Authority |
|---|---|
| Enterprise employee status | Enterprise |
| Canonical identity ID | Baobab CP |
| Enterprise subject | Enterprise IdP |
| Buyer role | Trade |
| Supplier approval | Supplier domain |
| ERP role | iDempiere |
| Tenant | CP |
| Legal entity | CP |
| Market | CP |

---

# 63. Attribute Conflict

When enterprise and Baobab values conflict, the configured authority SHALL win.

Do not implement:

```text
last write wins
```

for security-sensitive attributes without explicit justification.

---

# 64. Profile Synchronization

Low-risk attributes such as:

```text
display name
job title
department
```

MAY synchronize where useful.

But synchronization SHALL remain purpose-limited.

---

# 65. No Directory Dumping

Baobab SHALL not ingest an enterprise's entire directory merely because SCIM permits it.

Provision only users/groups required for Baobab access.

---

# 66. Just-In-Time Provisioning

Baobab MAY support JIT provisioning during trusted enterprise login.

```text
trusted federation
       │
       ▼
new subject
       │
       ▼
ExternalIdentity
       │
       ▼
controlled CanonicalIdentity mapping
       │
       ▼
eligible baseline relationship
```

---

# 67. JIT Does Not Mean JIT Admin

JIT SHALL NOT produce:

```text
new subject
    │
    ▼
ADMIN
```

merely from successful SSO.

---

# 68. JIT vs SCIM

Supported enterprise provisioning models MAY include:

```text
JIT only
SCIM only
SCIM + SSO
invitation + SSO
```

depending on customer capability.

---

# 69. Preferred Mature Enterprise Model

For larger B2B customers:

```text
SAML/OIDC
+
SCIM
```

is generally preferable because authentication and lifecycle can be managed separately.

Ory currently advertises enterprise SSO plus SCIM/directory synchronization as complementary B2B capabilities.

---

# 70. Small B2B Customers

Baobab SHALL NOT require every small business customer to operate an enterprise IdP.

They MAY use:

```text
native Ory identity
+
Baobab organization membership
```

---

# 71. Enterprise Federation Is Optional Capability

Therefore:

```text
B2B
   ≠
mandatory enterprise SSO
```

Federation is an enhancement for customers that need it.

---

# 72. ZuriBeans

ZuriBeans SHOULD support:

```text
small buyer
   │
   ▼
native identity

enterprise buyer
   │
   ▼
enterprise SSO
   │
   ▼
optional SCIM
```

Both resolve to the same Baobab buyer-domain architecture.

---

# 73. ZuriBeans Example

```text
ACME Entra ID
      │
      ▼
Ory federation
      │
      ▼
Jane
      │
      ▼
CanonicalIdentity
      │
      ▼
ACME BuyerOrganizationMembership
      │
      ▼
Trade
      │
      ▼
PURCHASER
```

Entra proves the external authentication.

Trade still owns `PURCHASER`.

---

# 74. ZuriBeans Purchase Approver

Even if Entra supplies:

```text
group = PurchasingManagers
```

Trade SHALL determine whether Jane possesses:

```text
BUYER_APPROVER
```

and what financial approval limits apply.

---

# 75. Thamani B2B

Thamani enterprise customers SHOULD similarly support federation.

Example:

```text
Logistics Corporation
       │
       ▼
Enterprise IdP
       │
       ▼
Ory
       │
       ▼
CanonicalIdentity
       │
       ▼
ThamaniOrganizationMembership
       │
       ▼
LOGISTICS_MANAGER
```

---

# 76. Thamani Personal Identity

The same person may also have:

```text
Jane
├── Personal Thamani Customer
└── ACME Logistics Manager
```

Enterprise deprovisioning SHALL remove/suspend the ACME relationship without deleting Jane's personal account.

---

# 77. Supplier Federation

Large suppliers MAY also use enterprise SSO.

Federation SHALL authenticate supplier representatives.

It SHALL NOT constitute supplier approval.

---

# 78. Supplier Example

```text
Supplier Entra
     │
     ▼
Ory
     │
     ▼
CanonicalIdentity
     │
     ▼
SupplierRepresentative
     │
     ▼
Supplier Domain
     │
     ▼
approved permissions
```

---

# 79. ERP Workforce Federation

Enterprise federation MAY authenticate Baobab workforce before iDempiere access.

The existing mapping remains:

```text
Enterprise IdP
      │
      ▼
CanonicalIdentity
      │
      ▼
CP ERP Context
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

The enterprise IdP SHALL NOT issue iDempiere `AD_Role`.

---

# 80. Federation Configuration Administration

Federation configuration is a privileged operation.

Only authorized organization administrators or Baobab administrators SHALL configure enterprise IdPs.

---

# 81. Organization Admin Self-Service

Where product maturity permits, Baobab SHOULD support:

```text
Organization Admin
      │
      ▼
Enterprise SSO Setup
      │
      ▼
metadata/configuration
      │
      ▼
domain verification
      │
      ▼
test login
      │
      ▼
activate
```

Ory currently provides enterprise SSO onboarding patterns including organization-scoped setup links and SCIM configuration.

Baobab MAY consume such capabilities while retaining canonical organization authority.

---

# 82. Configuration Testing

Federation SHALL be tested before activation.

Verify:

```text
issuer
signatures
redirects
subject mapping
attribute mapping
assurance mapping
domain association
logout behavior where supported
```

---

# 83. SAML Metadata

SAML metadata SHALL be treated as security-sensitive configuration.

Changes to:

```text
signing certificate
entity ID
SSO URL
```

SHALL be controlled and audited.

---

# 84. Certificate Rotation

Federation SHALL support overlapping/controlled certificate rotation to avoid unnecessary outages.

---

# 85. OIDC Configuration

Enterprise OIDC configuration SHALL validate:

```text
issuer
discovery metadata
client ID
client secret/private-key config
redirect URI
scopes
claim mapping
```

---

# 86. Redirect URI Security

Wildcard redirect URIs SHALL be prohibited unless a separately documented exceptional case requires them.

---

# 87. IdP-Initiated SSO

IdP-initiated SSO MAY be supported where required.

It SHALL still resolve into:

```text
trusted federation
→ ExternalIdentity
→ CanonicalIdentity
→ Context
```

and SHALL not bypass Baobab authorization.

---

# 88. SP-Initiated SSO

SP-initiated SSO SHOULD be preferred where it provides clearer estate/context routing.

---

# 89. Account Discovery Privacy

Login discovery SHALL avoid revealing unnecessary information about:

```text
whether an organization is a customer
whether a user exists
whether a specific email is registered
```

where practical.

---

# 90. Federation Failure

If an enterprise IdP is unavailable:

```text
enterprise SSO user
      │
      ▼
authentication unavailable
```

Baobab SHALL NOT silently issue a weaker local credential unless an explicitly governed fallback exists.

---

# 91. Local Fallback Accounts

Local fallback authentication for enterprise users SHOULD generally be disabled unless specifically required.

Otherwise federation policy can be bypassed.

---

# 92. Break-Glass Exception

A separately governed Baobab break-glass identity MAY exist for platform operations.

It SHALL not become a generic fallback for customer enterprise users.

---

# 93. Federation Revocation

When an enterprise federation is revoked:

```text
FederationTrust → REVOKED
```

Baobab SHALL stop accepting new authentication through that trust.

Existing sessions SHALL be handled according to risk and revocation policy.

---

# 94. Federation Suspension

Suspension MAY be used during:

```text
security incident
configuration failure
certificate issue
customer request
```

without deleting historical mapping.

---

# 95. Identity History

Historical federation relationships SHALL be retained sufficiently for audit.

Do not destroy the evidence needed to explain previous access.

---

# 96. Enterprise Offboarding

When an entire customer organization leaves Baobab:

```text
FederationTrust
      │
      ▼
REVOKED

SCIM credentials
      │
      ▼
REVOKED

Organization memberships
      │
      ▼
domain offboarding policy

CanonicalIdentity
      │
      ▼
preserved where independently required
```

---

# 97. Tenant Offboarding Is Separate

Customer offboarding SHALL follow canonical tenant/organization lifecycle.

Deleting the federation configuration alone is insufficient.

---

# 98. SCIM Deletion Semantics

A SCIM `DELETE` SHALL be mapped carefully.

Physical deletion of CanonicalIdentity SHOULD NOT be the default interpretation.

Prefer:

```text
enterprise relationship deprovisioned
```

---

# 99. Rehire/Rejoin

If Jane later rejoins Company A:

```text
existing CanonicalIdentity
       │
       ▼
new/renewed enterprise relationship
```

SHOULD be used rather than creating another Jane.

---

# 100. Enterprise Subject Change

If the enterprise changes its subject identifier:

```text
old subject
    │
    ▼
controlled identity migration/linking
    │
    ▼
same CanonicalIdentity
```

where equivalence is safely established.

---

# 101. Domain Change

Company rebranding:

```text
oldcompany.com
      │
      ▼
newcompany.com
```

SHALL NOT automatically create a new canonical organization.

---

# 102. Acquisition

Corporate acquisition may produce:

```text
old IdP
+
new parent IdP
```

during transition.

Baobab SHALL support controlled coexistence where necessary.

---

# 103. Merger

Organization merger SHALL be handled by canonical organization governance.

Federation metadata SHALL not dictate corporate structure.

---

# 104. SCIM Security Events

Canonical lifecycle events SHOULD include:

```text
federation.trust.created
federation.trust.activated
federation.trust.suspended
federation.trust.revoked

enterprise.identity.provisioned
enterprise.identity.updated
enterprise.identity.deprovisioned

enterprise.group.updated
enterprise.relationship.review_required
```

---

# 105. Provider Events Are Not Canonical Events

```text
ory.polis.connection.updated
```

or equivalent provider-native events SHALL be normalized before cross-engine consumption.

---

# 106. Audit

Federation audit SHOULD capture:

```text
organization
federation trust
actor
protocol
issuer
configuration action
mapping version
decision
timestamp
correlation ID
```

without logging assertions or tokens unnecessarily.

---

# 107. SCIM Audit

SCIM audit SHOULD capture:

```text
enterprise integration
resource operation
external identifier
canonical mapping
outcome
correlation ID
```

without logging credentials.

---

# 108. No Assertion Logging

Raw SAML assertions and OAuth/OIDC tokens SHALL NOT normally be logged.

---

# 109. No SCIM Secret Logging

SCIM bearer credentials, private keys and secrets SHALL never appear in ordinary logs.

---

# 110. Metrics

Monitor:

```text
enterprise login success/failure
federation routing failure
assurance mapping failure
SCIM provisioning rate
SCIM deprovisioning latency
SCIM failures
identity mapping conflicts
orphan enterprise identities
directory drift
certificate expiry
federation outages
```

---

# 111. Security Alerts

Alert on:

```text
unexpected federation config change
signing certificate anomaly
mass provisioning
mass deprovisioning
mapping collision
SCIM credential abuse
federation admin change
repeated invalid assertions
```

---

# 112. Reconciliation

Reconciliation SHALL identify:

```text
provider subject without ExternalIdentity
ExternalIdentity without CanonicalIdentity
inactive enterprise user with active membership
revoked federation still producing logins
SCIM user missing expected relationship
duplicate external mappings
```

---

# 113. Enterprise Trust Does Not Propagate Globally

Trusting:

```text
ACME Entra ID
```

for:

```text
ACME ZuriBeans buyer users
```

does not mean trusting it to authenticate:

```text
Baobab workforce
other customers
suppliers
CP administrators
```

---

# 114. Least Trust

Federation trust SHALL be constrained by:

```text
organization
estate
protocol
issuer
audience
attribute mappings
assurance mappings
lifecycle policy
```

---

# 115. Organization Claims

An external claim:

```text
organization = ACME
```

SHALL NOT create a canonical organization.

It may be used as evidence only within an explicitly configured trust.

---

# 116. Tenant Claims

External enterprise IdPs SHALL NOT dictate:

```text
tenant_id
legal_entity_id
market_id
digital_estate_id
```

as canonical authority.

CP resolves these.

---

# 117. Role Claims

External role claims MAY inform mapping policy.

They SHALL NOT override domain authority.

---

# 118. Group Explosion

Large enterprise directories can contain thousands of groups.

Baobab SHALL NOT ingest all groups into tokens.

---

# 119. Token Size

Enterprise group membership SHALL not be allowed to create oversized Baobab tokens.

Use server-side mapping/context resolution where necessary.

---

# 120. Federation Claims Minimized

Baobab SHOULD request only necessary claims.

Typical needs:

```text
stable subject
basic profile
email where appropriate
assurance evidence
```

plus explicitly justified enterprise attributes.

---

# 121. Privacy

Enterprise directory data may contain significant personal information.

SCIM RFC 7644 explicitly notes that SCIM resources can contain personally identifying and sensitive information and requires privacy considerations to be taken seriously.

Baobab SHALL minimize synchronized attributes.

---

# 122. Cross-Border Enterprise Identity

Enterprise customers may authenticate staff across several countries.

Federation SHALL not equate:

```text
IdP tenant geography
```

with:

```text
Baobab market
```

---

# 123. Data Residency

Federation configuration, directory projections and audit records SHALL follow Baobab's regional/data-residency architecture.

---

# 124. Enterprise Identity Is Global Where Appropriate

A single person MAY act across:

```text
ACME Uganda
ACME Kenya
ACME South Africa
```

through one CanonicalIdentity with multiple contexts.

---

# 125. Cross-Organization Users

Consultants and service providers MAY represent several unrelated organizations.

Baobab SHALL not force one organization per identity.

---

# 126. Context Selection

After authentication:

```text
Jane
 │
 ▼
available Baobab contexts
 ├── ACME Uganda
 ├── ACME Kenya
 └── Personal Thamani
```

CP determines legitimate contexts.

---

# 127. Federation Does Not Select Context Authoritatively

The upstream IdP MAY provide hints.

CP makes the canonical context decision.

---

# 128. Forced Enterprise SSO

An organization MAY require:

```text
all Company A users
must authenticate through Company A federation
```

This MAY be supported as organization policy.

---

# 129. Forced SSO Exceptions

Exceptions SHALL be narrowly governed for:

```text
bootstrap
emergency
migration
support
```

and audited.

---

# 130. Federation Bootstrap

Avoid circular dependency:

```text
Need SSO to configure SSO
```

The first verified organization administrator SHALL have an approved bootstrap authentication path.

After federation activation, policy may require enterprise SSO.

---

# 131. Federation Migration

Changing enterprise IdP:

```text
Okta
  │
  ▼
Entra ID
```

SHALL preserve CanonicalIdentity and business relationships.

---

# 132. Dual Federation Migration

During migration:

```text
Old IdP ─┐
         ├──► CanonicalIdentity
New IdP ─┘
```

may coexist temporarily.

This mirrors ADR-IAM-0022's provider migration principle.

---

# 133. Cutover

Enterprise federation cutover SHALL include:

```text
identity mapping validation
assurance equivalence
SCIM state validation
session policy
rollback
```

---

# 134. No Duplicate Authority

Dual federation SHALL NOT create duplicate memberships or duplicate approval limits.

---

# 135. SCIM Source of Lifecycle Truth

Where SCIM is configured as authoritative for enterprise employment status:

```text
enterprise directory
```

is authoritative for:

```text
enterprise relationship active/inactive
```

but not for all Baobab relationships.

---

# 136. Example

Jane leaves ACME.

SCIM says inactive.

Baobab SHALL revoke:

```text
Jane ↔ ACME
```

but SHALL NOT necessarily revoke:

```text
Jane ↔ Thamani Personal

Jane ↔ Supplier XYZ

Jane ↔ Company B
```

---

# 137. Domain Authority Example

```text
SCIM:
Jane active

Trade:
BUYER_APPROVER revoked
```

Result:

```text
Jane remains enterprise member
but cannot approve purchases.
```

---

# 138. IdP Compromise

If a customer enterprise IdP is suspected compromised:

```text
FederationTrust → SUSPENDED
```

MAY immediately stop new federated authentication.

Existing high-risk sessions SHOULD be reviewed/revoked according to policy.

---

# 139. Compromise Blast Radius

Because federation trust is organization-scoped, compromise of ACME's IdP SHOULD NOT compromise unrelated organizations.

---

# 140. Provider Compromise

Compromise of Ory/federation infrastructure remains a platform-level incident governed by ADR-IAM-0017/0018 and subsequent Ory architecture ADRs.

---

# 141. Failure Containment

An enterprise federation outage SHALL not cause:

```text
all Baobab identities
```

to fail.

Only affected federation paths should be impaired where architecture permits.

---

# 142. Availability

Large enterprise customers MAY require federation availability objectives.

These SHALL be incorporated into IAM SLOs and customer-facing service commitments where appropriate.

---

# 143. Enterprise SSO Licensing

Baobab SHALL explicitly verify whether required:

```text
SAML
enterprise SSO
SCIM
directory synchronization
self-hosting
HA
multi-region
```

capabilities are available under the selected Ory deployment/licensing model before implementation.

Ory currently advertises enterprise SSO and directory-sync capabilities, including self-hosted deployment options, but capability/licensing verification remains an implementation gate rather than an architectural assumption.

---

# 144. No Architecture by License Accident

If a selected commercial capability is unavailable under Baobab's deployment model, the solution SHALL be reconsidered through ADR rather than embedding an undocumented workaround.

---

# 145. Shared Contracts

`shared` SHOULD define provider-neutral contracts for:

```text
FederationTrust
EnterpriseSubject
EnterpriseIdentityLifecycleEvent
FederationAssuranceEvidence
DirectoryProvisioningEvent
FederationStatus
```

It SHALL NOT define Ory-specific administrative objects as canonical contracts.

---

# 146. CP Model

CP SHOULD know:

```text
canonical organization
trusted federation reference
ExternalIdentity
CanonicalIdentity
organization membership
context
```

but SHOULD NOT need to understand:

```text
SAML XML
Ory internal federation tables
Entra Graph internals
Okta API internals
```

---

# 147. baobab-iam Responsibility

`baobab-iam` owns:

```text
federation adapter
trust configuration integration
attribute normalization
assurance normalization
SCIM boundary
lifecycle normalization
reconciliation
security events
```

---

# 148. Infrastructure Responsibility

Infrastructure owns:

```text
DNS
TLS
secrets
certificates
network controls
service deployment
monitoring
regional placement
```

but not organization authority.

---

# 149. Digital Estate Responsibility

Digital Estates own:

```text
enterprise login UX
organization discovery UX
SSO setup UX where exposed
context-selection UX
error/recovery UX
```

They do not validate SAML signatures themselves.

---

# 150. Domain Responsibility

Domains retain:

```text
buyer roles
purchase authority
supplier authority
shipment authority
finance permissions
ERP permissions
```

---

# 151. Prohibited Shortcuts

The following are prohibited:

```text
IdP organization = Tenant

IdP group = Baobab role

IdP admin = Baobab admin

SCIM user = CanonicalIdentity

SCIM group = Trade role

email domain = legal entity

email equality = identity equality

SSO success = business authorization

enterprise MFA = assumed A3

SCIM delete = delete person

IdP disable = delete CanonicalIdentity

enterprise directory = CP

SAML assertion = permanent business state
```

---

# 152. Security Invariants

```text
Federation ≠ Authorization

SSO ≠ Tenant Membership

SCIM ≠ Authentication

SCIM ≠ Authorization

Enterprise Group ≠ Domain Role

Enterprise Organization ≠ Tenant

Enterprise Organization ≠ LegalEntity

Email Domain ≠ LegalEntity

External Subject ≠ CanonicalIdentity

IdP Admin ≠ Baobab Admin

IdP MFA ≠ Automatically A3

Directory User ≠ Buyer

Directory User ≠ Supplier

Deprovisioning ≠ Person Deletion

Enterprise Offboarding ≠ Canonical Identity Deletion

Federation Trust ≠ Global Trust
```

---

# 153. Implementation Gates

## IAM-F0 — Federation Capability and Licensing Audit

Verify current Ory capabilities and selected deployment model for:

```text
SAML
OIDC enterprise federation
SCIM
directory sync
self-hosting
HA
multi-region
admin APIs
```

No production implementation before this matrix is explicit.

---

## IAM-F1 — Federation Contracts

Implement provider-neutral:

```text
FederationTrust
EnterpriseSubject
FederationStatus
FederationAssuranceMapping
DirectoryLifecycleEvent
```

---

## IAM-F2 — Trust Registry

Implement organization-scoped federation trust registry and lifecycle.

---

## IAM-F3 — Ory Federation Adapter

Integrate approved Ory enterprise federation capability behind `baobab-iam`.

---

## IAM-F4 — Domain Verification

Implement secure organization-domain verification and audit.

---

## IAM-F5 — Identity Mapping

Implement:

```text
enterprise subject
→ ExternalIdentity
→ CanonicalIdentity
```

with collision handling and no email auto-linking.

---

## IAM-F6 — Assurance Mapping

Map upstream:

```text
acr
amr
provider assurance
```

to ADR-IAM-0024 Baobab assurance classes.

---

## IAM-F7 — SCIM Service

Implement SCIM 2.0 lifecycle boundary with:

```text
Users
Groups where justified
idempotency
tenant/organization isolation
rate limiting
audit
```

---

## IAM-F8 — Lifecycle Synchronization

Implement:

```text
joiner
mover
leaver
```

and reconciliation.

---

## IAM-F9 — ZuriBeans Enterprise SSO

Implement enterprise buyer federation while preserving Trade authorization.

---

## IAM-F10 — Thamani Enterprise SSO

Implement business-customer federation while preserving personal/business multi-context identity.

---

## IAM-F11 — Supplier Federation

Implement optional enterprise SSO for larger suppliers without conflating federation with supplier approval.

---

## IAM-F12 — ERP Workforce Federation

Validate enterprise SSO through canonical identity/context into iDempiere.

---

## IAM-F13 — Federation Administration UX

Implement secure self-service configuration for authorized organization administrators where appropriate.

---

## IAM-F14 — Observability and Reconciliation

Implement:

```text
metrics
alerts
drift detection
certificate monitoring
orphan detection
```

---

## IAM-F15 — Security Hardening

Perform:

```text
SAML attack testing
OIDC federation testing
SCIM isolation testing
cross-organization tests
group mapping attacks
account linking attacks
IdP compromise simulation
deprovisioning tests
```

---

# 154. Required Test Matrix

| Scenario | Expected |
|---|---|
| Trusted enterprise login | Canonical identity resolved |
| Unknown IdP | Reject |
| Wrong issuer | Reject |
| Invalid SAML signature | Reject |
| Wrong OIDC audience | Reject |
| Same email, different subject | No auto-link |
| Trusted upstream MFA | Map only according to explicit policy |
| Unknown assurance | Safe baseline |
| IdP group says Admin | No automatic Baobab admin |
| SCIM creates user | No automatic privileged role |
| SCIM disables user | Enterprise relationship deactivated |
| User has personal Thamani account | Personal relationship preserved |
| User belongs to Company B too | Company B relationship preserved |
| SCIM replay | Idempotent |
| SCIM credential for Company A used against B | Reject |
| Federation revoked | New authentication rejected |
| Federation config changed | Audit generated |
| Domain unverified | Federation not activated |
| Old/new IdP coexist during migration | Same CanonicalIdentity where verified |
| Customer IdP outage | No silent weak fallback |
| Leaver still has active sensitive relationship | Drift alert/remediation |

---

# 155. Production Readiness Checklist

### Trust

- [ ] federation trust registry
- [ ] organization verification
- [ ] domain verification
- [ ] issuer validation
- [ ] trust lifecycle
- [ ] revocation

### Protocols

- [ ] OIDC enterprise federation
- [ ] SAML where required
- [ ] SCIM 2.0
- [ ] secure metadata handling
- [ ] certificate/key rotation

### Identity

- [ ] stable external subject
- [ ] ExternalIdentity mapping
- [ ] CanonicalIdentity mapping
- [ ] no email auto-linking
- [ ] collision handling
- [ ] multi-organization identities

### Assurance

- [ ] upstream assurance mapping
- [ ] `acr`/`amr` validation
- [ ] unknown-assurance fallback
- [ ] local step-up where required
- [ ] no assumed MFA

### SCIM

- [ ] organization-isolated credentials
- [ ] Users endpoint
- [ ] Groups where needed
- [ ] idempotency
- [ ] rate limiting
- [ ] joiner/mover/leaver
- [ ] reconciliation
- [ ] deprovisioning priority

### Domains

- [ ] ZuriBeans federation
- [ ] Thamani B2B federation
- [ ] personal Thamani identity preserved
- [ ] supplier federation optional
- [ ] ERP mapping preserved
- [ ] domain authorization remains local

### Security

- [ ] SAML tests
- [ ] OIDC tests
- [ ] SCIM isolation tests
- [ ] mapping attack tests
- [ ] federation compromise procedure
- [ ] no raw assertions/tokens in logs
- [ ] secrets managed

### Operations

- [ ] certificate expiry alerts
- [ ] federation metrics
- [ ] SCIM metrics
- [ ] drift detection
- [ ] orphan detection
- [ ] audit events
- [ ] customer offboarding procedure

---

# 156. Final Architecture

```text
               CUSTOMER ENTERPRISE
                       │
            ┌──────────┴──────────┐
            │                     │
        SAML / OIDC             SCIM
            │                     │
            ▼                     ▼
      ┌──────────────────────────────┐
      │          ORY / IAM           │
      │                              │
      │ Federation                   │
      │ Authentication               │
      │ Directory Sync               │
      │ Assurance Evidence           │
      └──────────────┬───────────────┘
                     │
                     ▼
      ┌──────────────────────────────┐
      │        baobab-iam            │
      │                              │
      │ Trust Registry               │
      │ Identity Normalization       │
      │ Assurance Mapping            │
      │ Lifecycle Normalization      │
      │ Reconciliation               │
      └──────────────┬───────────────┘
                     │
                     ▼
      ┌──────────────────────────────┐
      │         baobab-cp            │
      │                              │
      │ ExternalIdentity             │
      │ CanonicalIdentity            │
      │ Organization                 │
      │ Membership                   │
      │ Context                      │
      │ Capability                   │
      └──────────────┬───────────────┘
                     │
          ┌──────────┼────────────┐
          │          │            │
          ▼          ▼            ▼
      ZuriBeans   Thamani        ERP
        Trade     Logistics    iDempiere
          │          │            │
          └──────────┼────────────┘
                     │
                     ▼
              DOMAIN AUTHORITY
```

And critically:

```text
Enterprise IdP
     │
     ▼
"Jane authenticated"
     │
     ▼
Baobab IAM
     │
     ▼
"This external subject maps to Jane"
     │
     ▼
Control Plane
     │
     ▼
"Jane may act in Company A context"
     │
     ▼
Domain
     │
     ▼
"Jane may perform THIS operation"
```

No layer silently assumes the responsibilities of the next.

---

# 157. Consequences

## Positive

This architecture provides:

- enterprise-grade B2B SSO;
- Microsoft Entra ID and other enterprise IdP interoperability;
- automated joiner/mover/leaver lifecycle;
- SCIM without surrendering canonical identity ownership;
- one-person/multiple-organization support;
- stronger customer offboarding;
- federation-aware assurance;
- enterprise identity portability;
- cleaner ZuriBeans B2B onboarding;
- correct Thamani B2B/B2C coexistence;
- optional supplier federation;
- reduced customer credential-management burden.

## Costs

Baobab must operate:

- federation trust configuration;
- SAML/OIDC interoperability;
- SCIM;
- organization-domain verification;
- attribute mapping;
- assurance mapping;
- lifecycle reconciliation;
- federation support tooling.

Enterprise federation should therefore be enabled for customers that need it rather than imposed on every B2B account.

## Principal Risks

```text
IdP roles leaking into business authorization
email auto-linking
stale enterprise users
SCIM over-privileging
federation trust misconfiguration
weak domain verification
provider/licensing assumptions
group explosion
cross-organization leakage
silent fallback to weaker authentication
```

The controls above are specifically intended to prevent these failure modes.

---

# 158. Final Decision Principle

Baobab SHALL treat an enterprise identity provider as a trusted source for a **specific and bounded set of identity assertions**, not as an external administrator of Baobab's business architecture.

The relationship is:

```text
ENTERPRISE
"Jane works in our identity domain."
        │
        ▼
IAM
"We trust this federation and
have authenticated its subject."
        │
        ▼
CANONICAL IDENTITY
"We know which Jane this is."
        │
        ▼
CONTROL PLANE
"We know which Baobab contexts
Jane may enter."
        │
        ▼
DOMAIN
"We know what Jane may do
inside this business context."
```

SCIM synchronizes lifecycle.

SAML/OIDC federates authentication.

Ory provides identity mechanics.

Baobab owns canonical identity and context.

Business domains own business authority.

> **Federate authentication, synchronize lifecycle, verify organizational trust, preserve canonical identity, and never outsource Baobab authorization to the customer's directory.**