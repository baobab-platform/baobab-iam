# ADR-0005: Realm, Organization, Tenant and Legal-Entity Model

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** IAM realm boundaries, Keycloak Organizations, Baobab tenants, legal entities, canonical entities, Digital Estates, buyer/supplier organizations and multi-market context  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  

---

# 1. Context

Baobab uses several organisational concepts that are related but not interchangeable.

The platform currently distinguishes, or is expected to distinguish:

- IAM realms;
- Keycloak Organizations;
- Baobab Tenants;
- legal entities;
- Canonical Entities;
- Digital Estates;
- buyer organisations;
- supplier organisations;
- internal operating organisations;
- engine-specific organisations;
- markets;
- engine instances;
- capability bindings.

Without an explicit architectural decision, implementation pressure may gradually collapse several of these concepts into one another.

Examples of dangerous simplifications include:

```text
Keycloak Organization = Tenant
```

or:

```text
Tenant = Legal Entity
```

or:

```text
Digital Estate = Tenant
```

or:

```text
Buyer Organization = Keycloak Organization
```

These shortcuts may appear convenient initially, but they would conflict with Baobab's existing canonical control-plane model and would create significant difficulties as Nabhold expands across markets, legal entities, digital estates and future SaaS customers.

This ADR defines the semantic and authority boundaries among these concepts.

---

# 2. Decision

Baobab SHALL maintain explicit separation among:

```text
Realm
IAM Organization
Canonical Entity
Legal Entity
Tenant
Digital Estate
Business Organization
Market
```

No relationship between these concepts SHALL be inferred solely from matching names or identifiers.

Relationships SHALL be represented through explicit canonical mappings and Control Plane configuration.

The foundational model SHALL be:

```text
                      KEYCLOAK
                         │
                         ▼
                       Realm
                         │
                         ▼
                  IAM Organization
                         │
                  explicit mapping
                         │
                         ▼
                Canonical Entity
                         │
          ┌──────────────┼───────────────┐
          ▼              ▼               ▼
     Legal Entity      Tenant      Business Organization
                          │
                          ▼
                    Digital Estate
                          │
                          ▼
                        Market
```

This diagram is conceptual rather than a strict ownership hierarchy.

Many relationships are potentially many-to-many.

---

# 3. Realm

A Keycloak Realm is an IAM isolation boundary.

The primary Baobab production realm SHALL initially be:

```text
baobab
```

A realm owns or scopes identity-provider concerns such as:

- users;
- clients;
- authentication flows;
- sessions;
- organizations;
- identity providers;
- client scopes;
- signing keys;
- realm roles;
- security policies.

A Realm SHALL NOT itself represent:

- one tenant;
- one legal entity;
- one Digital Estate;
- one market.

---

# 4. Realm Semantics

The relationship SHALL be:

```text
Realm
  │
  └── authentication/security namespace
```

not:

```text
Realm
  │
  └── business tenancy namespace
```

This distinction allows a single Baobab user to authenticate once and participate in multiple business contexts.

---

# 5. IAM Organization

A Keycloak Organization SHALL represent an identity-side organisational affiliation.

Suitable examples include:

- a B2B buyer company;
- a supplier company;
- a partner;
- selected corporate organisational structures;
- enterprise customers;
- invited external organisations.

An IAM Organization MAY assist with:

- user invitations;
- organisation-aware login;
- organisation membership;
- identity federation;
- organisation-specific identity-provider behaviour;
- identity-side groupings.

It SHALL NOT automatically establish a Baobab business or tenancy relationship.

---

# 6. IAM Organization Is Not Tenant

This invariant SHALL hold:

```text
IAM Organization ≠ Tenant
```

A Keycloak Organization named:

```text
Acme Hotels
```

does not become a Baobab Tenant simply because it exists in IAM.

The relationship, where required, SHALL be explicit:

```text
Keycloak Organization
        │
        ▼
Canonical Entity Mapping
        │
        ▼
Tenant / Buyer Organization / Supplier Organization
```

---

# 7. IAM Organization Is Not Legal Entity

Likewise:

```text
IAM Organization ≠ Legal Entity
```

A Keycloak Organization may correspond to a legal entity, but this correspondence is a business relationship rather than an IAM fact.

IAM does not establish:

- incorporation;
- jurisdiction;
- company registration number;
- tax registration;
- beneficial ownership;
- legal status.

Those are business/domain facts.

---

# 8. Canonical Entity

`CanonicalEntity` SHALL remain the Baobab platform abstraction used to represent cross-system entities requiring durable identity and mapping.

A Canonical Entity may represent, depending on the canonical model:

- legal entity;
- organisation;
- customer organisation;
- supplier organisation;
- other cross-engine business entity.

The existing Control Plane CanonicalEntity model SHALL be reused rather than reinvented inside IAM.

---

# 9. Canonical Entity as Integration Spine

The preferred mapping is:

```text
Keycloak Organization
        │
        ▼
CanonicalEntity
        │
        ├── ERP Business Partner
        ├── Trade Organization
        ├── Supplier Organization
        └── other engine references
```

This maintains cross-engine identity without giving Keycloak ownership over business entities.

---

# 10. Legal Entity

A Legal Entity represents an organisation recognised under applicable law.

Examples may include:

```text
Nabhold (Pty) Ltd
Zuribeans operating company
Thamani operating company
Equator & Estate operating company
external buyer company
external supplier company
```

Legal Entity attributes may include:

- jurisdiction;
- registration number;
- tax identity;
- legal name;
- incorporation status;
- registered address.

These SHALL NOT be stored as IAM authority data merely to make authentication convenient.

---

# 11. Tenant

A Tenant is the default Baobab isolation and consumption boundary.

The existing Baobab architectural decision remains:

> **A legal entity is the default tenant boundary, but Tenant and Legal Entity are not synonymous concepts.**

The distinction SHALL be preserved.

---

# 12. Why Tenant Is Not Legal Entity

The following may frequently be true:

```text
Legal Entity A
       │
       ▼
Tenant A
```

but Baobab SHALL support other future patterns.

For example:

```text
Legal Entity
    │
    ├── Tenant A
    └── Tenant B
```

or:

```text
Tenant
  │
  ├── Legal Entity A
  └── Legal Entity B
```

where a future deployment legitimately requires such a model.

Such configurations SHALL require explicit platform relationships and isolation policy.

---

# 13. Default Tenant Model

For current Baobab deployment, the default SHOULD remain:

```text
1 Legal Entity
      │
      ▼
1 primary Tenant
```

unless a documented business reason requires another relationship.

This default provides simplicity without making the architecture incapable of supporting future configurations.

---

# 14. Digital Estate

A Digital Estate is an externally or internally facing digital product/presentation experience.

Examples include:

```text
Zuribeans
Thamani
Nabhold
Equator & Estate
future Baobab estates
```

A Digital Estate SHALL NOT automatically be equivalent to:

- tenant;
- legal entity;
- IAM organisation;
- market;
- domain engine.

---

# 15. Digital Estate Relationship

A typical current relationship may be:

```text
Legal Entity
     │
     ▼
Tenant
     │
     ▼
Digital Estate
```

For example:

```text
Zuribeans legal entity
        │
        ▼
Zuribeans tenant
        │
        ▼
Zuribeans Digital Estate
```

However this SHALL remain a configured relationship rather than a fundamental identity equation.

---

# 16. One Tenant May Serve Multiple Digital Estates

Baobab SHALL permit:

```text
Tenant
  │
  ├── Digital Estate A
  ├── Digital Estate B
  └── Digital Estate C
```

if a future business model requires it.

For example, one legal entity could operate multiple branded storefronts while maintaining common back-office isolation.

---

# 17. One Digital Estate May Be Multi-Market

A Digital Estate may serve multiple markets.

For example:

```text
Zuribeans
    │
    ├── Uganda
    ├── South Africa
    └── future market
```

Likewise:

```text
Thamani
    │
    ├── South Africa
    ├── Uganda
    └── future markets
```

Therefore:

```text
Digital Estate ≠ Market
```

---

# 18. Market

A Market represents the commercial/regulatory geographic context in which platform capabilities operate.

A Market may influence:

- currency;
- tax;
- payment methods;
- catalogues;
- pricing;
- shipping;
- customs;
- ERP organisation mapping;
- data residency;
- regulatory configuration.

Market SHALL remain a Control Plane context concept.

---

# 19. Market Is Not Tenant

This invariant SHALL hold:

```text
Market ≠ Tenant
```

A tenant can operate in multiple markets.

Example:

```text
Zuribeans Tenant
        │
        ├── UG
        └── ZA
```

Market SHALL therefore form part of resolved context rather than identity.

---

# 20. Tenant–Market Relationship

The expected model is:

```text
Tenant
  │
  └── enabled markets
          │
          ├── UG
          ├── ZA
          └── ...
```

Control Plane policy SHALL determine whether a tenant may operate in a requested market.

---

# 21. Business Organization

A Business Organization represents a business-domain organisation participating in Baobab.

Potential types include:

```text
buyer
supplier
partner
internal organisation
```

Business organisation is a domain concept and SHALL NOT be reduced to an IAM construct.

---

# 22. Buyer Organization

A Zuribeans buyer organisation may have:

- legal identity;
- IAM representation;
- Trade organisation;
- canonical entity;
- representatives;
- commercial terms;
- purchase approvals;
- delivery sites;
- tax registrations.

Conceptually:

```text
                    Buyer Company
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        IAM Organization  Canonical Entity
                               │
                               ▼
                        Trade Organization
                               │
                               ├── members
                               ├── roles
                               ├── terms
                               └── approvals
```

Keycloak SHALL not become authoritative for the Trade-specific branch.

---

# 23. Supplier Organization

A supplier organisation may similarly have:

```text
Supplier Company
       │
       ├── IAM Organization
       ├── Canonical Entity
       ├── Supplier Domain Record
       └── ERP/Trade references
```

Supplier vetting and approval remain outside IAM.

---

# 24. Organization Representative

A human representing an organisation SHALL be modeled through explicit relationships.

Conceptually:

```text
CanonicalIdentity
       │
       ▼
Membership / Representation
       │
       ▼
CanonicalEntity
```

IAM Organization membership may mirror identity-side membership, but business authority SHALL be determined elsewhere.

---

# 25. Representative Does Not Own Organisation

The existence of a representative relationship SHALL not imply ownership.

Different business semantics may include:

```text
employee
director
buyer
approver
supplier admin
finance contact
sales contact
```

These relationships SHALL be modeled in the appropriate domain.

---

# 26. Organization Membership Synchronisation

Baobab MAY synchronize selected organisation membership state between Keycloak and Control Plane/domain systems.

Synchronization SHALL be directional and explicitly governed.

For example:

```text
Supplier approved representative
        │
        ▼
Canonical membership
        │
        ▼
IAM organization membership
```

may be valid.

But sync SHALL NOT establish a hidden second source of truth.

---

# 27. Source-of-Truth Rule

Every relationship SHALL have one clearly defined authority.

Example:

| Relationship | Authority |
|---|---|
| IAM organization membership | Baobab IAM |
| canonical identity | Control Plane |
| tenant membership | Control Plane |
| buyer membership | Trade |
| supplier approval | supplier domain |
| ERP organisation permission | ERP |
| legal incorporation | authoritative business/legal data source |

Synchronization does not transfer authority unless explicitly designed to do so.

---

# 28. Membership Types

Baobab SHOULD distinguish relationship semantics explicitly.

Possible canonical membership categories include:

```text
tenant member
legal entity representative
buyer representative
supplier representative
workforce member
Digital Estate administrator
```

The exact schema SHALL be established through Shared contracts.

One generic boolean such as:

```text
is_member = true
```

is insufficient.

---

# 29. Multi-Role Actor Example

One person may legitimately hold multiple relationships:

```text
                       Jane
                 CanonicalIdentity
                        │
       ┌────────────────┼─────────────────┐
       ▼                ▼                 ▼
Nabhold employee   Zuribeans buyer   Thamani consumer
       │                │
       ▼                ▼
ERP permissions    Acme Hotels
                   buyer membership
```

The architecture SHALL support this without creating three independent global identities.

---

# 30. Cross-Organization Identity

A user may represent more than one organisation.

Example:

```text
Consultant
   │
   ├── Organization A
   └── Organization B
```

Identity does not inherently determine which organisation is active.

Active organisational context SHALL be explicitly selected and authorized.

---

# 31. Organization Context Selection

Where an actor belongs to multiple organisations:

```text
authenticated actor
        │
        ▼
available contexts
   ┌────┴────┐
   ▼         ▼
Org A       Org B
```

The caller MAY select a desired context.

The server MUST verify the relationship before granting it.

---

# 32. Context Switching

Context switching SHALL be modeled as:

```text
current authenticated identity
          │
          ▼
request alternate context
          │
          ▼
Control Plane verification
          │
          ├── allowed
          │      ▼
          │  resolved context
          │
          └── denied
```

It SHALL NOT require re-authentication by default unless risk policy calls for step-up authentication.

---

# 33. Tenant Context Is Not Stored Permanently in Identity Token

Because one identity may operate across contexts, access tokens SHOULD avoid embedding a single permanent tenant identity as though it defines the user.

A token MAY contain:

- requested/current context;
- permitted coarse claims;

where the token profile requires it.

But the canonical model SHALL remain contextual rather than identity-defining.

---

# 34. Tenant Claims

If a token contains tenant-related claims, such claims SHALL be treated according to the exact trust contract defined in ADR-0006.

Mutable tenant authorization SHALL remain verifiable through Control Plane context resolution.

Token claims SHALL not permanently replace that resolution layer.

---

# 35. Legal Entity and ERP Mapping

Legal entities may map to iDempiere structures such as:

```text
Legal Entity
     │
     ▼
CanonicalEntity
     │
     ▼
AD_Client / AD_Org
```

The exact mapping depends on ERP implementation.

IAM SHALL not own this mapping merely because ERP users authenticate through Keycloak.

---

# 36. Buyer Organization and Trade Mapping

Similarly:

```text
Canonical Buyer Entity
        │
        ▼
Medusa/Trade Organization
```

shall remain explicit.

Trade owns commercial relationships.

Control Plane owns canonical mapping/context.

IAM owns authentication-side organization participation.

---

# 37. Supplier and ERP/Trade Mapping

A supplier may require both ERP and commerce mappings:

```text
Canonical Supplier
        │
        ├── Trade supplier relationship
        └── ERP Business Partner
```

IAM Organization membership may provide representatives access, but the supplier's operational status remains domain-owned.

---

# 38. Example — Zuribeans B2B

A likely Zuribeans flow is:

```text
Keycloak Realm: baobab
        │
        ▼
Buyer IAM Organization
"Acme Hotels"
        │
        ▼
CanonicalEntity
        │
        ├── buyer legal entity metadata
        │
        └── Trade Organization
                │
                ├── buyer members
                ├── roles
                ├── commercial terms
                ├── tax registrations
                └── approvals
```

A buyer representative's login:

```text
CanonicalIdentity
       │
       ▼
IAM org membership
       │
       ▼
CP context
       │
       ▼
Trade buyer membership
       │
       ▼
business authorization
```

---

# 39. Example — Thamani B2C

Most ordinary Thamani consumers SHOULD NOT require a dedicated Keycloak Organization.

Typical model:

```text
Thamani Consumer
      │
      ▼
CanonicalIdentity
      │
      ▼
Trade Customer
```

The surrounding context may be:

```text
Tenant: Thamani
Digital Estate: Thamani
Market: ZA
```

This is a contextual relationship, not an IAM organisation requirement.

---

# 40. Example — Thamani Supplier

A Thamani supplier could be:

```text
Supplier Legal Entity
        │
        ▼
CanonicalEntity
        │
        ├── IAM Organization
        ├── Supplier onboarding record
        └── ERP/Trade references
```

Its representatives authenticate individually.

Approval attaches to the supplier business relationship, not merely to the IAM Organization.

---

# 41. Example — Nabhold Executive

An executive may require access across several Baobab operating contexts.

```text
Executive CanonicalIdentity
           │
           ├── Nabhold tenant
           ├── Zuribeans visibility
           ├── Thamani visibility
           └── Equator & Estate visibility
```

One canonical identity SHALL support these relationships.

No separate Keycloak realm or account is required per estate.

---

# 42. Executive Access Does Not Imply Universal Business Roles

Cross-platform visibility SHALL be separately authorized.

For example:

```text
Nabhold executive
    │
    ├── may read operational dashboards
    └── may NOT necessarily approve ERP journals
```

Broad tenant visibility SHALL not automatically expand into engine-native transaction authority.

---

# 43. Future SaaS Tenant

Baobab SHALL be capable of supporting an external future tenant:

```text
External Company
      │
      ▼
Legal Entity
      │
      ▼
Canonical Entity
      │
      ▼
Baobab Tenant
      │
      ├── enabled capabilities
      ├── markets
      ├── Digital Estates
      └── engine instances
```

The tenant may additionally have a Keycloak Organization for its users.

The IAM Organization remains an authentication construct, not tenancy itself.

---

# 44. Future Multi-Legal-Entity Tenant

If Baobab later serves a group structure:

```text
Tenant
  │
  ├── Legal Entity A
  ├── Legal Entity B
  └── Legal Entity C
```

that arrangement SHALL be represented explicitly in the Control Plane.

This SHALL NOT be achieved merely by adding several groups to one IAM Organization.

---

# 45. Future Multi-Tenant Legal Entity

Similarly, if one legal entity operates:

```text
Tenant Retail
Tenant Wholesale
```

the separation SHALL be expressed through Control Plane tenancy and isolation configuration.

IAM remains an authentication layer.

---

# 46. Isolation Profiles

Tenant isolation SHALL remain governed through Control Plane isolation profiles and infrastructure/runtime architecture.

Keycloak organisation separation SHALL NOT be treated as sufficient tenant data isolation.

For example:

```text
Organization A
Organization B
```

inside one realm does not provide database isolation between Trade or ERP data by itself.

---

# 47. Engine Instance Resolution

Tenant and market context may ultimately resolve to different engine instances.

Conceptually:

```text
Identity
   │
   ▼
Tenant
   │
   ▼
Market
   │
   ▼
CapabilityBinding
   │
   ▼
EngineInstance
```

This remains a Control Plane responsibility.

IAM SHALL not embed engine-instance routing logic.

---

# 48. Capability Binding

A valid tenant relationship does not automatically imply access to every engine.

Example:

```text
Tenant A
   │
   ├── CMS enabled
   ├── Trade enabled
   └── ERP disabled
```

The Control Plane's CapabilityBinding model SHALL remain authoritative.

---

# 49. Naming Strategy

IAM and canonical identifiers SHALL not rely solely on human-readable organisation names.

Human names may change:

```text
Acme Ltd
   ↓
Acme Holdings Ltd
```

Mappings must remain intact.

Opaque immutable IDs SHALL anchor relationships.

---

# 50. Slug Usage

Human-readable slugs MAY be used for:

- URLs;
- realm login hints;
- organisation discovery;
- administrative display.

They SHALL NOT replace durable IDs.

Example:

```text
slug: acme-hotels
```

is presentation metadata.

---

# 51. Organization Domains

Verified email domains MAY assist organisation discovery or B2B login.

Example:

```text
acmehotels.com
```

may route a user toward the Acme IAM Organization.

Domain ownership SHALL not automatically grant business membership.

---

# 52. Domain-Based Auto-Joining

Automatic organisation membership solely because:

```text
email ends with @company.com
```

SHOULD be avoided unless explicitly approved through a controlled enterprise policy.

Email-domain possession alone may be insufficient proof of business authority.

---

# 53. Invitations

IAM Organization invitations MAY be used to establish identity-side affiliation.

Typical flow:

```text
Organization administrator
        │
        ▼
invite email
        │
        ▼
recipient authenticates
        │
        ▼
IAM Organization membership
        │
        ▼
canonical/domain membership workflow
```

The final business relationship SHALL be explicitly established in the authoritative domain.

---

# 54. Supplier Invitations

Supplier representatives may be invited after supplier approval.

Example:

```text
Supplier approved
      │
      ▼
authorized supplier admin
      │
      ▼
invite representative
      │
      ▼
IAM identity
      │
      ▼
supplier membership
```

The invitation itself SHALL not re-run or bypass supplier vetting.

---

# 55. Buyer Invitations

Zuribeans buyer administrators may invite other representatives.

Trade SHALL remain authoritative for their buyer-specific roles.

Example:

```text
IAM:
member of Acme Hotels

Trade:
buyer_role = procurement_manager
```

---

# 56. Organization Deactivation

Deactivating an IAM Organization SHALL not automatically erase the underlying Canonical Entity or legal entity.

The relevant domain relationships SHALL enter appropriate lifecycle states.

This distinction preserves business history and audit trails.

---

# 57. Tenant Suspension

Tenant suspension SHALL be controlled by `baobab-cp`.

It SHALL take precedence over active IAM authentication.

Example:

```text
User authenticates successfully
        │
        ▼
Tenant = SUSPENDED
        │
        ▼
access denied
```

---

# 58. Legal Entity Closure

Legal entity closure MAY trigger tenant and domain lifecycle changes, but it SHALL not automatically destroy historical identities or audit records.

Lifecycle propagation SHALL be explicit and auditable.

---

# 59. Digital Estate Disablement

A Digital Estate may be disabled without disabling:

- the tenant;
- the legal entity;
- IAM identities;
- other Digital Estates.

Example:

```text
Tenant
  │
  ├── Estate A ACTIVE
  └── Estate B DISABLED
```

This is one reason Digital Estate and Tenant remain separate.

---

# 60. Market Disablement

Similarly:

```text
Tenant
  │
  ├── ZA ACTIVE
  └── UG DISABLED
```

may be valid.

The user's global identity remains intact.

---

# 61. Context Resolution Object

A resolved platform context SHOULD carry distinct identifiers rather than one overloaded organization field.

Conceptually:

```json
{
  "canonical_identity_id": "...",
  "tenant_id": "...",
  "legal_entity_id": "...",
  "digital_estate_id": "...",
  "market_id": "...",
  "capability_id": "...",
  "engine_instance_id": "..."
}
```

Fields SHALL be included only where meaningful and defined by Shared contracts.

---

# 62. Do Not Overload `organization_id`

Baobab SHALL avoid a generic:

```text
organization_id
```

that ambiguously means:

- Keycloak Organization;
- buyer organisation;
- supplier organisation;
- legal entity;
- tenant.

Identifiers SHOULD be semantically explicit.

---

# 63. Namespace Discipline

Examples of clearer naming include:

```text
iam_organization_id
canonical_entity_id
legal_entity_id
tenant_id
buyer_organization_id
supplier_organization_id
digital_estate_id
market_id
```

Where existing canonical contracts have established naming, those conventions SHALL prevail.

---

# 64. Mapping Table

A conceptual mapping structure may include:

| Source concept | Target concept | Relationship |
|---|---|---|
| Keycloak Organization | CanonicalEntity | identity association |
| CanonicalEntity | LegalEntity | legal/business relationship |
| LegalEntity | Tenant | tenancy relationship |
| Tenant | DigitalEstate | platform product relationship |
| Tenant | Market | market enablement |
| CanonicalEntity | Trade organization | engine mapping |
| CanonicalEntity | ERP Business Partner | engine mapping |

Exact persistence SHALL reuse existing CP mapping primitives.

---

# 65. Many-to-Many Relationships

The implementation SHALL not assume all mappings are permanently 1:1.

Potential future relationships include:

```text
CanonicalEntity ↔ Tenant
Tenant ↔ LegalEntity
Tenant ↔ DigitalEstate
Tenant ↔ Market
CanonicalIdentity ↔ Organization
```

The schema SHOULD model cardinality deliberately.

---

# 66. Cross-Market Legal Entity

A single legal entity may operate in multiple markets.

Example:

```text
Legal Entity A
      │
      ▼
Tenant A
   ┌──┴───┐
   ▼      ▼
  ZA      UG
```

Market identity SHALL remain independent from legal identity.

---

# 67. Local Subsidiary Model

Baobab SHALL also support a pattern such as:

```text
Nabhold Group
     │
     ├── South African Legal Entity
     │          │
     │          ▼
     │       Tenant ZA
     │
     └── Ugandan Legal Entity
                │
                ▼
             Tenant UG
```

if operating structure requires it.

This can coexist with one IAM realm.

---

# 68. B2B Customer as Tenant

Most Zuribeans B2B buyers SHOULD NOT automatically become full Baobab Tenants merely because they are buyer organisations.

Typical model:

```text
Zuribeans Tenant
       │
       ▼
Trade
       │
       ├── Buyer Organization A
       ├── Buyer Organization B
       └── Buyer Organization C
```

This distinction prevents needless platform-tenancy proliferation.

---

# 69. Supplier as Tenant

Likewise, ordinary suppliers SHOULD not automatically become Baobab Tenants.

A supplier may instead be:

```text
CanonicalEntity
       +
Supplier relationship
       +
IAM Organization
```

A supplier becomes a Tenant only if it actually consumes isolated Baobab platform capabilities in a tenant capacity.

---

# 70. Tenant Creation Is Governance Action

Creating an IAM Organization SHALL not implicitly create a Tenant.

Tenant creation SHALL remain an explicit governance operation through the Control Plane.

This may require:

- legal/entity association;
- isolation profile;
- capability bindings;
- markets;
- engine instance configuration;
- lifecycle status.

---

# 71. IAM Organization Creation Is Identity Action

Creating an IAM Organization MAY occur as part of:

- buyer onboarding;
- supplier onboarding;
- enterprise federation;
- corporate administration.

It SHALL not automatically configure platform infrastructure.

---

# 72. Sequence — B2B Buyer Registration

```text
Buyer Company
     │
     ▼
Buyer application
     │
     ▼
business validation
     │
     ▼
CanonicalEntity
     │
     ├────────► Trade Organization
     │
     └────────► IAM Organization
                    │
                    ▼
             invite representatives
```

No new Baobab Tenant is necessarily created.

---

# 73. Sequence — New SaaS Tenant

```text
Customer contract
      │
      ▼
Legal Entity / Canonical Entity
      │
      ▼
Create Baobab Tenant
      │
      ├── isolation profile
      ├── markets
      ├── capabilities
      ├── engine instances
      └── Digital Estates
      │
      ▼
Optional IAM Organization
      │
      ▼
invite tenant users
```

Here a Tenant is appropriate because the customer consumes Baobab platform capabilities as an isolated customer.

---

# 74. Sequence — Thamani Consumer

```text
Consumer registers
      │
      ▼
IAM identity
      │
      ▼
CanonicalIdentity
      │
      ▼
Trade Customer
```

No:

```text
Tenant
IAM Organization
Legal Entity
```

needs to be created merely for ordinary consumer registration.

---

# 75. Rejected Alternative — Realm per Tenant

### Advantages

- strong apparent isolation;
- straightforward mental mapping.

### Disadvantages

- identity duplication;
- client duplication;
- administration explosion;
- difficult cross-tenant workforce access;
- poor SSO;
- difficult upgrades;
- policy fragmentation.

### Decision

Rejected as default.

---

# 76. Rejected Alternative — IAM Organization Equals Tenant

### Advantages

Simple mapping.

### Disadvantages

- conflates authentication and platform isolation;
- buyer organisations accidentally become tenants;
- supplier organisations accidentally become tenants;
- poor future SaaS flexibility;
- difficult legal-entity modelling.

### Decision

Rejected.

---

# 77. Rejected Alternative — Legal Entity Equals Tenant by Definition

### Advantages

Simple current model.

### Disadvantages

- permanently restricts tenancy design;
- fails future multi-entity tenancy;
- fails possible multi-tenant product isolation within one entity.

### Decision

Rejected as a universal invariant.

Legal entity remains the **default** tenant boundary.

---

# 78. Rejected Alternative — Digital Estate Equals Tenant

### Advantages

Simple routing.

### Disadvantages

- prevents multiple estates per tenant;
- conflates UX product with data isolation;
- makes estate lifecycle affect tenancy unnecessarily.

### Decision

Rejected.

---

# 79. Rejected Alternative — Every Buyer/Supplier Is Tenant

### Advantages

Strong isolation.

### Disadvantages

- excessive tenancy proliferation;
- unnecessary CP configuration;
- operational overhead;
- incorrect business semantics.

### Decision

Rejected.

Buyers and suppliers remain business organisations unless they genuinely consume the platform as tenants.

---

# 80. Consequences

## Positive

This model provides:

- preserved Control Plane semantics;
- clean IAM integration;
- flexible multi-market operations;
- future SaaS readiness;
- accurate buyer/supplier modelling;
- reduced tenant proliferation;
- cross-estate identity reuse;
- legal-entity flexibility;
- clear authority boundaries.

## Negative

It requires:

- explicit mappings;
- more identifiers;
- more deliberate context resolution;
- careful administrative tooling;
- avoidance of shortcut assumptions.

These costs are accepted.

---

# 81. Implementation Ownership

| Concept | Primary owner |
|---|---|
| Realm | `baobab-iam` |
| IAM Organization | `baobab-iam` |
| Canonical Identity | `baobab-cp` |
| Canonical Entity | `baobab-cp` |
| Tenant | `baobab-cp` |
| Legal Entity relationship | `baobab-cp` / authoritative business source |
| Digital Estate | `baobab-cp` |
| Market | `baobab-cp` |
| CapabilityBinding | `baobab-cp` |
| Buyer organization | `baobab-trade` |
| Supplier organization/status | supplier authoritative domain |
| ERP organisation permissions | `baobab-erp` |

---

# 82. Shared Contract Requirements

`baobab-platform/shared` SHOULD eventually expose clearly versioned structures for:

```text
tenant
legal entity reference
canonical entity
organization membership
Digital Estate
market context
identity context
```

Contracts SHALL preserve semantic distinction.

---

# 83. Required Tests

Automated and integration tests SHALL cover at minimum:

### Semantic isolation

- IAM Organization does not create Tenant;
- Tenant does not create IAM Organization automatically;
- buyer organisation does not become Tenant;
- supplier organisation does not become Tenant.

### Context

- identity belongs to multiple organisations;
- identity belongs to multiple tenants;
- valid tenant/invalid market;
- valid estate/disabled tenant;
- active tenant/disabled estate;
- active tenant/missing capability.

### Mapping

- Keycloak Organization → CanonicalEntity;
- CanonicalEntity → Trade organization;
- CanonicalEntity → ERP reference;
- duplicate mapping conflicts.

### Security

- forged IAM organization ID;
- forged tenant ID;
- organization member requesting unrelated tenant;
- consumer attempting organisational context;
- buyer attempting supplier context.

---

# 84. Migration Requirement

Existing repository data SHALL be audited for fields that currently overload terms such as:

```text
organization
tenant
company
entity
business
estate
```

Before migration, each field SHALL be classified according to the semantic model established in this ADR.

Ambiguous naming SHOULD be corrected deliberately rather than preserved indefinitely.

---

# 85. Documentation Requirement

The repository SHALL maintain a terminology/glossary reference showing at minimum:

| Term | Meaning |
|---|---|
| Realm | IAM isolation namespace |
| IAM Organization | identity-side organisation |
| CanonicalEntity | cross-platform business entity |
| LegalEntity | legally recognised organisation |
| Tenant | Baobab isolation/consumption boundary |
| DigitalEstate | digital experience/product |
| Buyer Organization | commerce-side B2B buyer |
| Supplier Organization | sourcing/supplier entity |
| Market | geographic/commercial operating context |

This glossary SHOULD be referenced by all IAM integration documentation.

---

# 86. Architectural Invariants

The following become binding:

```text
Realm ≠ Tenant

IAM Organization ≠ Tenant

IAM Organization ≠ Legal Entity

IAM Organization ≠ Buyer Organization automatically

IAM Organization ≠ Supplier Organization automatically

Tenant ≠ Legal Entity by definition

Digital Estate ≠ Tenant

Digital Estate ≠ Market

Buyer Organization ≠ Tenant by default

Supplier Organization ≠ Tenant by default

Legal Entity = default tenant boundary, not universal identity

All cross-concept relationships require explicit mapping
```

---

# 87. Target Conceptual Model

```text
                          BAOBAB REALM
                              │
                   ┌──────────┴──────────┐
                   │                     │
                   ▼                     ▼
              Human Identity       IAM Organization
                   │                     │
                   ▼                     │
            CanonicalIdentity            │
                   │                     │
                   └─────────┬───────────┘
                             ▼
                       Membership
                             │
                             ▼
                      CanonicalEntity
                             │
             ┌───────────────┼────────────────┐
             │               │                │
             ▼               ▼                ▼
        Legal Entity    Buyer/Supplier     Other entity
             │          Organization
             │               │
             ▼               ▼
           Tenant       Domain Engines
             │
     ┌───────┼────────────┐
     ▼       ▼            ▼
   Market  Digital      Capability
           Estate       Binding
                          │
                          ▼
                     EngineInstance
```

No single concept in this model substitutes for all the others.

---

# 88. Decision Summary

Baobab SHALL preserve a deliberate separation between identity structures and business/platform structures.

The practical rule is:

```text
Keycloak Realm
     │
     └── authentication boundary

Keycloak Organization
     │
     └── identity-side organisation

CanonicalEntity
     │
     └── cross-platform business identity

LegalEntity
     │
     └── legal organisation

Tenant
     │
     └── isolation / platform consumption

DigitalEstate
     │
     └── digital product experience

Market
     │
     └── geographic/commercial context
```

Mappings among these concepts SHALL be explicit, canonical and auditable.

The governing principle is:

> **Baobab shall model business reality in the Control Plane and domain engines, and use IAM constructs for authentication—not distort business reality to fit the identity provider's data model.**