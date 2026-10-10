# ADR-0004: Canonical Identity and External Identity Mapping

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owner:** `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Baobab canonical identities, external identities, engine-native identities, subject resolution, linking, unlinking and identity lifecycle  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  

---

# 1. Context

ADR-0001 established Baobab IAM as the authentication authority.

ADR-0002 selected Keycloak as the initial identity provider.

ADR-0003 established that Keycloak identity, Control Plane context and domain-engine authorization are distinct trust layers.

The next problem is identity continuity.

Baobab will authenticate many kinds of actors through different mechanisms over time:

- Keycloak-local accounts;
- enterprise OIDC providers;
- SAML providers;
- future social/federated identities;
- workload clients;
- Medusa customer identities;
- iDempiere `AD_User` records;
- Payload CMS users;
- external buyer representatives;
- suppliers;
- consumers;
- employees;
- administrators;
- service accounts.

The platform must be able to answer:

```text
"Which Baobab identity does this external subject represent?"
```

without turning:

```text
Keycloak user ID
email address
Medusa customer ID
iDempiere AD_User ID
```

into the permanent identity of the whole platform.

A durable identity layer is therefore required between authentication providers and business engines.

---

# 2. Decision

Baobab SHALL establish a **Canonical Identity** model owned by `baobab-cp`.

External identity-provider subjects and engine-native identities SHALL map explicitly to the canonical identity.

The core relationship SHALL be:

```text
External Identity
      │
      ▼
Canonical Identity
      │
      ├────────► Membership
      ├────────► Tenant Context
      ├────────► Legal Entity Context
      └────────► External References
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Trade       ERP        CMS
```

A Baobab canonical identity SHALL remain stable even when:

- email changes;
- username changes;
- identity provider changes;
- a second identity provider is linked;
- an engine-native user ID changes;
- a person joins or leaves organisations;
- domain memberships are revoked.

---

# 3. Canonical Identity Definition

A Canonical Identity represents the durable Baobab identity of an actor.

Conceptually:

```text
CanonicalIdentity
-----------------
id
actor_type
status
created_at
updated_at
```

It SHALL NOT contain the complete user profile.

It SHALL NOT become a dumping ground for:

- commerce preferences;
- supplier records;
- ERP employee records;
- HR profiles;
- customer carts;
- business roles;
- addresses;
- tax details;
- financial information.

Its primary purpose is **identity continuity and canonical reference**.

---

# 4. Identity Versus Person

Baobab SHALL distinguish:

```text
Identity
```

from:

```text
Person
```

These concepts may often correspond one-to-one, but the architecture SHALL not make that assumption mandatory.

Examples:

```text
Human person
   │
   ▼
Canonical Identity
```

but also:

```text
Workload
   │
   ▼
Canonical Identity
```

and potentially:

```text
External service principal
   │
   ▼
Canonical Identity
```

This enables a single canonical identity abstraction to represent human and machine actors while retaining explicit actor types.

---

# 5. Canonical Identifier

The canonical identifier SHALL be:

- opaque;
- globally unique within Baobab;
- immutable;
- non-semantic;
- non-recycled.

It SHALL NOT encode:

```text
tenant
country
estate
role
business unit
email
provider
```

A canonical identifier SHOULD be generated using the platform's established identifier standard.

If `baobab-platform/shared` defines a UUID or UUIDv7 convention for canonical entities, Canonical Identity SHALL follow that convention.

No separate incompatible identity-ID standard should be invented.

---

# 6. External Identity Definition

An External Identity represents an identity asserted by an authentication provider.

Conceptually:

```text
ExternalIdentity
----------------
id
canonical_identity_id
issuer
subject
provider_type
status
created_at
last_seen_at
```

The durable provider key SHALL be:

```text
issuer + subject
```

not:

```text
email
username
display name
```

---

# 7. Provider Subject Uniqueness

The following invariant SHALL hold:

```text
UNIQUE(issuer, subject)
```

A given external provider subject SHALL resolve to at most one Canonical Identity.

This prevents the same external credential from representing two Baobab identities simultaneously.

---

# 8. Why Issuer + Subject

OIDC defines `sub` within the namespace of an issuer.

Therefore:

```text
sub = "12345"
```

alone is not globally meaningful.

The durable identity key SHALL be:

```text
https://identity.example/realms/baobab
+
12345
```

conceptually represented as:

```text
(iss, sub)
```

This rule applies regardless of whether the provider is Keycloak or a future federated identity provider.

---

# 9. Email Is Not an Identity Key

This mapping is prohibited:

```text
token.email
   │
   ▼
SELECT canonical_identity
WHERE email = token.email
```

Email may be:

- mutable;
- reassigned;
- mistyped;
- federated inconsistently;
- case-normalized differently;
- compromised.

Email SHALL be treated as an attribute.

It MAY assist controlled identity linking, but it SHALL never constitute sufficient linking evidence by itself.

---

# 10. Username Is Not an Identity Key

Username SHALL likewise remain an attribute.

This is prohibited:

```text
username == canonical identity
```

because usernames may change or differ between providers.

---

# 11. Identity Resolution Flow

The normal authentication resolution flow SHALL be:

```text
Authenticate
    │
    ▼
Validate OIDC token
    │
    ▼
Extract iss + sub
    │
    ▼
Find ExternalIdentity
    │
    ├──── found ─────► CanonicalIdentity
    │
    └──── absent ────► controlled provisioning flow
```

No business-domain operation SHALL proceed merely because `iss + sub` exists.

The resulting Canonical Identity must then pass lifecycle and context resolution.

---

# 12. First Authentication

On first authentication, the system MAY automatically create a canonical identity where policy permits.

Target flow:

```text
First valid authentication
        │
        ▼
No external mapping exists
        │
        ▼
Determine provisioning policy
   ┌────┴─────────┐
   ▼              ▼
Allowed         Not allowed
   │              │
   ▼              ▼
Create          deny /
identity        require invitation
   │
   ▼
ExternalIdentity
   │
   ▼
CanonicalIdentity
```

Different actor types MAY use different provisioning policies.

---

# 13. Provisioning Policy by Actor

Automatic provisioning SHOULD not be universal.

For example:

| Actor | Potential provisioning policy |
|---|---|
| Thamani consumer | self-service allowed |
| Zuribeans buyer | invitation/application policy |
| Supplier representative | application/invitation policy |
| Workforce user | controlled provisioning |
| Platform administrator | explicitly provisioned |
| Workload | infrastructure/IAM provisioning |

The exact rules SHALL be defined by later domain-specific ADRs.

---

# 14. Multiple External Identities

One Canonical Identity MAY have multiple External Identities.

Example:

```text
                  CanonicalIdentity
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
      Baobab IAM      Microsoft      Google
        account         OIDC          OIDC
```

This enables federation and provider migration without duplicating the person.

---

# 15. Identity Linking

Linking a second identity provider SHALL be an explicit security-sensitive action.

The platform SHALL require sufficient evidence that both identities belong to the same actor.

A valid linking flow may require:

```text
Existing authenticated session
        +
authentication with new provider
        +
policy/risk checks
```

The system SHALL NOT link identities solely because:

```text
email A == email B
```

---

# 16. Identity-Linking Flow

```text
Existing Canonical Identity
         │
         ▼
Authenticate existing identity
         │
         ▼
Request new identity link
         │
         ▼
Authenticate with new provider
         │
         ▼
Verify link policy
         │
     ┌───┴────┐
     ▼        ▼
  approve    deny
     │
     ▼
ExternalIdentity
     │
     ▼
same CanonicalIdentity
```

Every successful link SHALL be auditable.

---

# 17. Linking Risks

Identity linking is an account-takeover boundary.

Threats include:

- email collision;
- malicious federation;
- compromised external account;
- session hijacking;
- mistaken administrative merge;
- provider account reassignment.

Therefore identity-link operations SHALL receive stronger scrutiny than ordinary profile updates.

---

# 18. Identity Unlinking

External identities MAY be unlinked where permitted.

Unlinking SHALL verify that the actor will not be left without a valid authentication path unless the operation is explicitly administrative.

Example:

```text
Canonical Identity
   │
   ├── Keycloak password identity
   └── Google identity
```

removing Google may be allowed.

But:

```text
Canonical Identity
   │
   └── Google identity
```

removing Google may require:

- establishing another credential first;
- administrative recovery;
- explicit account disablement.

---

# 19. Identity Merge

Identity merge SHALL NOT be a routine automatic operation.

A merge may be required when two Canonical Identities are discovered to represent the same real actor.

This is dangerous because each identity may already have:

- tenant memberships;
- buyer memberships;
- supplier relationships;
- customer records;
- ERP mappings;
- audit history.

Merges SHALL therefore require an explicit controlled process.

---

# 20. Merge Model

Conceptually:

```text
CanonicalIdentity A
       │
       ├── memberships
       └── external identities

CanonicalIdentity B
       │
       ├── memberships
       └── external identities

          │
          ▼
   controlled merge
          │
          ▼
CanonicalIdentity A
          │
          ├── transferred mappings
          └── alias/tombstone for B
```

One identity SHALL remain canonical.

The retired identity SHALL not simply disappear.

---

# 21. Identity Merge Auditability

Merge operations SHALL preserve:

```text
source identity
target identity
actor performing merge
reason
timestamp
affected memberships
affected mappings
affected external identities
```

The retired canonical ID SHOULD remain resolvable through historical audit records.

---

# 22. Identity Split

Identity split is the reverse failure mode: one Canonical Identity was incorrectly linked to identities belonging to different people.

The platform SHOULD maintain enough provenance to permit controlled remediation.

Because identity splitting can affect business ownership and audit records, it SHALL require security/administrative handling rather than ordinary self-service.

---

# 23. Engine-Native Identities

Domain systems may maintain local identities.

Examples:

```text
Medusa customer
Medusa admin actor
iDempiere AD_User
Payload user
```

These SHALL be represented as mappings rather than canonical identities.

---

# 24. External Reference Model

Baobab SHALL use the existing canonical external-reference/mapping architecture where appropriate.

Conceptually:

```text
CanonicalIdentity
      │
      ▼
ExternalReference
      │
      ├── engine = baobab-trade
      │   external_type = customer
      │   external_id = ...
      │
      ├── engine = baobab-erp
      │   external_type = AD_User
      │   external_id = ...
      │
      └── engine = baobab-cms
          external_type = user
          external_id = ...
```

Do not create parallel incompatible mapping infrastructure if the Control Plane's existing `ExternalReference` / `Mapping` model can represent identity mappings safely.

---

# 25. Trade Mapping

For Medusa:

```text
CanonicalIdentity
       │
       ▼
ExternalReference
       │
       ▼
Medusa Actor / Customer
```

Medusa customer IDs SHALL remain Trade-local identifiers.

They SHALL NOT become global identity keys.

---

# 26. ERP Mapping

For iDempiere:

```text
CanonicalIdentity
       │
       ▼
ExternalReference
       │
       ▼
AD_User
```

`AD_User_ID` SHALL remain an ERP-local identifier.

ERP permissions SHALL remain associated with iDempiere's own role model.

---

# 27. CMS Mapping

Payload CMS users MAY likewise map as:

```text
CanonicalIdentity
       │
       ▼
ExternalReference
       │
       ▼
Payload User
```

CMS editorial roles remain CMS domain state.

---

# 28. Multiple Engine Mappings

One canonical identity may have multiple engine mappings.

Example:

```text
Jane
CanonicalIdentity CI-123
        │
        ├── Medusa customer C-100
        ├── iDempiere AD_User 20013
        └── Payload user P-77
```

This is expected.

It does not mean each engine shares user tables.

---

# 29. Mapping Scope

Engine mappings SHALL include sufficient scope to avoid collisions.

A mapping may need to distinguish:

```text
engine
engine instance
external type
external ID
tenant/context
```

depending on the external system's identifier semantics.

The exact uniqueness constraints SHALL align with the Control Plane mapping model.

---

# 30. No Cross-Engine Foreign Keys

Domain databases SHALL NOT reference Canonical Identity by creating cross-database relational foreign keys.

Instead, they MAY persist the canonical identifier as an external logical reference where contractually appropriate.

Example:

```text
Trade DB:
canonical_identity_id = "..."
```

may be acceptable as an opaque logical reference.

But:

```text
FOREIGN KEY (...) REFERENCES baobab_cp.identity(...)
```

is prohibited.

---

# 31. Identity Status

Canonical Identity SHALL have a lifecycle state distinct from IAM credential state.

At minimum conceptual states may include:

```text
ACTIVE
SUSPENDED
DISABLED
ARCHIVED
```

The exact lifecycle will be refined in ADR-0016.

---

# 32. External Identity Status

External identities MAY independently have states such as:

```text
ACTIVE
UNLINKED
DISABLED
REVOKED
```

A canonical identity may remain active while one external identity is revoked.

---

# 33. Example

```text
Canonical Identity: ACTIVE

External Identity:
Google: REVOKED

External Identity:
Baobab IAM password/passkey: ACTIVE
```

The person may continue authenticating through the remaining valid identity.

---

# 34. Identity Deletion

Canonical identities SHOULD generally not be hard-deleted if they are referenced by:

- audit records;
- ERP activity;
- orders;
- supplier decisions;
- financial records;
- regulatory records.

Instead, lifecycle status and privacy-preserving data handling SHALL be used.

This preserves referential auditability.

---

# 35. Privacy and Pseudonymisation

Where personal information must be deleted or minimized, the canonical identifier MAY remain while PII is removed or anonymized where legally and operationally appropriate.

Example:

```text
CanonicalIdentity CI-123
status = ARCHIVED

email = removed
name = removed
phone = removed
```

while:

```text
Order 123 created by CI-123
```

remains auditable.

Legal retention rules SHALL be handled separately from this architectural decision.

---

# 36. Identity Profile Ownership

Canonical Identity SHALL not necessarily own the complete personal profile.

Profile data may be split by purpose:

```text
IAM
 └── authentication profile

Trade
 └── customer profile

ERP
 └── employee/business-partner profile

Supplier domain
 └── supplier representative profile
```

The platform SHALL avoid unnecessary duplication while also avoiding one giant global person record.

---

# 37. Minimal Canonical Profile

If `baobab-cp` stores identity attributes beyond the canonical ID, they SHOULD be minimal.

Potential fields:

```text
display_name
preferred_name
status
actor_type
```

Where attributes are not required for platform governance, they SHOULD remain in their authoritative domain.

---

# 38. Identity Resolution API

`baobab-cp` SHOULD expose an explicit internal identity resolution capability.

Conceptually:

```text
POST /internal/identity/resolve
```

Input:

```json
{
  "issuer": "https://identity.baobab.example/realms/baobab",
  "subject": "provider-subject"
}
```

Output:

```json
{
  "canonical_identity_id": "..."
}
```

Exact API shape SHALL follow established Baobab API conventions and Shared contracts.

---

# 39. Prefer Token-Derived Resolution

Where practical, callers SHOULD NOT be allowed to submit arbitrary issuer/subject pairs.

The preferred pattern is:

```text
validated caller token
      │
      ▼
extract verified iss + sub
      │
      ▼
resolve identity
```

This reduces identity-spoofing risk.

Explicit subject-resolution APIs should be limited to privileged internal use cases.

---

# 40. Identity Context Resolution

Identity resolution and platform-context resolution are related but distinct.

```text
Identity Resolution:
iss + sub
    │
    ▼
CanonicalIdentity
```

Then:

```text
Context Resolution:
CanonicalIdentity
      +
requested tenant/entity/market
      │
      ▼
authorized Baobab Context
```

Implementations SHOULD preserve this conceptual separation.

---

# 41. Membership Is Not Identity

This distinction SHALL remain explicit:

```text
CanonicalIdentity
       ≠
Membership
```

Example:

```text
CanonicalIdentity
      │
      ├── Zuribeans buyer membership
      ├── Thamani customer relationship
      └── Nabhold employee membership
```

Revoking one membership does not inherently delete the identity.

---

# 42. Organisation Is Not Identity

Likewise:

```text
CanonicalIdentity
       ≠
Organization
```

Identity-to-organisation association SHALL be represented through membership or other explicit relationships.

---

# 43. Canonical Identity and Tenant

A canonical identity SHALL not contain a single permanent:

```text
tenant_id
```

because one actor may belong to multiple tenants or contexts.

This is prohibited as a universal model:

```text
CanonicalIdentity
--------------
id
tenant_id
```

Prefer:

```text
CanonicalIdentity
       │
       ▼
Membership
       │
       ▼
Tenant
```

---

# 44. Identity and Digital Estate

Likewise, identity SHALL not be permanently owned by a Digital Estate.

A Thamani consumer may later interact with another estate using the same canonical identity if business rules permit.

Digital Estate association SHALL therefore be contextual rather than identity-defining.

---

# 45. Identity and Market

Market SHALL not be embedded into the canonical identity key.

A person may operate in:

```text
Uganda
South Africa
future markets
```

depending on memberships and domain relationships.

---

# 46. Identity and Legal Entity

An identity may have relationships with multiple legal entities.

For example:

```text
Person
  │
  ├── employee of Nabhold
  ├── buyer representative for Company A
  └── supplier representative for Company B
```

Therefore legal-entity membership SHALL remain relational.

---

# 47. Workload Canonical Identity

Workloads SHALL also receive durable canonical identities where the Control Plane identity model requires them.

Example:

```text
Keycloak client
    azp = baobab-trade
         │
         ▼
External workload identity
         │
         ▼
Canonical workload identity
         │
         ▼
capability/context policy
```

This supports:

- service auditability;
- service lifecycle;
- credential rotation;
- replacement of IAM provider implementation.

---

# 48. Human and Workload Namespace

Human and workload identities MAY share one canonical identifier namespace.

Actor type SHALL distinguish semantics.

Example:

```text
CI-001   human
CI-002   workload
CI-003   external human
```

This is preferable to multiple unrelated identifier formats unless existing Shared conventions dictate otherwise.

---

# 49. Service Account Sharing

One workload identity SHALL represent one independently controlled workload boundary.

Do not map:

```text
Trade + ERP + Pulse
```

to the same canonical workload identity.

Each needs separate revocation and audit.

---

# 50. Identity Event Model

Identity operations SHALL emit canonical events where appropriate.

Examples:

```text
identity.created.v1
identity.external-linked.v1
identity.external-unlinked.v1
identity.suspended.v1
identity.disabled.v1
identity.reactivated.v1
identity.merged.v1
```

Events SHALL use the existing Baobab canonical envelope.

---

# 51. Event Payload Discipline

Identity events SHALL contain canonical identifiers and necessary metadata.

They SHALL NOT contain:

```text
passwords
access tokens
refresh tokens
MFA secrets
private keys
recovery codes
```

PII SHALL be minimized.

---

# 52. Audit Trail

Identity mapping changes SHALL be auditable.

At minimum:

```text
who
what identity
which external provider
operation
reason
time
result
correlation ID
```

Administrative merge/link/unlink actions SHALL receive especially strong audit coverage.

---

# 53. Concurrency

Identity provisioning SHALL be safe under concurrent authentication.

Example:

Two simultaneous first-login requests for the same:

```text
(issuer, subject)
```

must not create:

```text
CanonicalIdentity A
CanonicalIdentity B
```

Database uniqueness constraints and transaction handling SHALL prevent this.

---

# 54. Required Database Invariants

At minimum enforce equivalent constraints for:

```text
CanonicalIdentity.id
    UNIQUE

ExternalIdentity(issuer, subject)
    UNIQUE

ExternalIdentity.id
    UNIQUE
```

Mapping-level uniqueness SHALL prevent one engine-native external identity from mapping ambiguously to multiple canonical identities unless a documented domain requirement explicitly permits it.

---

# 55. Idempotency

Identity creation and mapping APIs SHALL be idempotent where appropriate.

Repeated processing of:

```text
same valid external subject
```

SHALL resolve to the same canonical identity.

---

# 56. Identity Provisioning Race

Target implementation:

```text
resolve (iss, sub)
      │
      ├── exists ─────► return canonical identity
      │
      └── missing
             │
             ▼
       transactional create
             │
             ├── success
             │     ▼
             │  return identity
             │
             └── uniqueness conflict
                    │
                    ▼
                 re-read
                    │
                    ▼
              return identity
```

This pattern avoids duplicate creation under concurrency.

---

# 57. Migration from Existing Engine Users

Existing engine-native identities SHALL not be discarded blindly.

Migration SHALL:

1. inventory identities;
2. classify authoritative sources;
3. identify duplicates;
4. create canonical identities;
5. map engine-local identities;
6. validate business relationships;
7. avoid automatic merging solely by email;
8. retain migration provenance.

---

# 58. Legacy Medusa Users

If Trade already contains customer/admin identities, migration SHOULD create mappings such as:

```text
legacy Medusa customer
       │
       ▼
CanonicalIdentity
       │
       ▼
new IAM external identity
```

after controlled identity verification.

Do not simply assume identical email addresses are the same person.

---

# 59. Legacy iDempiere Users

Existing iDempiere `AD_User` records may represent:

- employees;
- business-partner contacts;
- system users;
- integration users.

Migration SHALL classify them before identity mapping.

Not every `AD_User` necessarily becomes an interactive Baobab IAM human.

---

# 60. Legacy CMS Users

Payload CMS users SHOULD likewise be assessed for:

```text
human workforce
service account
editor
administrator
```

before canonical mapping.

---

# 61. Duplicate Detection

Potential duplicates MAY be flagged using signals such as:

```text
verified email
verified phone
existing employee number
business relationship
manual administrator review
```

But automatic merge SHALL require stronger evidence than attribute similarity.

---

# 62. Account Enumeration

Identity resolution endpoints SHALL not expose whether arbitrary external identities exist to untrusted callers.

Responses SHALL avoid enabling account enumeration.

---

# 63. Administrative Search

Privileged administrators MAY search identities using:

- canonical ID;
- verified email;
- external provider;
- organisation context;
- engine mapping.

Such search SHALL be audited and least-privileged.

---

# 64. API Authorization

Identity-management operations SHALL distinguish at minimum:

```text
self-service
organisation administration
helpdesk
security administration
platform administration
workload administration
```

No generic `identity:admin` permission should casually grant every identity-management capability if more specific separation is feasible.

---

# 65. Self-Service Permissions

Users MAY be allowed to:

- view their external identities;
- link approved providers;
- unlink approved providers;
- update permitted authentication attributes.

They SHALL NOT self-modify:

```text
canonical identity ID
actor type
privileged status
tenant membership
ERP roles
supplier approval
```

---

# 66. Organisation Administrator Limits

An organisation administrator MAY manage identity relationships within their organisation where the business model permits.

They SHALL NOT gain authority over:

- global canonical identity state;
- unrelated organisations;
- platform roles;
- IAM platform administration.

---

# 67. Support/Helpdesk Boundary

Helpdesk functions may include:

- account recovery assistance;
- resend verification;
- approved MFA reset processes.

Helpdesk SHALL not automatically receive:

- tenant-management authority;
- ERP authorization;
- commerce authority;
- IAM system-admin rights.

---

# 68. Rejected Alternative — Keycloak User ID as Canonical Identity

### Advantages

- simple;
- fewer tables;
- easy lookup.

### Disadvantages

- strong vendor coupling;
- difficult provider replacement;
- difficult federation;
- business data tied to IdP internals;
- poor multi-provider identity support.

### Decision

Rejected.

---

# 69. Rejected Alternative — Email as Canonical Identity

### Advantages

- human-readable;
- readily available.

### Disadvantages

- mutable;
- reusable;
- provider-dependent;
- takeover risk;
- weak federation semantics.

### Decision

Rejected.

---

# 70. Rejected Alternative — Engine User as Canonical Identity

For example:

```text
Medusa customer = Baobab identity
```

or:

```text
AD_User = Baobab identity
```

### Advantages

Local simplicity.

### Disadvantages

- engine coupling;
- conflicting identifiers;
- difficult cross-engine identity;
- impossible clean provider replacement.

### Decision

Rejected.

---

# 71. Rejected Alternative — Separate Canonical Identity per Tenant

Under this model, the same human would receive separate global identities for each tenant.

### Advantages

Strong apparent separation.

### Disadvantages

- duplicate humans;
- poor SSO;
- difficult executive/workforce access;
- complicated supplier/buyer cross-relationships;
- poor user experience.

### Decision

Rejected as the default.

Memberships provide tenant separation without duplicating the canonical actor.

---

# 72. Rejected Alternative — Automatically Merge by Verified Email

Even verified email is insufficient as the only merge criterion.

Federated providers may assert the same address under different security and lifecycle conditions.

### Decision

Rejected.

Identity linking SHALL require explicit secure linking or governed administrative reconciliation.

---

# 73. Consequences

## Positive

The decision provides:

- stable identity across providers;
- Keycloak portability;
- multi-provider federation;
- clean engine mappings;
- multi-context users;
- safer migrations;
- better auditability;
- reduced email coupling;
- clean workload identity mapping.

## Negative

The platform gains:

- canonical identity persistence;
- mapping tables;
- linking/merge complexity;
- reconciliation requirements;
- additional lifecycle logic.

These costs are accepted because identity continuity is a foundational platform concern.

---

# 74. Implementation Ownership

Responsibility SHALL be divided as follows:

| Concern | Owner |
|---|---|
| Credential/authentication subject | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| External identity mapping contract | `shared` |
| Membership/context | `baobab-cp` |
| Trade user mapping | `baobab-trade` + CP mapping |
| ERP user mapping | `baobab-erp` + CP mapping |
| CMS user mapping | `baobab-cms` + CP mapping |
| Identity events | Shared contract + appropriate producer |

---

# 75. Suggested Data Model

Subject to alignment with existing Control Plane conventions:

```text
CanonicalIdentity
────────────────────────────
id
actor_type
status
created_at
updated_at


ExternalIdentity
────────────────────────────
id
canonical_identity_id
issuer
subject
provider_type
status
created_at
last_seen_at


ExternalReference
────────────────────────────
canonical_identity_id
engine_instance_id
external_type
external_id
scope
created_at
```

Do not implement duplicate concepts if existing CP entities already fulfil these roles.

---

# 76. Target Resolution Architecture

```text
               IDENTITY PROVIDERS

        ┌─────────┬─────────┬──────────┐
        │         │         │          │
        ▼         ▼         ▼          ▼
    Keycloak   Azure AD   Google   Future IdP
        │         │         │          │
        └─────────┴────┬────┴──────────┘
                       │
                    iss + sub
                       │
                       ▼
              ┌──────────────────┐
              │ ExternalIdentity │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ CanonicalIdentity│
              └────────┬─────────┘
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
  Membership      ExternalReference    Audit
       │               │
       ▼          ┌─────┼──────┐
 Tenant/Entity    ▼     ▼      ▼
                Trade  ERP    CMS
```

---

# 77. Required Tests

At minimum automate:

### Identity resolution

- known `(iss, sub)`;
- unknown `(iss, sub)`;
- same `sub`, different issuer;
- same issuer, different `sub`;
- concurrent first-login provisioning.

### Linking

- valid linking;
- failed second authentication;
- duplicate external subject;
- same email but different subject;
- unlink with alternative credential;
- unlink final credential denied where required.

### Lifecycle

- active identity;
- disabled canonical identity;
- revoked external identity;
- active identity with revoked membership.

### Engine mapping

- Medusa mapping;
- iDempiere mapping;
- duplicate external ID;
- wrong engine instance;
- mapping lookup.

### Security

- arbitrary subject spoofing;
- untrusted email merge;
- unauthorized link;
- unauthorized unlink;
- unauthorized merge;
- enumeration attempt.

---

# 78. Migration Verification

Before migrating existing identities, produce a reconciliation report containing:

```text
source system
source identity count
candidate canonical identities
duplicate candidates
unresolved identities
service accounts
human accounts
disabled accounts
mapping conflicts
```

No bulk migration should proceed while ambiguous duplicate identities are silently auto-merged.

---

# 79. Architectural Invariants

The following become binding:

```text
Canonical Identity ≠ Keycloak User

Canonical Identity ≠ Email

Canonical Identity ≠ Username

Canonical Identity ≠ Tenant Membership

Canonical Identity ≠ Medusa Customer

Canonical Identity ≠ iDempiere AD_User

Canonical Identity ≠ Payload User

One Canonical Identity may have many External Identities

One Canonical Identity may have many Engine References

(issuer, subject) maps to at most one Canonical Identity

Email equality does not prove identity equality
```

---

# 80. Follow-On Decisions

This ADR deliberately does not fully define:

- realm/tenant semantics already addressed separately;
- exact JWT profile;
- authorization scopes;
- workload credential policy;
- B2B membership roles;
- B2C account lifecycle;
- supplier approval;
- MFA/passkeys;
- identity deprovisioning retention.

The next decision is:

```text
ADR-0005
Realm, Organization, Tenant and Legal-Entity Model
```

---

# 81. Decision Summary

Baobab SHALL introduce a stable canonical identity layer between identity providers and business engines.

The durable relationship is:

```text
Authentication Provider
        │
      iss+sub
        │
        ▼
External Identity
        │
        ▼
Canonical Identity
        │
        ├── Memberships
        ├── Tenant Context
        ├── Legal Entity Context
        └── Engine References
```

External identity-provider identifiers remain external identifiers.

Engine-native IDs remain engine-native IDs.

Email remains an attribute.

Tenant and organisation relationships remain explicit relationships.

The central design principle is:

> **A Baobab identity must outlive any individual identity provider, engine, email address, tenant relationship or Digital Estate.**