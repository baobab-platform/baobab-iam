# ADR-0002: Keycloak as the Baobab Identity Provider

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Scope:** Baobab Platform Identity Provider  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:** ADR-0001 — Baobab Identity and Access Management Architecture

---

# 1. Context

ADR-0001 established a dedicated Baobab Identity and Access Management capability and defined the fundamental authority model:

> Baobab IAM proves identity.  
> Baobab Control Plane determines canonical platform context and entitlement.  
> Domain engines enforce business-domain authorization.

The next architectural decision is the technology used to provide the identity-provider capabilities required by `baobab-platform/baobab-iam`.

The selected identity platform must support a heterogeneous ecosystem composed of:

- Go services;
- Node.js/MedusaJS services;
- Java/iDempiere services;
- Payload CMS;
- Haystack-based intelligence services;
- browser applications;
- server-side Digital Estate applications;
- internal workforce applications;
- machine-to-machine clients;
- external B2B organisations;
- B2C consumers;
- suppliers;
- future tenants and Digital Estates.

The platform therefore requires standards-based support for:

- OpenID Connect;
- OAuth;
- service/workload authentication;
- SSO;
- MFA;
- WebAuthn/passkeys;
- recovery;
- federation;
- B2B organisational identity;
- sessions;
- administrative delegation;
- signing-key management;
- token issuance;
- user lifecycle;
- operational auditing.

Baobab must obtain these capabilities without turning the Control Plane into a bespoke authentication server or tying canonical Baobab identity permanently to a vendor-specific data model.

---

# 2. Decision

NABHOLD SHALL adopt **Keycloak** as the initial identity provider and authentication runtime for:

```text id="8dkeex"
baobab-platform/baobab-iam
```

The repository SHALL package and operate Keycloak through:

```text id="zbryg9"
Pinned upstream Keycloak
        +
Baobab realm configuration
        +
Baobab clients/scopes
        +
Baobab authentication policies
        +
Minimal extensions where unavoidable
        +
Baobab themes
        +
Provisioning automation
        +
Contract and integration tests
```

Baobab SHALL NOT maintain a general-purpose fork of Keycloak.

The architectural relationship is:

```text id="a71ehd"
               ┌──────────────────────┐
               │      Keycloak        │
               │     Baobab IAM       │
               └──────────┬───────────┘
                          │
                     OIDC / OAuth
                          │
                          ▼
               ┌──────────────────────┐
               │      baobab-cp       │
               │ Canonical Identity   │
               │ Context / Policy     │
               └──────────┬───────────┘
                          │
                    Domain context
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
       Trade             ERP             CMS
```

Keycloak is the authentication authority.

Keycloak is not the canonical Baobab identity model.

---

# 3. Selected Platform Baseline

At the time of this ADR, current Keycloak documentation identifies the 26.7.x line, with the current Server Administration Guide reporting version 26.7.3. The Baobab implementation SHALL pin an explicit approved Keycloak version rather than track an unbounded floating tag.

The exact version SHALL be recorded in:

```text id="2h56wk"
upstream.lock.yaml
```

or the repository's equivalent immutable upstream-version manifest.

Example:

```yaml id="v2ko1r"
keycloak:
  version: "26.7.3"
  image: "quay.io/keycloak/keycloak"
```

The production build SHALL NOT use:

```text id="m1ebag"
latest
nightly
snapshot
floating major tags
floating minor tags
```

as the runtime version selector.

---

# 4. Why Keycloak

Keycloak is selected because it provides a mature standards-oriented identity platform while remaining independently deployable and open source.

Capabilities relevant to Baobab include:

- OpenID Connect;
- OAuth;
- user and session management;
- realm and client management;
- identity brokering;
- user federation;
- account recovery;
- WebAuthn;
- MFA-capable authentication flows;
- administrative delegation;
- organisation-aware B2B identity;
- machine/service clients;
- token signing;
- JWKS publication;
- event and audit capabilities.

Keycloak's current organisation functionality explicitly supports B2B-oriented use cases including organisation members, invitations, organisation-specific authentication, identity brokering, organisation groups and organisation-specific token claims.

This aligns well with Baobab's combination of:

```text id="yop67i"
B2B identity
B2C identity
workforce identity
supplier identity
workload identity
```

without requiring a custom identity platform.

---

# 5. Keycloak Is an Implementation, Not the Baobab Domain Model

Baobab SHALL treat Keycloak as an implementation of the authentication boundary, not as the canonical business ontology.

The distinction is:

```text id="6gzzt3"
KEYCLOAK                          BAOBAB

Realm                            Platform IAM boundary
User ID                          External identity subject
Organization                     IAM organization construct
Client                           Relying application/service
Role                             Authentication-side role
Session                          Authentication session
IdP link                         Federated identity link

                   ≠

CanonicalIdentity
Tenant
LegalEntity
DigitalEstate
CanonicalEntity
CapabilityBinding
Market
Domain membership
ERP authority
Trade authority
Supplier approval
```

Keycloak database identifiers SHALL NOT leak into cross-platform APIs as Baobab canonical identifiers.

---

# 6. Realm Strategy

Baobab SHALL initially operate one primary realm:

```text id="11vovn"
baobab
```

Conceptually:

```text id="l34qht"
Keycloak
│
├── master
│   └── administrative boundary
│
└── baobab
    ├── users
    ├── organizations
    ├── clients
    ├── scopes
    ├── authentication flows
    └── identity providers
```

The `master` realm SHALL be treated as a restricted administrative construct and SHALL not be used as the ordinary application realm.

---

# 7. Why Not Realm per Tenant

The following model is rejected:

```text id="zmf31c"
Keycloak
├── nabhold-realm
├── zuribeans-realm
├── thamani-realm
├── buyer-a-realm
├── buyer-b-realm
├── supplier-a-realm
└── ...
```

A realm-per-tenant model would create:

- administrative proliferation;
- duplicate client definitions;
- duplicate authentication policies;
- duplicated identity-provider integration;
- difficult cross-tenant identities;
- cumbersome workforce access;
- poor multi-context user experience;
- expensive upgrades and policy rollout.

Baobab's tenant model is richer than Keycloak's realm boundary.

A tenant therefore SHALL NOT imply its own realm.

---

# 8. When Additional Realms May Be Justified

Additional realms are not prohibited permanently.

A new realm SHALL require an ADR or equivalent architecture review demonstrating a real isolation requirement such as:

- mandatory jurisdictional isolation;
- legally mandated credential separation;
- materially different authentication sovereignty;
- acquisition/federation boundary;
- externally managed identity domain;
- contractual requirement for isolated administration;
- severe blast-radius requirement that cannot be met otherwise.

Convenience SHALL NOT be sufficient justification.

---

# 9. Organizations

The Baobab realm SHOULD enable Keycloak Organizations for B2B-oriented identity scenarios.

Current Keycloak documentation describes Organizations as a mechanism for B2B and multi-tenant identity within a realm, including organisation membership, invitation flows, groups, identity-provider association, organisation-specific login and organisation-specific claims.

Target use cases include:

```text id="j61l1q"
Buyer companies
Supplier companies
Partner organizations
Selected internal corporate structures
External enterprise customers
```

---

# 10. Organization Is Not Tenant

The following invariant SHALL be enforced:

```text id="3g5d8o"
Keycloak Organization
        ≠
Baobab Tenant
```

Likewise:

```text id="3g5d8p"
Keycloak Organization
        ≠
Baobab LegalEntity
```

unless an explicit mapping exists.

Example:

```text id="8m808q"
Keycloak Organization
"Acme Hotels"

       │
       │ explicit mapping
       ▼

CanonicalEntity
"Acme Hotels Ltd"

       │
       ├── buyer organization
       ├── tenant membership
       └── Trade relationship
```

The mapping SHALL be represented through canonical Baobab identity/entity references.

---

# 11. Organization Membership

Keycloak organisation membership MAY be used for identity-oriented relationships such as:

- invitation to an organisation;
- association of an authenticated human with an organisation;
- organisation-specific login;
- external identity brokering;
- identity-side organisational grouping.

It SHALL NOT automatically grant:

- purchase authority;
- supplier approval;
- payment authority;
- ERP privileges;
- platform tenancy;
- commerce entitlement.

Those remain platform/domain decisions.

---

# 12. Organization Groups

Current Keycloak capabilities allow organisation-specific hierarchical groups and role mappings, while organisation groups remain distinct from realm groups. Current documentation also notes that organisation groups cannot directly be used in Keycloak Authorization Services group-based policies.

Baobab MAY use organisation groups for identity-side organisational structure such as:

```text id="nzb25k"
Procurement
Finance
Operations
Management
```

but SHOULD NOT place authoritative commercial or ERP permissions into these groups.

The distinction remains:

```text id="ts871b"
Identity-side grouping
         │
         ▼
Keycloak

Business authority
         │
         ▼
Trade / ERP / CMS / domain engine
```

---

# 13. Client Model

Each relying application or workload SHALL receive an explicitly registered client identity.

Likely clients include:

| Client | Type | Purpose |
|---|---|---|
| `baobab-control-plane` | confidential/resource | Control Plane |
| `baobab-trade` | confidential/workload | Trade engine |
| `baobab-erp` | confidential | ERP SSO/integration |
| `baobab-cms` | confidential | CMS |
| `baobab-pulse` | confidential/workload | intelligence engine |
| `zuribeans-web` | public or BFF-dependent | B2B estate |
| `thamani-web` | public or BFF-dependent | B2C estate |
| `nabhold-web` | application-specific | corporate estate |
| future estate clients | explicit | future integrations |

No universal Baobab client SHALL be used by all services.

---

# 14. Public and Confidential Clients

Browser-only applications SHALL NOT contain confidential client secrets.

Where direct browser OIDC is appropriate:

```text id="1oyd38"
Authorization Code
+
PKCE
```

SHALL be preferred.

Server-side applications, BFFs and workloads MAY use confidential clients where secrets or stronger client credentials can be protected.

Client type SHALL be selected from the actual runtime boundary, not merely from the repository name.

---

# 15. Client Isolation

Each service SHALL have distinct credentials.

This is prohibited:

```text id="zqupp6"
BAOBAB_CLIENT_ID=baobab-services
BAOBAB_CLIENT_SECRET=one-secret-for-everything
```

Instead:

```text id="zqupp7"
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
...
```

shall have independently revocable identities.

This reduces lateral movement after compromise.

---

# 16. Client Scopes

Client scopes SHALL be explicit, minimal and version-controlled where appropriate.

Examples may include:

```text id="prb51b"
openid
profile
email
context:resolve
identity:read
identity:self
```

Exact scopes SHALL be standardised through `baobab-platform/shared` under the relevant identity-contract ADR.

Business-domain permissions SHOULD NOT be converted blindly into OIDC scopes.

For example:

```text id="85whbv"
approve-purchase-order-under-500000
```

does not belong in the IAM token profile merely because OAuth scopes exist.

---

# 17. Token Design

Keycloak SHALL issue cryptographically signed tokens.

Relying services SHALL validate at minimum:

- issuer;
- intended audience;
- expiration;
- not-before where applicable;
- signature;
- allowed signing algorithm;
- relevant actor/client claims;
- required scopes.

The Control Plane SHALL not accept identity purely because the token parses successfully.

---

# 18. Canonical Subject Mapping

The Keycloak `sub` claim SHALL be treated as an external identity-provider subject.

Conceptual mapping:

```text id="mblq2a"
Keycloak

iss + sub
    │
    ▼
ExternalIdentity
    │
    ▼
CanonicalIdentity
    │
    ▼
Membership / Context
```

Use:

```text id="mblq2b"
issuer + subject
```

rather than email as the durable external identity key.

Email addresses are mutable.

---

# 19. Username and Email

Username and email MAY be used for:

- login;
- communication;
- display;
- account discovery under carefully controlled conditions.

They SHALL NOT serve as permanent cross-platform canonical identifiers.

The platform must tolerate:

```text id="d447lz"
email change
name change
username change
federated-provider change
```

without creating a new canonical identity unnecessarily.

---

# 20. Identity Federation

Keycloak identity brokering MAY be used in the future for:

```text id="hwvwoo"
enterprise OIDC providers
enterprise SAML providers
approved social identity providers
partner identity providers
```

Federation SHALL map the external subject into the Baobab identity layer.

Federated identity SHALL NOT automatically imply:

- tenant membership;
- entitlement;
- role;
- supplier approval;
- employee status.

Authentication proves possession/control of an identity.

It does not prove business authority.

---

# 21. Database

Keycloak SHALL use a dedicated relational database.

The selected production database SHALL be PostgreSQL.

Keycloak's current supported configuration includes PostgreSQL 17 among its supported database versions.

Baobab SHOULD therefore standardise IAM production deployments on:

```text id="vgke5m"
PostgreSQL 17
```

unless the infrastructure architecture adopts a newer supported Baobab-wide PostgreSQL standard before production rollout.

Keycloak SHALL have a database/schema boundary that prevents direct cross-engine database access.

---

# 22. No Shared Platform Database

The following architecture is prohibited:

```text id="hkgm99"
           Shared PostgreSQL schema
           /      |       \
      Keycloak    CP      Trade
```

Instead:

```text id="8v7cgj"
Keycloak DB
    │
    X

CP DB
    │
    X

Trade DB
```

where `X` denotes no direct cross-database ownership.

Integration SHALL occur through:

- OIDC/OAuth;
- approved APIs;
- canonical events;
- explicit mapping.

---

# 23. Direct Database Access Prohibition

Baobab applications SHALL NOT directly read or mutate Keycloak internal tables.

This includes:

```text id="wqm3kl"
baobab-cp
baobab-trade
baobab-erp
baobab-cms
Digital Estates
```

The Keycloak database is an implementation detail of IAM.

Approved access is through supported IAM interfaces.

---

# 24. Configuration as Code

Baobab realm configuration SHALL be reproducible.

Version-controlled configuration SHOULD cover:

- realm configuration;
- client definitions;
- client scopes;
- protocol mappers;
- authentication policies;
- password policies;
- required actions;
- organisation settings;
- event configuration;
- themes;
- approved identity providers excluding secrets.

Configuration SHALL be capable of deterministic deployment into an empty environment.

Manual Admin Console changes SHALL not be the sole source of production truth.

---

# 25. Secrets Must Not Be Exported into Configuration

Realm exports and bootstrap automation SHALL be inspected to prevent accidental persistence of:

- client secrets;
- administrator passwords;
- SMTP passwords;
- private keys;
- external IdP secrets.

Secret material SHALL come from the platform secret-management boundary owned by `baobab-platform/infrastructure`.

---

# 26. Extension Policy

Baobab SHALL strongly prefer configuration over custom Keycloak provider development.

The preference hierarchy is:

```text id="4z8msz"
1. Native Keycloak feature
        ↓
2. Standards-compliant configuration
        ↓
3. External Baobab adapter/service
        ↓
4. Minimal Keycloak SPI extension
        ↓
5. Fork Keycloak
```

Option 5 is effectively prohibited without a dedicated ADR.

---

# 27. Permitted Extensions

A custom provider MAY be written where a clear requirement cannot safely be fulfilled by:

- standard Keycloak configuration;
- standard OIDC/OAuth;
- Keycloak Admin API;
- external integration service;
- events.

Every custom provider SHALL:

- have automated tests;
- define supported Keycloak versions;
- document upgrade coupling;
- avoid private/internal APIs where possible;
- have an explicit owner;
- have an exit strategy.

---

# 28. Themes

Baobab MAY maintain Keycloak themes for:

- NABHOLD workforce;
- Zuribeans;
- Thamani;
- common Baobab account experiences.

Themes SHALL remain presentation customizations rather than repositories for business logic.

Do not implement authorization decisions inside templates.

---

# 29. Administrative Model

The Keycloak administration plane SHALL be highly restricted.

The `master` realm administrator SHALL not be used for routine identity administration.

Prefer delegated least-privilege administration where feasible.

Current Keycloak supports fine-grained administrative permissions across realm resources, including organisations.

Baobab SHALL distinguish at least:

```text id="6b0c4g"
IAM platform administrator
Identity administrator
Helpdesk/recovery operator
Organization administrator
Security auditor
Application/client administrator
```

where operational requirements justify delegation.

---

# 30. Privileged Authentication

Privileged IAM administrators SHALL use MFA.

Break-glass administrator access SHALL:

- be rare;
- use independently protected credentials;
- be monitored;
- be auditable;
- have a documented recovery procedure;
- not be used for routine administration.

---

# 31. Bootstrap Administrator

Initial administrator creation SHALL be automated securely.

Bootstrap administrator credentials SHALL NOT remain the permanent routine administrative account.

After initial realm provisioning:

```text id="24juk3"
bootstrap admin
      │
      ▼
create governed administrators
      │
      ▼
validate access
      │
      ▼
remove / disable bootstrap path
```

where Keycloak's supported operational model permits.

---

# 32. Production Runtime

Keycloak SHALL run in production mode.

Development startup modes SHALL not be used for production deployment.

Production configuration SHALL include appropriate:

- hostname configuration;
- proxy/forwarded-header trust;
- TLS boundary;
- database configuration;
- health endpoints;
- metrics;
- caching;
- clustering if required;
- resource limits;
- secrets;
- observability.

---

# 33. Container Strategy

Baobab SHALL use upstream-supported Keycloak container distribution as the base runtime.

A derived Baobab image MAY add:

- approved themes;
- approved providers;
- required build-time configuration;
- metadata/labels.

The derived image SHALL remain minimal.

Do not install unrelated operational tooling into the IAM container.

---

# 34. High Availability

The initial development environment MAY run a single Keycloak instance.

Production architecture SHALL be designed so that Keycloak is not permanently constrained to a single node.

Current Keycloak supported configurations include clustering/high-availability capabilities and external Infinispan-based scaling options.

The precise HA topology SHALL be defined by the dedicated availability/recovery ADR.

---

# 35. Session Architecture

Authentication sessions SHALL remain IAM-owned.

Domain engines MAY maintain domain-specific state, but they SHALL NOT independently reimplement the platform authentication session.

Examples:

```text id="p9t8ns"
IAM session
    │
    ├── Thamani authenticated session
    ├── Zuribeans authenticated session
    └── workforce SSO session
```

Business cart, workflow and ERP states remain engine-owned.

---

# 36. Logout

Logout SHALL be treated as a security operation rather than a frontend-only navigation action.

The implementation SHOULD account for:

- local application logout;
- IdP session logout;
- refresh-token invalidation;
- federated logout limitations;
- sensitive application session termination.

The exact cross-application logout model will be refined in the token/session ADR.

---

# 37. Account Recovery

Keycloak SHALL provide the authentication-side recovery mechanism.

Recovery success SHALL restore authentication capability only.

It SHALL NOT automatically restore:

- revoked tenant membership;
- suspended supplier status;
- removed buyer membership;
- revoked ERP authorization.

This prevents authentication recovery from becoming privilege recovery.

---

# 38. Events

Keycloak events MAY be consumed by Baobab IAM integration components to derive canonical security/audit events.

However:

```text id="4tszlu"
Keycloak internal event
        ≠
Canonical Baobab event automatically
```

Transformation into Shared canonical event contracts SHALL occur explicitly.

No sensitive credential material SHALL be propagated.

---

# 39. Upgrade Strategy

Keycloak SHALL be upgraded deliberately.

The upgrade process SHALL include:

```text id="7ql93n"
Review release notes
       │
       ▼
Review migration guidance
       │
       ▼
Build candidate image
       │
       ▼
Contract tests
       │
       ▼
OIDC integration tests
       │
       ▼
Theme/provider tests
       │
       ▼
Database migration rehearsal
       │
       ▼
Backup
       │
       ▼
Staging upgrade
       │
       ▼
Production rollout
```

Automatic unattended major-version upgrades are prohibited.

---

# 40. Version Compatibility

Custom Baobab Keycloak providers SHALL declare compatibility explicitly.

For example:

```text id="sy6gqk"
Supported Keycloak:
>= 26.7.0
< 27.0.0
```

when appropriate.

Providers without compatibility evidence SHALL block upgrade until tested or removed.

---

# 41. Portability Requirement

Baobab SHALL remain capable of replacing Keycloak without rewriting the entire platform.

Therefore, applications SHALL depend primarily on:

```text id="8mm74t"
OIDC
OAuth
Shared identity contracts
Canonical Baobab identity
Control Plane context APIs
```

rather than Keycloak-specific APIs.

Direct Keycloak APIs SHOULD be confined to:

```text id="1chd2q"
baobab-iam
approved administrative provisioning
explicit IAM adapters
```

---

# 42. Exit Strategy

If Keycloak is replaced in the future:

```text id="daw3iq"
Current:

Keycloak subject
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity

Replacement:

New IdP subject
      │
      ▼
ExternalIdentity
      │
      ▼
Same CanonicalIdentity
```

This is why the Control Plane canonical identity layer is mandatory.

Baobab business data SHALL not use Keycloak internal user IDs as permanent foreign keys.

---

# 43. Alternatives Considered

## Alternative A — Build IAM into baobab-cp

### Advantages

- maximum custom control;
- fewer runtime products.

### Disadvantages

- substantial authentication engineering;
- bespoke OAuth/OIDC security surface;
- credential storage burden;
- MFA/passkey burden;
- federation burden;
- recovery burden;
- protocol maintenance burden.

### Decision

Rejected.

---

## Alternative B — Medusa authentication as platform identity

### Advantages

- already present in Trade;
- convenient for commerce.

### Disadvantages

- commerce-centric;
- poor fit for ERP, CMS, workforce and platform workloads;
- couples platform identity to one engine;
- weak architectural separation.

### Decision

Rejected.

---

## Alternative C — iDempiere as identity authority

### Advantages

- workforce identity already exists in ERP.

### Disadvantages

- ERP-centric identity model;
- unsuitable for B2C consumers;
- unsuitable for Digital Estates;
- unsuitable as general workload identity provider;
- couples platform security to ERP lifecycle.

### Decision

Rejected.

---

## Alternative D — Identity per Digital Estate

### Advantages

- local independence;
- fast initial implementation.

### Disadvantages

- duplicated users;
- duplicated credentials;
- fragmented MFA;
- fractured SSO;
- inconsistent lifecycle;
- difficult cross-estate identity.

### Decision

Rejected.

---

## Alternative E — Managed proprietary IAM

A managed provider could reduce operational burden.

Potential advantages include:

- hosted availability;
- managed patching;
- reduced operational overhead.

Potential disadvantages include:

- recurring identity-based cost;
- vendor coupling;
- data-residency considerations;
- reduced infrastructure control;
- migration cost;
- potentially complex B2B pricing.

### Decision

Not selected as the primary platform at this stage.

This decision may be revisited if IAM operational burden materially exceeds the strategic benefit of self-hosting.

---

# 44. Decision Consequences

## Positive

Keycloak provides:

- standards-based authentication;
- mature OIDC/OAuth;
- common workforce identity;
- workload identity foundation;
- B2B organisation support;
- B2C authentication;
- federation capability;
- MFA/WebAuthn foundations;
- central session management;
- platform-wide authentication consistency.

## Negative

Baobab assumes responsibility for:

- operating another critical service;
- patching;
- upgrading;
- database management;
- signing-key security;
- disaster recovery;
- IAM monitoring;
- capacity planning.

These costs are accepted.

---

# 45. Security Consequences

Keycloak becomes a high-value target.

Compromise could permit forged or improperly authenticated access across multiple Baobab services.

Accordingly:

```text id="fltx5h"
baobab-iam = Tier-0
```

and its production security posture SHALL be at least as strict as the Control Plane.

---

# 46. Architectural Invariants Established

The following become binding unless explicitly superseded:

```text id="48gv8u"
Keycloak User ID ≠ Canonical Baobab Identity

Keycloak Organization ≠ Baobab Tenant

Keycloak Organization ≠ Legal Entity

Keycloak Role ≠ Domain Authorization automatically

Keycloak Database ≠ Shared Platform Database

Email ≠ Canonical Identity Key

One Realm ≠ One Tenant

Valid Keycloak Token ≠ Authorized Business Operation
```

---

# 47. Implementation Guidance

The repository SHOULD converge toward:

```text id="ufjhtu"
baobab-iam/
├── config/
│   ├── realm/
│   ├── clients/
│   ├── scopes/
│   ├── organizations/
│   └── authentication/
├── bootstrap/
├── providers/
├── themes/
├── tests/
├── docs/
├── runtime/
├── upstream.lock.yaml
├── contracts.lock.yaml
├── Dockerfile
└── compose.yaml
```

Implementation detail may vary where repository conventions justify it.

---

# 48. Required Verification

Before this ADR is considered implemented, tests SHALL demonstrate:

- deterministic realm bootstrap;
- valid OIDC discovery;
- valid JWKS retrieval;
- valid authorization-code login;
- PKCE support for public clients;
- valid client-credentials workload token;
- issuer validation;
- audience validation;
- expired-token rejection;
- wrong-client rejection;
- organisation membership behaviour;
- canonical subject mapping;
- independent client revocation;
- realm export/import recovery;
- database backup/restore compatibility.

---

# 49. Follow-On Decisions

This ADR intentionally does not fully define:

- canonical identity data model;
- detailed token profile;
- workload credential lifecycle;
- MFA requirements;
- session lifetimes;
- supplier lifecycle;
- Trade adapter details;
- iDempiere SSO mapping;
- DR topology.

Those belong to subsequent ADRs.

The immediate next decision is:

```text id="sz7s6z"
ADR-0003
Identity Authority and Trust Boundaries
```

---

# 50. Decision Summary

NABHOLD adopts Keycloak as the initial authentication runtime for Baobab IAM.

The platform SHALL:

```text id="pmx6yx"
Use Keycloak for authentication
Use OIDC/OAuth as the primary integration boundary
Use PostgreSQL for IAM persistence
Use one Baobab realm initially
Use Organizations where useful for B2B identity
Use separate clients per relying application/workload
Use configuration as code
Minimize custom Keycloak extensions
Avoid Keycloak-specific identifiers in business domains
Preserve canonical Baobab identity outside the IdP
Maintain an explicit replacement/exit path
```

The final architectural relationship is:

```text id="m7l7dy"
                   KEYCLOAK
                  Baobab IAM
                      │
                authenticate
                      │
                      ▼
              EXTERNAL SUBJECT
                      │
                      ▼
              CANONICAL IDENTITY
                 baobab-cp
                      │
                resolve context
                      │
                      ▼
                DOMAIN ENGINE
                      │
                 authorize work
```

Keycloak is therefore a critical Baobab platform dependency, but **not a permanent owner of Baobab's business identity model**.