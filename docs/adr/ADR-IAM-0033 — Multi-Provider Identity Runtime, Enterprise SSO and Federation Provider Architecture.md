# ADR-IAM-0033 — Multi-Provider Identity Runtime, Enterprise SSO and Federation Provider Architecture

**Status:** Accepted  
**Date:** 2026-10-04  
**Decision Owners:** Baobab Platform Architecture / Security Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold, Equator & Estate, and future Baobab Digital Estates  
**Decision Type:** Platform Architecture / IAM / Enterprise Federation / SSO / Provider Neutrality / Migration  
**Supersedes in Part:** ADR-IAM-0019, ADR-IAM-0022  
**Amends:** ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0026, and provider-specific assumptions in ADR-IAM-0027 through ADR-IAM-0032  
**Does Not Reinstate:** ADR-0002 — Keycloak as the Baobab Identity Provider  
**Preserves:** ADR-IAM-0001, 0003–0018 and 0019–0032 wherever their canonical-identity, authority-boundary, security, lifecycle, assurance, privacy, tenancy, context, domain-authorization, audit and resilience decisions do not conflict with this ADR  
**Native Human Identity Runtime:** Ory Kratos  
**OAuth/OIDC Authorization Runtime:** Ory Hydra  
**Initial Enterprise Federation / SSO Runtime:** Keycloak  
**Canonical Identity Authority:** Baobab Control Plane  
**Platform Context and Entitlement Authority:** Baobab Control Plane  
**Business Authorization Authority:** Respective authoritative domain engines

---

# 1. Decision

Baobab SHALL operate a **provider-neutral, multi-provider IAM architecture**.

The Baobab IAM architecture SHALL NOT require a single identity technology to implement every identity capability.

The initial production provider allocation SHALL be:

| IAM capability | Initial provider | Architectural authority |
|---|---|---|
| Human identity | Ory Kratos | IAM authentication boundary |
| Native credentials | Ory Kratos | IAM authentication boundary |
| Password authentication | Ory Kratos | IAM authentication boundary |
| Passkeys / WebAuthn | Ory Kratos | IAM authentication boundary |
| MFA | Ory Kratos | IAM authentication boundary |
| Account verification | Ory Kratos | IAM authentication boundary |
| Account recovery | Ory Kratos | IAM authentication boundary |
| Native authentication sessions | Ory Kratos | IAM authentication boundary |
| OAuth 2.x authorization server | Ory Hydra | IAM protocol boundary |
| OpenID Connect provider | Ory Hydra | IAM protocol boundary |
| OAuth token issuance | Ory Hydra | IAM protocol boundary |
| Workload authentication/token issuance | Ory Hydra | IAM protocol boundary |
| Enterprise SAML federation | Keycloak | IAM federation boundary |
| Enterprise OIDC federation | Keycloak | IAM federation boundary |
| Enterprise identity brokering | Keycloak | IAM federation boundary |
| Enterprise IdP routing | Keycloak + Baobab IAM | IAM federation boundary |
| Enterprise lifecycle provisioning / SCIM | Independently selected provider | IAM lifecycle boundary |
| Canonical identity | `baobab-cp` | Baobab canonical authority |
| Tenant / LegalEntity / DigitalEstate / Market context | `baobab-cp` | Baobab platform authority |
| Capability and platform entitlement | `baobab-cp` | Baobab platform authority |
| Commerce authorization | `baobab-trade` | Trade domain authority |
| ERP authorization | `baobab-erp` / iDempiere | ERP domain authority |
| CMS domain authorization | `baobab-cms` | CMS domain authority |

The authoritative target architecture is:

```text
                         BAOBAB IAM
                    Provider-Neutral Boundary
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
         Ory Kratos       Ory Hydra        Keycloak
             │                │                │
       Human identity     OAuth/OIDC       Enterprise
       Credentials        Token issuer     Federation
       Passkeys/MFA       Workloads        SAML/OIDC SSO
       Recovery                           Identity brokering
       Sessions                           Enterprise IdPs
             │                │                │
             └────────────────┼────────────────┘
                              │
                       ExternalIdentity
                              │
                              ▼
                       CanonicalIdentity
                              │
                              ▼
                         baobab-cp
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
            Trade            ERP             CMS
```

This architecture is normative.

---

# 2. Context

ADR-IAM-0019 changed Baobab from a Keycloak-centric identity architecture toward a provider-neutral architecture implemented initially through Ory Kratos and Ory Hydra.

That decision remains substantially correct.

The architectural problem identified by ADR-IAM-0019 was not that Keycloak was inherently unsuitable for every IAM capability.

The problem was that:

```text
Baobab IAM
     =
Keycloak
```

had allowed one implementation technology to become too closely associated with:

```text
identity
credentials
sessions
OAuth
OIDC
workloads
federation
organizations
authentication flows
administration
runtime topology
```

despite Baobab's broader architecture requiring provider-independent identity semantics.

ADR-IAM-0019 therefore established the more important principle:

> Baobab SHALL depend on identity standards and Baobab identity contracts, not on the business model of a particular identity provider.

That principle remains authoritative.

However, a new business requirement materially changes the appropriate provider allocation.

Enterprise customers increasingly require:

```text
Enterprise SSO
SAML federation
OIDC federation
customer-controlled identity providers
organization-aware login
enterprise identity brokering
```

as prerequisites for adopting B2B platforms.

Baobab serves business models where this requirement is especially important.

Examples include:

```text
ZuriBeans
    B2B buyers
    enterprise procurement teams
    suppliers
    partners

Thamani
    B2B logistics customers
    enterprise shipping accounts
    agents
    carriers
    business-account staff

Nabhold
    workforce
    subsidiaries
    executive systems

Future Baobab customers
    external companies
    corporate groups
    subsidiaries
    enterprise workforces
```

At the same time, Baobab's deployment strategy requires a strong self-hosted option.

The Ory ecosystem provides enterprise SSO capabilities, including SAML, OIDC and directory synchronization in commercial and managed offerings. However, Baobab SHALL NOT make the availability, commercial packaging or deployment model of one provider's enterprise federation feature the architectural definition of Baobab enterprise SSO.

Keycloak already provides mature standards-based identity brokering for external SAML 2.0 and OpenID Connect identity providers.

Therefore the appropriate response is not:

```text
Ory
   ↓
Keycloak
```

nor:

```text
Keycloak
   ↓
Ory
```

It is:

```text
                    BAOBAB IAM CONTRACT
                           │
                           ▼
                    IAM CAPABILITY
                           │
                           ▼
                  PROVIDER RESOLUTION
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
           Kratos        Hydra       Keycloak
```

---

# 3. Architectural Correction

ADR-IAM-0019 described the migration conceptually as:

```text
Provider-coupled IAM
        ↓
Provider-neutral Baobab Identity Architecture
        ↓
Ory as the initial identity-engine implementation
```

ADR-IAM-0033 retains the first two stages but corrects the final assumption.

The revised architecture is:

```text
Provider-coupled IAM
        │
        ▼
Provider-neutral Baobab Identity Architecture
        │
        ▼
Capability-oriented provider allocation
        │
        ├── Ory Kratos
        │      native human identity
        │
        ├── Ory Hydra
        │      OAuth/OIDC
        │
        └── Keycloak
               enterprise federation / SSO
```

Therefore:

> **Provider neutrality SHALL mean that Baobab owns identity semantics and capability contracts while one or more replaceable providers implement those capabilities.**

Provider neutrality SHALL NOT mean:

> Baobab must use exactly one identity provider.

---

# 4. This Is Not a Rollback to ADR-0002

ADR-0002 remains superseded.

Baobab SHALL NOT restore the previous architecture:

```text
                 Keycloak
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Credentials    OAuth       Federation
        │           │           │
        └───────────┼───────────┘
                    ▼
                 Baobab
```

Keycloak SHALL NOT again become:

- the universal Baobab identity provider;
- the canonical identity authority;
- the default native credential authority;
- the default native session authority;
- the platform OAuth authorization server;
- the general workload-token issuer;
- the Baobab organization model;
- the Baobab tenant model;
- the source of business authorization.

Instead:

```text
Keycloak
    =
initial provider implementation
for
ENTERPRISE_FEDERATION
and
ENTERPRISE_SSO
```

This is a materially narrower responsibility.

---

# 5. Permanent Authority Principle

The following rule remains authoritative:

> **Baobab IAM establishes identity and authentication evidence. Baobab Control Plane establishes canonical identity, platform context and entitlement. Authoritative domain engines establish business authorization.**

In the multi-provider architecture:

```text
Authentication / Federation
          │
          ├──── Ory Kratos
          ├──── Ory Hydra
          └──── Keycloak
                    │
                    ▼
           normalized identity
               evidence
                    │
                    ▼
             ExternalIdentity
                    │
                    ▼
             CanonicalIdentity
                    │
                    ▼
                baobab-cp
                    │
                    ▼
               Context
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      Trade        ERP         CMS
```

No provider bypasses this authority chain.

---

# 6. Capability Before Provider

Baobab SHALL model IAM requirements in terms of **capabilities**, not product names.

The platform SHOULD conceptually support:

```text
IdentityCapability

HUMAN_AUTHENTICATION
CREDENTIAL_MANAGEMENT
SESSION_MANAGEMENT
ACCOUNT_VERIFICATION
ACCOUNT_RECOVERY
MFA
PASSKEY
OAUTH_AUTHORIZATION_SERVER
OIDC_PROVIDER
WORKLOAD_TOKEN_ISSUANCE
ENTERPRISE_SSO
SAML_FEDERATION
OIDC_FEDERATION
IDENTITY_BROKERING
IDENTITY_LIFECYCLE_PROVISIONING
DIRECTORY_SYNCHRONIZATION
```

Provider selection occurs after capability determination.

Conceptually:

```text
RequiredCapability
        │
        ▼
ProviderCapabilityBinding
        │
        ▼
IdentityProviderInstance
```

---

# 7. Provider Capability Model

The provider-neutral IAM model SHOULD support an abstraction equivalent to:

```text
IdentityCapabilityProvider
├── provider_id
├── provider_type
├── capabilities[]
├── protocol_support[]
├── deployment_scope
├── environment
├── security_domain
├── region
├── health_status
├── lifecycle_status
├── configuration_reference
├── created_at
└── updated_at
```

Provider-specific secrets SHALL NOT be stored in this canonical representation.

---

# 8. Initial Provider Registry

Conceptually:

```yaml
providers:

  ory-kratos:
    provider_type: ORY_KRATOS
    capabilities:
      - HUMAN_AUTHENTICATION
      - CREDENTIAL_MANAGEMENT
      - SESSION_MANAGEMENT
      - ACCOUNT_VERIFICATION
      - ACCOUNT_RECOVERY
      - MFA
      - PASSKEY

  ory-hydra:
    provider_type: ORY_HYDRA
    capabilities:
      - OAUTH_AUTHORIZATION_SERVER
      - OIDC_PROVIDER
      - WORKLOAD_TOKEN_ISSUANCE

  keycloak-enterprise:
    provider_type: KEYCLOAK
    capabilities:
      - ENTERPRISE_SSO
      - SAML_FEDERATION
      - OIDC_FEDERATION
      - IDENTITY_BROKERING
```

This representation is illustrative.

The canonical schema SHALL be defined through `baobab-platform/shared` and/or the appropriate Control Plane contract rather than copied directly from this ADR.

---

# 9. Provider Selection Is a Platform Decision

Digital Estates SHALL NOT select IAM implementation products directly.

This is prohibited:

```text
ZuriBeans:
    identity_provider: keycloak
```

Prefer:

```text
ZuriBeans:
    required_capability:
        ENTERPRISE_SSO
```

followed by:

```text
ENTERPRISE_SSO
      │
      ▼
CapabilityBinding
      │
      ▼
keycloak-enterprise
```

Likewise, customer onboarding SHALL express desired identity capabilities rather than provider implementation preferences unless a contractual or sovereignty requirement explicitly requires a named provider.

---

# 10. Ory Kratos Responsibility

Ory Kratos remains Baobab's initial default native human-identity runtime.

Kratos SHALL own, where configured:

```text
native identity records
native credentials
password authentication
passkeys / WebAuthn
MFA
verification
recovery
native authentication sessions
self-service identity flows
authentication lifecycle hooks
```

Kratos SHALL NOT own:

```text
Tenant
LegalEntity
CanonicalOrganization
CanonicalIdentity
Market
DigitalEstate
Capability
CapabilityBinding
BuyerOrganization
SupplierOrganization
purchase authority
ERP permissions
platform authorization
```

---

# 11. Ory Hydra Responsibility

Ory Hydra remains Baobab's initial OAuth 2.x and OpenID Connect authorization-server runtime.

Hydra SHALL own:

```text
OAuth authorization-server mechanics
OpenID Connect protocol mechanics
OAuth clients
authorization-code flows
PKCE
workload client authentication
token issuance
token signing
token lifecycle
introspection where required
```

Hydra SHALL NOT own:

```text
CanonicalIdentity
Tenant
LegalEntity
organization hierarchy
business membership
business roles
purchase authority
supplier approval
ERP authorization
```

---

# 12. Keycloak Responsibility

Keycloak SHALL remain deployed as Baobab's initial **Enterprise Federation Provider**.

Its primary responsibilities SHALL be:

```text
SAML 2.0 identity brokering
enterprise OIDC identity brokering
enterprise IdP configuration
enterprise login routing
federation protocol translation
federation session handling where necessary
upstream identity-provider trust
upstream authentication evidence
enterprise federation audit events
```

Keycloak MAY use its organization capabilities internally where they materially simplify federation configuration and organization-specific IdP association.

However:

```text
Keycloak Organization
        ≠
Baobab CanonicalOrganization
        ≠
Baobab Tenant
        ≠
LegalEntity
        ≠
BuyerOrganization
        ≠
SupplierOrganization
```

This invariant is mandatory.

---

# 13. Why Keycloak Is Retained

Keycloak's current architecture supports identity brokering against external:

```text
SAML 2.0
OpenID Connect
OAuth-compatible identity providers
```

and supports organization-aware B2B identity scenarios.

The retained capability is therefore aligned with the new business requirement.

The decision is nevertheless based on capability suitability rather than permanent product preference.

The correct relationship is:

```text
Enterprise SSO requirement
        │
        ▼
ENTERPRISE_SSO capability
        │
        ▼
provider binding
        │
        ▼
Keycloak
```

not:

```text
Enterprise customer
        │
        ▼
must understand Keycloak
```

---

# 14. FederationTrust Remains Provider Neutral

ADR-IAM-0026's `FederationTrust` concept remains valid and SHALL be preserved.

It SHALL NOT become a Keycloak object.

Conceptually:

```text
FederationTrust
├── id
├── canonical_organization_id
├── protocol
├── upstream_issuer_or_entity_id
├── provider_capability
├── provider_binding
├── status
├── verified_domains[]
├── assurance_mapping
├── provisioning_mode
├── attribute_mapping_version
├── estate_scope[]
├── created_at
├── activated_at
└── revoked_at
```

Provider-specific references SHALL use external-reference/mapping mechanisms.

---

# 15. Provider-Specific Federation Reference

Where necessary:

```text
FederationTrust
       │
       ▼
ProviderBinding
       │
       ▼
ExternalReference
       │
       ▼
Keycloak
realm / IdP alias / organization association
```

Keycloak internal identifiers SHALL NOT become canonical federation identifiers.

---

# 16. Enterprise Authentication Flow

The preferred conceptual flow is:

```text
Digital Estate
      │
      ▼
Login Discovery
      │
      ▼
Baobab IAM
      │
      ├──────── Native Identity
      │              │
      │              ▼
      │          Ory Kratos
      │
      └──────── Enterprise Identity
                     │
                     ▼
              FederationTrust
                     │
                     ▼
              Provider Resolver
                     │
                     ▼
                  Keycloak
                     │
                     ▼
             Customer IdP
              Entra / Okta /
             Google / Ping /
               other IdP
```

Successful federation then produces:

```text
Customer IdP Subject
        │
        ▼
Keycloak federation evidence
        │
        ▼
Baobab normalization
        │
        ▼
ExternalIdentity
        │
        ▼
CanonicalIdentity
        │
        ▼
CP Context Resolution
        │
        ▼
Domain Authorization
```

---

# 17. Provider Chaining Is Not the Default Architecture

The following universal architecture is rejected:

```text
Customer IdP
     │
     ▼
Keycloak
     │
     ▼
Ory
     │
     ▼
Baobab
```

because it unnecessarily creates:

```text
additional session boundaries
additional failure modes
additional token translation
additional logout complexity
additional assurance propagation
additional subject correlation
additional operational dependencies
```

Baobab SHOULD normalize provider evidence at its IAM boundary rather than forcing every provider through another provider.

Provider chaining MAY nevertheless be used for a specific integration where protocol, UX or security requirements justify it.

Such chaining SHALL be explicit and tested.

---

# 18. Common Downstream Principal

Regardless of provider, downstream Baobab semantics SHALL converge.

Conceptually:

```text
Ory identity evidence
        │
        ├──────────────┐
        │              │
Keycloak federation    │
evidence               │
        │              │
        └──────┬───────┘
               ▼
       ExternalPrincipal
               │
               ▼
       ExternalIdentity
               │
               ▼
       CanonicalIdentity
```

The normalized principal SHOULD carry only provider-neutral evidence required by downstream processing.

---

# 19. Canonical Identity Is Unchanged

`CanonicalIdentity` remains provider independent.

A person SHALL NOT acquire a new canonical identity merely because they authenticate through:

```text
Ory today
Keycloak tomorrow
enterprise SAML
enterprise OIDC
native passkey
another future provider
```

Provider migration is not person creation.

---

# 20. Stable External Identity

External identity mapping SHALL continue to rely on stable provider evidence such as:

```text
issuer
+
subject
```

or the appropriate stable SAML identity semantics.

Email SHALL NOT become the durable canonical key.

---

# 21. No Email Auto-Linking

Suppose:

```text
Ory identity
email = jane@acme.example
```

and:

```text
Keycloak federation
upstream ACME Entra
email = jane@acme.example
```

Baobab SHALL NOT automatically conclude that these represent the same person solely because the email addresses match.

Identity linking SHALL continue to follow ADR-IAM-0004 and ADR-IAM-0025.

---

# 22. Enterprise SSO Does Not Grant Business Authority

Successful enterprise authentication establishes:

```text
authentication evidence
```

not:

```text
tenant membership
buyer authority
supplier authority
purchase authority
payment authority
ERP privilege
platform administration
```

For example:

```text
ACME Entra
     │
     ▼
Keycloak
     │
     ▼
Jane authenticated
```

does not imply:

```text
Jane may approve ACME purchase orders.
```

That remains a Trade/domain decision.

---

# 23. Enterprise Organization Is Not Baobab Organization

The following remain separate:

```text
Customer IdP tenant
Keycloak Organization
FederationTrust
CanonicalOrganization
LegalEntity
Baobab Tenant
BuyerOrganization
SupplierOrganization
```

Explicit mappings MAY connect them.

They SHALL NOT be conflated.

---

# 24. External Corporate Groups

The architecture SHALL support enterprise customers with subsidiaries.

Example:

```text
ACME Holdings
│
├── ACME Uganda Ltd
├── ACME Kenya Ltd
└── ACME South Africa Ltd
```

The customer may operate:

```text
one Entra tenant
```

while Baobab recognizes:

```text
multiple CanonicalOrganizations
multiple LegalEntities
multiple Markets
possibly multiple Tenants
```

The federation provider SHALL NOT redefine this hierarchy.

---

# 25. One IdP May Serve Multiple Baobab Organizations

A single enterprise IdP MAY authenticate people for several related organizations.

Therefore:

```text
one upstream IdP
        ≠
one CanonicalOrganization
```

FederationTrust scope SHALL determine permitted relationships.

---

# 26. One Organization May Have Multiple IdPs

A canonical organization MAY legitimately have:

```text
parent-company Entra
acquired-subsidiary Okta
regional identity provider
selected Baobab-native accounts
```

where policy permits.

Therefore:

```text
one organization
        ≠
one federation provider
```

---

# 27. Federation Provider Is Replaceable

Keycloak SHALL be treated as:

```text
provider_type = KEYCLOAK
capability = ENTERPRISE_SSO
```

not:

```text
enterprise_sso = keycloak
```

as a permanent architectural invariant.

Future implementations MAY include:

```text
Keycloak
Ory Enterprise SSO
another standards-compatible broker
customer-dedicated federation gateway
```

provided they satisfy Baobab contracts and security requirements.

Replacing Keycloak SHALL NOT require changing:

```text
CanonicalIdentity
FederationTrust
Tenant
LegalEntity
DigitalEstate
Market
Capability
domain authorization
```

---

# 28. SCIM Is Independently Resolved

SCIM SHALL NOT automatically be assigned to Keycloak merely because Keycloak provides enterprise SSO.

The architecture SHALL preserve:

```text
SSO
    ≠
Provisioning
```

and:

```text
Federation Provider
    ≠
Lifecycle Provisioning Provider
```

SCIM is an HTTP-based protocol for cross-domain identity provisioning and management.

Therefore Baobab MAY implement:

```text
Enterprise SSO
      │
      ▼
Keycloak
```

while independently implementing:

```text
SCIM lifecycle
      │
      ▼
Baobab IAM SCIM service
```

or:

```text
SCIM lifecycle
      │
      ▼
approved provider
```

without changing the enterprise federation architecture.

---

# 29. SCIM Does Not Own Canonical Identity

Regardless of implementation:

```text
SCIM User
    ≠
CanonicalIdentity
```

and:

```text
SCIM Group
    ≠
Baobab Role
```

SCIM SHALL feed lifecycle relationships through the appropriate Baobab IAM/Control Plane boundary.

It SHALL NOT write directly into Trade, ERP or CMS databases.

---

# 30. Ory Remains the Native Identity Default

Retaining Keycloak SHALL NOT halt the Ory migration for native identity.

Migration SHALL continue for:

```text
native human identities
native credentials
native MFA
native passkeys
native recovery
native sessions
OAuth clients
workload clients
OAuth/OIDC issuance
```

where those capabilities are allocated to Kratos/Hydra.

---

# 31. Revised Meaning of the Keycloak Migration

ADR-IAM-0022 SHALL no longer be interpreted as:

> Eliminate every Keycloak runtime from Baobab.

It SHALL instead mean:

> Remove Keycloak as the universal Baobab identity runtime and migrate capabilities to their approved provider boundaries.

Therefore the migration becomes:

```text
Old Keycloak
│
├── Human identities ─────────► Kratos
├── Native credentials ───────► Kratos
├── MFA/passkeys ─────────────► Kratos
├── Recovery ─────────────────► Kratos
├── Native sessions ──────────► Kratos
│
├── OAuth/OIDC server ────────► Hydra
├── workload clients ─────────► Hydra
├── token issuance ───────────► Hydra
│
└── Enterprise federation ────► Retained Keycloak
```

---

# 32. Keycloak Data Reduction

After migration, Keycloak SHOULD contain only the data necessary to perform its retained capability.

Baobab SHOULD progressively remove unnecessary Keycloak ownership of:

```text
native Baobab passwords
native registration
native account recovery
Baobab-native passkeys
ordinary native sessions
general workload clients
general Baobab OAuth clients
business roles
business organization truth
```

This reduces:

```text
attack surface
operational complexity
migration coupling
provider lock-in
duplicate identity state
```

---

# 33. Keycloak Organization Usage

Keycloak Organizations MAY be used as a federation-management convenience.

For example:

```text
Keycloak Organization
"ACME"

       │
       ├── ACME Entra IdP
       └── ACME subsidiary IdP
```

may simplify organization-specific federation routing.

However:

```text
Keycloak Organization
```

SHALL remain provider-local configuration.

The canonical organization continues to reside in Baobab's canonical model.

---

# 34. No Keycloak Organization Authorization Leakage

Keycloak organization membership, organization groups or organization token claims SHALL NOT directly establish authoritative Baobab business permissions.

This is prohibited:

```text
Keycloak Organization Group
"Finance"

       │
       ▼

iDempiere Finance Role
```

without an explicit Baobab-governed mapping.

Likewise:

```text
Keycloak Organization Admin
```

does not imply:

```text
Baobab Tenant Admin
```

---

# 35. Authentication Assurance

ADR-IAM-0024 remains authoritative.

Authentication assurance SHALL be normalized independently of provider.

Conceptually:

```text
Ory Kratos
     │
     └── assurance evidence
              │
              ▼
          BAOBAB-Ax

Keycloak / Enterprise IdP
     │
     └── acr/amr/SAML AuthnContext
              │
              ▼
       assurance mapping
              │
              ▼
          BAOBAB-Ax
```

Provider-specific assurance evidence SHALL be translated through explicit policy.

---

# 36. Enterprise SSO Does Not Automatically Mean MFA

This remains prohibited:

```text
Enterprise SSO
      =
BAOBAB-A3
```

The configured FederationTrust SHALL define trusted upstream assurance.

Unknown or insufficient evidence SHALL map to the configured safe baseline.

---

# 37. Step-Up

Where an enterprise session does not satisfy required assurance:

```text
Enterprise login
      │
      ▼
BAOBAB-A1/A2
      │
      ▼
high-risk operation
requires A3
      │
      ▼
STEP_UP_REQUIRED
```

The responsible authentication provider or an approved step-up flow MAY satisfy the requirement.

The domain engine requests assurance.

It SHALL NOT implement credential ceremonies itself.

---

# 38. Digital Estate UX

ADR-IAM-0023 remains authoritative.

Digital Estates own their authentication experience.

A login interface MAY present:

```text
Continue with your business account
Continue with Baobab account
```

without exposing infrastructure terminology such as:

```text
Login with Keycloak
Login with Kratos
```

Provider implementation details SHOULD remain invisible to ordinary users.

---

# 39. Login Discovery

Enterprise login discovery MAY use:

```text
verified email domain
organization selection
explicit enterprise login route
invitation context
known FederationTrust
```

to determine the appropriate federation.

Discovery is routing.

It is not identity proof.

It is not canonical linking.

It is not authorization.

---

# 40. No Provider Logic in Digital Estates

This is prohibited:

```text
if organization == "ACME":
    redirect_to_keycloak()

if organization == "XYZ":
    redirect_to_ory()
```

Digital Estates SHALL request the desired authentication/federation capability from the IAM boundary.

Provider resolution belongs to IAM.

---

# 41. Provider Resolver

`baobab-iam` SHOULD implement a provider-resolution abstraction.

Conceptually:

```text
AuthenticationRequest
        │
        ▼
Identity Requirement
        │
        ▼
Capability Resolver
        │
        ▼
ProviderCapabilityBinding
        │
        ▼
Provider Adapter
```

Inputs MAY include:

```text
required capability
FederationTrust
Digital Estate
IdentitySecurityDomain
environment
region
residency policy
assurance requirement
provider health
migration state
```

Provider resolution SHALL NOT override Control Plane business authority.

---

# 42. Provider Adapter Architecture

The provider boundary SHOULD support capability-oriented interfaces rather than a single enormous universal IdP interface.

Conceptually:

```text
HumanIdentityProvider
SessionProvider
OAuthProvider
WorkloadIdentityProvider
EnterpriseFederationProvider
LifecycleProvisioningProvider
```

Initial implementations:

```text
KratosHumanIdentityProvider
KratosSessionProvider

HydraOAuthProvider
HydraWorkloadIdentityProvider

KeycloakEnterpriseFederationProvider
```

This avoids forcing providers to implement capabilities they do not own.

---

# 43. Standards SHOULD Bypass Adapters Where Appropriate

Provider neutrality SHALL NOT result in unnecessary proprietary proxying.

Where a resource server can safely validate standards-based:

```text
OIDC discovery
JWKS
JWT
OAuth
```

directly, it SHOULD do so.

`baobab-iam` SHALL not become a mandatory synchronous hop for every request.

Provider adapters exist for:

```text
management
configuration
provisioning
normalization
lifecycle
reconciliation
migration
provider-specific operations
```

not to replace standards unnecessarily.

---

# 44. Token Authority

Hydra remains the default Baobab OAuth/OIDC token issuer.

Keycloak's retained federation capability SHALL NOT automatically make Keycloak a general-purpose token issuer for Baobab domain APIs.

Where Keycloak must issue protocol artifacts as part of federation, those artifacts SHALL be treated according to their bounded federation purpose.

The preferred downstream trust path remains:

```text
Baobab resource
      │
      ▼
approved Baobab token profile
      │
      ▼
Hydra
```

unless a specific federation flow explicitly requires otherwise.

---

# 45. Federation Evidence Exchange

Where enterprise authentication through Keycloak must establish a Baobab session or Hydra authorization flow, Baobab SHALL define a controlled federation handoff.

The handoff SHALL preserve:

```text
provider identity
upstream issuer
stable upstream subject
authentication time
assurance evidence
FederationTrust
correlation ID
security-domain context
```

without exposing unnecessary upstream tokens.

The precise protocol SHALL be defined in a technical specification and SHALL use standards where practical.

---

# 46. Upstream Tokens

Baobab SHALL NOT routinely propagate enterprise IdP access tokens into downstream domain services.

If an upstream token is required to call an enterprise-owned API, retrieval and use SHALL be:

```text
explicit
client-authorized
scope-limited
audited
short-lived
secret-protected
```

and treated as a distinct integration capability.

---

# 47. Logout Semantics

Multi-provider IAM introduces multiple session layers.

Baobab SHALL distinguish:

```text
Digital Estate session
Kratos session
Hydra authorization/session state
Keycloak federation session
upstream enterprise IdP session
```

Logout SHALL have explicitly documented semantics.

Baobab SHALL NOT claim universal upstream logout unless the protocol/provider actually guarantees it.

Local logout MUST at minimum invalidate the Baobab-controlled application session and applicable Baobab authentication state.

---

# 48. Session Ownership

A provider session is not a business context.

Therefore:

```text
Kratos Session
      ≠
CP Context
```

and:

```text
Keycloak Federation Session
      ≠
CP Context
```

Business context SHALL be resolved independently.

---

# 49. Federation Lifecycle

The FederationTrust lifecycle remains:

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
    ├────► SUSPENDED
    │
    ├────► ROTATING
    │
    └────► REVOKED
```

Provider configuration SHALL follow the canonical trust lifecycle rather than becoming the source of that lifecycle.

---

# 50. Federation Revocation

If a FederationTrust becomes:

```text
SUSPENDED
```

or:

```text
REVOKED
```

new enterprise authentication through that trust SHALL be denied regardless of whether the Keycloak IdP configuration remains technically functional.

Canonical Baobab security state outranks provider availability.

---

# 51. Lifecycle and Deprovisioning

ADR-IAM-0016 remains authoritative.

Enterprise deprovisioning SHALL affect the enterprise relationship, not necessarily the human's canonical identity.

Example:

```text
ACME disables Jane
      │
      ▼
enterprise relationship revoked
      │
      ▼
ACME authority removed
```

Jane may still be:

```text
Thamani personal customer
Company B representative
supplier representative
Baobab-native account holder
```

Therefore:

```text
Enterprise deprovisioning
        ≠
CanonicalIdentity deletion
```

---

# 52. Security Boundaries

Each provider SHALL have a distinct operational security boundary.

At minimum:

```text
Kratos
├── dedicated database/logical database
├── dedicated credentials
└── dedicated administrative interface

Hydra
├── dedicated database/logical database
├── dedicated credentials
└── dedicated administrative interface

Keycloak
├── dedicated database/logical database
├── dedicated credentials
└── dedicated administrative interface
```

No provider SHALL read another provider's internal database.

---

# 53. No Shared IAM Database Model

This is prohibited:

```text
       shared IAM schema
       /      |       \
   Kratos   Hydra   Keycloak
```

Provider integration SHALL occur through:

```text
standards
approved APIs
events
provider adapters
canonical mappings
```

not shared tables.

---

# 54. Cryptographic Separation

ADR-IAM-0028 remains authoritative.

Kratos, Hydra and Keycloak SHALL NOT share cryptographic secrets merely because they belong to Baobab IAM.

At minimum, separate:

```text
Hydra signing keys
Kratos application secrets
Keycloak signing/federation keys
OAuth client credentials
SAML signing/encryption certificates
database credentials
TLS identities
backup encryption keys
```

A compromise of one provider SHALL NOT unnecessarily compromise another.

---

# 55. Federation Certificates

SAML signing/encryption certificates SHALL be governed as federation trust material.

They SHALL have:

```text
owner
purpose
provider
FederationTrust
validity
rotation procedure
revocation procedure
compromise procedure
audit trail
```

Certificate rotation SHALL support controlled overlap where the protocol and upstream enterprise support it.

---

# 56. Keycloak Signing Keys

Keycloak signing keys used for retained federation functionality SHALL NOT be treated as equivalent to Hydra's Baobab OAuth signing keys.

The two trust domains SHALL remain cryptographically distinguishable.

---

# 57. Multi-Region and Residency

ADR-IAM-0027 remains authoritative.

Provider placement SHALL respect:

```text
IdentitySecurityDomain
ResidencyPolicy
region
backup region
security classification
```

The existence of Keycloak SHALL NOT introduce a parallel region/tenant model.

Conceptually:

```text
IdentitySecurityDomain
       │
       ├── Kratos instance
       ├── Hydra instance
       └── Keycloak federation instance
```

where required.

Not every security domain necessarily requires every provider.

---

# 58. Provider Availability

Provider failure SHALL have capability-specific impact.

Example:

```text
Keycloak unavailable
      │
      ├── enterprise federation unavailable
      │
      └── native Kratos authentication MAY remain available
```

Likewise:

```text
Kratos unavailable
      │
      ├── native login affected
      │
      └── architecture SHALL avoid assuming
          Keycloak must therefore become native identity
```

Failure of one provider SHALL not silently transfer authority to another.

---

# 59. No Unsafe Automatic Provider Failover

This is prohibited:

```text
Keycloak down
     │
     ▼
automatically authenticate enterprise user
through native password
```

unless the identity has an independently valid native credential and policy explicitly permits that authentication method.

Availability SHALL NOT weaken authentication policy.

---

# 60. Provider Health

The IAM control layer SHOULD expose provider health by capability.

Conceptually:

```text
ProviderHealth
├── provider_id
├── capability
├── security_domain
├── region
├── status
├── checked_at
└── evidence
```

Health state SHALL distinguish:

```text
provider runtime health
upstream federation health
canonical trust status
```

---

# 61. Audit Normalization

ADR-IAM-0017 remains authoritative.

Provider events SHALL normalize into Baobab security/audit events.

Examples:

```text
Kratos login success
Hydra token issued
Keycloak federation success
Keycloak upstream IdP failure
FederationTrust suspended
enterprise assurance mapping failure
provider configuration changed
```

Canonical events SHALL preserve provider provenance without forcing downstream consumers to understand provider-specific event formats.

---

# 62. Security Operations

ADR-IAM-0029 remains authoritative.

Security operations SHALL correlate events across providers.

Example:

```text
Keycloak enterprise login
        │
        ▼
Hydra token issuance
        │
        ▼
CP context resolution
        │
        ▼
Trade high-risk operation
```

SHALL be traceable through correlation identifiers where practical.

---

# 63. Compromise Containment

Provider compromise SHALL be contained at the narrowest authoritative boundary.

Examples:

```text
Enterprise IdP compromised
      │
      ▼
Suspend FederationTrust
```

```text
Keycloak federation runtime compromised
      │
      ▼
Suspend affected provider instance
revoke federation sessions/trust as required
```

```text
Hydra signing key compromised
      │
      ▼
ADR-IAM-0028 emergency signing-key rotation
```

```text
Kratos credential compromise
      │
      ▼
credential/session containment
```

A provider compromise SHALL NOT automatically delete CanonicalIdentity records.

---

# 64. Privacy

ADR-IAM-0030 remains authoritative.

Each provider SHALL store only information necessary for its assigned capability.

Keycloak's retained federation deployment SHOULD minimize replicated identity attributes.

For example, Keycloak SHOULD NOT become a shadow CRM merely because enterprise attributes are available upstream.

---

# 65. Data Minimization

Federation attribute mapping SHOULD prefer:

```text
stable subject
display identity
verified email where required
assurance evidence
necessary organization/federation attributes
```

rather than wholesale directory replication.

---

# 66. Administration

ADR-IAM-0031 remains authoritative.

Administrative authority SHALL be provider-specific and least privileged.

Conceptually:

```text
Baobab IAM Platform Admin
        ≠
Kratos Admin
        ≠
Hydra Admin
        ≠
Keycloak Admin
        ≠
Customer Federation Admin
```

Access to one administrative plane SHALL NOT imply access to another.

---

# 67. Delegated Enterprise Administration

Authorized enterprise administrators MAY manage appropriate federation configuration through a Baobab-controlled administrative workflow.

They SHALL NOT receive unrestricted Keycloak administration merely because Keycloak implements federation.

Preferred:

```text
Enterprise Admin
      │
      ▼
Baobab Federation Management
      │
      ▼
validated operation
      │
      ▼
Keycloak provider adapter
```

rather than:

```text
Enterprise Admin
      │
      ▼
Keycloak Admin Console
```

---

# 68. Configuration as Code

Provider infrastructure and non-secret configuration SHALL be reproducible.

The repository SHOULD distinguish:

```text
providers/
├── ory/
│   ├── kratos/
│   └── hydra/
│
└── keycloak/
    └── federation/
```

The exact repository structure SHALL be determined after auditing the current implementation.

Provider configuration SHALL remain version-controlled where safe.

Secrets SHALL remain external.

---

# 69. Keycloak Scope Reduction

Existing Keycloak configuration SHALL be audited into:

```text
MIGRATE
RETAIN
REMOVE
DEFER
```

Examples:

| Existing Keycloak concern | Disposition |
|---|---|
| Native user credentials | MIGRATE to Kratos |
| Native passkeys/MFA | MIGRATE to Kratos |
| Native recovery | MIGRATE to Kratos |
| General OAuth clients | MIGRATE to Hydra |
| Workload clients | MIGRATE to Hydra |
| Enterprise SAML IdPs | RETAIN |
| Enterprise OIDC IdPs | RETAIN |
| Identity brokering | RETAIN |
| Federation-specific organization configuration | RETAIN where useful |
| Business roles | REMOVE / migrate to authority owner |
| Business organization truth | REMOVE |
| Keycloak themes for native login | REMOVE after estate UX migration |
| Federation-specific login UX | RETAIN or integrate behind estate UX |
| Generic realm administration assumptions | REDUCE |
| SCIM | DEFER to independent provider decision |

---

# 70. Migration Ledger

ADR-IAM-0022's migration ledger SHALL be extended with capability ownership.

Conceptually:

```text
MigrationRecord
├── object_type
├── object_id
├── source_provider
├── source_capability
├── target_provider
├── target_capability
├── migration_state
├── canonical_identity_reference
├── verification_state
├── rollback_state
└── timestamps
```

No secrets SHALL be stored in the migration ledger.

---

# 71. Keycloak Is Not Decommissioned Globally

The final Keycloak migration gate SHALL no longer require:

```text
zero Keycloak runtime
```

It SHALL require:

```text
zero unauthorized Keycloak capability ownership
```

This is a major distinction.

Migration is complete when Keycloak owns only capabilities deliberately assigned to it.

---

# 72. Ory Migration Completion Criterion

The Ory migration SHALL be considered complete for native IAM when:

```text
Kratos
    owns approved native human identity capabilities

Hydra
    owns approved OAuth/OIDC/workload capabilities

Keycloak
    no longer owns those capabilities
    except where explicitly required for federation mechanics

CP
    remains canonical authority

domain engines
    remain business authorization authorities
```

---

# 73. Provider Portability Test

Every provider capability SHOULD pass a portability test.

For enterprise federation:

> Could Baobab replace Keycloak with another SAML/OIDC broker without changing CanonicalIdentity, FederationTrust, Tenant, LegalEntity, DigitalEstate or domain authorization contracts?

If the answer is no, provider coupling has leaked into Baobab architecture.

For native identity:

> Could Baobab replace Kratos without changing CanonicalIdentity or business-domain semantics?

For OAuth:

> Could Baobab replace Hydra while retaining its canonical client/workload contracts and downstream authorization semantics?

These tests SHALL guide architecture reviews.

---

# 74. Provider Lock Manifest

`baobab-iam` SHOULD maintain a provider manifest equivalent to:

```yaml
identity_providers:

  human_identity:
    provider: ory-kratos
    version: pinned

  oauth_authorization:
    provider: ory-hydra
    version: pinned

  enterprise_federation:
    provider: keycloak
    version: pinned
```

The manifest records implementation selection.

It does not define canonical Baobab semantics.

---

# 75. Version Pinning

All IAM providers SHALL use explicitly approved versions.

Production deployments SHALL NOT use:

```text
latest
nightly
snapshot
floating major tags
unbounded floating minor tags
```

Provider upgrades SHALL follow ADR-IAM-0032 operational governance.

---

# 76. Compatibility Matrix

Baobab SHOULD maintain a compatibility matrix covering at least:

| Component | Compatibility concern |
|---|---|
| Kratos | identity schema / API / session behavior |
| Hydra | OAuth/OIDC behavior / token profile / migrations |
| Keycloak | SAML/OIDC brokering / federation configuration |
| PostgreSQL | provider-supported database versions |
| APISIX | ingress and routing |
| Digital Estates | login/federation contract |
| Control Plane | canonical principal/context contract |
| Shared | IAM schemas/events/contracts |

---

# 77. Database Architecture

Each provider SHALL retain independent database ownership.

Conceptually:

```text
Kratos
   │
   ▼
Kratos DB

Hydra
   │
   ▼
Hydra DB

Keycloak
   │
   ▼
Keycloak DB

baobab-cp
   │
   ▼
CP DB
```

No provider database is a canonical integration API.

---

# 78. PostgreSQL

Where supported by the pinned provider versions, PostgreSQL 17 remains the Baobab production database baseline for IAM persistence.

Provider compatibility SHALL be verified against the exact pinned version before deployment or upgrade.

---

# 79. Infrastructure

`baobab-platform/infrastructure` SHALL treat the three runtimes as independently deployable security-sensitive workloads.

Conceptually:

```text
IAM Namespace / Security Boundary
│
├── Kratos
│   ├── public/self-service plane
│   └── restricted admin plane
│
├── Hydra
│   ├── public OAuth plane
│   └── restricted admin plane
│
└── Keycloak Federation
    ├── federation/public plane
    └── restricted admin plane
```

Network policy SHALL expose only required surfaces.

---

# 80. Gateway

APISIX MAY provide:

```text
routing
TLS termination where appropriate
rate limiting
WAF controls
request correlation
edge observability
```

but SHALL NOT become:

```text
canonical identity authority
FederationTrust authority
tenant authority
business authorization authority
```

---

# 81. DNS and Endpoints

Provider-neutral user-facing endpoint naming SHOULD be preferred where practical.

Baobab SHOULD avoid forcing Digital Estates to hard-code provider hostnames if an IAM routing boundary can safely abstract them.

However, standards discovery and issuer semantics SHALL remain cryptographically correct.

Provider abstraction SHALL NOT falsify issuer identity.

---

# 82. Failure Isolation

The architecture SHOULD preserve the following property:

```text
Keycloak enterprise federation outage
             │
             X
             │
native Kratos authentication
```

where `X` means the outage SHOULD NOT inherently disable unrelated native authentication.

Likewise, federation failure SHOULD NOT corrupt CP canonical identity state.

---

# 83. Observability

Metrics SHOULD be capability-oriented as well as provider-oriented.

Examples:

```text
native_login_success_rate
native_login_failure_rate
enterprise_sso_success_rate
enterprise_sso_failure_rate
federation_upstream_latency
federation_provider_latency
token_issuance_latency
provider_health
assurance_mapping_failure
unknown_federation_subject
identity_mapping_conflict
FederationTrust rejection
```

Provider names MAY appear as dimensions.

They SHALL NOT replace capability semantics.

---

# 84. Reconciliation

Baobab IAM SHALL reconcile:

```text
desired provider configuration
        │
        ▼
actual provider configuration
```

for each provider.

For Keycloak federation this MAY include:

```text
configured IdPs
expected FederationTrust mappings
organization associations
redirect URIs
certificates
attribute mappings
assurance mappings
enabled/disabled status
```

Drift SHALL be observable.

---

# 85. Federation Drift

Example:

```text
Baobab:
FederationTrust = SUSPENDED

Keycloak:
IdP = ENABLED
```

is security-significant drift.

The reconciler SHALL converge toward the Baobab-approved state or fail safely.

---

# 86. Provider Failure Does Not Change Authority

If provider state and canonical Baobab state disagree:

```text
canonical security restriction
```

SHALL win.

Examples:

```text
Keycloak says federation active
CP says organization suspended
        │
        ▼
DENY
```

```text
Kratos session valid
CP membership revoked
        │
        ▼
DENY
```

```text
Hydra token valid
CapabilityBinding revoked
        │
        ▼
DENY
```

---

# 87. No Business Authorization in Provider Adapters

Provider adapters SHALL NOT contain rules such as:

```text
if keycloak_group == "buyers":
    allow_purchase()
```

They MAY normalize identity evidence.

They SHALL NOT become domain authorization engines.

---

# 88. Workload Identity

Hydra remains the default workload-token provider.

Keycloak's retained presence SHALL NOT cause workload identities to migrate back to Keycloak.

The preferred model remains:

```text
Workload
    │
    ▼
Hydra
    │
    ▼
short-lived token
    │
    ▼
CP context/capability validation
    │
    ▼
target service
```

with mTLS or stronger client authentication where required.

---

# 89. ERP SSO

iDempiere integration SHALL remain provider neutral.

The ERP SHALL receive an approved Baobab identity/token profile.

It SHALL NOT need to know whether the original human authenticated through:

```text
Kratos
Keycloak federation
Entra
Okta
SAML
OIDC
```

Canonical mapping remains:

```text
External Identity
      │
      ▼
CanonicalIdentity
      │
      ▼
CP context
      │
      ▼
AD_User
      │
      ▼
AD_Role / AD_Client / AD_Org
```

---

# 90. Trade SSO

Trade SHALL likewise remain provider neutral.

Enterprise authentication SHALL NOT replace Trade buyer-organization membership or purchasing authority.

```text
SSO
    │
    ▼
authenticated human
    │
    ▼
CP organization context
    │
    ▼
Trade customer/buyer relationship
    │
    ▼
Trade authorization
```

---

# 91. CMS SSO

CMS authentication MAY originate from native or federated identity.

Payload's own domain authorization remains independent.

Federation SHALL not create CMS administrative authority automatically.

---

# 92. Supplier Access

Supplier federation MAY be supported.

However:

```text
successful supplier-company SSO
        ≠
approved supplier
```

and:

```text
enterprise employee
        ≠
authorized supplier representative
```

Supplier approval and representative relationships remain governed by their authoritative domain workflows.

---

# 93. Thamani B2B and B2C

Thamani requires both:

```text
B2C identities
```

and:

```text
B2B enterprise identities
```

The same human MAY be:

```text
personal shipper
consignee
recipient
Company A employee
Company B representative
carrier representative
```

Therefore provider identity SHALL remain separate from business relationships.

Native personal authentication MAY use Kratos.

Enterprise business authentication MAY use Keycloak federation.

Both SHALL converge on CanonicalIdentity.

---

# 94. ZuriBeans B2B

ZuriBeans enterprise buyers MAY use:

```text
native Baobab authentication
```

or:

```text
enterprise SSO
```

depending on organization policy.

Authentication method SHALL NOT change Trade's authoritative purchasing model.

---

# 95. Migration Safety

No existing identity SHALL be migrated merely because this ADR introduces multi-provider architecture.

Migration SHALL remain:

```text
planned
cohort-based
observable
reversible where practical
identity-preserving
security-preserving
```

---

# 96. Dual Provider Does Not Mean Duplicate Person

During migration a person MAY temporarily have:

```text
ExternalIdentity
    provider = legacy Keycloak native

ExternalIdentity
    provider = Kratos

ExternalIdentity
    provider = enterprise federation
```

all mapped to:

```text
one CanonicalIdentity
```

where identity linking has been established safely.

---

# 97. Legacy Keycloak Native Identity Retirement

Legacy native Keycloak identities SHALL eventually be classified as:

```text
MIGRATED
FEDERATION_ONLY
EXCEPTION
RETIRED
```

No account SHALL remain indefinitely ambiguous between native and federation authority.

---

# 98. Keycloak Realm Strategy

Keycloak's retained realm architecture SHALL be optimized for federation rather than reproducing Baobab tenancy.

A realm-per-tenant model remains rejected unless a security, sovereignty or contractual requirement justifies it.

Provider realm boundaries SHALL NOT be inferred from Baobab tenant boundaries.

---

# 99. Keycloak Extensions

Baobab SHALL prefer:

```text
native Keycloak federation capability
        ↓
standards-compliant configuration
        ↓
external Baobab adapter
        ↓
minimal Keycloak extension
        ↓
Keycloak fork
```

A general-purpose Keycloak fork remains prohibited without a dedicated ADR.

---

# 100. Keycloak SCIM Preview Features

The existence of provider-specific SCIM functionality SHALL NOT automatically make that provider Baobab's SCIM authority.

Preview or experimental features SHALL NOT become production architectural dependencies without explicit evaluation and acceptance.

SCIM provider selection remains separate.

---

# 101. Provider-Neutral Contract Tests

Baobab SHALL implement contract tests demonstrating equivalent canonical outcomes across providers.

Examples:

```text
Kratos authenticated Jane
        │
        ▼
CanonicalIdentity = C123
```

and:

```text
ACME SAML → Keycloak → Jane
        │
        ▼
CanonicalIdentity = C123
```

where controlled identity linking establishes the same person.

The downstream context contract SHALL not differ merely because authentication providers differ.

---

# 102. Federation Contract Tests

Tests SHALL cover at least:

```text
OIDC federation
SAML federation
unknown IdP
suspended FederationTrust
revoked FederationTrust
wrong issuer
wrong audience
invalid signature
expired assertion/token
subject mapping
attribute mapping
assurance mapping
organization scope
estate scope
identity collision
no email auto-linking
provider outage
upstream outage
certificate rotation
logout behavior
reconciliation drift
```

---

# 103. Security Tests

Security testing SHALL include:

```text
IdP mix-up
issuer confusion
audience confusion
SAML signature validation
SAML destination validation
SAML replay
OIDC state/nonce validation
redirect URI validation
login CSRF
account linking attacks
email takeover
FederationTrust spoofing
organization confusion
cross-tenant federation leakage
upstream token leakage
admin-plane exposure
provider compromise containment
```

---

# 104. Resilience Tests

Resilience testing SHALL prove:

```text
Keycloak outage does not corrupt Kratos
Kratos outage does not transfer authority to Keycloak
Hydra outage does not corrupt federation trust
provider restart preserves correct state
federation config can be reconstructed
database restore is provider-isolated
key rotation survives provider restart
regional recovery preserves FederationTrust
```

---

# 105. ADR-IAM-0019 Amendment

ADR-IAM-0019 remains authoritative for:

```text
provider neutrality
Ory native identity migration
canonical identity preservation
CP authority
domain authorization
Baobab-owned UX
provider portability
```

It is superseded where it implies:

```text
Ory must implement every IAM capability
```

or:

```text
Keycloak must be completely removed from Baobab
```

---

# 106. ADR-IAM-0020 Amendment

ADR-IAM-0020 remains authoritative but its provider contract SHALL now be interpreted as:

```text
capability-oriented
multi-provider
```

rather than:

```text
one interchangeable universal IdP
```

The preferred abstraction is multiple narrow provider interfaces.

---

# 107. ADR-IAM-0021 Amendment

ADR-IAM-0021 remains authoritative for Ory runtime architecture.

Its scope is clarified:

```text
Kratos
    native human identity runtime

Hydra
    OAuth/OIDC runtime
```

It SHALL NOT be interpreted as requiring Ory to own enterprise federation.

---

# 108. ADR-IAM-0022 Amendment

ADR-IAM-0022 is superseded where it defines final Keycloak decommissioning as complete runtime removal.

The revised cutover target is:

```text
Keycloak-centric
      │
      ▼
multi-provider
```

not:

```text
Keycloak
      │
      ▼
zero Keycloak
```

Keycloak federation capability SHALL survive migration.

---

# 109. ADR-IAM-0026 Amendment

ADR-IAM-0026 remains authoritative for:

```text
FederationTrust
organization verification
OIDC/SAML federation
assurance mapping
enterprise lifecycle
SCIM semantics
canonical identity
no email auto-linking
organization separation
```

Its statement:

```text
Identity Runtime:
Ory Kratos + Ory Hydra,
with enterprise federation through Ory
```

is superseded.

The revised model is:

```text
Native Identity:
Ory Kratos

OAuth/OIDC:
Ory Hydra

Enterprise Federation:
provider-neutral capability
initially Keycloak
```

---

# 110. ADR-IAM-0027 Amendment

Multi-region topology SHALL consider each provider independently while preserving the common IdentitySecurityDomain.

Keycloak's retained federation runtime SHALL comply with residency, failover, fencing and DR requirements applicable to its data and security role.

---

# 111. ADR-IAM-0028 Amendment

Cryptographic governance SHALL explicitly include Keycloak federation:

```text
SAML signing keys
SAML encryption keys
OIDC federation client credentials
broker signing keys
federation certificates
upstream trust anchors
```

without merging them with Hydra signing authority.

---

# 112. ADR-IAM-0029 Amendment

Security operations SHALL treat:

```text
enterprise federation compromise
Keycloak federation compromise
upstream IdP compromise
```

as first-class incident classes.

Containment SHOULD allow suspension of the affected FederationTrust without unnecessarily disabling unrelated native authentication.

---

# 113. ADR-IAM-0030 Amendment

Privacy governance SHALL apply to identity attributes replicated into Keycloak.

Federation data SHOULD be minimized and retained according to Baobab privacy policy.

---

# 114. ADR-IAM-0031 Amendment

Privileged administration SHALL recognize distinct:

```text
Kratos administration
Hydra administration
Keycloak federation administration
FederationTrust administration
```

with separation of duties.

---

# 115. ADR-IAM-0032 Amendment

Production governance SHALL include all active IAM providers.

Operational acceptance SHALL therefore assess:

```text
Kratos
Hydra
Keycloak federation
provider resolution
cross-provider identity normalization
cross-provider observability
cross-provider incident response
```

---

# 116. Rejected Alternative — Return Fully to Keycloak

Rejected:

```text
Keycloak
    owns everything again
```

because this would restore the coupling ADR-IAM-0019 intentionally removed.

It would also make future provider substitution unnecessarily expensive.

---

# 117. Rejected Alternative — Force All Enterprise SSO Through Ory

Rejected as a mandatory architecture.

Baobab SHALL not make its enterprise SSO roadmap dependent on a single provider's commercial packaging, deployment mode or enterprise feature availability.

Ory enterprise federation MAY become another provider implementation later.

---

# 118. Rejected Alternative — One Keycloak per Enterprise Customer

Rejected by default.

It creates:

```text
operational proliferation
upgrade complexity
configuration drift
resource overhead
backup complexity
security-management overhead
```

Dedicated instances MAY be justified by:

```text
regulatory isolation
contractual isolation
security-domain isolation
data sovereignty
extreme blast-radius requirements
```

through an explicit isolation decision.

---

# 119. Rejected Alternative — Put SAML in Every Digital Estate

Rejected.

SAML/OIDC enterprise federation belongs at the IAM boundary.

Digital Estates SHALL not become federation engines.

---

# 120. Rejected Alternative — Put SAML in Domain Engines

Rejected.

Trade, ERP and CMS SHALL consume normalized identity/context.

They SHALL NOT independently broker enterprise identity.

---

# 121. Rejected Alternative — Keycloak Organization as Tenant

Rejected.

The provider's organization abstraction is not Baobab's canonical business ontology.

---

# 122. Rejected Alternative — Universal Provider Chaining

Rejected:

```text
everything
   ↓
Keycloak
   ↓
Ory
   ↓
Baobab
```

because provider neutrality does not justify needless runtime dependency.

---

# 123. Implementation Programme

ADR-IAM-0033 introduces the following implementation gates.

| Gate | Objective |
|---|---|
| IAM-MP0 | Current-state and migration-branch reconciliation |
| IAM-MP1 | Capability taxonomy and provider ownership matrix |
| IAM-MP2 | Provider-neutral contract extensions |
| IAM-MP3 | Provider capability registry |
| IAM-MP4 | Provider resolver |
| IAM-MP5 | Kratos capability-boundary confirmation |
| IAM-MP6 | Hydra capability-boundary confirmation |
| IAM-MP7 | Keycloak federation-runtime reduction |
| IAM-MP8 | EnterpriseFederationProvider adapter |
| IAM-MP9 | FederationTrust/provider binding |
| IAM-MP10 | Enterprise login discovery/routing |
| IAM-MP11 | Federation-to-canonical identity normalization |
| IAM-MP12 | Assurance normalization and step-up integration |
| IAM-MP13 | SCIM provider decoupling |
| IAM-MP14 | Cross-provider events/audit/reconciliation |
| IAM-MP15 | Cryptographic and secret separation |
| IAM-MP16 | Multi-provider HA/DR/residency |
| IAM-MP17 | Digital Estate integration |
| IAM-MP18 | Migration/cutover reconciliation |
| IAM-MP19 | Security and resilience certification |
| IAM-MP20 | Production operational acceptance |

---

# 124. IAM-MP0 — Reconcile Current Implementation

Before modifying code:

```text
audit main
audit open PRs
audit migration branches
audit Keycloak assets
audit Kratos assets
audit Hydra assets
audit Shared contracts
audit CP provider/capability contracts
audit infrastructure
```

Every existing Keycloak asset SHALL be classified:

```text
MIGRATE
RETAIN
REMOVE
DEFER
```

No migration task SHALL delete a retained federation asset merely because ADR-IAM-0022 previously expected full retirement.

---

# 125. IAM-MP1 — Capability Matrix

Create the normative provider-capability matrix.

No implementation SHALL proceed from product assumptions alone.

---

# 126. IAM-MP2 — Contracts

`baobab-platform/shared` SHALL define or amend the minimum cross-repository contracts necessary to express:

```text
IdentityCapability
IdentityCapabilityProvider
ProviderCapabilityBinding
FederationTrust provider binding
ExternalPrincipal
normalized assurance evidence
provider lifecycle state
```

without embedding Keycloak or Ory-specific semantics into canonical contracts.

---

# 127. IAM-MP3 — Provider Registry

Implement the provider registry and provider-instance metadata required by IAM.

Reuse existing Baobab provider/engine/capability concepts where semantically appropriate rather than inventing a competing architecture.

---

# 128. IAM-MP4 — Provider Resolver

Implement deterministic capability resolution.

Resolution SHALL be:

```text
testable
observable
fail-safe
security-domain aware
residency aware
```

and SHALL not permit arbitrary user-controlled provider selection.

---

# 129. IAM-MP5 / MP6 — Ory Boundaries

Verify that Kratos and Hydra implementations conform exactly to their assigned capabilities.

Remove accidental assumptions that either is the universal IAM provider.

---

# 130. IAM-MP7 — Reduce Keycloak

Transform the retained Keycloak deployment from:

```text
general Baobab IdP
```

into:

```text
enterprise federation provider
```

without prematurely deleting federation configuration.

---

# 131. IAM-MP8 — Federation Adapter

Implement:

```text
EnterpriseFederationProvider
```

with Keycloak as the initial adapter.

Canonical code SHALL depend on the interface/capability, not Keycloak APIs.

---

# 132. IAM-MP9 — FederationTrust Binding

Bind canonical FederationTrust records to provider instances through explicit provider bindings and external references.

---

# 133. IAM-MP10 — Login Discovery

Implement provider-neutral enterprise login discovery.

Digital Estates SHALL not embed provider-specific routing logic.

---

# 134. IAM-MP11 — Identity Normalization

Ensure native and federated identities converge safely through:

```text
ExternalIdentity
      │
      ▼
CanonicalIdentity
```

with no email auto-linking.

---

# 135. IAM-MP12 — Assurance

Normalize provider-specific authentication evidence into ADR-IAM-0024 assurance levels.

Test both native and enterprise federation flows.

---

# 136. IAM-MP13 — SCIM

Keep lifecycle provisioning independently selectable.

Do not couple SCIM implementation to Keycloak merely because federation uses Keycloak.

---

# 137. IAM-MP14 — Events and Reconciliation

Normalize provider events and implement provider-state reconciliation.

---

# 138. IAM-MP15 — Cryptography

Verify independent:

```text
keys
certificates
secrets
trust anchors
client credentials
```

for Kratos, Hydra and Keycloak.

---

# 139. IAM-MP16 — Resilience

Prove independent provider failure domains and DR procedures.

---

# 140. IAM-MP17 — Digital Estates

Validate at minimum:

```text
ZuriBeans B2B native login
ZuriBeans enterprise SSO

Thamani B2C native login
Thamani B2B enterprise SSO

Nabhold workforce/enterprise login
```

without provider-specific domain logic.

---

# 141. IAM-MP18 — Migration Reconciliation

Reconcile ADR-IAM-0022 implementation state.

Cancel tasks whose only purpose was deleting the Keycloak federation capability.

Continue migration tasks that move native identity/OAuth responsibilities to Ory.

---

# 142. IAM-MP19 — Security Certification

Run:

```text
federation security tests
cross-provider identity tests
account-linking attack tests
tenant-isolation tests
provider-compromise tests
key/certificate rotation tests
failure-mode tests
DR exercises
```

before production acceptance.

---

# 143. IAM-MP20 — Production Acceptance

Production acceptance SHALL require evidence that:

```text
providers own only approved capabilities
canonical contracts contain no provider leakage
federation is operational
native authentication is operational
OAuth/workload issuance is operational
provider failures are isolated
audit correlation works
reconciliation works
DR works
security tests pass
```

---

# 144. Production Invariants

The following invariants are mandatory:

```text
Provider != CanonicalIdentity

Provider Organization != Tenant

Provider Organization != LegalEntity

Authentication != Authorization

Federation != Business Membership

SSO != MFA

SSO != SCIM

SCIM != Authorization

Keycloak != Baobab IAM

Ory != Baobab IAM

Kratos Session != CP Context

Keycloak Session != CP Context

Hydra Token != Business Authority

Valid Federation != Tenant Entitlement

Valid Token != Domain Authorization

Provider Availability != Security Authority
```

---

# 145. Decision Consequences

## Positive

Baobab gains:

```text
self-hosted enterprise SSO
SAML interoperability
enterprise OIDC federation
reduced dependence on one provider
continued Ory migration
stronger provider neutrality
capability-oriented architecture
smaller Keycloak responsibility
future provider portability
failure isolation
better alignment with Baobab's wider provider model
```

## Negative

Baobab must operate:

```text
Kratos
Hydra
Keycloak
```

rather than two IAM runtimes.

This increases:

```text
deployment complexity
observability requirements
patching responsibility
database operations
security monitoring
integration testing
DR complexity
```

The architecture accepts this cost because the providers perform materially different bounded capabilities and because enterprise federation is a business requirement.

---

# 146. Strategic Consequence

The architecture deliberately chooses:

```text
more runtime components
```

in exchange for:

```text
less architectural coupling
```

This is acceptable only while capability boundaries remain strict.

If Keycloak gradually regains unrelated responsibilities, the architecture SHALL be considered to have regressed.

---

# 147. Future Evolution

The provider registry allows future changes such as:

```text
ENTERPRISE_SSO
        │
        ▼
Keycloak
```

becoming:

```text
ENTERPRISE_SSO
        │
        ▼
another provider
```

without redefining Baobab canonical identity.

Likewise:

```text
HUMAN_AUTHENTICATION
        │
        ▼
Kratos
```

may someday change without redefining Baobab's business ontology.

That is the practical meaning of provider neutrality.

---

# 148. Final Decision

Baobab SHALL NOT choose between:

```text
Ory
```

and:

```text
Keycloak
```

as mutually exclusive platform identities.

Baobab SHALL own the identity architecture.

Providers SHALL implement bounded capabilities within it.

The authoritative architecture is:

```text
                         BAOBAB IAM
                    Provider-Neutral Boundary
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
         Ory Kratos       Ory Hydra        Keycloak
             │                │                │
       Human identity     OAuth/OIDC       Enterprise
       Credentials        Token issuer     Federation
       Passkeys/MFA       Workloads        SAML/OIDC SSO
       Recovery                           Identity brokering
       Sessions                           Enterprise IdPs
             │                │                │
             └────────────────┼────────────────┘
                              │
                       ExternalIdentity
                              │
                              ▼
                       CanonicalIdentity
                              │
                              ▼
                         baobab-cp
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
            Trade            ERP             CMS
```

The permanent architectural rule is:

> **Baobab owns identity semantics and capability contracts. Providers implement bounded identity capabilities. Ory Kratos owns the initial native human-identity capability, Ory Hydra owns the initial OAuth/OIDC and workload-token capability, and Keycloak owns the initial enterprise federation and SSO capability. None of them owns canonical Baobab identity, tenant context or business authorization.**

Or, more concisely:

```text
BAOBAB OWNS THE CONTRACT
          │
          ▼
CAPABILITY DEFINES THE NEED
          │
          ▼
PROVIDER IMPLEMENTS THE CAPABILITY
          │
     ┌────┼────┐
     ▼    ▼    ▼
 Kratos Hydra Keycloak
```

This decision supersedes any earlier Baobab IAM requirement that provider neutrality requires complete Keycloak removal or that Ory must implement every IAM capability.

It does **not** reverse the Ory migration.

It completes the architectural objective behind that migration:

> **Baobab IAM is provider-neutral precisely because neither Ory nor Keycloak is Baobab IAM.**