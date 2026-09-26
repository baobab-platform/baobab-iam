# ADR-IAM-0019 — Migration from Keycloak to Ory and Provider-Neutral Baobab Identity Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/baobab-cp`, `baobab-platform/shared`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/infrastructure`, ZuriBeans, Thamani, Nabhold and future Baobab Digital Estates  
**Decision Type:** Platform Architecture / Identity / Security / Migration  
**Supersedes:** ADR-0002 — Keycloak as the Baobab Identity Provider  
**Amends:** ADR-0001, ADR-0003 through ADR-0018 where provider-specific Keycloak implementation assumptions occur  
**Preserves:** The canonical identity, authority-boundary, tenancy, context, workload, domain-authorization, lifecycle, audit and resilience architecture established by ADR-0001 through ADR-0018  
**Selected Identity Technology:** Ory Kratos + Ory Hydra  
**Explicitly Not Adopted at This Stage:** Ory Keto, Ory Oathkeeper, provider-owned Baobab authorization, provider-owned Baobab tenancy

---

# 1. Decision Summary

Baobab SHALL migrate its platform identity runtime from **Keycloak** to a deliberately **provider-neutral Baobab identity architecture**, initially implemented using:

- **Ory Kratos** for human identity, credentials, authentication, authentication sessions, recovery, verification, MFA/passkeys and identity lifecycle;
- **Ory Hydra** for OAuth 2.x, OpenID Connect, authorization-code flows, PKCE, workload authentication, token issuance, OAuth clients and standards-based service-to-service authentication;
- **Baobab-owned Digital Estate identity user interfaces** for ZuriBeans, Thamani and future estates;
- `baobab-iam` as the provider integration, configuration, lifecycle, migration, reconciliation and identity-policy boundary;
- `baobab-cp` as the continuing authority for canonical identity association, tenant context, legal entities, Digital Estates, markets, capabilities, capability bindings, platform memberships, engine resolution and platform authorization;
- authoritative domain engines as the continuing authorities for domain-specific authorization.

The migration SHALL **not** invalidate or discard the architectural work already completed under ADR-0001 through ADR-0018.

The fundamental Baobab authority model remains:

```text
WHO is this actor?
        │
        ▼
Identity Infrastructure
Ory Kratos / Ory Hydra

IN WHICH BAOBAB CONTEXT MAY THE ACTOR OPERATE?
        │
        ▼
Baobab Control Plane

WHAT MAY THE ACTOR DO IN THAT CONTEXT?
        │
        ▼
Authoritative Domain Engine
```

The primary architectural change is therefore **not merely**:

```text
Keycloak
   ↓
Ory
```

It is:

```text
Provider-coupled IAM
        ↓
Provider-neutral Baobab Identity Architecture
        ↓
Ory as the initial identity-engine implementation
```

This distinction is normative.

---

# 2. Context

Baobab has already invested substantially in its identity architecture.

The existing IAM programme established eighteen ADRs covering:

1. IAM architecture;
2. Keycloak selection;
3. trust boundaries;
4. canonical identity;
5. realm/organization/tenant/legal-entity separation;
6. OIDC/OAuth token architecture;
7. workload identity;
8. platform authorization;
9. workforce SSO;
10. ZuriBeans B2B identity;
11. Thamani customer identity;
12. supplier identity;
13. Medusa authentication;
14. iDempiere SSO;
15. credentials/MFA/passkeys/recovery;
16. lifecycle/revocation/deprovisioning;
17. audit/observability;
18. availability/backup/DR.

Implementation has also progressed materially.

Repository inspection at the time of this decision shows that the programme is **not greenfield**. Among the implemented or partially implemented capabilities are:

- the Control Plane `CanonicalIdentity` / `ExternalIdentity` identity spine;
- workload identity contracts and registered workload clients;
- OIDC scopes and actor-type distinctions;
- Trade workforce/admin OIDC integration;
- Payload CMS OIDC integration;
- ZuriBeans browser and workload clients;
- Thamani browser and workload client scaffolding;
- iDempiere workforce OIDC groundwork;
- CP context/mapping endpoint protection;
- role and scope governance;
- MFA-related workforce configuration;
- administrative audit logging;
- identity disable/revoke-session kill-switch testing;
- credential/audit security tests;
- workload isolation tests;
- ZuriBeans/Thamani structural isolation tests;
- workload lifecycle registry consistency checks;
- CI security scanning;
- SBOM generation;
- disaster-recovery documentation;
- incident-response documentation;
- production-hardening work;
- multi-region/residency analysis;
- canonical contracts shared across repositories.

The current repository itself states that all original IAM gates have received at least a phase-one pass, while numerous later phases remain incomplete.

Therefore this ADR SHALL NOT treat the previous implementation as disposable.

---

# 3. Problem Statement

Keycloak is capable, but the Baobab implementation has demonstrated that maintaining Keycloak-specific realm exports, authentication flows, Organizations configuration, themes, client definitions, administrative semantics, extensions and operational hardening consumes significant engineering effort.

Several unresolved or partially implemented items are specifically Keycloak-oriented rather than Baobab-domain requirements.

Examples include:

```text
Keycloak realm configuration
Keycloak Organizations
Keycloak-specific browser flows
Keycloak conditional OTP flows
Keycloak theme configuration
Keycloak Admin Events API
Keycloak event-listener SPI decisions
Keycloak realm exports
Keycloak client-role configuration
Keycloak bootstrap mechanics
Keycloak image/runtime hardening
```

At the same time, much of the completed work is **not inherently Keycloak-specific**.

Examples include:

```text
CanonicalIdentity
ExternalIdentity
issuer + subject identity mapping
human/workload distinction
workload registry
scope contracts
tenant isolation
context resolution
CapabilityBinding
EngineInstance resolution
Trade domain authorization
ERP domain authorization
supplier approval boundaries
audit contracts
security events
DR invariants
revocation semantics
```

The architecture therefore requires a migration that distinguishes carefully between:

1. **Baobab architectural assets that remain;**
2. **standards-based integration that can be retained with configuration changes;**
3. **Keycloak-specific implementation that must be replaced;**
4. **unfinished work that should now be implemented against the provider-neutral architecture instead of Keycloak.**

---

# 4. Research Basis

This decision was informed by current Ory documentation and published migration experience.

Ory Kratos is an API-first, headless identity and user-management system. It provides login, registration, MFA, recovery, profile management and sessions while intentionally leaving the user interface to the consuming product. Ory documents Kratos as available in open-source, commercial self-hosted and managed forms.

Ory Hydra is a Go-based OAuth 2.0 and OpenID Connect server. It is OpenID Certified, supports machine-to-machine authentication and deliberately does not own user/password management; authentication is delegated to Kratos or another identity system.

This decomposition is materially aligned with Baobab's existing separation of concerns.

## 4.1 Relevant Azure AD migration evidence

Ory's published HGV case study describes the migration of **27 applications in approximately 30 days** from Azure AD B2C to Ory Network. HGV cited complex user flows, customization constraints and outages among the reasons for migration.

This evidence is vendor-published customer testimony and SHALL therefore be treated as migration evidence rather than an independent performance benchmark.

Nevertheless, it demonstrates that Ory has been used in a real multi-application replacement of an established CIAM platform.

## 4.2 Relevant composable-platform evidence

The commercetools case is especially relevant to Baobab because commercetools operates a composable/headless commerce architecture.

Its published case study describes:

- more than 20,000 monthly enterprise business users;
- B2B identity requirements;
- custom authentication UX;
- headless integration;
- multi-region requirements;
- migration away from fragmented identity systems;
- the desire to avoid implementing authentication/security primitives internally.

The ability to **bring a custom UI** was explicitly identified as a major selection factor.

This resembles Baobab's architectural philosophy:

```text
Specialized Headless Engine
        │
        ▼
Canonical Baobab Boundary
        │
        ▼
Baobab-owned Digital Experience
```

Ory permits the identity layer to follow the same model.

## 4.3 Migration capabilities

Kratos supports bulk identity import using existing password hashes and supports multiple hash formats including bcrypt, Argon2, PBKDF2 and scrypt. It also supports graceful password migration using a webhook where credentials cannot be imported directly.

Recent Ory releases additionally support importing TOTP, lookup-secret, WebAuthn, passkey, OIDC and SAML credential types through identity administration APIs.

These capabilities materially reduce migration risk from the existing Keycloak deployment.

---

# 5. Architectural Principle

This ADR establishes the following permanent architectural principle:

> **Baobab SHALL depend on identity standards and Baobab identity contracts, not on the business model of a particular identity provider.**

Ory is selected as the initial implementation of this architecture.

Ory SHALL NOT become a new source of Baobab business truth.

---

# 6. Provider-Neutral Identity Boundary

The following conceptual model becomes authoritative:

```text
                   IDENTITY PROVIDER / ENGINE
                         Ory today
                            │
                            │
                  OAuth / OIDC / APIs
                            │
                            ▼
                ┌───────────────────────┐
                │      baobab-iam       │
                │                       │
                │ provider integration  │
                │ lifecycle             │
                │ provisioning          │
                │ event normalization   │
                │ reconciliation        │
                │ migration             │
                │ identity policy       │
                └───────────┬───────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │       baobab-cp       │
                │                       │
                │ CanonicalIdentity     │
                │ ExternalIdentity      │
                │ Membership            │
                │ Tenant                │
                │ LegalEntity           │
                │ DigitalEstate         │
                │ Market                │
                │ Capability            │
                │ CapabilityBinding     │
                │ EngineInstance        │
                └───────────┬───────────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
        Trade              ERP              CMS
       MedusaJS         iDempiere          Payload
```

However, `baobab-iam` SHALL NOT become a mandatory synchronous hop for every authenticated request.

Normal standards-based validation SHOULD follow:

```text
Client
  │
  │ access token
  ▼
Resource Server
  │
  ├── validate issuer
  ├── validate signature/JWKS
  ├── validate audience
  ├── validate expiry
  ├── validate required scopes
  │
  ▼
issuer + subject
  │
  ▼
baobab-cp identity/context resolution
```

This prevents `baobab-iam` from becoming an unnecessary availability bottleneck.

---

# 7. Selected Ory Components

Baobab SHALL initially adopt only:

```text
Ory Kratos
+
Ory Hydra
```

Baobab SHALL NOT initially adopt:

```text
Ory Keto
Ory Oathkeeper
```

unless a later ADR demonstrates a requirement.

The reason is architectural duplication.

Baobab already has:

```text
baobab-cp
    → platform authorization

APISIX / infrastructure
    → gateway concerns

domain engines
    → domain authorization
```

Introducing Keto or Oathkeeper without a proven requirement risks creating overlapping authorities.

---

# 8. Ory Kratos Responsibility

Kratos SHALL own human authentication concerns including, where configured:

- identity records used for authentication;
- credential material;
- password authentication;
- passkeys/WebAuthn;
- TOTP/MFA;
- verification;
- recovery;
- authentication sessions;
- social/federated identity connection;
- self-service authentication flows;
- authentication lifecycle hooks.

Kratos SHALL NOT own:

- Baobab Tenant;
- LegalEntity;
- Market;
- DigitalEstate;
- Capability;
- CapabilityBinding;
- BuyerOrganization authorization;
- supplier approval;
- purchase authority;
- ERP permissions;
- canonical Baobab business relationships.

---

# 9. Ory Hydra Responsibility

Hydra SHALL own standards-based authorization-server concerns including:

- OAuth 2.x;
- OpenID Connect;
- authorization-code flow;
- PKCE;
- OAuth clients;
- client credentials;
- workload token issuance;
- token lifecycle;
- OAuth consent where applicable;
- cryptographic signing;
- token introspection where required.

Hydra supports machine-to-machine authentication using Client Credentials and private-key/JWT-based client authentication.

Hydra SHALL NOT become Baobab's business authorization server.

---

# 10. Authority Model — Unchanged

The following ADR-0001 principle remains authoritative:

> **Baobab IAM proves identity. Baobab Control Plane determines platform context and entitlement. Each authoritative engine determines business-domain authorization.**

With Ory, this becomes:

```text
Authentication
      │
      ▼
Kratos / Hydra
      │
      ▼
Canonical identity and context
      │
      ▼
baobab-cp
      │
      ▼
Domain authorization
      │
      ├── Trade
      ├── ERP
      ├── CMS
      └── other authoritative engines
```

---

# 11. What Remains Unchanged

The following architecture SHALL remain.

## 11.1 Canonical identity

```text
External Identity
      │
      ▼
CanonicalIdentity
```

`CanonicalIdentity` remains provider-independent.

Changing authentication provider SHALL NOT create a new canonical person.

## 11.2 Identity key

The fundamental external identity mapping remains based on stable provider identity evidence:

```text
issuer + provider subject
```

not:

```text
email
```

Email matching SHALL NOT automatically merge identities.

## 11.3 Tenant authority

Tenant remains owned by `baobab-cp`.

```text
Kratos Identity ≠ Tenant
Hydra Client    ≠ Tenant
Ory Organization ≠ Tenant
```

where any Ory organization feature is later used.

## 11.4 Legal entities

```text
Identity Provider Organization
        ≠
LegalEntity
```

## 11.5 Markets and regions

```text
Market ≠ Region
Identity Region ≠ Market
Identity Region ≠ Tenant
```

## 11.6 Domain authorization

Trade remains authoritative for commerce authorization.

iDempiere remains authoritative for ERP authorization.

Payload remains authoritative for CMS domain authorization.

Supplier-domain approval remains separate from authentication.

---

# 12. What Changes

The following Keycloak-specific implementation SHALL be retired or translated.

| Current | Target |
|---|---|
| Keycloak realm | Ory deployment/security domain configuration |
| Keycloak users | Kratos identities |
| Keycloak browser authentication flows | Kratos self-service flows |
| Keycloak Organizations | Baobab domain relationships and, only where needed, Ory enterprise identity federation |
| Keycloak clients | Hydra OAuth/OIDC clients |
| Keycloak service accounts | Hydra workload clients |
| Keycloak realm roles | Provider-neutral IAM/admin scopes or domain-owned roles |
| Keycloak conditional OTP | Kratos assurance/MFA flows |
| Keycloak Admin Events | Kratos/Hydra lifecycle events normalized by Baobab |
| Keycloak event-listener SPI | Ory hooks/webhooks/event integration |
| Keycloak realm export | Ory configuration-as-code |
| Keycloak themes | Baobab-owned Digital Estate identity UI |
| Keycloak Admin API | Kratos/Hydra administrative APIs |
| Keycloak image/runtime | Kratos/Hydra runtime images |
| Keycloak bootstrap | Ory idempotent provisioning/bootstrap |

---

# 13. `baobab-iam` SHALL NOT Be Deleted

The `baobab-iam` repository remains strategically necessary.

Its role changes.

Before:

```text
baobab-iam
     │
     ▼
Keycloak deployment/configuration
```

After:

```text
                 baobab-iam
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
     Kratos        Hydra       Integration
     config        config       boundary
        │            │             │
        └────────────┼─────────────┘
                     │
              lifecycle/events
                     │
              reconciliation
                     │
                 migration
```

A target structure SHOULD resemble:

```text
baobab-iam/
├── kratos/
│   ├── config/
│   ├── schemas/
│   ├── hooks/
│   └── migrations/
│
├── hydra/
│   ├── config/
│   ├── clients/
│   ├── scopes/
│   └── policies/
│
├── internal/
│   ├── provider/
│   ├── lifecycle/
│   ├── provisioning/
│   ├── reconciliation/
│   ├── events/
│   ├── audit/
│   └── migration/
│
├── contracts/
├── deployments/
├── tests/
├── docs/
└── provider.lock.yaml
```

The precise structure SHALL be validated against the current repository before refactoring.

---

# 14. Provider-Neutral Contract

Baobab SHOULD define an explicit provider capability contract.

Conceptually:

```go
type IdentityProvider interface {
    GetIdentity(
        context.Context,
        ExternalSubject,
    ) (*ProviderIdentity, error)

    DisableIdentity(
        context.Context,
        ExternalSubject,
    ) error

    RevokeSessions(
        context.Context,
        ExternalSubject,
    ) error

    ProvisionWorkload(
        context.Context,
        WorkloadSpec,
    ) (*WorkloadIdentity, error)
}
```

This abstraction SHALL apply only to provider-specific lifecycle/management operations.

Baobab SHALL NOT abstract standard protocols unnecessarily.

The following SHOULD remain direct standards:

```text
OIDC Discovery
OAuth Authorization
OAuth Token Endpoint
JWKS
Token Introspection
PKCE
OAuth Client Credentials
```

Baobab SHALL NOT create a proprietary "Baobab OAuth."

---

# 15. Digital Estate Identity UX

A major reason for selecting Ory is that authentication UX becomes a Baobab-owned product capability.

Kratos is explicitly headless: applications consume authentication APIs and supply their own interface.

The architecture SHALL therefore become:

```text
                  KRATOS
                    │
          authentication flows
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
   ZuriBeans     Thamani      Future Estate
       │            │
       ▼            ▼
   ZB Design     TG Design
    System        System
       │            │
   Login UX      Login UX
   Invite UX     Consumer UX
   Recovery      Business UX
   Passkeys      Recovery
                 Passkeys
```

The identity engine owns secure authentication mechanics.

The estate owns presentation and user experience.

---

# 16. Identity UI Reuse

Baobab MAY create reusable identity primitives.

However, the canonical `shared` repository SHALL NOT become a frontend framework.

A separate package MAY eventually provide:

```text
@baobab/identity-ui
```

or:

```text
@baobab/identity-contracts
```

with primitives such as:

```text
IdentityFlow
IdentityNode
PasskeyChallenge
MFAChallenge
RecoveryChallenge
VerificationChallenge
SessionSummary
IdentityError
```

Digital Estates retain final UI ownership.

---

# 17. ZuriBeans B2B — What Remains

ADR-0010 remains substantially valid.

ZuriBeans remains strictly B2B.

The authoritative relationship remains:

```text
Kratos Identity
       │
       ▼
CanonicalIdentity
       │
       ▼
Trade BuyerMembership
       │
       ▼
BuyerOrganization
       │
       ▼
Trade authorization
       │
       ├── purchaser
       ├── approver
       ├── finance
       ├── viewer
       └── administrative authority
```

A person's successful authentication SHALL NOT grant buyer authority.

The already implemented ZuriBeans/Thamani structural client isolation SHALL be recreated and re-proven under Hydra.

Existing cross-estate isolation tests SHALL be translated rather than discarded.

---

# 18. ZuriBeans B2B — What Changes

The completed Keycloak Organizations work SHALL NOT be mechanically recreated as Ory organizations.

The previous relationship:

```text
Keycloak Organization
        │
        ▼
Identity affiliation
```

shall be reconsidered against the existing CP/Trade organization model.

Where enterprise SSO requires identity-side organization metadata, Ory enterprise organization/federation capabilities MAY be used.

However:

```text
Ory Organization ≠ BuyerOrganization
Ory Organization ≠ Tenant
```

remains mandatory.

---

# 19. Thamani Architecture Correction

ADR-0011 and Gate IAM-7 currently describe Thamani primarily as B2C.

This is incomplete.

Thamani is a **shipping/logistics business serving both B2C and B2B customers**.

ADR-0011 SHALL therefore be interpreted and subsequently amended accordingly.

The target identity model is:

```text
                         THAMANI
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
            B2C                           B2B
             │                             │
             ▼                             ▼
 Individual Shipper                Business Customer
 Recipient                                │
 Consignee                         ┌───────┼────────┐
 Individual Customer               ▼       ▼        ▼
                                 Admin   Operator  Approver
                                            │
                                            ▼
                                         Finance
```

Future relationships MAY include:

```text
agents
carriers
brokers
customs intermediaries
warehouse partners
delivery partners
```

subject to separate domain ADRs.

---

# 20. Thamani Identity Rule

A single human MAY simultaneously be:

```text
Jane
│
├── individual Thamani customer
├── employee of Business A
└── authorized representative of Business B
```

Baobab SHALL NOT create three global identities merely because Jane has three business relationships.

Instead:

```text
Kratos Identity
       │
       ▼
CanonicalIdentity
       │
       ├── B2C relationship
       ├── Business A membership
       └── Business B membership
```

The relationship belongs to CP/domain systems.

Authentication remains singular.

---

# 21. Thamani Gate IAM-7 Consequence

The existing Gate IAM-7 customer-identity implementation was largely scoped rather than completed.

That is advantageous.

The previously unresolved question:

> Where does the customer OIDC redirect terminate?

is materially changed by Ory.

Kratos permits the estate to own its authentication interface directly.

The target SHOULD therefore prefer:

```text
Thamani UI
    │
    ▼
Kratos flow
    │
    ▼
authenticated identity/session
    │
    ▼
Hydra OAuth/OIDC where protocol tokens are required
    │
    ▼
Baobab CP / Trade
```

rather than blindly recreating the previous Keycloak redirect topology.

A dedicated Thamani ADR SHALL finalize BFF/session/token exposure decisions before implementation.

---

# 22. Guest Commerce Remains

The existing Thamani guest-order security work SHALL remain.

Guest commerce SHALL NOT require synthetic Kratos identities.

```text
Guest
  │
  ▼
guest commerce session
  │
  ▼
order
```

Later conversion:

```text
Guest order
    │
    ├── authenticated identity
    ├── secure ownership proof
    └── explicit claim operation
            │
            ▼
      customer account
```

Email equality alone SHALL remain insufficient proof for claiming historical guest orders.

---

# 23. Supplier Identity Remains

ADR-0012 remains provider-neutral.

```text
Kratos
  │
representative authentication
  ▼
CanonicalIdentity
  │
  ▼
SupplierOrganization
  │
  ├── verification
  ├── certifications
  ├── products
  ├── capacity
  ├── banking readiness
  ├── market eligibility
  └── approval
```

Authentication SHALL NOT imply supplier approval.

---

# 24. Workforce SSO Remains

The workforce architecture remains:

```text
Employee
   │
   ▼
Kratos
   │
   ▼
Hydra/OIDC
   │
   ▼
CanonicalIdentity
   │
   ▼
CP entitlement
   │
   ├── Trade
   ├── ERP
   ├── CMS
   └── Pulse
```

The completed Trade and CMS OIDC integration SHOULD be adapted primarily through issuer/client configuration rather than rewritten where their implementation is already standards-compliant.

---

# 25. iDempiere Integration

The existing architecture remains:

```text
Ory
  │
OIDC
  ▼
CanonicalIdentity
  │
  ▼
CP ERP context
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

These invariants remain:

```text
CanonicalIdentity ≠ AD_User
IAM role          ≠ AD_Role
Tenant            ≠ AD_Client universally
LegalEntity       ≠ AD_Org universally
```

The existing documented iDempiere limitation involving email/username matching rather than canonical `issuer + subject` mapping remains technical debt and SHALL not be hidden by the Ory migration.

---

# 26. Medusa Integration

Medusa authentication SHOULD become provider-neutral.

Configuration SHOULD evolve toward:

```text
BAOBAB_IAM_ISSUER
BAOBAB_OIDC_CLIENT_ID
BAOBAB_OIDC_AUDIENCE
```

rather than:

```text
KEYCLOAK_*
```

Where the current provider is named internally, it SHOULD be refactored toward:

```text
baobab-oidc
```

or another provider-neutral name.

Medusa remains authoritative for its domain actors and permissions.

---

# 27. Workload Identity Remains

ADR-0007 remains substantially intact.

Current registered workload concepts SHALL be migrated from Keycloak confidential/service clients to Hydra OAuth clients.

The conceptual mapping is:

```text
Keycloak workload client
          │
          ▼
Hydra OAuth client
```

while:

```text
WorkloadIdentity
workload registry
lifecycle status
allowed scopes
CP authorization
```

remain Baobab contracts.

---

# 28. Existing Workload Lifecycle Work SHALL Be Preserved

Current implementation already enforces consistency between the shared workload registry and Keycloak client enabled state.

This SHALL be translated to Hydra.

Example:

```text
Registry
status = ACTIVE
      │
      ▼
Hydra client must be active

Registry
status = SUSPENDED | REVOKED | RETIRED
      │
      ▼
Hydra client must not retain usable authentication authority
```

CI SHALL continue enforcing this invariant.

The provider changes.

The lifecycle contract does not.

---

# 29. OAuth and Token Profile

ADR-0006 remains authoritative wherever it defines protocol/security requirements rather than Keycloak mechanics.

Continue to require:

```text
Authorization Code
+
PKCE S256
```

for appropriate browser/public-client flows.

Continue to reject:

```text
Implicit Flow
ROPC as normal application architecture
```

Continue:

```text
exact issuer validation
audience validation
expiry validation
scope validation
short-lived access tokens
minimal claims
```

Hydra is OpenID Certified and implements OAuth/OIDC separately from human credential storage.

---

# 30. Token Claims SHALL Remain Minimal

The migration SHALL NOT be used to stuff Baobab context into Hydra tokens.

Avoid:

```json
{
  "tenant": "...",
  "legal_entity": "...",
  "market": "...",
  "buyer_role": "...",
  "purchase_limit": "...",
  "supplier_approved": true
}
```

as long-lived authorization truth.

Instead:

```text
token
  │
  ▼
identity evidence
  │
  ▼
CP
  │
  ▼
current authoritative context
```

---

# 31. Kratos Identity Traits

Kratos traits MAY contain stable identity/profile information required for authentication/user experience.

Example:

```json
{
  "email": "jane@example.com",
  "name": {
    "first": "Jane",
    "last": "Doe"
  }
}
```

They SHALL NOT become a shadow CP/domain database.

Do not place mutable Baobab authority such as:

```text
tenant
purchase_limit
supplier_approved
market entitlement
ERP role
buyer approval authority
```

in Kratos traits as authoritative state.

---

# 32. Canonical Identity Migration

Existing `CanonicalIdentity` records SHALL NOT be recreated.

Migration SHALL use dual external identity association.

```text
                  CanonicalIdentity
                   /             \
                  /               \
     Keycloak ExternalIdentity   Ory ExternalIdentity
              OLD                      NEW
```

Transition:

```text
Existing CanonicalIdentity
        │
        ▼
identify Keycloak external mapping
        │
        ▼
migrate/provision Kratos identity
        │
        ▼
verify ownership
        │
        ▼
create Ory ExternalIdentity mapping
        │
        ▼
authenticate through Ory
        │
        ▼
verify same CanonicalIdentity
        │
        ▼
retire Keycloak mapping
```

This is a migration of **authentication authority**, not a migration of canonical identity ownership.

---

# 33. Credential Migration

Migration SHALL attempt to avoid unnecessary password resets.

Kratos supports bulk import of identities using existing password hashes across multiple algorithms.

The migration implementation SHALL inspect the actual Keycloak credential formats in use before assuming direct portability.

Preferred order:

```text
1. Direct supported hash import
2. Credential-type import where supported
3. Graceful first-login migration
4. Verified recovery/reset only where unavoidable
```

No credential SHALL be downgraded merely to simplify migration.

---

# 34. MFA and Passkey Migration

Existing MFA work SHALL not be discarded.

Current assurance requirements remain.

Migration SHALL inventory:

```text
password credentials
TOTP
WebAuthn credentials
passkeys
recovery credentials
federated identities
active sessions
```

Recent Ory identity APIs support importing multiple credential categories including TOTP, WebAuthn and passkey credentials.

Actual Keycloak-to-Ory portability SHALL be proven through migration tests before production cutover.

Unsupported authenticators SHALL trigger explicit re-enrollment, not silent assurance downgrade.

---

# 35. Authentication Assurance Remains

ADR-0015's assurance model remains.

For example:

```text
Ordinary consumer
        ↓
baseline assurance

Buyer representative
        ↓
baseline/enhanced

Buyer approver
        ↓
enhanced / step-up

Supplier administrator
        ↓
enhanced

ERP finance/admin
        ↓
privileged

IAM/security administrator
        ↓
highest assurance
```

The provider-specific mechanism changes.

The policy does not.

---

# 36. Recovery Remains an Identity Operation

Account recovery SHALL restore access to identity.

It SHALL NOT restore:

```text
Tenant membership
Buyer membership
Purchase authority
Supplier approval
ERP role
Suspended capability
Revoked platform entitlement
```

Those authorities remain external to Kratos.

---

# 37. Lifecycle Architecture Remains

ADR-0016's separation remains:

```text
Identity lifecycle
Credential lifecycle
Session lifecycle
Membership lifecycle
Entitlement lifecycle
Domain-actor lifecycle
Workload lifecycle
```

These SHALL NOT collapse into a single `enabled` boolean.

---

# 38. Event Normalization

Ory-native events/hooks SHALL NOT become Baobab's canonical event schema.

Instead:

```text
Kratos / Hydra event
        │
        ▼
baobab-iam
        │
normalize
        ▼
Baobab identity/security event
        │
        ▼
platform event infrastructure
```

This is critical to provider neutrality.

---

# 39. Canonical Event Example

Conceptually:

```json
{
  "event_type": "identity.session.revoked.v1",
  "provider": "ory",
  "provider_subject": "ory-subject",
  "canonical_identity_id": "ci_...",
  "correlation_id": "...",
  "occurred_at": "...",
  "reason_code": "SECURITY_REVOCATION"
}
```

Consumers SHOULD NOT need to know Kratos' internal event representation.

---

# 40. Audit Architecture Remains

ADR-0017 remains authoritative.

Continue separating:

```text
Provider operational logs
Provider security audit
Canonical Baobab security events
CP authorization audit
Domain audit
Metrics
Traces
Alerts
```

No provider log stream becomes the sole Baobab security truth.

---

# 41. Existing Audit Investment

Current Keycloak audit tests have already established useful security expectations, including:

- administrative event visibility;
- credential-revocation visibility;
- secret-redaction expectations;
- correlation requirements.

Those tests SHALL be converted into provider-neutral acceptance tests.

Example:

```text
TEST:
Disable identity

EXPECT:
provider disables authentication

AND:
sessions revoked

AND:
security event produced

AND:
no credential secret appears in audit

AND:
CP subsequently denies protected context
```

The expected behavior remains.

Only the provider adapter changes.

---

# 42. Availability and DR

ADR-0018 remains authoritative at the security-policy level.

The provider-specific deployment sections SHALL be rewritten for Kratos/Hydra.

Hydra supports PostgreSQL production deployment and has official Kubernetes/Helm deployment support.

Baobab SHOULD remain aligned with PostgreSQL 17 unless verified compatibility requirements dictate otherwise.

Kratos and Hydra SHOULD use isolated schemas/databases according to their supported deployment model rather than sharing Baobab application tables.

---

# 43. DR Security Invariant

The existing requirement remains:

> **Disaster recovery SHALL NOT resurrect security authority that was revoked after the recovered backup point.**

Therefore:

```text
Database Restore
       │
       ▼
Provider state
       │
       ▼
Security reconciliation
       │
       ├── revoked identities
       ├── revoked workloads
       ├── suspended memberships
       └── security journal/checkpoint
       │
       ▼
Traffic enabled
```

Traffic SHALL NOT resume solely because a database restore succeeded.

---

# 44. Multi-Region Architecture

Identity-region topology remains distinct from Baobab business topology.

```text
Identity Region
     ≠
Market

Identity Region
     ≠
Tenant

Identity Region
     ≠
LegalEntity
```

The existing CP `Region`, `Market`, `CapabilityBinding` and `EngineInstance` model remains untouched.

---

# 45. Self-Hosted Deployment Baseline

The initial target SHALL be **self-hosted Ory Kratos + Hydra on Baobab-controlled infrastructure**, subject to infrastructure ADR validation.

Reasons include:

- Baobab data-residency control;
- deployment independence;
- African regional expansion requirements;
- avoidance of tying Baobab Market semantics to vendor SaaS regions;
- provider portability;
- existing PostgreSQL operational direction;
- existing container/Kubernetes production architecture.

Ory's open-source core remains Apache-2 licensed, while Ory also provides a commercial self-hosted Enterprise License with additional enterprise capabilities and support.

The production licensing/support choice SHALL be made separately based on required B2B/SAML/SCIM/HA features, support obligations and cost.

---

# 46. Enterprise Feature Boundary

The implementation team SHALL NOT assume that every capability advertised for Ory Network exists identically in OSS self-hosted Kratos/Hydra.

Ory documents enterprise-only capabilities including certain B2B organization, multi-tenancy, SAML, SCIM and advanced production features.

Therefore every required enterprise feature SHALL be classified:

```text
OSS
OEL
Ory Network
Baobab-owned
Not required
```

before production architecture is finalized.

---

# 47. B2B Enterprise Federation

Future ZuriBeans and Thamani enterprise customers may require federation with corporate identity providers such as Microsoft Entra.

The architecture SHALL permit:

```text
Enterprise Customer IdP
        │
        ▼
Ory federation
        │
        ▼
Kratos identity
        │
        ▼
CanonicalIdentity
        │
        ▼
CP relationship/context
```

Enterprise federation SHALL authenticate the person.

It SHALL NOT automatically grant business authority.

---

# 48. Authentication UI Ownership

Authentication UI SHALL become part of each Digital Estate's product architecture.

This does not mean Baobab implements cryptographic authentication itself.

The separation is:

```text
Baobab Estate
     │
     ├── presentation
     ├── interaction
     ├── branding
     ├── accessibility
     └── product journey

Kratos
     │
     ├── secure flow state
     ├── credential validation
     ├── MFA
     ├── passkeys
     ├── recovery
     └── sessions
```

This distinction is central to the Ory selection.

---

# 49. Security Rule for Custom UI

Custom UI SHALL NOT imply custom security protocols.

Digital Estates SHALL render provider-issued flow state and submit user input through supported APIs.

They SHALL NOT implement:

```text
password hashing
TOTP validation
WebAuthn ceremonies
token signing
OAuth authorization server logic
session cryptography
recovery-token cryptography
```

independently.

---

# 50. Existing Client Registrations

Existing logical clients SHALL be preserved conceptually.

Examples include:

```text
baobab-control-plane
baobab-control-plane-admin
baobab-trade
baobab-trade-admin
baobab-trade-workload
baobab-erp
baobab-erp-admin
baobab-erp-workload
baobab-cms
baobab-cms-admin
baobab-cms-workload
baobab-pulse
baobab-pulse-workload
zuribeans-web
zuribeans-backend-workload
thamani-web
thamani-backend-workload
```

The implementation changes from Keycloak client JSON to Hydra/Kratos/Ory configuration.

Logical application identities SHOULD remain stable where practical.

---

# 51. Existing Scope Contracts

Existing scopes such as:

```text
actor-type-human
actor-type-workload
context-resolve
erp-integrate
onboarding-request
onboarding-authorise
```

SHALL be reviewed for semantic correctness and migrated where still valid.

The migration SHALL NOT rename stable Baobab scopes merely because the provider changed.

---

# 52. Keycloak Organizations Work

Existing Gate IAM-6 work proving Keycloak Organizations and ZuriBeans separation SHALL be treated as valuable evidence, but Keycloak Organization objects themselves are provider-specific.

Preserve:

```text
buyer isolation requirement
identity affiliation requirement
multi-company representation requirement
cross-buyer denial tests
```

Replace:

```text
Keycloak Organization dependency
```

with the minimum Ory/CP/Trade combination required.

---

# 53. Existing ZuriBeans/Thamani Isolation Tests

The current tests proving:

```text
Thamani ≠ ZuriBeans
```

are architectural assets.

Equivalent tests SHALL exist after migration.

At minimum:

```text
ZuriBeans workload credential
    cannot authenticate as
Thamani workload

Thamani workload credential
    cannot authenticate as
ZuriBeans workload

ZuriBeans redirect/callback
    cannot be used by
Thamani client

Thamani redirect/callback
    cannot be used by
ZuriBeans client
```

Later CP/domain tests SHALL additionally prove actual resource isolation.

---

# 54. No Tenant Claim Shortcut

Existing implementation correctly avoids treating a JWT `tenant_id` claim as the canonical authorization boundary.

This remains correct.

The Ory migration SHALL NOT introduce a shortcut such as:

```text
Hydra token tenant_id
        =
authoritative tenant
```

CP remains responsible for current context resolution.

---

# 55. Migration Strategy

Migration SHALL be incremental and reversible.

The high-level phases are:

```text
DISCOVER
   ↓
FREEZE CONTRACTS
   ↓
INTRODUCE PROVIDER-NEUTRAL CONFIG
   ↓
DEPLOY ORY IN PARALLEL
   ↓
MIGRATE NON-HUMAN CLIENTS
   ↓
MIGRATE TEST HUMAN IDENTITIES
   ↓
MIGRATE ESTATE FLOWS
   ↓
MIGRATE WORKFORCE
   ↓
MIGRATE PRODUCTION IDENTITIES
   ↓
DUAL-RUN / VERIFY
   ↓
CUTOVER
   ↓
REVOKE KEYCLOAK AUTHORITY
   ↓
OBSERVE
   ↓
REMOVE KEYCLOAK RUNTIME
```

---

# 56. Phase 0 — Migration Discovery

Before modifying runtime behavior, inventory:

```text
Keycloak realm
clients
client secrets
redirect URIs
scopes
roles
Organizations
users
credentials
MFA registrations
WebAuthn/passkeys
federated identities
sessions
admin events
authentication flows
themes
workload clients
service accounts
event integrations
bootstrap scripts
CI assumptions
Docker/runtime assumptions
DR procedures
```

Each artifact SHALL be classified:

```text
PRESERVE
TRANSLATE
REPLACE
RETIRE
DEFER
```

---

# 57. Phase 1 — Freeze Provider-Neutral Contracts

Before Ory integration, stabilize:

```text
Principal
ExternalIdentity
CanonicalIdentity
WorkloadIdentity
identity scopes
identity events
security events
context contracts
authorization decision contracts
```

in `shared`/CP.

No Ory-specific field SHALL enter a canonical contract unless explicitly namespaced.

---

# 58. Phase 2 — Ory Foundation

Deploy isolated non-production:

```text
Kratos
Hydra
PostgreSQL persistence
mail/courier integration
secrets
JWKS/signing material
observability
backup
health/readiness
```

No production authority changes yet.

---

# 59. Phase 3 — Workload Migration

Workload identities SHOULD migrate before large-scale human identities because they are deterministic and highly testable.

For each workload:

```text
existing workload registry
        │
        ▼
Hydra client
        │
        ▼
client_credentials
        │
        ▼
CP validation
        │
        ▼
same capability/context behavior
```

Existing workload lifecycle tests SHALL pass unchanged at the semantic level.

---

# 60. Phase 4 — Test Human Migration

Create representative identities covering:

```text
workforce user
ZuriBeans buyer
multi-company buyer
Thamani B2C customer
Thamani B2B representative
supplier representative
ERP user
privileged administrator
```

Prove identity mapping before bulk migration.

---

# 61. Phase 5 — Digital Estate UI

Build Kratos-backed estate identity flows.

ZuriBeans SHALL test:

```text
login
invitation
verification
recovery
MFA/passkey
multi-company context
logout
```

Thamani SHALL test:

```text
consumer registration
consumer login
business representative login
business invitation
recovery
passkey
guest coexistence
business/personal context switching
logout
```

---

# 62. Phase 6 — Workforce Migration

Migrate workforce applications:

```text
Control Plane administration
Trade administration
ERP
CMS
Pulse
```

Existing OIDC integrations SHOULD be reconfigured rather than replaced wherever standards compliance permits.

---

# 63. Phase 7 — Production Identity Migration

Production migration SHALL use:

```text
batch
    ↓
verify
    ↓
observe
    ↓
next batch
```

rather than an unbounded big-bang cutover.

Metrics SHALL include:

```text
login success
login failure
migration failure
recovery rate
MFA failure
passkey failure
OIDC callback errors
token validation errors
CP identity mapping errors
duplicate canonical identity attempts
```

---

# 64. Phase 8 — Dual External Identity Period

During controlled migration:

```text
CanonicalIdentity
      │
      ├── Keycloak ExternalIdentity
      └── Ory ExternalIdentity
```

MUST be permitted.

This enables rollback without canonical-identity duplication.

---

# 65. Phase 9 — Cutover

Cutover criteria SHALL include:

- all critical client registrations migrated;
- workload flows proven;
- human login proven;
- recovery proven;
- MFA/passkeys proven where applicable;
- CP identity resolution proven;
- Trade authorization proven;
- ERP SSO proven;
- CMS SSO proven;
- cross-tenant denial proven;
- cross-estate denial proven;
- lifecycle/revocation proven;
- audit proven;
- backup/restore proven;
- incident-response runbook updated;
- rollback rehearsed.

---

# 66. Phase 10 — Keycloak Retirement

Keycloak SHALL NOT be deleted immediately after traffic cutover.

Retirement sequence:

```text
Stop new registrations
      ↓
Stop new client creation
      ↓
Stop credential changes
      ↓
Revoke token authority
      ↓
Preserve audit/migration evidence
      ↓
Archive required exports
      ↓
observe
      ↓
remove runtime
```

Retention SHALL comply with security/privacy requirements.

---

# 67. Rollback

Rollback SHALL preserve:

```text
CanonicalIdentity
domain data
Trade customers/orders
ERP mappings
CMS users/content
supplier relationships
workload registry
```

Rollback SHALL switch authentication authority, not restore obsolete business data.

A failed Ory migration SHALL NOT require rolling back CP/domain databases.

---

# 68. Dual-Issuer Security

During migration, CP/resource servers MAY temporarily trust:

```text
Keycloak issuer
+
Ory/Hydra issuer
```

but only under explicit migration configuration.

Each issuer SHALL have:

- exact issuer matching;
- separate JWKS trust;
- explicit audience rules;
- migration expiry date;
- monitoring;
- rollback procedure.

Permanent unbounded dual-issuer trust is prohibited.

---

# 69. External Identity Uniqueness

Conceptually:

```text
UNIQUE(provider, issuer, provider_subject)
```

SHALL prevent accidental duplicate mappings.

The provider field SHOULD be descriptive, not authoritative.

The authoritative identity proof remains the trusted issuer/subject relationship.

---

# 70. No Email Auto-Linking

The migration SHALL NOT perform:

```text
same email
    ↓
same person automatically
```

Where a migrated Keycloak identity and Ory identity need linking, the migration process SHALL use trusted migration metadata or verified account ownership.

---

# 71. Existing CI/CD Investment

Existing CI/CD hardening SHALL remain.

Preserve:

```text
action pinning
dependency management
secret scanning
container scanning
SBOM generation
contract verification
integration testing
production-hardening checks
```

Keycloak-specific test harnesses SHALL be replaced by Ory equivalents rather than deleting the security assertions.

---

# 72. Provider-Neutral Acceptance Tests

Tests SHOULD be expressed as behavior.

Bad:

```text
Keycloak realm contains flow X
```

Better:

```text
privileged workforce identity cannot authenticate
without required assurance
```

Bad:

```text
Keycloak client enabled=false
```

Better:

```text
revoked workload cannot obtain usable credentials
```

Provider-specific structural tests MAY still exist underneath these acceptance tests.

---

# 73. Security Test Matrix

The migration SHALL prove at least:

| Scenario | Expected |
|---|---|
| valid identity, valid context | allow |
| valid identity, wrong tenant | deny |
| valid identity, revoked CP membership | deny |
| valid Ory session, suspended CanonicalIdentity | deny |
| buyer A accesses buyer B | deny |
| ZuriBeans credential used as Thamani | deny |
| Thamani credential used as ZuriBeans | deny |
| workload revoked | token acquisition/use denied according to lifecycle policy |
| guest claims order by email only | deny |
| supplier authenticated but unapproved | no supplier business authority |
| ERP user lacks AD_Role | ERP denies |
| stale restored IAM database resurrects revoked actor | reconciliation prevents authority |
| invalid issuer | deny |
| wrong audience | deny |
| expired token | deny |
| tampered token | deny |

---

# 74. Observability

Kratos and Hydra SHALL participate in Baobab observability.

Required correlation SHOULD include:

```text
request_id
correlation_id
trace_id
provider
issuer
subject hash/reference where appropriate
canonical_identity_id where resolved
client_id
decision_id
outcome
reason_code
```

Credentials, authorization codes, access tokens, refresh tokens and secrets SHALL NOT be logged.

---

# 75. Privacy

The migration SHALL minimize identity data duplication.

Kratos SHALL hold authentication/profile data required for identity operations.

CP SHALL hold canonical identity/context.

Domain engines SHALL hold domain data.

No migration SHALL create an unrestricted replicated user profile across all engines.

---

# 76. Secrets

Secrets SHALL be externally managed.

Repository configuration SHALL contain references/templates, not production secrets.

Hydra system secrets, OAuth client credentials, signing material, database credentials and webhook credentials SHALL follow infrastructure secret-management policy.

---

# 77. Database Isolation

Ory persistence SHALL remain logically isolated from:

```text
baobab-cp database
Trade database
ERP database
CMS database
Pulse database
```

No cross-database joins SHALL be introduced.

Integration occurs through APIs/contracts/events.

---

# 78. PostgreSQL

Baobab SHOULD retain PostgreSQL as the initial persistence technology for self-hosted Kratos/Hydra, subject to version compatibility verification during implementation.

This aligns with Baobab's PostgreSQL operational baseline and avoids adding another distributed database solely for IAM.

Multi-region persistence SHALL be a separate infrastructure decision.

---

# 79. B2B Organizations

Ory enterprise organization features MAY be adopted where they provide useful identity-side B2B federation.

They SHALL NOT redefine Baobab organization semantics.

Always:

```text
Identity-provider organization
        ≠
CanonicalEntity
        ≠
Tenant
        ≠
LegalEntity
        ≠
BuyerOrganization
        ≠
SupplierOrganization
```

Mappings MAY connect them.

Identity equality SHALL not.

---

# 80. Enterprise SSO

Enterprise SSO SHALL follow:

```text
Customer IdP
     │
     ▼
Ory federation
     │
     ▼
Kratos identity
     │
     ▼
CanonicalIdentity
     │
     ▼
CP relationship
     │
     ▼
domain authorization
```

A successful corporate SSO assertion SHALL never create purchase authority automatically.

---

# 81. Social Identity

Consumer/social identity providers MAY be federated through Ory.

Social identity SHALL map to an external identity.

Email coincidence SHALL not be sufficient for unsafe account linking.

---

# 82. Identity Provider Failure

Provider failure behavior SHALL distinguish:

```text
new authentication
token refresh
existing valid access token
CP context resolution
domain authorization
```

A temporary Kratos outage need not automatically invalidate already-valid independently verifiable OAuth access tokens where security policy permits.

A CP/domain denial SHALL never be bypassed because IAM is unavailable.

---

# 83. Revocation

Revocation SHALL be layered.

```text
credential compromise
      ↓
provider credential/session revocation

platform suspension
      ↓
CP identity/membership denial

domain suspension
      ↓
domain authorization denial
```

These are separate controls.

---

# 84. Break-Glass

Existing break-glass principles remain.

Break-glass SHALL not rely on a universal permanent superuser.

Use:

```text
time-limited
strongly authenticated
audited
reason-coded
reviewed
```

emergency access.

---

# 85. Provider Portability Test

Provider neutrality SHALL be periodically tested architecturally.

A useful question is:

> If Ory were replaced tomorrow, which repositories would require business-logic changes?

The desired answer is:

```text
primarily baobab-iam
+
issuer/client configuration
+
estate authentication adapters/UI bindings
```

not:

```text
every Baobab engine
```

---

# 86. ADR Impact Matrix

| ADR | Status under ADR-IAM-0019 | Effect |
|---|---|---|
| ADR-0001 IAM Architecture | **Preserved / amended** | Provider becomes Ory; authority model unchanged |
| ADR-0002 Keycloak as IdP | **Superseded** | Replaced by this ADR |
| ADR-0003 Trust Boundaries | **Preserved** | Provider-neutral wording |
| ADR-0004 Canonical Identity | **Preserved** | Core migration anchor |
| ADR-0005 Realm/Org/Tenant/Legal Entity | **Amended** | Remove Keycloak realm assumptions; preserve separations |
| ADR-0006 OIDC/OAuth | **Preserved / amended** | Hydra implementation |
| ADR-0007 Workload Identity | **Preserved / amended** | Hydra clients replace Keycloak workload clients |
| ADR-0008 Platform Authorization | **Preserved** | CP/domain authority unchanged |
| ADR-0009 Workforce SSO | **Preserved / amended** | Ory replaces Keycloak |
| ADR-0010 ZuriBeans B2B | **Preserved / amended** | Remove dependency on Keycloak Organizations |
| ADR-0011 Thamani B2C | **Scope correction required** | Thamani is B2B + B2C logistics |
| ADR-0012 Supplier Identity | **Preserved** | Provider-neutral |
| ADR-0013 Medusa Integration | **Preserved / amended** | Provider-neutral OIDC/Ory |
| ADR-0014 iDempiere SSO | **Preserved / amended** | Issuer/client change |
| ADR-0015 MFA/Passkeys/Recovery | **Preserved / reimplemented** | Kratos implementation |
| ADR-0016 Lifecycle/Revocation | **Preserved / reimplemented** | Ory hooks/events |
| ADR-0017 Audit/Observability | **Preserved / reimplemented** | Normalize Ory audit/events |
| ADR-0018 HA/Backup/DR | **Preserved / provider section rewritten** | Kratos/Hydra/PostgreSQL topology |

---

# 87. Implementation Preservation Matrix

| Existing investment | Treatment |
|---|---|
| `CanonicalIdentity` | **Keep** |
| `ExternalIdentity` | **Keep and extend for Ory** |
| CP context resolver | **Keep** |
| CapabilityBinding | **Keep** |
| EngineInstance resolver | **Keep** |
| tenant/legal-entity separation | **Keep** |
| market/region separation | **Keep** |
| workload registry | **Keep** |
| workload lifecycle states | **Keep** |
| scope vocabulary | **Keep after review** |
| Trade domain authorization | **Keep** |
| Thamani ownership/IDOR protections | **Keep** |
| supplier identity/domain separation | **Keep** |
| ERP native authorization | **Keep** |
| CMS domain authorization | **Keep** |
| OIDC integration patterns | **Reuse/refactor** |
| security event contracts | **Keep** |
| audit expectations | **Keep** |
| DR invariants | **Keep** |
| incident-response runbooks | **Update, don't discard** |
| SBOM/security CI | **Keep** |
| Keycloak realm JSON | **Retire after translation** |
| Keycloak Organizations config | **Replace selectively** |
| Keycloak authentication flows | **Replace with Kratos flows/policy** |
| Keycloak themes | **Replace with estate-owned UI** |
| Keycloak SPI decision | **Retire** |
| Keycloak Admin Events integration | **Replace** |
| Keycloak Docker runtime | **Replace** |

---

# 88. Work Still Outstanding Before Migration

This ADR does not claim that previous IAM work is complete.

Existing outstanding work includes, among other things:

- full ZuriBeans buyer/organization isolation;
- remaining workforce membership/authorization phases;
- passkey rollout;
- high-risk action step-up;
- recovery hardening;
- break-glass exercises;
- access review;
- supplier-domain ownership;
- Thamani identity architecture;
- guest-order claim mechanism;
- ERP canonical mapping improvements;
- lifecycle event propagation;
- audit retention policy;
- DR security journal/reconciliation;
- real backup/restore exercise;
- multi-region later phases;
- penetration testing;
- load testing;
- bulk revocation;
- incident-response exercise.

These SHALL now be implemented against the provider-neutral/Ory architecture where applicable.

They SHALL NOT first be completed against Keycloak merely to be rewritten immediately.

---

# 89. Migration Gate Plan

The migration SHOULD proceed through dedicated gates.

```text
IAM-M0  Baseline / freeze / inventory
IAM-M1  Provider-neutral contracts
IAM-M2  Ory Kratos foundation
IAM-M3  Ory Hydra foundation
IAM-M4  Workload migration
IAM-M5  Canonical identity migration adapter
IAM-M6  Workforce SSO migration
IAM-M7  ZuriBeans B2B identity migration
IAM-M8  Thamani B2B+B2C identity implementation
IAM-M9  Supplier identity integration
IAM-M10 Trade/Medusa provider migration
IAM-M11 ERP/iDempiere provider migration
IAM-M12 MFA/passkeys/recovery
IAM-M13 Lifecycle/events/revocation
IAM-M14 Audit/observability
IAM-M15 HA/backup/DR
IAM-M16 Multi-region readiness
IAM-M17 Production hardening
IAM-M18 Dual-run/cutover
IAM-M19 Keycloak retirement
```

Each gate SHOULD produce its own logical PR or coordinated cross-repository PR set.

---

# 90. Gate IAM-M0 — Baseline

Required outputs:

```text
Keycloak asset inventory
implemented-capability inventory
ADR traceability matrix
migration risk register
credential inventory
client inventory
test inventory
provider-specific dependency inventory
rollback baseline
```

No runtime migration occurs.

---

# 91. Gate IAM-M1 — Provider-Neutral Contracts

Remove unnecessary Keycloak terminology from canonical contracts.

Do not remove historical ADR references.

Add explicit provider metadata where needed.

Prove that CP identity resolution does not require Keycloak-specific business semantics.

---

# 92. Gate IAM-M2/M3 — Ory Foundation

Provision Kratos and Hydra with:

```text
pinned versions
pinned images/digests
PostgreSQL
health/readiness
secrets
migrations
backups
observability
non-root/container hardening
CI security scans
SBOM
configuration-as-code
```

No production identity cutover yet.

---

# 93. Gate IAM-M4 — Workloads

Migrate deterministic workloads first.

Test:

```text
client credentials
scope enforcement
audience enforcement
CP context resolution
revocation
lifecycle status
cross-estate credential rejection
```

---

# 94. Gate IAM-M5 — Identity Migration Adapter

Implement migration tooling capable of:

```text
Keycloak identity
       ↓
migration record
       ↓
Kratos identity
       ↓
Ory ExternalIdentity
       ↓
existing CanonicalIdentity
```

Every migration SHALL be idempotent.

---

# 95. Gate IAM-M6 — Workforce

Repoint:

```text
CP admin
Trade admin
CMS
ERP
Pulse
```

to Hydra/Ory as appropriate.

Preserve domain authorization.

---

# 96. Gate IAM-M7 — ZuriBeans

Build estate-owned authentication UX.

Prove:

```text
buyer invitation
login
recovery
MFA/passkey
multi-company representation
cross-buyer denial
cross-estate denial
```

---

# 97. Gate IAM-M8 — Thamani

This gate SHALL replace the obsolete B2C-only framing.

Implement both:

```text
Thamani B2C
+
Thamani B2B
```

with a shared human identity model and separate business relationships.

---

# 98. Gate IAM-M9 — Suppliers

Do not proceed until supplier-domain ownership is resolved.

IAM authenticates supplier representatives.

The supplier domain decides supplier authority.

---

# 99. Gate IAM-M10/M11 — Trade and ERP

Prefer configuration/provider adaptation over unnecessary rewrites.

Existing standards-compliant code is an asset.

---

# 100. Gate IAM-M12 — Assurance

Prove:

```text
password
passkey
TOTP/MFA
recovery
step-up
privileged access
credential migration
```

according to ADR-0015.

---

# 101. Gate IAM-M13 — Lifecycle

Prove:

```text
disable
session revoke
membership revoke
workload revoke
event emission
cache invalidation
reconciliation
```

---

# 102. Gate IAM-M14 — Audit

Translate Ory provider activity into Baobab canonical security events.

Prove secret redaction.

---

# 103. Gate IAM-M15 — DR

Perform a real backup/restore exercise.

Prove:

```text
revoked before disaster
        │
        ▼
old backup restored
        │
        ▼
security reconciliation
        │
        ▼
actor remains revoked
```

---

# 104. Gate IAM-M16 — Multi-Region

Do not conflate Ory topology with CP Market topology.

Prove regional failure scenarios before active-active complexity is introduced.

---

# 105. Gate IAM-M17 — Production Hardening

Required:

```text
penetration test
load test
login-storm test
rate limiting
brute-force protections
dependency scanning
image scanning
SBOM
secret scanning
incident drill
bulk revocation
capacity assumptions
SLOs
alerts
```

---

# 106. Gate IAM-M18 — Cutover

Dual-run.

Observe.

Cut over only after acceptance criteria pass.

---

# 107. Gate IAM-M19 — Retirement

Remove Keycloak runtime only after:

```text
migration verified
rollback window closed
audit exported
required evidence retained
all issuers migrated
all clients migrated
all production flows verified
```

---

# 108. PR Requirements

Every migration PR SHALL identify:

- ADR sections implemented;
- preserved behavior;
- changed provider behavior;
- migration impact;
- security impact;
- tenancy impact;
- data migration;
- tests;
- negative tests;
- observability;
- deployment;
- rollback;
- known limitations.

---

# 109. Prohibited Migration Shortcuts

The migration SHALL NOT:

```text
recreate CanonicalIdentity records
auto-link identities by email
move Tenant into Kratos
move LegalEntity into Kratos
move Market into Kratos
move purchase authority into Kratos
move supplier approval into Kratos
move ERP roles into Kratos
trust tenant headers
trust network location
create universal executive superusers
share workload credentials
log credentials/tokens
introduce cross-database joins
complete unfinished Keycloak work only to replace it immediately
delete existing security tests because they reference Keycloak
adopt Keto merely because Ory provides it
adopt Oathkeeper merely because Ory provides it
```

---

# 110. Consequences — Positive

The decision provides:

### Provider portability

Baobab business architecture no longer depends on one IdP's object model.

### Digital Estate UX sovereignty

ZuriBeans and Thamani can own authentication experiences while relying on hardened identity primitives.

### Better architectural alignment

Ory's headless composition resembles Baobab's own engine architecture.

### Preservation of previous investment

Canonical identity, CP context, authorization boundaries, contracts, tests and domain integrations remain valuable.

### Go alignment

Hydra is Go-based, fitting naturally beside the Go Control Plane.

### Standards alignment

OAuth/OIDC remain the integration boundary.

### Future migration reduction

A future provider replacement should primarily affect `baobab-iam` and configuration, not every engine.

---

# 111. Consequences — Negative

Baobab assumes additional product responsibility for authentication UX.

Self-hosted Kratos + Hydra introduces more moving components than a single integrated IAM server.

Baobab must operate:

```text
Kratos
Hydra
their persistence
mail/courier integration
custom identity UI
provider configuration
migration tooling
```

Enterprise B2B capabilities such as SAML, SCIM, organizations and advanced HA features may require Ory Enterprise licensing rather than OSS alone.

This SHALL be evaluated before production procurement.

---

# 112. Why Not ZITADEL

ZITADEL remains a credible alternative and would likely provide a simpler direct Keycloak replacement.

It was not selected because Baobab's architectural direction places high value on:

- headless engines;
- Digital Estate UX ownership;
- composability;
- provider-neutral boundaries;
- separating authentication from OAuth/OIDC;
- avoiding another identity provider becoming a business-domain model.

Ory's Kratos/Hydra separation more closely mirrors Baobab's own engine-oriented architecture.

This is an architectural choice, not a claim that ZITADEL is generally inferior.

---

# 113. Why Not Continue with Keycloak

The decision does not claim that Keycloak lacks capability.

The issue is architectural and operational fit.

Baobab has encountered increasing provider-specific engineering effort around:

```text
realm configuration
Organizations
authentication flows
themes
admin events
SPIs
bootstrap configuration
runtime hardening
provider-specific tests
```

while much of Baobab's actual business identity architecture already lives correctly outside Keycloak.

Continuing to deepen provider coupling would increase future migration cost.

---

# 114. Research Evidence Limitation

The HGV and commercetools examples cited in this ADR are Ory-published customer case studies.

They demonstrate real reported deployment/migration patterns but SHALL NOT be interpreted as independent benchmarks or guarantees of equivalent Baobab migration duration, reliability or cost.

Baobab SHALL validate Ory through its own integration, security, performance and DR tests.

---

# 115. Architecture After Migration

```text
┌──────────────────────────────────────────────────────────────────┐
│                     BAOBAB DIGITAL ESTATES                       │
│                                                                  │
│       ZuriBeans            Thamani              Future           │
│          B2B              B2B + B2C             Estates          │
│            │                  │                    │              │
│            └──────────────────┼────────────────────┘              │
│                               │                                  │
│                    Estate-owned Identity UX                      │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
                    ┌─────────────────────┐
                    │     Ory Kratos      │
                    │                     │
                    │ Human identity      │
                    │ Credentials         │
                    │ MFA / Passkeys      │
                    │ Recovery            │
                    │ Verification        │
                    │ Sessions            │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Ory Hydra      │
                    │                     │
                    │ OAuth 2.x           │
                    │ OpenID Connect      │
                    │ PKCE                │
                    │ Workload OAuth      │
                    │ Token issuance      │
                    └──────────┬──────────┘
                               │
                 standards-based identity evidence
                               │
          ┌────────────────────┴────────────────────┐
          │                                         │
          ▼                                         ▼
┌──────────────────────┐                 ┌──────────────────────┐
│      baobab-iam      │                 │      baobab-cp       │
│                      │                 │                      │
│ provider config      │                 │ CanonicalIdentity    │
│ provisioning         │                 │ ExternalIdentity     │
│ lifecycle            │                 │ Tenant               │
│ event normalization  │                 │ LegalEntity          │
│ reconciliation       │                 │ Market               │
│ migration            │                 │ DigitalEstate        │
│ IAM policy           │                 │ CapabilityBinding    │
└──────────────────────┘                 │ EngineInstance       │
                                         └──────────┬───────────┘
                                                    │
                           ┌────────────────────────┼───────────────┐
                           ▼                        ▼               ▼
                    ┌─────────────┐          ┌────────────┐  ┌───────────┐
                    │    Trade    │          │    ERP     │  │    CMS    │
                    │  MedusaJS   │          │ iDempiere  │  │  Payload  │
                    │             │          │            │  │           │
                    │ Domain AuthZ│          │ ERP AuthZ  │  │ CMS AuthZ │
                    └─────────────┘          └────────────┘  └───────────┘
```

---

# 116. Final Invariants

After migration, all of the following MUST remain true:

```text
Authentication ≠ Authorization

Identity Provider ≠ Control Plane

Identity Provider Organization ≠ Tenant

Identity Provider Organization ≠ LegalEntity

Identity Provider Organization ≠ BuyerOrganization

Identity Provider Organization ≠ SupplierOrganization

CanonicalIdentity ≠ Provider Identity

CanonicalIdentity ≠ Medusa Customer

CanonicalIdentity ≠ AD_User

Tenant ≠ Market

Market ≠ Region

Tenant ≠ AD_Client universally

LegalEntity ≠ AD_Org universally

Supplier authentication ≠ Supplier approval

Buyer authentication ≠ Purchase authority

Workload identity ≠ Human identity

Valid token ≠ Valid Baobab context

Valid Ory session ≠ Active Baobab entitlement

Successful DR restore ≠ Restored authorization authority
```

---

# 117. Final Decision

Baobab SHALL migrate from Keycloak to **Ory Kratos + Ory Hydra**.

The migration SHALL preserve the substantial identity architecture and implementation work already completed.

Keycloak-specific configuration SHALL be translated or retired.

Provider-neutral contracts, canonical identity, Control Plane authority, workload contracts, domain authorization, security invariants, audit semantics and resilience requirements SHALL remain.

`baobab-iam` SHALL remain a first-class Baobab repository and evolve from a Keycloak deployment repository into the **Baobab provider-neutral Identity Integration and Policy Boundary**.

The architectural objective is not merely to make Ory work.

It is to ensure that:

> **Baobab owns its identity architecture without owning credential cryptography, and consumes identity providers without allowing those providers to define Baobab's business architecture.**

The selected implementation is Ory today.

The architecture belongs to Baobab.

---

# 118. Acceptance Statement

ADR-IAM-0019 is satisfied only when Baobab can demonstrate:

```text
Ory authenticates the actor
        │
        ▼
Baobab identifies the canonical actor
        │
        ▼
Control Plane independently resolves context
        │
        ▼
authoritative engine independently authorizes action
```

and when replacing Ory in the future would not require redefining:

```text
CanonicalIdentity
Tenant
LegalEntity
Market
DigitalEstate
CapabilityBinding
BuyerOrganization
SupplierOrganization
Trade authorization
ERP authorization
Baobab security events
```

That is the provider-neutral architecture established by this decision.