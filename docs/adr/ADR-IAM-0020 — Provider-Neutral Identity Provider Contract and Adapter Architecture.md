# ADR-IAM-0020 — Provider-Neutral Identity Provider Contract and Adapter Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/infrastructure`, ZuriBeans, Thamani, Nabhold, and future Baobab Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0019  
**Supersedes:** No ADR  
**Extends:** ADR-IAM-0001, ADR-IAM-0003, ADR-IAM-0004, ADR-IAM-0006, ADR-IAM-0007, ADR-IAM-0008, ADR-IAM-0016, ADR-IAM-0017, ADR-IAM-0019  
**Decision Type:** Platform Architecture / IAM / Integration / Provider Portability / Security  
**Initial Provider Implementation:** Ory Kratos + Ory Hydra

---

# 1. Decision

Baobab SHALL establish a **provider-neutral Identity Provider Contract and Adapter Architecture** between Baobab's canonical identity architecture and any external or self-hosted identity technology.

The selected initial implementation is:

```text
Ory Kratos
+
Ory Hydra
```

However, neither Ory nor any future identity provider SHALL become part of Baobab's canonical business-domain model.

The provider-neutral boundary SHALL be implemented primarily in:

```text
baobab-platform/baobab-iam
```

with canonical contracts shared through:

```text
baobab-platform/shared
```

and canonical identity/context authority remaining in:

```text
baobab-platform/baobab-cp
```

This ADR makes provider neutrality an **enforceable technical architecture**, rather than merely an objective stated by ADR-IAM-0019.

The central rule is:

> **Baobab owns identity meaning. The configured identity provider owns identity mechanics.**

Accordingly:

```text
Provider
   │
   │ proves/authenticates identity
   ▼
Baobab Identity Boundary
   │
   │ normalizes provider semantics
   ▼
Baobab Control Plane
   │
   │ resolves canonical identity/context
   ▼
Domain Engine
   │
   │ evaluates domain authority
   ▼
Business Operation
```

---

# 2. Context

ADR-IAM-0019 decided to migrate Baobab from Keycloak to Ory Kratos and Ory Hydra.

That decision exposed a broader architectural concern.

Simply replacing:

```text
Keycloak
    ↓
Ory
```

would solve the immediate technology migration but would leave Baobab vulnerable to repeating the same architectural coupling.

For example:

```text
Keycloak realm
Keycloak organization
Keycloak user ID
Keycloak service account
Keycloak role
```

could simply become:

```text
Ory project
Ory organization
Kratos identity ID
Hydra client
Ory permission/metadata
```

throughout the platform.

That would be a migration of coupling rather than removal of coupling.

ADR-IAM-0019 therefore established the principle:

> Baobab SHALL depend on identity standards and Baobab identity contracts, not on the business model of a particular identity provider.

This ADR defines how that principle is implemented.

---

# 3. Existing Investment Must Be Preserved

Baobab is not designing identity from scratch.

The existing IAM programme has already implemented or materially progressed:

- `CanonicalIdentity`;
- `ExternalIdentity`;
- `issuer + subject` identity mapping;
- human/workload distinctions;
- workload registries;
- workload lifecycle;
- OAuth/OIDC scopes;
- CP identity/context resolution;
- Capability and CapabilityBinding;
- EngineInstance resolution;
- ZuriBeans/Thamani client isolation;
- Trade workforce authentication;
- CMS workforce authentication;
- iDempiere OIDC groundwork;
- identity lifecycle;
- administrative audit;
- security events;
- session revocation;
- IAM kill switches;
- SBOM/security CI;
- disaster-recovery requirements;
- cross-estate security tests;
- canonical contracts.

These are predominantly **Baobab assets**, not Keycloak assets.

They SHALL survive the migration.

This ADR therefore introduces a boundary around provider-specific implementation rather than redesigning Baobab's identity architecture.

---

# 4. Architectural Objective

The target is:

```text
                 ┌─────────────────────────┐
                 │     DIGITAL ESTATES     │
                 │                         │
                 │ ZuriBeans     Thamani   │
                 │ Nabhold        Future   │
                 └────────────┬────────────┘
                              │
                    OAuth/OIDC / sessions
                              │
                              ▼
                 ┌─────────────────────────┐
                 │   IDENTITY PROVIDER     │
                 │                         │
                 │   Ory today             │
                 │   Provider X tomorrow   │
                 └────────────┬────────────┘
                              │
                  standards + management API
                              │
                              ▼
             ┌────────────────────────────────┐
             │          baobab-iam            │
             │                                │
             │ Identity Provider Adapter      │
             │ Provisioning                   │
             │ Lifecycle                      │
             │ Event Normalisation            │
             │ Reconciliation                 │
             │ Migration                      │
             │ Provider Policy Configuration  │
             └───────────────┬────────────────┘
                             │
                    Baobab contracts
                             │
                             ▼
             ┌────────────────────────────────┐
             │           baobab-cp            │
             │                                │
             │ CanonicalIdentity              │
             │ ExternalIdentity               │
             │ Tenant                         │
             │ LegalEntity                    │
             │ Market                         │
             │ DigitalEstate                  │
             │ Capability                     │
             │ CapabilityBinding              │
             │ EngineInstance                 │
             └───────────────┬────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
            Trade           ERP            CMS
```

---

# 5. Provider Neutrality Is Not Provider Ignorance

Baobab SHALL NOT pretend that identity providers are identical.

Ory, Keycloak, ZITADEL, Microsoft Entra, Auth0 and other identity systems expose different:

- lifecycle APIs;
- event models;
- session models;
- credential-management APIs;
- workload-management APIs;
- federation capabilities;
- administrative models;
- recovery mechanisms;
- organization abstractions.

Attempting to hide all differences behind one enormous universal interface would create a brittle lowest-common-denominator abstraction.

Therefore provider neutrality means:

> **Provider-specific mechanics are contained behind explicit boundaries while Baobab-domain semantics remain provider-independent.**

It does **not** mean:

> Every provider must expose an identical API.

---

# 6. Three Integration Categories

Every identity interaction SHALL be classified into one of three categories.

## Category A — Open Standards

Use the standard directly.

Examples:

```text
OIDC Discovery
OAuth Authorization Endpoint
OAuth Token Endpoint
JWKS
Authorization Code
PKCE
Client Credentials
Token Introspection
standard JWT validation
```

These SHALL NOT be unnecessarily wrapped in proprietary Baobab equivalents.

---

## Category B — Provider Management Operations

These SHALL pass through provider-specific adapter implementations.

Examples:

```text
ProvisionIdentity
DisableIdentity
RevokeProviderSessions
ProvisionWorkload
DisableWorkload
ImportCredential
ConfigureIdentityProvider
ReadProviderIdentity
ReconcileProviderIdentity
```

---

## Category C — Baobab Business Semantics

These SHALL NEVER be delegated to the provider.

Examples:

```text
ResolveCanonicalIdentity
ResolveTenant
ResolveLegalEntity
ResolveMarket
ResolveDigitalEstate
ResolveCapability
ResolveCapabilityBinding
ResolveBuyerMembership
ResolveSupplierAuthority
ResolvePurchaseAuthority
ResolveERPAuthority
```

This distinction is fundamental.

---

# 7. Standards Must Remain Standards

Baobab SHALL NOT introduce APIs such as:

```text
POST /baobab/oauth/token
POST /baobab/oidc/authorize
GET  /baobab/jwks
```

merely to hide Ory.

Applications SHOULD interact with standards-compliant OAuth/OIDC endpoints where appropriate.

For example:

```text
Digital Estate
      │
      │ Authorization Code + PKCE
      ▼
OAuth/OIDC Provider
      │
      │ access token
      ▼
Resource Server
```

The provider-neutral boundary exists around **management and semantic integration**, not around mature Internet standards.

---

# 8. Authentication Request Path

`baobab-iam` SHALL NOT become a synchronous proxy for ordinary token validation.

The normal request path SHOULD be:

```text
Client
   │
   │ access token
   ▼
API / Resource Server
   │
   ├── validate issuer
   ├── validate signature
   ├── validate audience
   ├── validate expiry
   └── validate required scopes
   │
   ▼
External Principal
   │
   │ issuer + subject
   ▼
baobab-cp
   │
   ▼
CanonicalIdentity
   │
   ▼
Context
   │
   ▼
Domain Authorization
```

Not:

```text
Client
   │
   ▼
API
   │
   ▼
baobab-iam
   │
   ▼
Provider
   │
   ▼
baobab-iam
   │
   ▼
CP
```

for every request.

This avoids creating a platform-wide IAM bottleneck.

---

# 9. Provider Adapter Responsibility

The adapter SHALL exist primarily for control-plane operations involving the configured identity provider.

Conceptually:

```go
type IdentityProvider interface {
    ProviderInfo(ctx context.Context) (ProviderInfo, error)

    GetIdentity(
        ctx context.Context,
        subject ExternalSubject,
    ) (*ProviderIdentity, error)

    ProvisionIdentity(
        ctx context.Context,
        spec IdentityProvisioningSpec,
    ) (*ProviderIdentity, error)

    DisableIdentity(
        ctx context.Context,
        subject ExternalSubject,
    ) error

    EnableIdentity(
        ctx context.Context,
        subject ExternalSubject,
    ) error

    RevokeSessions(
        ctx context.Context,
        subject ExternalSubject,
    ) error

    ProvisionWorkload(
        ctx context.Context,
        spec WorkloadProvisioningSpec,
    ) (*ProviderWorkload, error)

    DisableWorkload(
        ctx context.Context,
        workload ProviderWorkloadReference,
    ) error

    ReconcileIdentity(
        ctx context.Context,
        subject ExternalSubject,
    ) (*ReconciliationResult, error)
}
```

This is conceptual, not a mandate for an oversized single Go interface.

Implementation SHOULD prefer capability-oriented interfaces.

---

# 10. Capability-Oriented Interfaces

Rather than creating one monolithic provider interface, implementation SHOULD separate provider capabilities.

For example:

```go
type IdentityReader interface {
    GetIdentity(
        context.Context,
        ExternalSubject,
    ) (*ProviderIdentity, error)
}

type IdentityProvisioner interface {
    ProvisionIdentity(
        context.Context,
        IdentityProvisioningSpec,
    ) (*ProviderIdentity, error)
}

type IdentityLifecycleManager interface {
    DisableIdentity(
        context.Context,
        ExternalSubject,
    ) error

    EnableIdentity(
        context.Context,
        ExternalSubject,
    ) error
}

type SessionRevoker interface {
    RevokeSessions(
        context.Context,
        ExternalSubject,
    ) error
}

type WorkloadProvisioner interface {
    ProvisionWorkload(
        context.Context,
        WorkloadProvisioningSpec,
    ) (*ProviderWorkload, error)
}

type IdentityReconciler interface {
    ReconcileIdentity(
        context.Context,
        ExternalSubject,
    ) (*ReconciliationResult, error)
}
```

This prevents providers from being forced to implement irrelevant capabilities.

---

# 11. Capability Discovery

Provider implementations SHOULD expose capability metadata.

Conceptually:

```json
{
  "provider": "ory",
  "capabilities": {
    "human_identity": true,
    "session_revocation": true,
    "workload_identity": true,
    "password_import": true,
    "totp_import": true,
    "passkey_import": true,
    "enterprise_sso": "deployment-dependent",
    "scim": "deployment-dependent"
  }
}
```

Baobab SHALL NOT silently assume a capability exists.

Missing required capabilities SHALL fail deployment validation.

---

# 12. Provider Identity Model

The adapter SHALL expose a minimal normalized identity representation.

Example:

```go
type ProviderIdentity struct {
    Provider       string
    Issuer         string
    Subject        string
    Status         ProviderIdentityStatus
    CreatedAt      time.Time
    UpdatedAt      time.Time
    Attributes     map[string]any
}
```

The `Attributes` field is provider metadata.

It SHALL NOT become authoritative Baobab business state.

---

# 13. External Subject

The provider-independent identity key SHOULD resemble:

```go
type ExternalSubject struct {
    Issuer  string
    Subject string
}
```

This preserves the architecture established by ADR-IAM-0004.

Canonical identity resolution remains:

```text
issuer
   +
subject
   │
   ▼
ExternalIdentity
   │
   ▼
CanonicalIdentity
```

---

# 14. Provider Field

An optional provider descriptor MAY exist:

```text
provider = "ory"
provider = "keycloak"
provider = "entra"
```

but SHALL NOT replace issuer validation.

Provider labels are operational metadata.

The trusted identity boundary remains based on verified issuer/subject evidence.

---

# 15. Canonical Identity Remains in CP

The adapter SHALL NOT own `CanonicalIdentity`.

```text
Ory Identity
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity
```

Ownership:

```text
Ory Identity       → identity provider
ExternalIdentity   → baobab-cp
CanonicalIdentity  → baobab-cp
```

This remains unchanged from ADR-IAM-0004.

---

# 16. No Provider User ID in Domain Models

Domain engines SHALL NOT introduce canonical fields such as:

```text
keycloak_user_id
ory_identity_id
zitadel_user_id
auth0_user_id
```

for business identity.

Instead:

```text
canonical_identity_id
```

SHOULD be used where canonical human identity is required.

Provider references belong in `ExternalIdentity` or provider-integration state.

---

# 17. Provider-Neutral Principal

`shared` SHOULD define a stable principal contract.

Conceptually:

```json
{
  "actor_type": "human",
  "issuer": "https://identity.example",
  "subject": "provider-subject",
  "client_id": "zuribeans-web",
  "scopes": [
    "openid",
    "profile"
  ],
  "authentication": {
    "methods": [
      "passkey"
    ]
  }
}
```

This represents authenticated evidence.

It does not represent complete authorization.

---

# 18. Principal Is Not Context

The following is prohibited:

```text
Principal
   │
   └── tenant = authoritative tenant
```

Instead:

```text
Principal
   │
   ▼
ExternalIdentity
   │
   ▼
CanonicalIdentity
   │
   ▼
Context Resolver
   │
   ▼
Tenant / LegalEntity / Market / Estate
```

Client-supplied or token-supplied context remains a request, not automatically authoritative truth.

---

# 19. Provider-Neutral Configuration

Applications SHALL progressively replace provider-specific environment names.

Avoid:

```text
KEYCLOAK_URL
KEYCLOAK_REALM
KEYCLOAK_CLIENT_ID
KEYCLOAK_CLIENT_SECRET
```

Prefer:

```text
BAOBAB_IAM_ISSUER
BAOBAB_IAM_DISCOVERY_URL
BAOBAB_IAM_CLIENT_ID
BAOBAB_IAM_CLIENT_SECRET
BAOBAB_IAM_AUDIENCE
```

Provider-management services MAY additionally use:

```text
BAOBAB_IAM_PROVIDER=ory
```

Provider-specific adapter configuration MAY use explicitly namespaced variables internally.

For example:

```text
ORY_KRATOS_ADMIN_URL
ORY_HYDRA_ADMIN_URL
```

Such variables SHALL remain confined to `baobab-iam`, infrastructure or provider-specific modules.

---

# 20. Configuration Boundary

Desired:

```text
                  DOMAIN REPOSITORIES

Trade ───────────────┐
ERP ─────────────────┤
CMS ─────────────────┤── BAOBAB_IAM_ISSUER
Pulse ───────────────┤── BAOBAB_IAM_AUDIENCE
Estates ─────────────┘

                        │
                        ▼

                   baobab-iam
                        │
                        ├── ORY_KRATOS_*
                        └── ORY_HYDRA_*
```

Provider-specific administrative configuration SHOULD NOT leak throughout the polyrepo architecture.

---

# 21. Provider Adapter Registry

`baobab-iam` SHOULD use an explicit provider registry or factory.

Conceptually:

```go
type ProviderName string

const (
    ProviderOry ProviderName = "ory"
)

func NewIdentityProvider(
    cfg ProviderConfig,
) (IdentityProvider, error) {
    switch cfg.Provider {
    case ProviderOry:
        return ory.New(cfg.Ory)
    default:
        return nil, ErrUnsupportedProvider
    }
}
```

This is intentionally simple.

A plugin framework is not required.

---

# 22. No Premature Multi-Provider Runtime

Provider neutrality does not require Baobab to operate several interchangeable IAM providers simultaneously.

The initial production topology SHOULD remain:

```text
Baobab
   │
   ▼
Ory
```

not:

```text
Baobab
 ├── Ory
 ├── Keycloak
 ├── ZITADEL
 └── Auth0
```

except during controlled migrations or federation.

The architecture supports replacement.

It does not require unnecessary runtime complexity.

---

# 23. Provider Adapter Is Not Federation

These are distinct concepts.

```text
Provider Adapter
       │
       └── Baobab integrates its primary IAM infrastructure

Federation
       │
       └── external identity provider authenticates a user
```

Example:

```text
Microsoft Entra
      │
      │ enterprise federation
      ▼
     Ory
      │
      ▼
Baobab Identity Boundary
```

Baobab does not need a Microsoft-specific primary provider adapter merely because a customer uses Microsoft Entra for SSO.

---

# 24. Federation Boundary

Enterprise federation SHALL remain provider-managed where appropriate.

Baobab receives normalized authentication evidence.

```text
Enterprise IdP
      │
      ▼
Configured IAM Provider
      │
      ▼
ExternalSubject
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity
```

Federation SHALL not bypass canonical identity resolution.

---

# 25. Human Identity Provisioning

Where Baobab initiates identity provisioning:

```text
Baobab workflow
      │
      ▼
baobab-iam
      │
      ▼
IdentityProvisioner
      │
      ▼
Ory adapter
      │
      ▼
Kratos
```

The returned provider identity SHALL subsequently be mapped through CP.

---

# 26. Self-Service Registration

Where the provider supports self-service registration, `baobab-iam` need not proxy every registration request.

Example:

```text
ZuriBeans UI
      │
      ▼
Kratos registration flow
      │
      ▼
identity created
      │
      ▼
Baobab lifecycle integration
      │
      ▼
ExternalIdentity
      │
      ▼
CanonicalIdentity
```

This is compatible with provider neutrality because the UI consumes a defined authentication-flow adapter rather than embedding Ory business semantics throughout the estate.

---

# 27. Identity UI Adapter

Because Kratos is headless, Digital Estates require a presentation integration.

The UI boundary SHOULD normalize provider flow representations before they become deeply embedded in estate components.

Conceptually:

```text
Kratos flow
    │
    ▼
Baobab identity-flow adapter
    │
    ▼
IdentityFlow
    │
    ├── identifier
    ├── password
    ├── passkey
    ├── verification
    ├── recovery
    └── MFA
    │
    ▼
Estate UI
```

This SHALL remain lightweight.

Baobab SHALL NOT attempt to invent a universal authentication-flow protocol.

---

# 28. Digital Estate Ownership

The estate owns:

```text
layout
branding
content
accessibility
interaction
navigation
responsive behavior
journey integration
```

The provider owns:

```text
credential verification
flow state
security challenges
passkey ceremony
MFA verification
session creation
recovery cryptography
```

The adapter maps between them.

---

# 29. Authentication Flow Security

The UI adapter SHALL NOT alter security requirements returned by the provider.

For example, if the provider requires:

```text
passkey challenge
```

the adapter SHALL NOT silently render:

```text
password-only fallback
```

unless provider policy explicitly permits it.

Provider neutrality SHALL never become security downgrading.

---

# 30. Workload Identity Contract

Workload identity SHALL also remain provider-neutral.

Conceptually:

```go
type WorkloadSpec struct {
    WorkloadID       string
    DisplayName      string
    AllowedScopes    []string
    AllowedAudiences []string
    LifecycleStatus  WorkloadLifecycleStatus
}
```

This contract SHALL NOT contain:

```text
keycloak_service_account
hydra_internal_client_uuid
```

as canonical fields.

---

# 31. Workload Provisioning

Flow:

```text
Workload Registry
       │
       ▼
baobab-iam
       │
       ▼
WorkloadProvisioner
       │
       ▼
Ory/Hydra adapter
       │
       ▼
OAuth client
```

The registry remains authoritative for Baobab workload meaning.

Hydra owns the OAuth credential mechanics.

---

# 32. Workload Revocation

A revoked workload MUST cease to obtain or use authority according to established lifecycle policy.

```text
Workload Registry
status = REVOKED
       │
       ▼
Lifecycle reconciliation
       │
       ▼
Provider client disabled/revoked
       │
       ▼
new authentication denied
```

Any remaining token validity window SHALL be governed by ADR-IAM-0006/0007 security requirements.

---

# 33. Lifecycle Commands

Provider-neutral lifecycle commands SHOULD use semantic names.

Examples:

```text
DisableIdentity
EnableIdentity
RevokeSessions
SuspendWorkload
RevokeWorkload
```

Avoid domain-neutral code issuing provider operations directly such as:

```text
DisableKratosIdentity
DeleteHydraClient
DisableKeycloakUser
```

outside provider modules.

---

# 34. Lifecycle Events

Similarly, canonical events SHOULD express Baobab meaning.

Provider:

```text
ory.kratos.session.revoked
```

Adapter:

```text
identity.session.revoked.v1
```

Consumers subscribe to:

```text
identity.session.revoked.v1
```

not the provider-native event.

---

# 35. Event Normalisation Pipeline

```text
┌────────────────────┐
│ Provider Event     │
│ Kratos / Hydra     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Provider Adapter   │
│ validation         │
│ deduplication      │
│ normalization      │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Baobab IAM Event   │
│ Contract           │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Event Transport    │
└─────────┬──────────┘
          │
    ┌─────┼──────┐
    ▼     ▼      ▼
   CP   Trade   ERP
```

---

# 36. Canonical Event Envelope

`shared` SHOULD maintain a canonical envelope such as:

```json
{
  "event_id": "evt_...",
  "event_type": "identity.disabled.v1",
  "occurred_at": "2026-09-26T00:00:00Z",
  "correlation_id": "corr_...",
  "actor": {},
  "subject": {
    "canonical_identity_id": "ci_..."
  },
  "source": {
    "component": "baobab-iam",
    "provider": "ory"
  },
  "reason_code": "SECURITY_ADMIN_ACTION"
}
```

Provider-native payload MAY be retained securely for diagnostic purposes where appropriate but SHALL NOT become the cross-engine contract.

---

# 37. Event Idempotency

Provider events may be:

- duplicated;
- delayed;
- retried;
- reordered.

The adapter SHALL therefore support:

```text
event ID
provider event ID
deduplication
idempotency
event version
occurred_at
received_at
```

Consumers SHALL not assume exactly-once delivery.

---

# 38. Reconciliation

Events alone are insufficient for security correctness.

The adapter SHALL support reconciliation.

```text
Expected Baobab state
        │
        ├─────────────┐
        │             │
        ▼             ▼
 Provider state    CP state
        │             │
        └──────┬──────┘
               ▼
            Compare
               │
       ┌───────┴───────┐
       ▼               ▼
    consistent       drift
                       │
                       ▼
                 remediate/alert
```

---

# 39. Reconciliation Examples

Examples include:

```text
CP identity DISABLED
Provider identity ACTIVE
        ↓
security drift
```

and:

```text
Workload registry REVOKED
Hydra client ACTIVE
        ↓
security drift
```

and:

```text
Provider identity exists
No ExternalIdentity mapping
        ↓
orphan candidate
```

---

# 40. Reconciliation Authority

Reconciliation SHALL understand which system is authoritative for each fact.

| Fact | Authority |
|---|---|
| credential | provider |
| provider authentication session | provider |
| provider subject | provider |
| CanonicalIdentity | CP |
| ExternalIdentity mapping | CP |
| Tenant | CP |
| LegalEntity | CP |
| Market | CP |
| CapabilityBinding | CP |
| workload meaning/lifecycle | Baobab workload registry |
| Trade buyer authority | Trade |
| supplier approval | supplier domain |
| ERP role | iDempiere |

The adapter SHALL NOT "repair" domain state using provider data.

---

# 41. Provider Status Is Not Canonical Status

Example:

```text
Kratos identity = active
```

does not imply:

```text
CanonicalIdentity = permitted
```

Similarly:

```text
CanonicalIdentity = active
```

does not imply:

```text
buyer membership = active
```

Authorization continues to evaluate all relevant layers.

---

# 42. Identity Disable Flow

Example:

```text
Security Administrator
         │
         ▼
Disable CanonicalIdentity
         │
         ▼
baobab-cp
         │
         ├── immediately deny context
         │
         └── lifecycle command
                    │
                    ▼
               baobab-iam
                    │
                    ▼
             Provider Adapter
                    │
                    ▼
             disable identity
                    │
                    ▼
             revoke sessions
```

CP denial SHOULD not wait for eventual provider propagation where immediate platform denial is required.

---

# 43. Provider Failure During Disable

If:

```text
CP disable succeeds
```

but:

```text
provider disable fails
```

Baobab SHALL remain secure because CP denies authorization.

The adapter SHALL retry provider synchronization.

```text
CP = DISABLED
Provider = ACTIVE
       │
       ▼
authentication might still succeed
       │
       ▼
CP context authorization denies
```

This demonstrates why authentication and authorization remain separate.

---

# 44. Provider Failure During Provisioning

Provisioning SHALL be idempotent.

A workflow SHALL tolerate:

```text
request
  ↓
provider identity created
  ↓
network failure
  ↓
Baobab retries
```

without creating duplicate identities.

Use deterministic idempotency/migration keys where provider APIs permit.

---

# 45. Provider-Specific IDs

Provider IDs MAY be persisted in integration records.

For example:

```json
{
  "provider": "ory",
  "provider_identity_id": "...",
  "issuer": "...",
  "subject": "..."
}
```

They SHALL NOT become foreign keys across Baobab domain databases.

---

# 46. Mapping Spine

The canonical mapping remains:

```text
Provider Identity
       │
       ▼
ExternalIdentity
       │
       ▼
CanonicalIdentity
       │
       ├── ExternalReference → Trade
       ├── ExternalReference → ERP
       ├── ExternalReference → CMS
       └── ExternalReference → other engines
```

Provider-specific identity IDs stop at the external identity boundary.

---

# 47. Domain Engine Integration

Domain engines SHOULD know:

```text
canonical identity
context
authorization evidence
```

not:

```text
Kratos internal schema
Hydra administration model
Keycloak realm
Ory organization semantics
```

---

# 48. Trade Example

Correct:

```text
Hydra token
    │
    ▼
validated principal
    │
    ▼
CanonicalIdentity
    │
    ▼
BuyerMembership
    │
    ▼
Trade authorization
```

Incorrect:

```text
Hydra role
    │
    ▼
purchase approval
```

Purchase authority remains a Trade-domain concern.

---

# 49. ERP Example

Correct:

```text
authenticated principal
      │
      ▼
CanonicalIdentity
      │
      ▼
ERP mapping
      │
      ▼
AD_User
      │
      ▼
AD_Role
```

Incorrect:

```text
Ory role
   =
AD_Role
```

---

# 50. Supplier Example

Correct:

```text
authenticated identity
      │
      ▼
CanonicalIdentity
      │
      ▼
SupplierRepresentative
      │
      ▼
SupplierOrganization
      │
      ▼
Supplier domain authority
```

Incorrect:

```text
Kratos identity active
      =
supplier approved
```

---

# 51. Thamani Example

A Thamani customer may simultaneously hold:

```text
CanonicalIdentity Jane
       │
       ├── Personal customer relationship
       │
       ├── Business A representative
       │
       └── Business B representative
```

The provider authenticates Jane.

The adapter does not encode those relationships.

CP/domain systems do.

---

# 52. ZuriBeans Example

A ZuriBeans buyer:

```text
Kratos authentication
        │
        ▼
CanonicalIdentity
        │
        ▼
BuyerOrganizationMembership
        │
        ▼
Trade authorization
```

The adapter SHALL not translate an Ory organization into a buyer organization automatically.

---

# 53. Provider Organization Boundary

If Ory organization capabilities are later used:

```text
Ory Organization
       │
       │ explicit mapping if needed
       ▼
Baobab relationship
```

Never:

```text
Ory Organization
       =
Tenant
```

or:

```text
Ory Organization
       =
BuyerOrganization
```

---

# 54. Provider Roles

Provider roles MAY be used for narrowly provider-related administration.

Examples:

```text
IAM operator
identity support
provider administrator
```

They SHALL NOT become the universal platform authorization model.

---

# 55. Administrative Separation

Provider administration SHALL remain distinct from:

```text
CP administration
Trade administration
ERP administration
CMS administration
supplier administration
executive access
```

A provider administrator SHALL not automatically become a Baobab platform superuser.

---

# 56. Privileged Provider Operations

Operations such as:

```text
disable identity
credential reset
MFA reset
session revocation
identity merge support
federation configuration
```

SHALL require appropriately privileged service/workforce identities.

They SHALL be audited.

---

# 57. Provider API Credentials

Administrative provider credentials SHALL:

- be service-specific;
- be least privilege;
- be secret-managed;
- be rotatable;
- never be embedded in Digital Estates;
- never be exposed to browsers;
- never be shared casually between environments.

---

# 58. Environment Isolation

Development, test, staging and production SHALL have isolated identity-provider security boundaries.

Production credentials SHALL not authenticate against development provider administration APIs.

Provider neutrality SHALL not weaken environment isolation.

---

# 59. Migration Adapter

During Keycloak → Ory migration, `baobab-iam` MAY temporarily contain:

```text
provider/
├── keycloak/
└── ory/
```

This is permitted specifically for migration.

The architecture becomes:

```text
                Migration Service
                      │
             ┌────────┴────────┐
             ▼                 ▼
       Keycloak Adapter     Ory Adapter
             │                 │
             ▼                 ▼
         Keycloak          Kratos/Hydra
```

This SHALL NOT imply permanent multi-provider operation.

---

# 60. Migration Mapping

Example:

```text
Keycloak
 issuer = old-issuer
 sub    = abc
      │
      ▼
ExternalIdentity A
      │
      ▼
CanonicalIdentity 42
      ▲
      │
ExternalIdentity B
      ▲
      │
Ory
 issuer = new-issuer
 sub    = xyz
```

This is the core mechanism enabling migration without destroying canonical identity continuity.

---

# 61. Migration Ledger

The migration SHOULD maintain an auditable ledger.

Conceptually:

```text
migration_id
canonical_identity_id
source_provider
source_subject
target_provider
target_subject
credential_strategy
migration_status
verification_status
started_at
completed_at
rollback_status
```

Sensitive credential material SHALL NOT be recorded in the ledger.

---

# 62. Provider-Neutral Migration Status

Statuses SHOULD describe migration meaning:

```text
PENDING
PROVISIONED
CREDENTIAL_MIGRATED
VERIFIED
CUTOVER
ROLLED_BACK
RETIRED
```

rather than provider-specific workflow states.

---

# 63. Provider Replacement Test

ADR compliance SHALL include a design-time provider replacement exercise.

Teams SHOULD ask:

> What changes if Ory is replaced?

Expected:

```text
baobab-iam provider implementation
provider deployment
provider configuration
OAuth/OIDC issuer/client configuration
estate flow binding
migration tooling
```

Unexpected:

```text
Tenant model
LegalEntity model
BuyerOrganization
SupplierOrganization
Trade authorization
ERP authorization
CanonicalIdentity
CapabilityBinding
Market
DigitalEstate
```

If the second list changes merely because the provider changes, this ADR has been violated.

---

# 64. Repository Boundary

Target direction:

```text
baobab-iam/
├── cmd/
│   └── identity-adapter/
│
├── internal/
│   ├── identity/
│   ├── lifecycle/
│   ├── provisioning/
│   ├── reconciliation/
│   ├── events/
│   ├── migration/
│   └── provider/
│       ├── contracts/
│       └── ory/
│
├── kratos/
│   ├── config/
│   ├── schemas/
│   └── hooks/
│
├── hydra/
│   ├── config/
│   ├── clients/
│   └── scopes/
│
├── tests/
│   ├── contract/
│   ├── integration/
│   ├── migration/
│   └── security/
│
├── deployments/
└── docs/
```

Exact restructuring SHALL follow repository inspection and staged migration.

---

# 65. `shared` Boundary

`shared` SHOULD contain provider-neutral contracts only.

For example:

```text
contracts/
└── identity/
    └── v1/
        ├── principal.schema.json
        ├── external-subject.schema.json
        ├── workload-identity.schema.json
        ├── authentication-context.schema.json
        └── identity-event.schema.json
```

It SHALL NOT contain:

```text
kratos-identity.schema.json
hydra-client.schema.json
```

as canonical cross-platform contracts.

Provider-specific schemas belong in `baobab-iam`.

---

# 66. CP Boundary

`baobab-cp` SHALL remain unaware of unnecessary provider implementation details.

It MAY know:

```text
issuer
subject
provider descriptor
authentication metadata
```

where needed.

It SHOULD NOT need to understand:

```text
Kratos flow IDs
Hydra admin APIs
Kratos credential internals
Hydra consent internals
```

---

# 67. Infrastructure Boundary

`infrastructure` owns deployment concerns such as:

```text
DNS
TLS
network policy
secrets
PostgreSQL deployment
Kubernetes
backups
monitoring
regional placement
```

It SHALL not redefine canonical identity semantics.

---

# 68. API Gateway Boundary

APISIX or another gateway MAY:

```text
terminate TLS
validate basic token properties
rate limit
route
apply infrastructure policy
```

It SHALL NOT become the canonical identity/context authority.

Gateway-injected headers SHALL not be blindly trusted without an established trusted-hop contract.

---

# 69. Error Model

Provider errors SHOULD be normalized at the adapter boundary.

Examples:

```text
IDENTITY_NOT_FOUND
IDENTITY_ALREADY_EXISTS
IDENTITY_DISABLED
SESSION_REVOCATION_FAILED
PROVIDER_UNAVAILABLE
PROVIDER_RATE_LIMITED
PROVIDER_CONFIGURATION_ERROR
WORKLOAD_NOT_FOUND
WORKLOAD_DISABLED
UNSUPPORTED_PROVIDER_CAPABILITY
```

Internal provider error details SHOULD remain observable without leaking sensitive information to clients.

---

# 70. Retry Model

Retry only operations known to be safe/idempotent or protected by idempotency controls.

Examples:

```text
read identity           → retryable
reconciliation          → retryable
idempotent provisioning → retryable
session revocation      → provider semantics determine
credential mutation     → careful handling required
```

Blind retries are prohibited for security-sensitive non-idempotent operations.

---

# 71. Circuit Breaking

Provider-management operations SHOULD support:

```text
timeouts
bounded retries
circuit breaking
backoff
health monitoring
```

where appropriate.

Provider outage SHALL not cause uncontrolled request amplification.

---

# 72. Rate Limits

Provider administrative APIs may impose rate limits.

Bulk migration and reconciliation SHALL therefore use:

```text
bounded concurrency
backoff
checkpointing
resume capability
```

rather than unrestricted parallelism.

---

# 73. Reconciliation Scheduling

Reconciliation frequency SHALL reflect security importance.

For example:

```text
revoked workload drift
      → high priority

disabled privileged identity drift
      → high priority

non-security profile metadata drift
      → lower priority
```

The implementation SHALL not treat all drift equally.

---

# 74. Security Event Priority

Canonical events SHOULD carry reason/severity metadata sufficient for downstream security processing.

Example:

```json
{
  "event_type": "identity.disabled.v1",
  "severity": "high",
  "reason_code": "SECURITY_COMPROMISE"
}
```

Provider-specific severity terminology SHALL be normalized where appropriate.

---

# 75. Audit Requirements

Every privileged adapter operation SHALL record:

```text
actor
subject
action
provider
correlation ID
reason
outcome
timestamp
```

without recording:

```text
password
access token
refresh token
authorization code
client secret
private key
recovery secret
```

---

# 76. Observability

Provider adapters SHALL expose:

```text
request count
failure count
latency
rate-limit responses
reconciliation drift
provisioning failures
revocation failures
event normalization failures
orphan identities
migration status
```

Metrics SHALL avoid high-cardinality identity labels where inappropriate.

---

# 77. Tracing

Distributed tracing SHOULD permit:

```text
business request
      │
      ▼
CP
      │
      ▼
baobab-iam
      │
      ▼
provider
```

for administrative/lifecycle workflows.

Normal token validation SHOULD not require such a call chain.

---

# 78. Data Minimization

The adapter SHALL retrieve only provider information needed for its operation.

It SHALL not create a shadow copy of the entire provider identity database.

---

# 79. Credential Boundary

Credential material belongs to the provider.

Baobab SHALL not ordinarily persist:

```text
password hashes
TOTP secrets
passkey private material
recovery secrets
```

Migration tooling MAY temporarily process supported credential representations where required, but SHALL use strict security controls and minimize persistence.

---

# 80. Passkeys

Passkey ceremonies remain provider-owned.

Baobab UI may present the experience.

The provider executes and validates the WebAuthn operation.

The adapter SHALL not implement cryptographic WebAuthn verification independently.

---

# 81. MFA

MFA policy remains governed by Baobab's assurance ADRs.

Provider implementation satisfies the policy.

```text
Baobab policy
     │
     ▼
required assurance
     │
     ▼
provider configuration
```

not:

```text
provider default
     │
     ▼
Baobab policy
```

---

# 82. Provider Defaults

Security-sensitive provider defaults SHALL be treated as configuration inputs, not Baobab policy.

Explicitly configure where necessary:

```text
token lifetimes
session lifetimes
MFA
recovery
credential policy
redirect URIs
CORS
trusted origins
client authentication
logout behavior
```

---

# 83. Version Pinning

The configured provider version SHALL be pinned.

Provider upgrades SHALL follow controlled promotion:

```text
development
    ↓
integration
    ↓
staging
    ↓
security verification
    ↓
production
```

Floating production tags are prohibited.

---

# 84. Contract Versioning

Baobab provider-neutral contracts SHALL use explicit versioning.

Example:

```text
identity.principal.v1
identity.disabled.v1
workload.revoked.v1
```

Provider upgrades SHALL not silently alter canonical contracts.

---

# 85. Backward Compatibility

When a canonical identity contract changes:

```text
v1
 ↓
v2
```

the change SHALL follow shared contract governance.

The provider adapter SHALL absorb provider-specific changes wherever possible.

---

# 86. Testing Layers

The architecture requires four distinct test layers.

### Provider tests

```text
Does Ory perform the expected operation?
```

### Adapter contract tests

```text
Does Ory behavior satisfy Baobab's provider contract?
```

### Platform tests

```text
Does CP correctly resolve identity/context?
```

### Domain tests

```text
Does Trade/ERP/etc correctly authorize the operation?
```

All four are required.

---

# 87. Provider Contract Test Suite

`baobab-iam` SHOULD maintain reusable contract tests.

Conceptually:

```text
provider creates identity
provider reads identity
provider disables identity
provider enables identity
provider revokes sessions
provider provisions workload
provider disables workload
provider reports unsupported capability correctly
```

A future provider implementation SHALL pass the relevant suite before adoption.

---

# 88. Negative Tests

Provider-neutral security tests SHALL include:

```text
unknown issuer
wrong audience
expired token
tampered token
disabled identity
revoked workload
wrong estate
wrong tenant
stale membership
duplicate external mapping
provider unavailable
provider rate limited
event replay
event duplication
out-of-order event
```

---

# 89. Cross-Provider Migration Test

Migration tooling SHALL prove:

```text
Provider A identity
       │
       ▼
CanonicalIdentity
       ▲
       │
Provider B identity
```

without creating:

```text
duplicate CanonicalIdentity
```

---

# 90. Failure Containment

A provider-management outage SHALL not automatically make every already-authenticated API request dependent on `baobab-iam`.

Conversely, a valid cached/locally validated token SHALL not override a CP/domain security denial.

This creates layered resilience.

---

# 91. Provider Compromise

If the primary identity provider is suspected compromised:

```text
Provider compromise
      │
      ├── stop new trust
      ├── rotate signing/trust material
      ├── suspend affected issuers
      ├── invoke CP security controls
      ├── revoke sensitive capabilities
      └── initiate incident response
```

The provider-neutral architecture SHALL support issuer-level kill switches.

---

# 92. Issuer Registry

Trusted issuers SHOULD be governed centrally.

Conceptually:

```text
TrustedIssuer
├── issuer
├── provider
├── environment
├── status
├── allowed audiences
├── discovery metadata
└── migration expiry
```

Resource servers SHOULD not accumulate arbitrary hard-coded issuers.

---

# 93. Migration Issuer

A legacy issuer MAY be marked:

```text
MIGRATION_ONLY
```

with an expiry.

Example:

```text
Keycloak issuer
status = MIGRATION_ONLY
expires = <cutover deadline>
```

This prevents accidental permanent dual trust.

---

# 94. Client Registry

OAuth clients SHOULD have Baobab-owned logical identity independent of provider internal IDs.

Example:

```text
logical client:
zuribeans-web

provider:
ory

provider client ID:
<actual Hydra client ID>
```

The logical application identity survives provider migration.

---

# 95. Redirect URI Governance

Redirect URIs SHALL be controlled through configuration-as-code and tests.

Wildcards SHOULD be prohibited except where explicitly justified.

Cross-estate callback confusion SHALL be tested.

---

# 96. Scope Governance

Scopes remain Baobab contracts.

Provider configuration implements them.

```text
Baobab scope registry
        │
        ▼
provider client configuration
```

not:

```text
provider-created arbitrary scope
        │
        ▼
automatically becomes Baobab authority
```

---

# 97. Audience Governance

Audiences SHALL be explicit.

A token issued for:

```text
baobab-trade
```

SHALL not automatically authorize:

```text
baobab-erp
```

Provider neutrality SHALL preserve audience isolation.

---

# 98. Provider-Specific Extensions

Provider-specific extensions MAY be implemented only when:

1. the requirement cannot reasonably be satisfied through standards or configuration;
2. the extension is isolated inside the provider implementation;
3. no Baobab canonical contract becomes provider-specific;
4. tests exist;
5. upgrade implications are documented.

---

# 99. No Provider Fork by Default

Baobab SHOULD prefer:

```text
native capability
    ↓
configuration
    ↓
adapter
    ↓
supported extension
```

before:

```text
fork provider
```

Forking Ory or a future provider requires a separate architectural decision.

---

# 100. Build-vs-Provider Boundary

Baobab SHALL build:

```text
identity UX
canonical identity
context resolution
provider adapters
event normalization
reconciliation
migration tooling
domain relationships
```

Baobab SHALL NOT rebuild:

```text
OAuth server
OIDC provider
password verifier
WebAuthn server
TOTP engine
session cryptography
token signing system
```

unless a future ADR explicitly changes this decision.

---

# 101. Security Ownership

The security responsibility model is:

| Concern | Owner |
|---|---|
| credential validation | identity provider |
| OAuth/OIDC | identity provider |
| provider sessions | identity provider |
| identity UX | Digital Estate + IAM integration |
| canonical identity | CP |
| external identity mapping | CP |
| tenant/context | CP |
| capability | CP |
| buyer authorization | Trade |
| supplier approval | supplier domain |
| ERP authorization | iDempiere |
| provider lifecycle integration | baobab-iam |
| canonical identity events | baobab-iam/shared |
| gateway/network security | infrastructure |

---

# 102. Provider-Neutrality Enforcement

CI SHOULD eventually detect prohibited provider coupling.

Examples:

```text
keycloak_user_id
ory_identity_id
kratos_identity_id
hydra_client_uuid
```

appearing in canonical domain contracts SHOULD trigger architectural review.

Provider-specific repositories/modules are exempt where such identifiers are legitimate.

---

# 103. Architecture Fitness Test

A repository passes the provider-neutrality fitness test when:

```text
Provider changes
     │
     ▼
Does repository business logic change?
```

For most repositories:

```text
NO
```

Configuration may change.

Protocol issuer/client metadata may change.

Business semantics should not.

---

# 104. Exceptions

Some components legitimately remain provider-aware:

```text
baobab-iam provider module
migration tooling
provider deployment configuration
provider integration tests
infrastructure manifests
identity UI flow adapter
```

Provider awareness is not itself a violation.

**Provider leakage into canonical business semantics is the violation.**

---

# 105. Ory Implementation

The initial provider implementation SHALL contain separate Kratos and Hydra integration concerns.

Conceptually:

```text
provider/ory/
├── identity/
│   └── kratos
│
├── oauth/
│   └── hydra
│
├── lifecycle/
├── events/
├── workloads/
├── migration/
└── reconciliation/
```

Kratos and Hydra SHALL not be treated as if they were one monolithic server.

---

# 106. Kratos Boundary

Kratos integration owns provider mechanics for:

```text
human identity
credentials
verification
recovery
MFA
passkeys
provider authentication sessions
```

---

# 107. Hydra Boundary

Hydra integration owns provider mechanics for:

```text
OAuth clients
OIDC
authorization code
PKCE
token issuance
client credentials
token introspection where used
workload OAuth
```

---

# 108. Kratos-Hydra Integration

Their internal integration SHALL remain an IAM implementation concern.

Other Baobab engines SHOULD not need to understand why:

```text
Kratos
+
Hydra
```

are separate products.

They consume standards and Baobab contracts.

---

# 109. Future Provider Example

Suppose Baobab later adopts another provider.

The desired change is:

```text
provider/
├── ory/
└── future-provider/
```

plus deployment/migration configuration.

The following remain unchanged:

```text
CanonicalIdentity
ExternalIdentity concept
Tenant
LegalEntity
Market
DigitalEstate
Capability
CapabilityBinding
BuyerOrganization
SupplierOrganization
Trade authorization
ERP authorization
```

This is the primary architectural success criterion.

---

# 110. Consequences — Positive

This architecture:

- protects Baobab from deep provider lock-in;
- preserves the substantial work already completed;
- isolates Ory-specific implementation;
- keeps OAuth/OIDC standards native;
- prevents `baobab-iam` from becoming a request-path bottleneck;
- preserves CP authority;
- preserves engine-native authorization;
- supports controlled future provider migration;
- enables Ory's headless identity UX without contaminating domain models;
- improves testability;
- provides a natural location for lifecycle/reconciliation logic;
- provides an explicit home for migration tooling;
- normalizes security events;
- supports polyrepo evolution.

---

# 111. Consequences — Negative

The architecture introduces an additional integration layer.

Baobab must maintain:

```text
provider adapters
provider contract tests
reconciliation
event normalization
migration tooling
```

Poor abstraction design could produce unnecessary complexity.

Therefore the implementation SHALL remain intentionally narrow.

The provider-neutral layer SHALL exist where provider differences matter.

It SHALL not wrap standards merely for architectural purity.

---

# 112. Alternatives Considered

## Direct Ory integration everywhere

Rejected.

```text
Trade ──────► Ory
ERP ─────────► Ory
CMS ─────────► Ory
CP ──────────► Ory
Estates ─────► Ory internals
```

would recreate provider coupling.

---

## Proxy all authentication through `baobab-iam`

Rejected.

It would:

- add latency;
- create a central availability dependency;
- duplicate standard OAuth/OIDC functionality;
- complicate scaling;
- undermine independent JWT validation.

---

## Build a universal IAM abstraction

Rejected.

Attempting to normalize every feature of every IdP would produce a lowest-common-denominator identity platform that Baobab itself would have to maintain.

---

## Keep Keycloak-specific architecture

Rejected by ADR-IAM-0019.

---

# 113. Implementation Sequence

Recommended sequence:

```text
IAM-A0
Current provider-coupling inventory
       ↓
IAM-A1
Canonical contract audit
       ↓
IAM-A2
Provider-neutral configuration
       ↓
IAM-A3
Provider capability interfaces
       ↓
IAM-A4
Ory implementation
       ↓
IAM-A5
Contract tests
       ↓
IAM-A6
Lifecycle/reconciliation
       ↓
IAM-A7
Event normalization
       ↓
IAM-A8
Digital Estate flow adapter
       ↓
IAM-A9
Cross-repository coupling removal
       ↓
IAM-A10
Provider replacement fitness test
```

These MAY be coordinated with ADR-IAM-0019 migration gates rather than creating duplicate implementation programmes.

---

# 114. Definition of Done

ADR-IAM-0020 is implemented when:

- canonical identity contracts contain no unnecessary Keycloak/Ory semantics;
- provider-specific management APIs are isolated;
- standards-based OAuth/OIDC remains directly consumable;
- `baobab-iam` has an explicit provider boundary;
- Ory Kratos/Hydra implement the required provider capabilities;
- CP remains canonical identity/context authority;
- domain engines remain domain authorization authorities;
- provider-native events are normalized;
- reconciliation exists;
- workload lifecycle is provider-neutral;
- Digital Estates do not implement credential cryptography;
- provider-specific IDs do not leak into canonical domain models;
- provider contract tests pass;
- negative security tests pass;
- future provider replacement can be described without changing Baobab's domain model.

---

# 115. Final Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         DIGITAL ESTATES                             │
│                                                                     │
│    ZuriBeans          Thamani          Nabhold        Future        │
│       B2B            B2B + B2C                                     │
└───────────────┬─────────────────────────────────────────────────────┘
                │
                │ standards / identity flows
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     IDENTITY PROVIDER                               │
│                                                                     │
│               Ory Kratos + Ory Hydra                               │
│                                                                     │
│ Identity │ Credentials │ Sessions │ OAuth │ OIDC │ Workloads       │
└───────────────┬─────────────────────────────────────────────────────┘
                │
                │ provider-specific management
                │ provider events
                │ standards
                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         baobab-iam                                  │
│                                                                     │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │              PROVIDER-NEUTRAL BOUNDARY                          │ │
│ │                                                                 │ │
│ │ Provisioning │ Lifecycle │ Workloads │ Events │ Reconciliation │ │
│ │ Migration    │ Capability Discovery │ Provider Policy          │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                              │                                      │
│                 ┌────────────┴────────────┐                         │
│                 │ Ory Provider Adapter    │                         │
│                 └─────────────────────────┘                         │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                         Baobab contracts
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           baobab-cp                                 │
│                                                                     │
│ CanonicalIdentity │ ExternalIdentity │ Tenant │ LegalEntity         │
│ Market │ DigitalEstate │ Capability │ CapabilityBinding            │
│ EngineInstance │ Context │ IsolationProfile                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                 ┌──────────────┼───────────────┐
                 ▼              ▼               ▼
             ┌───────┐      ┌───────┐       ┌───────┐
             │ Trade │      │  ERP  │       │  CMS  │
             │       │      │       │       │       │
             │Domain │      │Domain │       │Domain │
             │ AuthZ │      │ AuthZ │       │ AuthZ │
             └───────┘      └───────┘       └───────┘
```

---

# 116. Final Invariants

The following SHALL remain true regardless of identity provider:

```text
Provider Identity ≠ CanonicalIdentity

Provider Organization ≠ Tenant

Provider Organization ≠ LegalEntity

Provider Organization ≠ BuyerOrganization

Provider Organization ≠ SupplierOrganization

Provider Role ≠ Trade Role

Provider Role ≠ AD_Role

Authentication ≠ Authorization

Valid Provider Session ≠ Valid Baobab Context

Valid OAuth Token ≠ Current Business Authority

Email Equality ≠ Identity Equality

Workload Identity ≠ Human Identity

Identity Provider ≠ Control Plane

Control Plane ≠ Domain Authorization Engine

Provider Event ≠ Canonical Baobab Event

Provider Availability ≠ Platform Authorization Authority
```

---

# 117. Architectural Test

The simplest test of this ADR is:

```text
        Replace Ory
            │
            ▼
What must change?
```

A compliant architecture answers:

```text
Provider adapter
Provider deployment
Provider configuration
Migration tooling
Issuer/client configuration
Identity-flow binding
```

A non-compliant architecture answers:

```text
CanonicalIdentity
Tenant
LegalEntity
Market
BuyerOrganization
SupplierOrganization
Trade authorization
ERP authorization
DigitalEstate model
```

The second outcome is prohibited.

---

# 118. Final Decision Principle

Baobab SHALL maintain a provider-neutral identity boundary while using Ory Kratos and Ory Hydra as its selected identity implementation.

Provider neutrality SHALL be achieved through:

1. standards where standards already exist;
2. adapters where provider management semantics differ;
3. canonical Baobab contracts where platform meaning is required;
4. strict authority boundaries between identity, context and domain authorization.

The objective is **not abstraction for abstraction's sake**.

The objective is to ensure that Baobab can benefit deeply from Ory without allowing Ory to become Baobab's architecture.

> **Identity providers are replaceable infrastructure. Canonical identity is Baobab architecture.**

That distinction SHALL govern all subsequent IAM implementation.