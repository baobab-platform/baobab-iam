# MCP IMPLEMENTATION PROMPT

## Capability-Led Migration of `baobab-platform/baobab-iam` from Keycloak to Ory

You are an MCP engineering agent working primarily across:

```text
baobab-platform/baobab-iam
baobab-platform/shared
baobab-platform/baobab-cp
```

and, where integration evidence requires it:

```text
baobab-platform/zuribeans
baobab-platform/thamani
baobab-platform/infrastructure
```

Other Baobab repositories may be inspected when required to establish architectural compatibility, but changes outside the core migration repositories must be narrowly justified.

Your mission is to **continue and complete the migration of Baobab IAM from Keycloak to Ory using a capability-led, provider-neutral architecture**.

Do not approach this as:

> “replace Keycloak configuration with Ory configuration.”

That would be architecturally incorrect.

The required outcome is:

> **Baobab IAM exposes stable Baobab-owned identity capabilities and contracts, while Ory becomes the current provider implementing those capabilities behind a provider-neutral boundary.**

The architecture must remain capable of replacing Ory in future without forcing Baobab digital estates, the Control Plane, Trade, ERP, CMS, Pulse, or other domain engines to rewrite their identity semantics.

---

# 1. Governing architectural principle

The migration SHALL preserve the following separation:

```text
┌──────────────────────────────────────────────────────────┐
│                    BAOBAB PLATFORM                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  WHO IS THE ACTOR?                                       │
│        │                                                 │
│        ▼                                                 │
│  baobab-iam                                              │
│  Identity Security Engine                                │
│  ─────────────────────────                               │
│  Authentication                                          │
│  Identity lifecycle                                      │
│  Sessions                                                │
│  Federation                                              │
│  Assurance                                               │
│  Workload identity                                       │
│  Security/revocation                                     │
│        │                                                 │
│        │ Principal / verified identity                   │
│        ▼                                                 │
│  baobab-cp                                               │
│  Control Plane                                           │
│  ─────────────                                           │
│  Canonical identity association                          │
│  Tenant context                                          │
│  Legal entity context                                    │
│  Market                                                  │
│  Digital estate                                          │
│  Capability bindings                                     │
│  Engine resolution                                       │
│  Administrative grants                                   │
│        │                                                 │
│        │ authoritative context                           │
│        ▼                                                 │
│  DOMAIN ENGINE                                           │
│  ─────────────                                           │
│  Trade / ERP / CMS / etc.                                │
│                                                          │
│  WHAT MAY THE ACTOR DO IN THIS DOMAIN?                   │
│                                                          │
│  Decided by the authoritative domain engine.             │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The invariant is:

```text
Identity Provider
    ≠ Tenant Authority
    ≠ Business Authorization Authority
    ≠ Capability Authority
    ≠ Legal Entity Authority
```

The configured identity provider owns **identity mechanics**.

Baobab owns **identity meaning**.

---

# 2. Mandatory ADR authority

Before changing code, read all Accepted IAM ADRs.

Treat them as **Accepted architectural decisions**, not proposals.

At minimum inspect and reconcile:

| ADR | Subject |
|---|---|
| ADR-IAM-0019 | Migration from Keycloak to Ory and Provider-Neutral Baobab Identity Architecture |
| ADR-IAM-0020 | Provider-Neutral Identity Provider Contract and Adapter Architecture |
| ADR-IAM-0021 | Ory Kratos and Hydra Deployment, Persistence and Runtime Architecture |
| ADR-IAM-0022 | Keycloak-to-Ory Identity Migration, Dual-Issuer Trust and Cutover Architecture |
| ADR-IAM-0023 | Digital Estate Authentication UX, Browser Session and BFF Security Boundary |
| ADR-IAM-0024 | Authentication Assurance, MFA, Passkeys, Step-Up and Risk-Based Authentication |
| ADR-IAM-0025 | Identity Proofing, Verification, Recovery and High-Risk Rebinding |
| ADR-IAM-0026 | Enterprise Federation, B2B SSO, Organisation Trust and Identity Federation |
| ADR-IAM-0027 | Multi-Region, Data Residency, Sovereignty, HA and DR |
| ADR-IAM-0028 | Cryptographic Key Management, Key Rotation, Secrets, Certificates and Trust |
| ADR-IAM-0029 | Security Operations, Threat Detection and Identity Compromise Containment |
| ADR-IAM-0030 | Identity Privacy, PII Governance, Retention and Erasure |
| ADR-IAM-0031 | Administration, Delegated Administration, Privileged Access and Break-Glass |
| ADR-IAM-0032 | Production Governance, SLOs, Capacity, Compatibility, Upgrade and Operational Acceptance |

Also inspect earlier Accepted ADRs wherever ADR-IAM-0019–0032 reference or supersede them.

Do not assume that the later migration ADRs invalidate earlier implemented architecture. Determine explicitly:

```text
KEEP
ADAPT
SUPERSEDE
DEPRECATE
REMOVE
```

for every relevant existing facility.

---

# 3. Start with repository archaeology — do not code immediately

Before implementation:

1. Inspect `main`.
2. Inspect all open PRs.
3. Inspect migration-related branches.
4. Determine whether work already exists that overlaps this mission.
5. Inspect current CI state.
6. Inspect Shared contracts and capability catalogue.
7. Inspect Control Plane identity/capability integration.
8. Inspect existing Keycloak implementation.
9. Inspect current Ory implementation.
10. Inspect digital-estate clients.
11. Inspect deployment and infrastructure configuration.
12. Inspect tests.
13. Inspect migration utilities.
14. Inspect documentation.
15. Identify stale Keycloak-specific assumptions.

Do not duplicate existing work.

Do not overwrite architectural corrections already implemented in open PRs.

Where open work exists, either:

```text
reuse → extend → stack
```

rather than creating competing implementations.

---

# 4. Construct the authoritative IAM Capability Matrix

Before modifying implementation, create or update a machine-readable and human-readable IAM Capability Matrix.

The matrix MUST classify every capability into one of three categories.

## 4.1 Classification

```text
A. PLATFORM_RESOLVABLE_CAPABILITY
   A Baobab capability that legitimately participates in Shared catalogue
   + Control Plane capability resolution.

B. IAM_MANAGEMENT_OPERATION
   An operation exposed by baobab-iam but not independently resolved as a
   Baobab CapabilityBinding.

C. PROVIDER_INTERNAL_OPERATION
   Ory/Keycloak mechanics that MUST NOT leak into Baobab platform semantics.
```

Example:

```text
identity.authentication.perform
    → PLATFORM_RESOLVABLE_CAPABILITY

identity.human.disable
    → likely IAM_MANAGEMENT_OPERATION

delete_ory_kratos_session()
    → PROVIDER_INTERNAL_OPERATION
```

Do not convert every API endpoint into a Capability.

---

# 5. Required capability families

Use the following capability families as the target architectural model.

## Capability Family 1 — Human Identity Lifecycle

Required platform/service behaviour includes:

```text
provision
read
update
enable
disable
delete where legally permissible
anonymise
credential lifecycle
verification state
```

Potential logical operations:

```text
identity.human.provision
identity.human.read
identity.human.update
identity.human.enable
identity.human.disable
identity.human.delete
identity.human.anonymise
identity.human.verify
```

Do NOT assume each deserves its own Shared capability key.

Evaluate them using the three-category classification.

---

# 6. Capability Family 2 — Authentication

Provide provider-neutral authentication semantics for:

```text
login
registration
logout
email/identifier verification
password authentication
passkeys
MFA
authentication challenge
step-up authentication
authentication assurance
```

The canonical capability:

```text
identity.authentication.perform
```

already exists conceptually and should remain provider-neutral.

Avoid unnecessary proliferation such as:

```text
identity.passkey.add
identity.passkey.remove
identity.password.change
identity.totp.enable
```

as Control Plane-resolvable capabilities unless an Accepted ADR provides an architectural reason.

These generally belong beneath the broader authentication capability.

---

# 7. Capability Family 3 — OAuth 2.0 / OpenID Connect

Baobab IAM must provide standards-compliant identity protocol behaviour including:

```text
Authorization Code + PKCE
token issuance
token refresh where permitted
token introspection if used
token revocation
OIDC discovery
JWKS publication
client lifecycle
audience handling
issuer validation
subject handling
ACR/AMR propagation
nonce/state/PKCE enforcement
```

Ory Hydra may implement these mechanics.

Baobab contracts must not become Hydra-shaped.

Correct:

```text
Baobab Authentication Port
       ↓
Ory Provider Adapter
       ↓
Hydra
```

Incorrect:

```text
Digital Estate
       ↓
Hydra-specific Baobab contract
```

---

# 8. Capability Family 4 — Session Security

Implement provider-neutral session semantics supporting:

```text
session creation
session verification
session expiry
session revocation
global logout
authentication age
session assurance
session compromise handling
```

Browser-facing architecture MUST conform to ADR-IAM-0023.

Preferred architecture:

```text
Browser
   │
   │ Secure + HttpOnly + SameSite estate session
   ▼
Digital Estate BFF
   │
   │ server-side OAuth/OIDC interaction
   ▼
Baobab IAM
   │
   ▼
Ory
```

Avoid:

```text
Browser JavaScript
   │
   ├── access token in localStorage
   ├── refresh token in localStorage
   └── long-lived provider credentials
```

The browser should generally interact using the digital estate's secure session abstraction.

---

# 9. Capability Family 5 — Workload Identity

Treat workload identity as Tier-0.

Required behaviour:

```text
workload provisioning
short-lived workload token issuance
federated workload identity
credential rotation
disablement
revocation
scope constraints
audience constraints
lifecycle reconciliation
```

Existing canonical capability:

```text
identity.workload-token.issue
```

must remain provider-neutral.

Prefer:

```text
federated workload identity
+
short-lived credentials
```

over static client secrets.

Where JWT bearer federation is used, follow the relevant OAuth/JWT bearer standards and existing Accepted ADR constraints.

A static long-lived client secret must not silently become the default migration mechanism.

---

# 10. Capability Family 6 — Authentication Assurance

Implement:

```text
MFA
passkeys/WebAuthn
authentication assurance classification
step-up
authentication age
risk signals
re-authentication
```

Important authority rule:

```text
IAM says:
    "This actor authenticated at assurance level X."

Domain/Control policy says:
    "Operation Y requires assurance level X."
```

IAM must not decide arbitrary business authorization merely because it can perform step-up authentication.

---

# 11. Capability Family 7 — Recovery and Identity Proofing

Explicitly distinguish:

```text
authentication
identity verification
identity proofing
relationship verification
authorization
```

These are not synonymous.

Provide secure mechanisms for:

```text
account recovery
authenticator recovery
credential rebinding
high-risk recovery
proofing evidence
verification evidence
recovery throttling
security notification
recovery audit trail
```

A recovered email account alone must not automatically grant privileged Baobab authority.

---

# 12. Capability Family 8 — Enterprise Federation

Support provider-neutral federation for enterprise/B2B scenarios.

Potential protocols include:

```text
OIDC
SAML
SCIM
```

Architecture:

```text
Enterprise IdP
      │
      ▼
Federation Adapter
      │
      ▼
baobab-iam
      │
      │ authenticated external identity
      ▼
baobab-cp
      │
      ▼
CanonicalIdentity / membership / context
```

Critical invariant:

```text
External IdP group
      ≠ automatically
Baobab Role
```

Any mapping:

```text
External Group
      → Baobab role / membership / authority
```

must be explicit, governed and auditable.

---

# 13. Capability Family 9 — Provider Abstraction

This is one of the most important migration deliverables.

Create or strengthen a formal provider abstraction similar to:

```text
                 ┌──────────────────────┐
                 │   Baobab IAM Core    │
                 └──────────┬───────────┘
                            │
                     Provider Ports
                            │
          ┌─────────────────┼─────────────────┐
          │                                   │
          ▼                                   ▼
┌───────────────────┐               ┌───────────────────┐
│ Ory Provider      │               │ Keycloak Provider │
│ Adapter           │               │ Adapter            │
└─────────┬─────────┘               └─────────┬─────────┘
          │                                   │
     Kratos/Hydra                           Keycloak
```

Provider adapters SHOULD normalize:

```text
identity lifecycle
authentication
sessions
OAuth clients
tokens
federation
assurance
verification
errors
provider events
migration mapping
health
```

Baobab-owned domain types must exist above provider-specific SDK/data structures.

The rest of Baobab must not depend on:

```text
KratosIdentity
HydraClient
KeycloakUser
KeycloakRole
KeycloakRealm
```

as canonical platform concepts.

---

# 14. Capability Family 10 — Security Operations

Implement or complete capabilities supporting:

```text
identity compromise containment
session revocation
credential revocation
client revocation
workload revocation
security events
audit
incident response
bulk revocation
kill-switch behaviour
break-glass support
security reconciliation
```

Avoid creation of a giant:

```text
SUPER_ADMIN
```

Identity administration must follow the governance model of ADR-IAM-0031.

Privileged action should be evaluated using concepts equivalent to:

```text
capability
+
scope
+
context
+
assurance
+
time
+
purpose
```

Control Plane AdministrativeGrants remain authoritative where specified.

---

# 15. Capability Family 11 — Privacy and Identity Lifecycle Governance

Implement:

```text
retention
erasure
anonymisation
data export
data minimisation
PII classification
identity deletion workflows
audit retention
legal hold compatibility
```

Do not confuse IAM erasure with domain-record erasure.

Example:

```text
Delete IAM profile
      ≠
Delete legally required ERP transaction
      ≠
Delete trade invoice
      ≠
Delete audit evidence
```

Retention obligations remain domain-specific.

---

# 16. Capability Family 12 — Operational Identity Platform

The migration is incomplete unless the new provider can be operated safely.

Implement production-grade support for:

```text
health
readiness
liveness
metrics
tracing
structured logging
SLOs
capacity monitoring
key rotation
secret rotation
backup
restore
DR
multi-region strategy
migration reconciliation
provider compatibility
upgrade strategy
rollback
conformance testing
```

Operational readiness is part of identity capability delivery, not a later infrastructure afterthought.

---

# 17. Explicit authority exclusions

The following MUST NOT become IAM-owned authority merely because IAM stores identity-related information.

| Concern | Authority |
|---|---|
| Tenant creation/lifecycle | Control Plane |
| Tenant membership authority | Control Plane |
| LegalEntity lifecycle | Control Plane |
| CorporateGroup relationships | Control Plane |
| Market participation | Control Plane |
| DigitalEstate authority | Control Plane |
| Capability catalogue semantics | Shared |
| CapabilityBinding | Control Plane |
| Capability grants | Control Plane/domain policy |
| Engine resolution | Control Plane |
| AdministrativeGrant | Control Plane |
| Buyer purchasing authority | Trade/domain engine |
| Supplier approval | Supplier/domain workflow |
| Pricing authority | Trade |
| Inventory authority | Trade |
| ERP financial authority | ERP |
| Credit authority | authoritative business domain |
| Approval limits | authoritative business domain |

Ory MUST NOT become the hidden database for these concepts.

---

# 18. Required capability matrix format

Create a matrix with at least these columns:

| Field | Requirement |
|---|---|
| Capability Family | One of the 12 families |
| Capability/Operation | Stable logical name |
| Classification | Platform capability / IAM operation / provider internal |
| Tier | Tier 0 / Tier 1 |
| Owning ADR | Accepted IAM ADR |
| Shared Contract | Contract/schema if applicable |
| IAM Port | Provider-neutral interface |
| Ory Mechanism | Kratos/Hydra/etc. |
| Keycloak Source | Existing migration source |
| CP Dependency | Control Plane dependency |
| Digital Estate Dependency | Estate dependencies |
| Migration Phase | Migration sequence |
| Implementation Status | Missing/Partial/Implemented |
| Tests | Existing/missing |
| Conformance Evidence | Required proof |
| Observability | Metrics/events |
| Security Requirements | Assurance/revocation/etc. |
| Retirement Dependency | What blocks Keycloak removal |

Commit this matrix to the repository in an appropriate architecture/migration documentation location.

Prefer a machine-readable companion representation where practical.

---

# 19. Shared capability catalogue rules

Audit:

```text
baobab-platform/shared
```

Determine the exact current state of the canonical capability catalogue.

Do not invent capability keys in `baobab-iam` that contradict Shared.

Existing known capability concepts include:

```text
identity.authentication.perform
identity.workload-token.issue
```

For proposed capabilities, determine first whether the concept is:

```text
Platform Capability
Management Operation
Internal Provider Operation
```

Only the first category should ordinarily enter the canonical Shared capability catalogue.

Every new platform capability requires:

```text
stable semantics
authority definition
input contract
output contract
error semantics
versioning expectations
provider neutrality
conformance tests
```

Do not encode implementation names such as:

```text
ory.*
hydra.*
kratos.*
keycloak.*
```

into canonical Baobab capability keys.

---

# 20. Capability provider declaration

Audit and correct:

```text
.baobab/capability-provider.yaml
```

Keep:

```text
engine_id: baobab-iam
```

Never change it to:

```text
engine_id: ory
engine_id: hydra
engine_id: kratos
```

Provider instances may distinguish implementation providers, for example conceptually:

```text
baobab-iam.ory
baobab-iam.keycloak
```

during migration.

The provider declaration must never redefine canonical capability semantics owned by Shared.

---

# 21. Build formal provider ports

Create or consolidate provider-neutral ports.

The exact language/API style must follow the existing repository, but conceptually the architecture should resemble:

```text
IdentityProvider
├── HumanIdentityProvider
├── AuthenticationProvider
├── SessionProvider
├── OAuthProvider
├── WorkloadIdentityProvider
├── AssuranceProvider
├── RecoveryProvider
├── FederationProvider
├── SecurityProvider
└── ProviderHealth
```

Do NOT create one enormous interface if that would violate interface segregation.

Prefer cohesive interfaces.

For example:

```text
type SessionProvider interface {
    VerifySession(...)
    RevokeSession(...)
    RevokeAllSessions(...)
}
```

rather than:

```text
type IdentityEverything interface {
    ...97 unrelated methods...
}
```

Provider adapters must be replaceable independently where reasonable.

---

# 22. Define normalized Baobab identity models

Provider-neutral models should cover, as applicable:

```text
ExternalIdentity
ProviderSubject
IdentityStatus
AuthenticationResult
AuthenticationAssurance
Session
SessionStatus
CredentialReference
OAuthClient
WorkloadIdentity
FederatedIdentity
RecoveryState
VerificationState
ProviderEvent
SecurityEvent
ProviderHealth
MigrationMapping
```

Avoid embedding provider SDK objects in public Baobab contracts.

For example:

```text
BAD

type Principal struct {
    KratosIdentity *kratos.Identity
}
```

Prefer:

```text
GOOD

type ProviderSubject struct {
    ProviderID string
    Issuer     string
    Subject    string
}
```

with provider-specific details contained behind adapters.

---

# 23. Identity mapping and canonical identity

Follow ADR-IAM-0022 carefully.

Migration mapping must use stable combinations such as:

```text
source issuer
+
source subject
→
canonical identity
→
target issuer
+
target subject
```

Do not perform identity correlation purely using:

```text
email
display name
username
telephone
```

unless an Accepted decision explicitly permits it under controlled conditions.

Email is not a globally stable identity key.

The Control Plane remains authoritative for canonical Baobab identity association where prescribed by architecture.

---

# 24. Token-format neutrality

Do not assume every accepted credential is a compact JWT.

The implementation must preserve the current provider-neutral direction for token verification and credential handling.

Conceptually:

```text
Credential
   │
   ▼
Verifier Registry
   │
   ├── JWT verifier
   ├── opaque-token verifier
   └── future verifier
```

Avoid architecture equivalent to:

```text
split(token, ".")
if len(parts) != 3:
    reject
```

at platform contract boundaries.

JWT-specific parsing belongs inside a JWT-specific verifier.

---

# 25. Issuer and validator flexibility

The architecture must permit migration periods involving:

```text
old issuer
new issuer
multiple validators
multiple estates
multiple audiences
```

Do not enforce accidental constraints equivalent to:

```text
one validator per audience globally
```

unless required by a canonical contract.

Multiple validators may legitimately exist during transition.

---

# 26. Context ownership

Do not allow IAM to become the owner of Baobab Context.

For cross-service requests:

```text
Authenticated subject
        │
        ▼
Canonical principal
        │
        ▼
Control Plane Context
```

The actual authenticated subject/principal must be the context owner according to current Control Plane contracts.

A validator, gateway or intermediary is not the business principal merely because it validated the credential.

---

# 27. Ory implementation architecture

Use Ory components only for their appropriate responsibilities.

Conceptually:

```text
                       BAOBAB IAM
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
        ▼                                     ▼
┌──────────────────┐                 ┌──────────────────┐
│ Ory Kratos       │                 │ Ory Hydra       │
├──────────────────┤                 ├──────────────────┤
│ Human identities │                 │ OAuth 2.0       │
│ Login flows      │                 │ OIDC            │
│ Registration     │                 │ Clients         │
│ Verification     │                 │ Tokens          │
│ Recovery         │                 │ Consent flows   │
│ Sessions         │                 │ Discovery/JWKS  │
└──────────────────┘                 └──────────────────┘
```

Do not introduce Ory Keto or Oathkeeper merely because they are Ory products.

Only introduce new components if:

1. an Accepted ADR requires them, or
2. a demonstrated architectural gap exists,
3. alternatives are evaluated,
4. authority boundaries remain correct, and
5. the architectural decision is documented.

---

# 28. Digital-estate migration

Digital estates should consume Baobab IAM contracts rather than Ory internals.

For each estate, inspect current authentication integration.

At minimum assess:

```text
ZuriBeans
Thamani
```

and any Nabhold estate integration already present.

Desired flow:

```text
┌──────────────┐
│   Browser    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Estate BFF   │
└──────┬───────┘
       │
       │ provider-neutral Baobab auth integration
       ▼
┌──────────────┐
│ baobab-iam   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Ory          │
└──────────────┘
```

The estate should not depend deeply on Ory-specific identity storage or APIs.

---

# 29. Migration lifecycle

Use a controlled migration lifecycle.

## Phase A — Architecture Baseline

```text
Audit
  ↓
Capability Matrix
  ↓
Contract classification
  ↓
Gap analysis
```

No destructive changes.

---

## Phase B — Provider-Neutral Contract Hardening

```text
Shared contracts
      ↓
IAM ports
      ↓
Normalized types
      ↓
Conformance tests
```

At the end of this phase, Keycloak and Ory should theoretically be implementable behind the same Baobab boundary.

---

## Phase C — Ory Provider Completion

```text
Kratos adapter
Hydra adapter
Session adapter
Workload identity adapter
Federation adapter
Assurance adapter
Recovery adapter
Security operations adapter
```

Implement only the adapters actually required by capability classification.

---

## Phase D — Dual Provider Operation

Conceptually:

```text
                    baobab-iam
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
         Keycloak                Ory
         legacy                  target
             │                   │
             └─────────┬─────────┘
                       │
                  reconciliation
```

During this period:

```text
old identities remain usable where allowed
new identities can be created in target provider where approved
issuer handling supports migration
mapping remains deterministic
revocation remains enforceable
audit remains intact
```

---

# 30. Migration ordering

Use the following default sequence unless live repository evidence shows a safer dependency order.

```text
1. Capability contracts
        ↓
2. Provider abstraction
        ↓
3. Ory runtime foundations
        ↓
4. Workload identities
        ↓
5. Human identity migration tooling
        ↓
6. Dual issuer / dual provider verification
        ↓
7. Digital estate migration
        ↓
8. Federation migration
        ↓
9. Security/recovery/assurance completion
        ↓
10. Operational proving
        ↓
11. Cutover
        ↓
12. Keycloak retirement
```

Do not retire Keycloak before the replacement capability is proven.

---

# 31. Workload migration first

Where practical, migrate workloads before humans.

Why:

```text
workload identities
      ↓
more deterministic
      ↓
easier conformance testing
      ↓
lower UX complexity
      ↓
proves token + issuer + audience + CP integration
```

Required verification includes:

```text
token issuance
issuer
audience
expiry
scope
revocation
rotation
federated identity
Control Plane acceptance
domain-engine acceptance
```

---

# 32. Human migration

Human migration must preserve:

```text
canonical principal continuity
external identity mapping
verification state where trustworthy
credential security
session behaviour
recovery capability
assurance information where valid
auditability
```

Do not blindly migrate credential material that cannot safely or legitimately be transferred.

Where credentials cannot be migrated:

```text
migration
   ↓
verified activation/recovery flow
   ↓
new authenticator establishment
```

is preferable to insecure credential conversion.

---

# 33. Authentication cutover strategy

Support controlled cohort migration where useful.

Possible migration dimensions:

```text
digital estate
tenant
identity class
workload vs human
market
internal workforce
supplier
buyer/customer
administrators
```

Do not perform uncontrolled global cutover unless repository evidence and testing justify it.

---

# 34. Rollback

Every migration phase must answer:

> What happens if Ory fails after this phase is deployed?

Document rollback before cutover.

Rollback must consider:

```text
identity writes
session divergence
credential changes
new Ory-only accounts
revocations
issuer changes
client changes
mapping updates
key rotations
```

A rollback plan that merely says:

```text
redeploy Keycloak
```

is insufficient.

---

# 35. Conformance tests

Build provider conformance tests.

A provider should have to pass the same behavioural contract regardless of implementation.

Conceptually:

```text
ProviderConformanceSuite
        │
        ├── KeycloakAdapter
        │       └── PASS
        │
        └── OryAdapter
                └── PASS
```

Conformance areas should include:

```text
identity creation
identity disabling
authentication
session validation
session revocation
OAuth token issuance
workload identity
issuer behaviour
audience behaviour
assurance propagation
error normalization
security event production
health
```

Avoid brittle tests that merely assert provider-specific JSON shape.

---

# 36. Contract tests across repositories

Add or strengthen contract tests between:

```text
shared ↔ baobab-iam
baobab-iam ↔ baobab-cp
baobab-iam ↔ digital estate
baobab-iam ↔ infrastructure
```

Where versioned contracts exist, validate them in CI.

A provider upgrade must not silently break Baobab consumers.

---

# 37. Security testing

Include tests for:

```text
cross-tenant isolation
cross-estate isolation
issuer confusion
audience confusion
token substitution
session fixation
session replay
revoked session use
revoked identity use
disabled workload use
expired token
invalid PKCE
state mismatch
nonce mismatch
weak recovery path
MFA bypass
step-up bypass
administrator privilege escalation
credential stuffing protections where applicable
```

Include negative tests.

A security system proven only by happy-path tests is not proven.

---

# 38. Migration-specific tests

Test:

```text
Keycloak identity → canonical identity → Ory identity

Keycloak issuer accepted during migration

Ory issuer accepted during migration

revocation works across transition

same email / different subject does not accidentally merge

same subject / different issuer remains distinguishable

new Ory-only identity works

old Keycloak-only identity works while migration permits

disabled source identity does not regain authority through migration

context principal matches authenticated canonical principal
```

---

# 39. Event architecture

Audit identity event requirements.

Normalize provider events into Baobab identity/security events where needed.

Conceptually:

```text
Ory Event
   │
   ▼
Provider Adapter
   │
   ▼
Baobab IAM Event
   │
   ├── identity.created
   ├── identity.disabled
   ├── session.revoked
   ├── authenticator.changed
   └── security.compromise-detected
```

Do not leak provider webhook schemas as canonical Baobab event contracts.

Determine whether the event belongs to:

```text
IAM
Control Plane
digital estate
domain engine
```

before publishing it.

---

# 40. Security event correlation

Ensure observability permits correlation using appropriate identifiers such as:

```text
trace ID
request ID
canonical principal ID where permissible
provider subject
issuer
client ID
digital estate
tenant/context where legitimately supplied
```

Do not log secrets or raw credentials.

Avoid unnecessary PII in logs.

---

# 41. Key and secret management

Implement ADR-IAM-0028 requirements.

At minimum inspect:

```text
Hydra signing keys
OIDC/JWKS lifecycle
TLS certificates
client credentials
workload identity keys
database credentials
webhook secrets
provider API secrets
migration secrets
backup encryption keys
```

No production secret may be committed to Git.

Document rotation procedures.

Test rotation where feasible.

---

# 42. Data architecture

Follow ADR-IAM-0021 and 0027.

Inspect:

```text
Kratos persistence
Hydra persistence
database isolation
backup model
restore model
regional topology
data residency
replication
migration data
identity mapping data
audit data
```

Do not collapse logically separate stores merely for local-development convenience if Accepted ADRs require separation.

---

# 43. Health model

Expose useful health information without leaking secrets.

Differentiate:

```text
process alive
service ready
provider healthy
database reachable
cryptographic dependencies healthy
migration reconciliation healthy
federation dependency healthy
```

Where Baobab Control Plane generic engine health facilities exist, integrate with those contracts rather than inventing an IAM-only health authority.

---

# 44. Reconciliation

Create reconciliation processes for migration.

Reconciliation should detect, where relevant:

```text
missing Ory identity
missing canonical mapping
duplicate mapping
disabled source but active target
incorrect issuer
incorrect subject
orphan OAuth client
stale workload identity
revocation mismatch
migration drift
```

Reconciliation must preferably be idempotent.

---

# 45. Migration ledger

Maintain explicit migration state.

Conceptually:

```text
PENDING
DISCOVERED
MAPPED
PROVISIONED
VERIFIED
CUTOVER
RECONCILED
FAILED
ROLLED_BACK
RETIRED
```

Do not infer migration completion merely from the presence of an Ory record.

Migration state must distinguish:

```text
created
validated
usable
cut over
reconciled
```

---

# 46. Error taxonomy

Provider errors must be normalized.

Example:

```text
Ory:
some_provider_specific_error

        ↓ adapter

Baobab:
IDENTITY_NOT_FOUND
IDENTITY_DISABLED
AUTHENTICATION_FAILED
ASSURANCE_INSUFFICIENT
SESSION_EXPIRED
SESSION_REVOKED
PROVIDER_UNAVAILABLE
FEDERATION_FAILURE
CONFLICT
RATE_LIMITED
```

Do not expose raw provider internals unnecessarily to consumers.

---

# 47. API design

Any IAM management API should:

```text
authenticate caller
resolve caller identity
obtain appropriate Baobab context
enforce appropriate administrative authority
validate inputs
perform provider-neutral operation
audit privileged changes
return normalized errors
```

Do not authorize operations simply because an OAuth scope appears in a token.

Scopes may permit invocation of an endpoint.

They do not automatically prove business authority.

---

# 48. Digital estate BFF boundaries

For estate integrations, explicitly document:

```text
Browser responsibility
BFF responsibility
IAM responsibility
Control Plane responsibility
Domain-engine responsibility
```

Example:

| Layer | Responsibility |
|---|---|
| Browser | interaction and secure session cookie |
| Estate BFF | server-side auth flow and estate session |
| IAM | identity/authentication/session mechanics |
| Control Plane | canonical context and platform authority |
| Domain engine | domain authorization |

Keep this distinction enforced in code.

---

# 49. CI/CD requirements

The migration must be continuously verifiable.

CI should cover:

```text
format
lint
unit tests
contract tests
provider conformance
integration tests
security/static analysis
dependency scanning
configuration validation
migration tests
container build
SBOM where platform standards require it
vulnerability scan
```

Reuse the Baobab Shared/Foundation CI architecture where applicable.

Do not introduce incompatible duplicate CI implementations without reason.

---

# 50. Local development

Ensure developers can run an appropriate Ory development stack.

Development configuration must remain visibly different from production.

Do not weaken production security merely to simplify local development.

Provide documented setup for:

```text
Kratos
Hydra
PostgreSQL
mail/test verification flow where required
Baobab IAM
Control Plane integration
test client/digital estate
```

---

# 51. Documentation remediation

Audit the existing README and documentation.

Remove stale statements such as:

```text
Keycloak is the current production/runtime implementation
```

when no longer accurate.

However, do not erase migration history.

Clearly distinguish:

```text
legacy provider
migration state
target provider
current supported state
retirement status
```

Update architecture diagrams.

---

# 52. Production readiness evidence

For every capability family, record:

```text
implemented
tested
observable
recoverable
documented
provider-neutral
migration-safe
security-reviewed
```

A feature does not become production-ready solely because code exists.

---

# 53. Tiering

Use the following starting priority.

## Tier 0 — required for safe migration/cutover

```text
Human identity lifecycle
Authentication
OAuth/OIDC
Sessions
Workload identity
Authentication assurance
Provider abstraction
Security operations
Operational platform capability
```

## Tier 1 — required before declaring full IAM programme complete

```text
Recovery/proofing hardening
Enterprise federation
Privacy lifecycle completion
advanced regionalisation
advanced risk policy
```

Promote Tier 1 items to Tier 0 where current digital-estate requirements depend upon them.

---

# 54. Migration Gate structure

Implement through explicit gates.

## Gate 0 — Repository and Architectural Audit

Deliver:

```text
repo audit
open PR audit
branch audit
ADR crosswalk
legacy-vs-target inventory
capability matrix draft
migration dependency graph
```

No broad code changes.

---

## Gate 1 — Capability and Authority Classification

Deliver:

```text
final capability matrix
platform capability vs management operation classification
authority ownership table
Shared catalogue delta
CP dependency table
```

Gate criterion:

> No ambiguous ownership remains for capabilities being implemented.

---

## Gate 2 — Provider-Neutral Core

Deliver:

```text
provider-neutral types
ports/interfaces
normalized errors
provider registry
provider configuration abstraction
provider conformance harness
```

---

## Gate 3 — Shared Contracts

Deliver required changes to:

```text
baobab-platform/shared
```

including only legitimate canonical capabilities/contracts.

Do not add provider internals.

---

## Gate 4 — Control Plane Compatibility

Validate:

```text
principal resolution
context ownership
capability resolution
engine/provider registration
token verification abstraction
multiple issuer support
multiple validator support
bounded context
AdministrativeGrant compatibility
```

Do not move CP responsibilities into IAM.

---

## Gate 5 — Ory Runtime Foundation

Complete:

```text
Kratos
Hydra
PostgreSQL
runtime configuration
health
secrets integration
migration configuration
local dev support
production config separation
```

---

## Gate 6 — Workload Identity

Complete and prove:

```text
workload provisioning
federated workload identity
short-lived token issuance
rotation
disable
revoke
audience/scope enforcement
CP integration
```

---

## Gate 7 — Human Identity Lifecycle

Complete:

```text
provision
update
disable
enable
verification
deletion/anonymisation where applicable
migration mapping
```

---

## Gate 8 — Authentication and Sessions

Complete:

```text
login
registration
logout
session validation
session revocation
global logout
browser/BFF pattern
```

---

## Gate 9 — Assurance, MFA and Passkeys

Complete:

```text
MFA
passkeys
step-up
assurance propagation
authentication age
negative tests
```

---

## Gate 10 — Recovery and Security Operations

Complete:

```text
recovery
credential rebinding
kill switch
compromise containment
bulk revocation
security events
break-glass integration
```

---

## Gate 11 — Federation

Complete required:

```text
OIDC federation
SAML where required
SCIM where required
enterprise organisation trust
explicit group/role mapping governance
```

---

## Gate 12 — Dual Provider and Migration Engine

Complete:

```text
Keycloak + Ory coexistence
mapping
dual issuer validation
migration ledger
reconciliation
rollback
cutover controls
```

---

## Gate 13 — Digital Estate Migration

Migrate estates incrementally.

At minimum assess and test:

```text
ZuriBeans
Thamani
```

Do not couple estate business models to provider internals.

---

## Gate 14 — Privacy and Governance

Complete:

```text
retention
erasure
anonymisation
audit governance
PII handling
data residency controls
```

---

## Gate 15 — Resilience and Operations

Prove:

```text
backup
restore
DR
key rotation
secret rotation
capacity
SLOs
alerts
health
upgrade compatibility
```

A documented restore that has never been exercised is not sufficient evidence.

---

## Gate 16 — Cutover Readiness

Run:

```text
security tests
load tests
migration rehearsal
rollback rehearsal
DR test
bulk revocation test
provider failure test
issuer failover scenarios
estate compatibility test
contract compatibility test
```

Produce formal cutover evidence.

---

## Gate 17 — Ory Cutover

Only after all blocking evidence passes:

```text
new provider becomes preferred/default
migration cohorts cut over
reconciliation runs
observability confirms stability
```

Do not remove Keycloak yet.

---

## Gate 18 — Keycloak Retirement

Keycloak may only be removed when:

```text
all required identities migrated or deliberately excepted
all required clients migrated
all estate dependencies removed
all workloads migrated
dual issuer window closed safely
no unresolved migration ledger failures
rollback decision approved
retention/export requirements satisfied
operational evidence accepted
```

Then:

```text
disable
observe
archive required evidence
remove runtime dependency
remove stale configuration
remove stale secrets
remove deprecated code
update documentation
```

---

# 55. Gate dependency diagram

```text
G0 Audit
   │
   ▼
G1 Capability Classification
   │
   ▼
G2 Provider-Neutral Core
   │
   ├───────────────┐
   ▼               ▼
G3 Shared       G5 Ory Runtime
   │               │
   ▼               │
G4 Control Plane   │
   └───────┬───────┘
           ▼
      G6 Workloads
           │
           ▼
      G7 Humans
           │
           ▼
      G8 Auth/Sessions
           │
           ▼
      G9 Assurance
           │
           ▼
     G10 Recovery/SecOps
           │
           ├─────────────► G11 Federation
           │
           ▼
     G12 Dual Provider
           │
           ▼
     G13 Digital Estates
           │
           ▼
     G14 Governance
           │
           ▼
     G15 Operations
           │
           ▼
     G16 Readiness
           │
           ▼
     G17 Cutover
           │
           ▼
     G18 Keycloak Retirement
```

---

# 56. Pull-request strategy

Use small, reviewable PRs.

Avoid one enormous migration PR.

Recommended pattern:

```text
PR 1  Capability matrix + audit
PR 2  Provider-neutral domain/interfaces
PR 3  Shared capability contract changes
PR 4  CP integration changes
PR 5  Ory runtime hardening
PR 6  Workload identity
PR 7  Human identity
PR 8  Authentication/session
...
```

Where dependencies require stacking:

```text
PR-A
  └── PR-B
       └── PR-C
```

Document the dependency explicitly.

Do not duplicate code across stacked branches merely to make them independently compile if the repository's established stacked-PR practice provides a better solution.

---

# 57. Branch discipline

Before each gate:

```text
refresh live repository state
inspect newly opened PRs
inspect changes merged since previous gate
rebase/update safely
```

Baobab is a polyrepo platform.

Assume another repository may have evolved while you were implementing the current gate.

Never rely indefinitely on the initial audit snapshot.

---

# 58. Do not merge blindly

For every PR:

1. run repository-local checks;
2. inspect CI;
3. inspect failed workflow logs;
4. correct failures caused by the PR;
5. verify contract compatibility;
6. verify no unrelated architectural regressions;
7. verify tests;
8. summarize residual risk.

Do not declare a gate complete merely because GitHub displays green checks if required migration evidence remains absent.

---

# 59. Required implementation evidence per gate

Every gate report must include:

| Evidence | Required |
|---|---|
| Changed repositories | Yes |
| Changed files | Yes |
| ADRs consulted | Yes |
| Capability matrix rows affected | Yes |
| Authority boundary impact | Yes |
| Tests added/changed | Yes |
| CI result | Yes |
| Security impact | Yes |
| Migration impact | Yes |
| Rollback impact | Yes |
| Outstanding blockers | Yes |
| Next dependency | Yes |

---

# 60. Definition of Done for a capability

A capability is not complete until:

```text
[ ] authority is defined
[ ] classification is correct
[ ] provider-neutral contract exists where needed
[ ] implementation exists
[ ] Ory adapter exists
[ ] legacy migration path is understood
[ ] positive tests exist
[ ] negative tests exist
[ ] provider conformance tests pass
[ ] Control Plane integration is correct
[ ] digital-estate integration is correct where applicable
[ ] security characteristics are documented
[ ] observability exists
[ ] rollback behaviour is known
[ ] operational evidence exists
[ ] documentation is updated
```

---

# 61. Definition of Done for migration

The migration is complete only when this architecture is true:

```text
                    BAOBAB CONSUMERS
                          │
                          ▼
                ┌───────────────────┐
                │ Baobab IAM        │
                │ Stable Contracts  │
                └─────────┬─────────┘
                          │
                   Provider Ports
                          │
                          ▼
                ┌───────────────────┐
                │ Ory Adapter       │
                └─────────┬─────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
          Ory Kratos              Ory Hydra
```

and this is no longer true:

```text
Baobab Consumer
      │
      ▼
Keycloak-specific semantics

or

Baobab Consumer
      │
      ▼
Ory-specific semantics
```

Provider replacement must be possible principally through:

```text
new adapter
+
conformance certification
+
controlled migration
```

rather than rewriting platform consumers.

---

# 62. Architectural acceptance tests

Before declaring the programme complete, answer **YES** to all of the following.

### Provider neutrality

```text
Can Ory theoretically be replaced without rewriting ZuriBeans?
Can it be replaced without rewriting Thamani?
Can it be replaced without redefining tenant semantics?
Can it be replaced without redefining capability semantics?
```

### Authority

```text
Does Control Plane remain authority for Baobab context?
Does Shared remain authority for canonical capability semantics?
Do domain engines remain authority for business decisions?
Does IAM remain identity security infrastructure rather than business authority?
```

### Migration safety

```text
Can an identity be deterministically mapped?
Can migration be reconciled?
Can migration failures be diagnosed?
Can cutover be rolled back?
Can compromised identities be revoked during migration?
```

### Security

```text
Are privileged actions separately authorized?
Are session and token revocations enforced?
Are passkeys/MFA/step-up properly modelled?
Are recovery flows protected?
Are secrets outside source control?
```

### Operations

```text
Can Ory be monitored?
Can it be backed up?
Can it be restored?
Can keys be rotated?
Can the provider be upgraded safely?
Can a provider outage be diagnosed?
```

### Retirement

```text
Are all Keycloak dependencies known?
Are all active dependencies migrated?
Is the retirement reversible until the approved point of no return?
Is required legacy evidence retained?
```

If any answer is NO, migration is not complete.

---

# 63. Important anti-patterns

Do not introduce any of the following.

## Anti-pattern A — Ory becomes the architecture

```text
Baobab → Hydra concepts everywhere
Baobab → Kratos identity model everywhere
```

Reject.

---

## Anti-pattern B — role storage becomes authorization

```text
Ory identity trait:
    role = "buyer-admin"

therefore:
    actor can approve purchase
```

Reject.

Business authority must come from the appropriate Baobab authority.

---

## Anti-pattern C — every method becomes a capability

```text
identity.password.change
identity.password.reset
identity.password.validate
identity.password.history.read
...
```

Reject capability explosion.

---

## Anti-pattern D — email is canonical identity

```text
same email → same person
```

Reject.

---

## Anti-pattern E — migration means bulk copy

```text
copy Keycloak users
→ Ory
→ delete Keycloak
```

Reject.

Migration includes semantic compatibility, canonical mapping, sessions, clients, credentials, issuers, workloads, revocation, reconciliation, operations and rollback.

---

## Anti-pattern F — scopes equal business authority

```text
scope = administrator:write
→ authorize everything
```

Reject.

---

## Anti-pattern G — temporary migration architecture becomes permanent

Every compatibility layer introduced for dual-provider operation must have an explicit lifecycle:

```text
introduced
used
observed
deprecated
removed
```

---

# 64. Implementation philosophy

Preserve existing good work.

The project has already implemented substantial IAM architecture.

Do not rewrite working abstractions merely because Ory provides a different native model.

Use:

```text
existing Baobab semantics
        +
provider-neutral ports
        +
Ory adapters
```

rather than:

```text
Ory semantics
        →
redesign Baobab
```

---

# 65. Final migration flow

The target programme should resemble:

```text
┌─────────────────────────┐
│ Accepted IAM ADRs       │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Capability Matrix       │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Authority Classification│
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Shared Contracts        │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Provider-Neutral IAM    │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Ory Adapter             │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Conformance Tests       │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Workload Migration      │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Human Migration         │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Digital Estate Migration│
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Operational Proof       │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Ory Cutover             │
└────────────┬────────────┘
             ▼
┌─────────────────────────┐
│ Keycloak Retirement     │
└─────────────────────────┘
```

---

# 66. Execution instruction

Proceed methodically through the gates.

Do **not** pause merely because one gate is complete if the next gate can safely proceed.

Pause only when:

```text
human authorization is genuinely required
a destructive action requires approval
an architectural contradiction cannot be resolved from Accepted ADRs
a security-sensitive production credential/action requires intervention
a repository permission prevents progress
or proceeding would invalidate another active PR
```

Otherwise continue.

At every stage:

```text
inspect
reason
implement
test
verify
document
report
continue
```

Do not substitute assumptions for repository evidence.

Do not report work as complete when only scaffolding exists.

---

# 67. Expected final state

The desired end state is not merely:

> “Ory is running.”

It is:

> **Baobab IAM is a production-grade, provider-neutral Identity Security Engine whose Baobab-owned capabilities are implemented by Ory, integrated correctly with the Control Plane, safely consumed by digital estates and domain engines, operationally proven, migration-reconciled, and no longer dependent on Keycloak-specific semantics.**

The architecture should make a future provider migration substantially less disruptive than this one.

That is the real success criterion.