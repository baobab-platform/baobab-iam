# ADR-0007: Workload Identity and Service-to-Service Authentication

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`, `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Machine identities, service-to-service authentication, OAuth client credentials, mTLS, workload lifecycle, credential rotation, APISIX trust boundaries, delegated calls and engine integrations  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  
- ADR-0005 — Realm, Organization, Tenant and Legal-Entity Model  
- ADR-0006 — OIDC, OAuth and Token Profile  

---

# 1. Context

Baobab is a polyrepo, polyglot platform composed of independently deployable workloads.

Current and planned workloads include:

- `baobab-cp`;
- `baobab-trade`;
- `baobab-erp`;
- `baobab-cms`;
- `baobab-pulse`;
- Digital Estate backends;
- integration workers;
- event publishers and consumers;
- scheduled jobs;
- provisioning agents;
- operational automation;
- future headless engines.

These workloads communicate across:

- API boundaries;
- gateway boundaries;
- internal networks;
- event infrastructure;
- engine integration points;
- deployment environments.

A service being "internal" is not sufficient proof of identity.

Baobab therefore requires a machine-identity model that can answer:

```text id="x2dwqd"
Which workload is calling?
Which credential proves that?
Which audience is being addressed?
Which scopes were granted?
Which platform context is allowed?
Was the call initiated by the workload itself,
or performed on behalf of a human?
```

This ADR defines the workload identity and service-to-service authentication architecture.

---

# 2. Decision

Baobab SHALL use **explicit workload identities** for service-to-service authentication.

The baseline model SHALL be:

```text id="1ocn3q"
Workload
    │
    ▼
Client authentication
    │
    ▼
Baobab IAM
    │
    ▼
Short-lived OAuth access token
    │
    ▼
Target service
```

Where risk or infrastructure policy requires stronger transport identity, the model SHALL additionally use mTLS:

```text id="ayq06v"
mTLS
  +
OAuth workload token
```

These mechanisms serve different purposes and SHALL NOT be conflated.

---

# 3. Core Principle

The governing rule SHALL be:

> **Every independently deployable workload must possess an independently revocable identity.**

This means:

```text id="op4v72"
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
baobab-cp
estate backend
worker
```

SHALL NOT share one common service identity.

---

# 4. Workload Identity Definition

A Workload Identity represents a non-human actor operating on behalf of a Baobab service or automated process.

Examples include:

```text id="c28xsu"
baobab-trade
baobab-erp
baobab-pulse
baobab-cms
zuribeans-backend
thamani-backend
event-relay
migration-runner
provisioning-agent
```

The workload identity SHALL be distinct from:

```text id="j607nc"
human administrator
consumer
supplier representative
buyer representative
```

---

# 5. Canonical Workload Identity

Where Control Plane identity governance requires it, each workload SHALL map to a Canonical Identity with:

```text id="52vxap"
actor_type = workload
```

Conceptually:

```text id="jn4q6z"
IAM Client
   │
   ▼
External Workload Identity
   │
   ▼
CanonicalIdentity
actor_type=workload
```

This allows service identity to remain stable if the IAM implementation changes.

---

# 6. One Identity Per Workload Boundary

The following is prohibited:

```text id="uv4kv3"
client_id = baobab-services
```

used by:

```text id="2ph3a4"
Trade
ERP
CMS
Pulse
```

Instead:

```text id="ymvxol"
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
```

SHALL be separately identifiable.

---

# 7. Why Shared Service Accounts Are Rejected

Shared service accounts prevent reliable answers to:

```text id="jxnsa0"
Which service performed the operation?
Which credential must be revoked?
Which service was compromised?
Which workload should receive this scope?
```

They also increase blast radius.

Therefore shared platform-wide service credentials SHALL NOT be used.

---

# 8. OAuth Client Credentials

The baseline workload authentication mechanism SHALL be OAuth Client Credentials for service-owned operations.

Target flow:

```text id="nh9cq4"
baobab-trade
      │
      │ client authentication
      ▼
Baobab IAM
      │
      │ access token
      ▼
baobab-cp
```

The resulting token SHALL be short-lived.

---

# 9. Client-Credentials Semantics

A Client Credentials token represents the workload itself.

It SHALL NOT silently represent a human user.

Example:

```text id="n5yzuf"
actor_type = workload
azp = baobab-trade
```

This means:

> The Trade service is acting as Trade.

It does not mean:

> Jane is acting through Trade.

Those are distinct call types.

---

# 10. Service-Owned Operations

Client Credentials SHALL be appropriate for operations such as:

- polling configuration;
- background synchronization;
- publishing canonical events;
- retrieving engine bindings;
- scheduled ERP synchronization;
- inventory reconciliation;
- system health operations;
- platform provisioning.

Example:

```text id="p6xvhy"
baobab-trade
      │
      ▼
retrieve allowed CP context
      │
      ▼
perform inventory sync
```

No human identity is required.

---

# 11. Human-Initiated Operations

A workload performing an action initiated by a human SHALL preserve the distinction between:

```text id="ay3gvh"
human subject
```

and:

```text id="wpzp9d"
service actor
```

The workload SHALL not discard the initiating identity where audit or authorization requires it.

---

# 12. Actor and Subject

The desired semantic model is:

```text id="vnsooq"
Subject:
Jane

Actor:
baobab-trade

Target:
baobab-erp
```

This is different from:

```text id="c0tm7a"
Subject:
baobab-trade

Actor:
baobab-trade
```

used for a service-owned background task.

---

# 13. Delegated Calls

A delegated call occurs when a workload invokes another service on behalf of an authenticated subject.

Conceptually:

```text id="q78s1o"
Jane
 │
 ▼
Zuribeans
 │
 ▼
Trade
 │
 ▼
ERP
```

The architecture SHALL preserve sufficient provenance to determine:

```text id="97gzss"
Jane initiated the action
Trade executed the downstream call
ERP received the request
```

---

# 14. Delegation SHALL NOT Mean Blind Token Forwarding

The following pattern is prohibited as a universal integration strategy:

```text id="pshlgn"
receive user's token
       │
       ▼
forward same token everywhere
```

because:

- audiences may differ;
- scopes may differ;
- downstream services may not be intended token recipients;
- delegation boundaries become unclear;
- token theft blast radius increases.

---

# 15. Delegated Token Strategy

Where downstream delegation is required, Baobab MAY use:

- appropriately audience-bound user token;
- token exchange;
- explicit delegated-context mechanism;
- service token plus signed/canonical actor context.

The exact mechanism SHALL depend on risk and protocol support.

Regardless of mechanism, provenance SHALL remain explicit.

---

# 16. Token Exchange

Token exchange MAY be adopted for cases requiring:

```text id="zl2yvu"
user subject
     +
service actor
     +
downstream audience
```

The expected conceptual result is:

```text id="ykjoou"
Original:
subject = Jane
audience = Trade

Exchanged:
subject = Jane
actor = Trade
audience = ERP
```

Token exchange SHALL NOT be mandatory for every service call.

---

# 17. No Service Impersonation

A service SHALL NOT create or modify arbitrary claims such as:

```text id="jptmz1"
X-User-ID: jane
X-Tenant-ID: ...
```

and expect the downstream system to trust them as identity.

Identity delegation SHALL require cryptographic or canonical trust.

---

# 18. Workload Token Profile

A workload token SHOULD contain the equivalent of:

```json id="gwck17"
{
  "iss": "https://identity.baobab.example/realms/baobab",
  "sub": "service-account-baobab-trade",
  "aud": "baobab-control-plane",
  "azp": "baobab-trade",
  "actor_type": "workload",
  "scope": "context:resolve",
  "iat": 1788900000,
  "exp": 1788900900
}
```

Exact Keycloak claim representation SHALL be documented through Shared contracts.

---

# 19. `sub`

For workload tokens, `sub` SHALL identify the external IAM service subject.

It SHALL not be assumed to equal the canonical workload ID.

The mapping remains:

```text id="4xwmoa"
iss + sub
    │
    ▼
ExternalIdentity
    │
    ▼
Canonical workload identity
```

---

# 20. `azp`

`azp` SHOULD identify the client granted the token.

Sensitive internal APIs MAY require an expected:

```text id="7065ol"
azp
```

in addition to other token checks.

Example:

```text id="cj3r9q"
context resolver:
expected azp = baobab-trade
```

where the policy is endpoint-specific.

---

# 21. `actor_type`

Workload tokens SHALL identify:

```text id="y8s9d1"
actor_type = workload
```

or the equivalent Baobab versioned claim.

An endpoint requiring workload identity SHALL reject:

```text id="57ynv3"
actor_type = human
```

unless explicitly allowed.

---

# 22. Scope

Each workload SHALL receive only scopes required for its function.

Examples:

```text id="ygwfd1"
context:resolve
mapping:read
events:publish
engine-binding:read
```

Exact scope names SHALL be defined in `baobab-platform/shared`.

---

# 23. Scope Minimization

This is prohibited as a default:

```text id="ixco98"
scope = *
```

or:

```text id="o834hy"
scope = admin
```

for all internal workloads.

Workload permissions SHALL follow least privilege.

---

# 24. Audience

Workload access tokens SHALL be audience-bound.

Example:

```text id="l7q0pe"
Trade → CP

aud = baobab-control-plane
```

A token intended for Control Plane SHALL not automatically work against ERP.

---

# 25. Audience-Specific Tokens

Where one workload calls multiple services, it SHOULD obtain appropriately scoped/audience-bound credentials.

Example:

```text id="41ibx8"
Trade
  │
  ├── token aud=baobab-control-plane
  └── token aud=baobab-erp
```

if direct Trade → ERP calls are architecturally approved.

---

# 26. Short-Lived Tokens

Workload Access Tokens SHALL be short-lived.

Because workloads can obtain replacement tokens programmatically, there is little operational justification for multi-day bearer access tokens.

The baseline SHOULD align with the existing Control Plane security posture of approximately 15 minutes maximum token lifetime unless a stricter policy is established.

---

# 27. Workload Credentials

The credential used to obtain a workload token MAY initially be:

```text id="j9vj17"
client secret
```

but Baobab SHOULD retain the ability to move sensitive clients toward stronger client authentication such as key- or certificate-backed credentials.

---

# 28. Client Secrets

Where client secrets are used, they SHALL be:

- unique per client;
- generated with high entropy;
- stored in secret management;
- never committed to Git;
- never embedded in container images;
- rotatable;
- scoped per environment.

---

# 29. No Shared Client Secret

This is prohibited:

```text id="pmf1kc"
BAOBAB_SERVICE_SECRET
```

shared by every service.

Each workload SHALL have independent credential material.

---

# 30. Environment Isolation

Workload credentials SHALL differ across:

```text id="66wl57"
development
test
staging
production
```

A development credential SHALL not authenticate against production IAM.

---

# 31. Secret Injection

Secrets SHALL be injected at runtime through the infrastructure secret-management boundary.

They SHALL not be stored in:

```text id="96wtwp"
.env.example with real values
GitHub repository secrets files
Docker image layers
realm exports
Helm values committed in plaintext
application logs
```

---

# 32. Secret Rotation

Client secrets SHALL be rotatable without requiring prolonged platform downtime.

Preferred process:

```text id="k1eo7x"
issue replacement credential
        │
        ▼
deploy workload with replacement
        │
        ▼
verify token acquisition
        │
        ▼
revoke old credential
```

Where dual credentials are not supported, coordinated rotation SHALL be automated as far as practicable.

---

# 33. Rotation Frequency

Credential rotation frequency SHALL be based on:

- risk;
- secret-management capability;
- compliance;
- credential type;
- compromise exposure.

Baobab SHALL not rely solely on calendar rotation as protection.

Immediate rotation SHALL occur after suspected compromise.

---

# 34. mTLS

mTLS MAY be required for sensitive service-to-service paths.

Its role SHALL be:

```text id="xh7snf"
connection-level workload authentication
```

not:

```text id="96swxe"
complete application authorization
```

---

# 35. mTLS and OAuth

Where both are enabled:

```text id="2qp3ez"
mTLS
   │
   └── confirms transport peer

OAuth token
   │
   └── confirms application identity/scopes

Control Plane
   │
   └── confirms Baobab context

Domain Engine
   │
   └── confirms business permission
```

Each layer remains distinct.

---

# 36. Infrastructure Ownership of mTLS

`baobab-platform/infrastructure` SHALL own production transport configuration including:

- certificate issuance/integration;
- trust stores;
- gateway TLS;
- mTLS enforcement;
- certificate rotation;
- service endpoints.

Application repositories SHALL consume these controls rather than invent parallel PKI systems.

---

# 37. APISIX

Where APISIX is the Baobab production gateway, it MAY:

- terminate TLS;
- enforce mTLS;
- rate-limit workloads;
- route internal APIs;
- reject malformed/invalid authentication attempts.

APISIX SHALL NOT become the canonical workload-identity authority.

---

# 38. Gateway Headers

If APISIX injects headers such as:

```text id="zjytue"
X-Baobab-Client
X-Baobab-mTLS-Subject
X-Baobab-Trace-ID
```

these SHALL be treated according to ADR-0003.

They MAY carry convenience/provenance metadata.

They SHALL not replace token validation.

---

# 39. Header Stripping

The gateway SHALL strip client-supplied versions of reserved internal headers.

An external caller SHALL not be able to submit:

```text id="4waun8"
X-Baobab-Client: baobab-erp
```

and impersonate ERP.

---

# 40. Certificate Identity

Where mTLS is used, certificate identity SHALL map to the expected workload boundary.

The mapping SHALL be explicit.

Examples:

```text id="55re1d"
certificate identity
       │
       ▼
baobab-trade
```

rather than trusting arbitrary certificates signed by an overly broad CA for all privileges.

---

# 41. Certificate Rotation

mTLS certificates SHALL be:

- short- or bounded-lived;
- automatically renewable where practical;
- separately revocable where infrastructure supports it;
- monitored for expiry.

Manual emergency certificate replacement SHALL be documented.

---

# 42. Workload Registration

Every workload requiring IAM access SHALL be registered deliberately.

Registration SHALL capture:

```text id="66e1aj"
workload name
repository
runtime
owner
environment
client ID
allowed audiences
allowed scopes
credential type
rotation owner
```

---

# 43. Workload Inventory

`baobab-iam` SHOULD maintain a machine-readable workload client registry.

Conceptually:

```yaml id="9qyz32"
workloads:
  - id: baobab-trade
    actor_type: workload
    audiences:
      - baobab-control-plane
    scopes:
      - context:resolve
```

Exact format may follow repository conventions.

---

# 44. Workload Ownership

Every workload client SHALL have a defined owning repository/team.

Orphaned IAM clients SHALL be considered a security defect.

---

# 45. Workload Lifecycle

A workload identity SHALL support lifecycle states such as:

```text id="nt6gb7"
PROVISIONED
ACTIVE
SUSPENDED
REVOKED
RETIRED
```

Exact canonical lifecycle terminology SHALL align with later lifecycle ADRs.

---

# 46. Provisioning

Provisioning flow:

```text id="8mr1mu"
New service approved
       │
       ▼
register workload
       │
       ▼
create IAM client
       │
       ▼
assign minimal scopes/audiences
       │
       ▼
provision credential
       │
       ▼
create canonical workload mapping
       │
       ▼
integration test
```

---

# 47. Retirement

When a workload is retired:

```text id="cq5t6r"
disable client
      │
      ▼
revoke credentials
      │
      ▼
remove capability grants
      │
      ▼
retain audit history
      │
      ▼
mark canonical workload retired
```

Credentials SHALL not remain active merely because the repository still exists historically.

---

# 48. Workload Suspension

A compromised workload identity SHOULD be suspendable independently without disabling:

```text id="c212xp"
other engines
entire IAM realm
entire tenant
```

This is another reason workloads require separate identities.

---

# 49. `baobab-cp`

The Control Plane SHALL expose workload-protected APIs using the token profile established in ADR-0006.

Existing context-resolution behavior SHOULD remain:

```text id="76rv7x"
actor_type = workload
required scope = context:resolve
authorized client = explicit
```

with valid issuer and audience checks.

---

# 50. Trade → Control Plane

Expected flow:

```text id="jgu8q2"
baobab-trade
      │
      ▼
obtain workload token
      │
      ▼
request context resolution
      │
      ▼
baobab-cp
      │
      ▼
resolve tenant/entity/market/entitlement
```

Trade SHALL not cache authorization indefinitely if the underlying context is mutable.

---

# 51. ERP → Control Plane

ERP integration components MAY authenticate as:

```text id="2vcqam"
baobab-erp
```

to resolve canonical mappings or platform context.

ERP SHALL not reuse a human administrator credential for machine integration.

---

# 52. Pulse → Control Plane

`baobab-pulse` SHALL have its own workload identity.

This prevents intelligence pipelines from sharing credentials with Trade or ERP.

---

# 53. CMS → Control Plane

`baobab-cms` SHALL likewise use a dedicated workload identity where platform context or mapping APIs are required.

---

# 54. Digital Estate Backends

A server-side estate backend MAY require its own workload identity.

Examples:

```text id="tr2dtr"
zuribeans-backend
thamani-backend
```

These SHALL not reuse `baobab-trade` credentials.

The estate backend and Trade engine are distinct workload boundaries.

---

# 55. Frontend Applications

Pure browser applications SHALL NOT receive workload credentials.

A frontend is not a confidential workload.

If server-side capabilities are required, introduce:

```text id="5dxkx4"
BFF/backend
```

with its own identity.

---

# 56. Workers

Background workers MAY share a workload identity with their parent service only if they are genuinely part of the same deployment/security boundary.

Otherwise they SHOULD receive distinct identities.

Decision factors include:

- separate deployment;
- separate secret boundary;
- separate blast radius;
- different scopes;
- different operational owner.

---

# 57. Scheduled Jobs

A scheduled job SHALL authenticate as a workload.

It SHALL not rely on:

```text id="sw245f"
hard-coded API key
administrator password
browser session
```

---

# 58. CI/CD Automation

GitHub Actions or other CI/CD automation requiring runtime administrative access SHALL use a separately governed automation identity.

CI/CD identities SHALL not reuse ordinary production service credentials.

---

# 59. Deployment Identity Versus Runtime Identity

These SHALL be distinguished:

```text id="8ohd0s"
deployment identity
```

used for provisioning/deployment, from:

```text id="2t9drz"
runtime workload identity
```

used by the running service.

Compromise of runtime workload SHALL not automatically grant deployment authority.

---

# 60. Migration Identity

Database or platform migration jobs SHOULD use separately scoped administrative/migration identities.

They SHOULD be:

- time-bounded;
- environment-specific;
- disabled after use where feasible.

---

# 61. Administrative Automation

Automation that performs IAM or CP administration SHALL use a privileged workload identity distinct from ordinary service runtime identities.

Example:

```text id="kts9w9"
iam-provisioner
```

should not be:

```text id="ht47v8"
baobab-trade
```

---

# 62. Engine-to-Engine Calls

Direct engine-to-engine calls SHALL be deliberate architectural integrations.

Example:

```text id="sx89cd"
Trade → ERP
```

SHALL require:

```text id="2hjgyd"
Trade workload authentication
appropriate ERP audience
approved integration scope
canonical context
ERP domain authorization
```

---

# 63. No Internal Trust Shortcut

This is prohibited:

```text id="vjf3c7"
if request.source_ip in internal_network:
    allow
```

Network controls MAY supplement identity but SHALL not replace it.

---

# 64. Event Producers

Event producers SHALL have identifiable workload provenance.

Canonical events SHOULD identify the producer workload where the event envelope supports it.

Example:

```text id="b6k7df"
producer = baobab-trade
```

---

# 65. Event Consumers

Event brokers or consumers SHALL likewise use distinct machine credentials where supported.

Event infrastructure SHALL not become an authentication-free side channel between engines.

---

# 66. Event Provenance

Where a service consumes a canonical event, it SHOULD be possible to determine:

```text id="10tmvh"
which workload published it
which event contract version
which canonical context
```

according to Shared event conventions.

---

# 67. Credential Leakage

Workload credentials SHALL be treated as Tier-sensitive secrets.

Repositories SHALL implement scanning/prevention for accidental exposure in:

- Git commits;
- CI logs;
- Docker layers;
- diagnostics;
- crash dumps;
- support bundles.

---

# 68. Logging

Workload logs MAY record:

```text id="jw3jma"
client_id
canonical workload ID
audience
scope decision
tenant/context ID
request ID
trace ID
```

They SHALL NOT log:

```text id="v4lepp"
client_secret
access_token
private key
certificate private key
```

---

# 69. Audit

Service-to-service audit records SHOULD answer:

```text id="xl6wv5"
Which workload called?
Which credential class authenticated it?
Which human subject, if any, initiated it?
Which tenant/entity context applied?
Which service received the call?
Which decision allowed or denied it?
```

---

# 70. Observability

Authentication failures SHALL be observable by:

- workload;
- client;
- target audience;
- failure category;
- environment.

Metrics SHOULD distinguish:

```text id="nprwh0"
invalid credential
expired token
wrong audience
missing scope
wrong actor type
mTLS failure
context denial
```

without exposing secrets.

---

# 71. Rate Limiting

IAM token endpoints SHOULD be protected against abnormal credential attempts.

Resource APIs MAY rate-limit by:

```text id="he2crd"
client
workload
route
tenant/context
```

where appropriate.

---

# 72. Token Caching

Workloads MAY cache access tokens until shortly before expiry.

They SHOULD NOT request a new token for every API operation unless necessary.

They SHALL not cache beyond expiration.

---

# 73. Token Refresh Pattern

Client Credentials workloads do not require user-style refresh tokens as the baseline.

They SHOULD obtain a new access token using their workload credential when the current token approaches expiration.

---

# 74. Startup Behavior

A workload SHALL NOT need a permanently valid token baked into its deployment.

Instead:

```text id="nob5na"
runtime starts
     │
     ▼
authenticate to IAM
     │
     ▼
obtain short-lived access token
```

---

# 75. IAM Outage

If IAM is temporarily unavailable:

- already valid tokens MAY continue to be accepted until expiration;
- new workload tokens cannot be issued;
- services SHALL NOT fall back to shared static bypass credentials.

---

# 76. CP Outage

If `baobab-cp` is unavailable for an operation requiring authoritative context, the workload SHALL fail closed.

It SHALL not substitute:

```text id="22lopc"
tenant ID from environment
tenant ID from header
last unbounded cached decision
```

unless a separately approved bounded-resilience strategy exists.

---

# 77. Credential Compromise

On suspected workload credential compromise:

```text id="5fn30m"
identify workload
      │
      ▼
revoke/rotate credential
      │
      ▼
disable client if necessary
      │
      ▼
review token/audit activity
      │
      ▼
issue replacement
      │
      ▼
restore service
```

Other workloads SHOULD remain unaffected.

---

# 78. Service Compromise

If a workload itself is compromised, credential rotation alone may be insufficient.

Incident response MAY include:

- client suspension;
- network isolation;
- container/image replacement;
- secret replacement;
- certificate replacement;
- event replay investigation;
- downstream access review.

---

# 79. Secret Versus Certificate Compromise

Baobab SHALL distinguish:

```text id="hvrzaq"
OAuth client credential compromise
```

from:

```text id="wfzfnm"
mTLS private key compromise
```

because remediation may differ.

---

# 80. Stronger Workload Authentication

Baobab SHOULD evolve higher-risk workloads toward stronger authentication where infrastructure maturity justifies it.

Potential mechanisms include:

- private-key-based client authentication;
- mTLS client authentication;
- workload federation;
- short-lived infrastructure identities.

This ADR does not mandate one stronger mechanism for every service.

---

# 81. No Permanent API-Key Architecture

Long-lived manually distributed API keys SHALL NOT be adopted as the normal Baobab workload identity model.

If an external system supports only API keys, that key SHALL be treated as an integration-specific external credential, wrapped behind a Baobab workload integration boundary where feasible.

---

# 82. External Engine Constraints

Some third-party/open-source engines may not support Baobab's preferred workload identity pattern natively.

In such cases Baobab SHOULD use:

```text id="zp3p7c"
adapter
gateway
plugin
sidecar
supported extension
```

rather than weakening the entire platform to the lowest common denominator.

---

# 83. iDempiere Integration

If an iDempiere API surface cannot directly consume the preferred OAuth workload token, the Baobab ERP integration layer SHALL mediate the security contract.

The platform SHALL not expose internal ERP APIs anonymously merely because iDempiere uses a different native security model.

---

# 84. Medusa Integration

Medusa integration modules SHALL authenticate their own outbound calls using the Trade workload identity.

They SHALL not rely on customer/user tokens for service-owned synchronization.

---

# 85. Pulse Integrations

Pulse may consume external APIs using third-party API keys.

Those external provider credentials SHALL remain separate from Baobab workload identity.

Conceptually:

```text id="8se4h1"
Pulse authenticates to Baobab
        │
        └── Baobab workload identity

Pulse authenticates to external data provider
        │
        └── provider-specific credential
```

The two SHALL not be conflated.

---

# 86. Digital Estate BFFs

A Digital Estate BFF SHALL use:

```text id="3yvx4f"
human session/user token
```

for human-subject operations and its own:

```text id="ffnci2"
workload identity
```

for service-owned operations.

The architecture SHALL not use one credential ambiguously for both.

---

# 87. Workload Context Resolution

Typical flow:

```text id="h3abio"
Workload token
      │
      ▼
CP validates:
iss
aud
exp
actor_type
azp
scope
      │
      ▼
Canonical workload resolution
      │
      ▼
Requested tenant/entity/context
      │
      ▼
Policy decision
```

---

# 88. Context SHALL Be Explicit

A workload's identity does not automatically imply access to every tenant.

Example:

```text id="mmu0kz"
baobab-trade
```

may operate across multiple tenants, but each request SHALL resolve a permitted tenant context.

---

# 89. Workload Entitlement

The Control Plane MAY govern whether a workload may access:

```text id="9tuaro"
tenant
capability
engine instance
market
```

through existing platform policy and CapabilityBinding semantics.

IAM SHALL not own those business/platform relationships.

---

# 90. Workload Scope and CP Context

Authorization SHALL combine:

```text id="1f41g8"
IAM scope
      +
Control Plane context
```

Example:

```text id="8gqmzy"
scope: context:resolve
```

means the client may invoke the resolver.

It does not mean:

```text id="butjtl"
all tenants are authorized
```

---

# 91. No Scope-to-Tenant Shortcut

This is prohibited:

```text id="tvvbqs"
scope=context:resolve
        │
        ▼
allow requested tenant
```

The requested tenant SHALL still be evaluated.

---

# 92. Rejected Alternative — Shared API Key

### Advantages

- simple;
- easy to implement.

### Disadvantages

- no workload attribution;
- large blast radius;
- difficult rotation;
- weak auditability;
- static long-lived secret.

### Decision

Rejected.

---

# 93. Rejected Alternative — Internal Network Trust

### Advantages

Operational simplicity.

### Disadvantages

- lateral movement;
- weak service attribution;
- poor zero-trust posture;
- unsuitable for hybrid/cloud deployments.

### Decision

Rejected.

---

# 94. Rejected Alternative — mTLS Only

### Advantages

Strong transport identity.

### Disadvantages

- poor application-level scope semantics;
- does not express OAuth audience;
- difficult delegated human context;
- insufficient platform authorization on its own.

### Decision

Rejected as the complete authentication model.

mTLS remains complementary.

---

# 95. Rejected Alternative — OAuth Only with One Shared Client

### Advantages

Uses standards.

### Disadvantages

- still lacks workload isolation;
- weak auditability;
- broad compromise blast radius.

### Decision

Rejected.

---

# 96. Rejected Alternative — Forward Human Token Everywhere

### Advantages

Simple user-provenance propagation.

### Disadvantages

- audience violations;
- over-broad token exposure;
- confused delegation;
- difficult service-owned operations.

### Decision

Rejected as universal strategy.

---

# 97. Rejected Alternative — Permanent Service Tokens

### Advantages

No token endpoint dependency.

### Disadvantages

- large replay window;
- poor revocation;
- secret proliferation;
- operational risk.

### Decision

Rejected.

---

# 98. Consequences

## Positive

This decision provides:

- independently auditable workloads;
- reduced credential blast radius;
- consistent engine authentication;
- clear user-versus-service semantics;
- short-lived API access;
- clean APISIX/mTLS integration;
- improved incident response;
- future workload-federation readiness.

## Negative

It introduces:

- more IAM clients;
- credential lifecycle management;
- token caching;
- certificate management where mTLS applies;
- more integration tests;
- explicit delegated-call design.

These costs are accepted.

---

# 99. Implementation Ownership

| Concern | Owner |
|---|---|
| Workload clients | `baobab-iam` |
| Workload identity contracts | `shared` |
| Canonical workload identity | `baobab-cp` |
| mTLS/PKI | `infrastructure` |
| Gateway controls | `infrastructure` |
| Runtime secret injection | `infrastructure` |
| Token validation | each service |
| Tenant/context authorization | `baobab-cp` |
| Domain authorization | target engine |

---

# 100. Shared Contract Requirements

`baobab-platform/shared` SHOULD define:

```text id="xk9sa7"
workload identity claim shape
actor_type values
scope registry
audience naming
delegation metadata
service identity event contracts
```

Existing Shared identity contracts SHALL be extended rather than duplicated.

---

# 101. Suggested Workload Registry

A configuration artifact MAY resemble:

```yaml id="s5mnnw"
workloads:
  baobab-trade:
    audience:
      - baobab-control-plane
    scopes:
      - context:resolve

  baobab-erp:
    audience:
      - baobab-control-plane
    scopes:
      - context:resolve
      - mapping:read

  baobab-pulse:
    audience:
      - baobab-control-plane
    scopes:
      - context:resolve
```

Actual permissions SHALL be determined from repository requirements rather than copied blindly from this illustrative example.

---

# 102. Required Integration Tests

At minimum:

### Client authentication

- valid workload credential;
- invalid credential;
- revoked credential;
- wrong client;
- wrong environment credential.

### Token validation

- valid workload token;
- expired token;
- wrong issuer;
- wrong audience;
- wrong `azp`;
- wrong actor type;
- missing scope.

### Isolation

- Trade token rejected as ERP client where not permitted;
- ERP credential cannot impersonate Trade;
- estate backend cannot use Trade credential;
- development credential rejected in production.

### Context

- authorized tenant;
- unauthorized tenant;
- disabled tenant;
- missing CapabilityBinding;
- invalid market.

### Delegation

- service-owned operation;
- human-initiated operation;
- downstream provenance retained;
- arbitrary identity-header spoof rejected.

---

# 103. mTLS Tests

Where mTLS is enabled, test:

```text id="0q9992"
valid certificate
expired certificate
wrong client certificate
untrusted CA
missing client certificate
revoked/replaced certificate
certificate/header spoofing
```

---

# 104. Rotation Tests

Production-readiness tests SHALL prove:

```text id="zkw82h"
client secret rotation
certificate rotation where applicable
old credential rejection
new credential acceptance
```

without relying on manual database changes.

---

# 105. Incident Tests

A staging security exercise SHOULD demonstrate:

```text id="4u66iw"
compromise one workload
      │
      ▼
revoke only that workload
      │
      ▼
other Baobab services continue operating
```

This is a key design objective.

---

# 106. Architectural Invariants

The following become binding:

```text id="62jbbj"
Internal Service ≠ Trusted Service

One Workload = One Independently Revocable Identity

Workload Token ≠ Human Token

Client Credentials ≠ Human Delegation

mTLS ≠ OAuth Authorization

mTLS ≠ Tenant Authorization

Scope ≠ Tenant Access

Network Location ≠ Identity

Gateway Header ≠ Workload Identity

Long-Lived Shared API Key ≠ Acceptable Default Workload Authentication

Deployment Identity ≠ Runtime Identity

External Provider Credential ≠ Baobab Workload Identity
```

---

# 107. Target Architecture

```text id="oi05e3"
                         BAOBAB IAM
                         Keycloak
                            │
                 ┌──────────┼──────────┐
                 │          │          │
                 ▼          ▼          ▼
              Trade        ERP        Pulse
              Client      Client      Client
                 │          │          │
                 └──────────┼──────────┘
                            │
                     short-lived tokens
                            │
                            ▼
                      ┌───────────┐
                      │  APISIX   │
                      │ TLS/mTLS  │
                      └─────┬─────┘
                            │
                            ▼
                      ┌───────────┐
                      │baobab-cp  │
                      │ Context   │
                      └─────┬─────┘
                            │
                ┌───────────┼────────────┐
                ▼           ▼            ▼
              Trade         ERP         CMS
```

Every arrow represents an authenticated integration boundary.

---

# 108. Human Delegation Architecture

```text id="6tv9ok"
                   HUMAN USER
                       │
                       ▼
                 Baobab IAM
                       │
                  user identity
                       │
                       ▼
                 Digital Estate
                       │
                       ▼
                    Trade
                       │
              delegated operation
                       │
                       ▼
                     ERP

Audit must preserve:

subject = human
actor   = Trade
target  = ERP
```

This SHALL remain distinct from a background Trade workload operation.

---

# 109. Decision Summary

Baobab SHALL use explicit, independently managed workload identities for every meaningful service boundary.

The standard service-owned flow is:

```text id="evk85e"
Workload
   │
   ▼
OAuth client authentication
   │
   ▼
Baobab IAM
   │
   ▼
short-lived workload token
   │
   ▼
API / Control Plane
```

For sensitive transport paths:

```text id="9kxv5b"
mTLS + OAuth
```

MAY be required.

The platform SHALL reject:

```text id="zh36pg"
shared API keys
implicit internal trust
shared service accounts
unbounded service tokens
blind user-token forwarding
gateway-header identity
```

as foundational workload-authentication strategies.

The governing principle is:

> **Every Baobab workload must be able to prove who it is independently, be authorized only for what it needs, and be revoked without taking unrelated services with it.**