# ADR-0006: OIDC, OAuth and Token Profile

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** OpenID Connect, OAuth, browser flows, workload flows, token classes, claims, audiences, scopes, token lifetimes, JWKS, signing, revocation and validation  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  
- ADR-0005 — Realm, Organization, Tenant and Legal-Entity Model  

---

# 1. Context

Baobab IAM has established:

- Keycloak as the authentication authority;
- `baobab-cp` as the canonical identity and platform-context authority;
- explicit trust boundaries;
- provider identity mapping via `issuer + subject`;
- separation among Realm, Organization, Tenant, Legal Entity, Digital Estate and Market.

The next architectural decision is the security contract by which identities and applications communicate.

Baobab will use tokens across:

- public browser clients;
- server-side Digital Estates;
- BFF architectures;
- Control Plane administration;
- MedusaJS;
- iDempiere;
- Payload CMS;
- Baobab Pulse;
- service-to-service integrations;
- supplier and buyer portals;
- future external clients.

Without a strict common token profile, individual repositories could make incompatible decisions about:

- grant types;
- access-token lifetimes;
- refresh tokens;
- claims;
- audiences;
- scopes;
- tenant data in JWTs;
- service credentials;
- signing algorithms;
- issuer validation;
- key rotation.

That would create an authentication system in name but a collection of incompatible security interpretations in practice.

---

# 2. Decision

Baobab SHALL standardize on:

```text
OpenID Connect
       +
OAuth 2.x-compatible standards
       +
Baobab-defined token and claims profile
```

for authentication and delegated access.

The profile SHALL follow current OAuth security best practice, including Authorization Code + PKCE for browser-based flows and explicit audience, issuer and token validation. RFC 9700 requires PKCE for public clients and recommends PKCE for confidential authorization-code clients; current browser-app guidance likewise identifies Authorization Code + PKCE as the recommended browser pattern.

The architectural model SHALL be:

```text
               HUMAN / BROWSER
                      │
                      ▼
               Authorization Code
                    + PKCE
                      │
                      ▼
                  Baobab IAM
                      │
                      ▼
               Access / ID Tokens
                      │
                      ▼
                Baobab APIs
```

and:

```text
                  WORKLOAD
                     │
                     ▼
              Client Authentication
                     │
                     ▼
                 Baobab IAM
                     │
                     ▼
             Short-lived Access Token
                     │
                     ▼
             CP / Domain Service
```

---

# 3. Protocol Responsibility

OpenID Connect SHALL be used primarily for:

```text
authentication
identity assertions
SSO
```

OAuth SHALL be used primarily for:

```text
authorization delegation
API access
workload access
```

The distinction SHALL be preserved in documentation and implementation.

---

# 4. Token Classes

Baobab SHALL distinguish at least:

```text
ID Token
Access Token
Refresh Token
Authorization Code
```

These artifacts SHALL NOT be treated interchangeably.

---

# 5. ID Token

The ID Token is an authentication assertion intended for the OIDC client.

It MAY contain:

- issuer;
- subject;
- audience;
- authentication time;
- nonce;
- authentication-context information;
- identity profile claims.

It SHALL NOT be used as the ordinary bearer credential for Baobab APIs.

OpenID Connect defines `iss`, `sub` and `aud` as core ID Token claims, with `sub` being issuer-local and `aud` identifying the intended relying party.

---

# 6. Access Token

The Access Token SHALL be the primary bearer credential for protected Baobab APIs unless a sender-constrained token profile is adopted later.

It SHALL represent:

```text
authenticated principal
        +
client
        +
approved scopes
        +
intended audience
```

It SHALL NOT become a complete serialized copy of Baobab authorization state.

---

# 7. Refresh Token

Refresh Tokens SHALL be used only where the client architecture and risk profile justify them.

Refresh Tokens SHALL:

- never be sent to ordinary resource APIs;
- remain confined to the client/authorization-server interaction;
- receive stronger storage protection than Access Tokens;
- be independently revocable where supported;
- avoid browser persistence where safer alternatives exist.

For browser architectures using a BFF, refresh tokens SHOULD preferentially remain server-side.

---

# 8. Authorization Code

Authorization Codes SHALL:

- be short-lived;
- be single-use;
- be bound to the registered redirect URI;
- be protected by PKCE for public clients;
- not appear in logs.

They SHALL not be reused as API credentials.

---

# 9. Browser Flow

Public browser clients SHALL use:

```text
Authorization Code Grant
        +
PKCE
        +
S256
```

RFC 9700 requires PKCE for public clients and identifies `S256` as the code challenge method that does not expose the verifier through the authorization request.

The following SHALL NOT be used for new Baobab browser applications:

```text
Implicit Grant
Resource Owner Password Credentials
client secret embedded in frontend code
```

---

# 10. Browser Flow Diagram

```text
Browser
   │
   │ authorization request
   │ + code_challenge
   ▼
Baobab IAM
   │
   │ authentication
   ▼
Browser
   │
   │ authorization code
   ▼
Client
   │
   │ code + code_verifier
   ▼
Baobab IAM
   │
   ▼
Access Token / ID Token
```

The verifier SHALL remain known only to the initiating client context.

---

# 11. Exact Redirect URIs

Redirect URI validation SHALL use explicitly registered destinations.

Wildcard redirect patterns SHALL be minimized and avoided where possible.

OAuth Security BCP requires exact redirect URI matching, with narrowly defined native-app exceptions.

Production clients SHALL NOT accept arbitrary:

```text
redirect_uri
return_to
next
callback
```

values without strict validation.

---

# 12. Open Redirectors

Authentication clients SHALL NOT expose open redirect endpoints that can be abused to leak authorization codes or tokens.

Example prohibited pattern:

```text
/login/callback?next=https://attacker.example
```

without strict allow-listing.

---

# 13. State and Nonce

OIDC clients SHALL use appropriate transaction-binding protections.

`state` MAY be used for application-state and CSRF binding.

`nonce` SHALL be used where required by the OIDC flow and SHALL be transaction-specific.

Neither SHALL be static.

---

# 14. PKCE Policy

Baobab SHALL require PKCE for public clients.

Baobab SHOULD also enable PKCE for confidential authorization-code clients where supported.

This follows current OAuth Security BCP, which requires PKCE for public clients and recommends it for confidential authorization-code clients.

---

# 15. BFF Pattern

Baobab MAY prefer a Backend-for-Frontend for higher-risk Digital Estates or administrative applications.

Target pattern:

```text
Browser
   │
   │ secure session cookie
   ▼
BFF
   │
   │ OAuth/OIDC
   ▼
Baobab IAM
   │
   ▼
Baobab APIs
```

The BFF MAY retain:

- access tokens;
- refresh tokens;
- confidential client credentials.

The browser SHALL not receive secrets it does not need.

---

# 16. BFF Cookies

Where BFF session cookies are used, they SHOULD be configured with:

```text
Secure
HttpOnly
SameSite appropriate to flow
bounded lifetime
```

and CSRF protections SHALL be applied to state-changing operations.

---

# 17. Direct SPA Pattern

A direct SPA-to-IAM architecture MAY be used where appropriate.

If selected:

- PKCE is mandatory;
- no client secret may exist in the browser;
- token persistence shall be minimized;
- XSS risk shall be treated as access-token compromise risk.

Current browser-app guidance emphasizes that malicious JavaScript executing in the application origin can access application capabilities and token material, which is one reason server-mediated patterns may be preferable for higher-risk applications.

---

# 18. Workload Flow

Machine identities SHALL use an OAuth workload flow approved for the client type.

The baseline SHALL be:

```text
OAuth client credentials
```

for service-owned operations.

Conceptually:

```text
baobab-trade
     │
     │ authenticate client
     ▼
Baobab IAM
     │
     ▼
Access Token
     │
     ▼
baobab-cp
```

---

# 19. Workload Claims

A workload token SHOULD identify at least:

```text
iss
sub
aud
azp / authorized client
actor_type = workload
scope
iat
exp
```

where the actual Keycloak token representation supports the corresponding semantics.

The Control Plane SHALL not infer workload identity solely from `client_id` supplied in request content.

---

# 20. Human Token Claims

Human access tokens SHOULD identify:

```text
iss
sub
aud
azp
actor_type = human
scope
iat
exp
```

plus only minimal additional claims needed by resource servers.

---

# 21. External Human Classification

External users such as:

```text
buyer representatives
supplier representatives
consumers
partners
```

MAY use:

```text
actor_type = human
```

with relationship classification resolved through the Control Plane and domain engines.

Baobab SHOULD avoid defining a new actor type for every business role.

---

# 22. Actor Type Versus Business Role

This is correct:

```text
actor_type = human
```

and later:

```text
Trade:
buyer_role = approver
```

This is discouraged:

```text
actor_type = buyer_po_approver
```

Authentication claims SHALL not absorb domain ontology.

---

# 23. Subject Claim

The OIDC `sub` claim SHALL represent the authentication-provider subject only.

It SHALL NOT be interpreted as:

```text
CanonicalIdentity ID
Tenant ID
Employee ID
Customer ID
Supplier ID
```

The durable Baobab mapping remains:

```text
iss + sub
    │
    ▼
ExternalIdentity
    │
    ▼
CanonicalIdentity
```

---

# 24. Issuer Claim

Every relying service SHALL validate `iss` against an explicit approved issuer.

For example:

```text
https://identity.baobab.example/realms/baobab
```

A caller SHALL not select its own trusted issuer through request parameters.

---

# 25. Audience

Each protected resource SHALL define explicit acceptable audiences.

Examples:

```text
baobab-control-plane
baobab-trade
baobab-erp
baobab-cms
baobab-pulse
```

A token whose audience does not include the intended resource SHALL be rejected.

---

# 26. Audience Isolation Diagram

```text
             Token A
       aud=baobab-trade
             │
        ┌────┴────┐
        ▼         ▼
     Trade       CP
     ACCEPT      REJECT
```

unless a specifically defined token-exchange or multi-audience profile permits otherwise.

---

# 27. `azp`

Where Keycloak provides `azp`, Baobab SHALL treat it as the authorized client identity where relevant.

For workload flows, `azp` is particularly useful for verifying which client requested the token.

The Control Plane MAY require:

```text
azp = expected workload client
```

for sensitive internal APIs.

---

# 28. Scope

OAuth scopes SHALL represent coarse delegated capabilities.

Examples:

```text
context:resolve
identity:self
identity:read
identity:link
tenant:read
tenant:write
```

Exact scope names SHALL be version-controlled through `baobab-platform/shared`.

---

# 29. Scope Naming

Scopes SHOULD follow a stable:

```text
resource:action
```

pattern unless existing Shared conventions specify otherwise.

Examples:

```text
context:resolve
identity:read
identity:link
membership:read
```

---

# 30. What Scopes Shall Not Represent

Scopes SHALL NOT encode highly volatile business permissions.

Avoid:

```text
purchase-order:approve-under-500000
supplier:approved-for-coffee
erp:journal-post-za
```

These belong to authoritative business systems.

---

# 31. Roles

Keycloak roles MAY be used for coarse IAM/platform administration where appropriate.

They SHALL NOT become the universal Baobab authorization model.

Domain roles remain engine-owned.

---

# 32. Token Size Discipline

Baobab SHALL keep access tokens reasonably compact.

Do not embed complete collections of:

```text
all tenant memberships
all markets
all organizations
all buyer roles
all supplier relationships
all ERP roles
all engine permissions
```

merely to avoid server-side authorization checks.

---

# 33. Platform Context Claims

A token MAY include selected platform-context claims where:

- the context was already authoritatively resolved;
- the claim has a bounded lifetime;
- the audience requires it;
- staleness risk is accepted.

However the default architecture SHALL not depend on such claims for mutable authorization.

---

# 34. Tenant Claim Policy

A tenant identifier in a JWT SHALL NOT be interpreted as permanent tenant membership.

The distinction is:

```text
token says:
current/resolved tenant = T1

not:

identity permanently belongs only to T1
```

Where tenant authorization may change quickly, services SHOULD re-resolve or otherwise validate context.

---

# 35. Legal Entity Claim Policy

Legal entity information SHALL generally remain contextual.

It SHALL not become a global identity-defining claim.

---

# 36. Market Claim Policy

Market MAY appear in a context-specific token if useful, but SHALL remain constrained by:

```text
tenant
capability
engine instance
```

resolution.

A client SHALL not gain a market merely because it submits a desired market claim.

---

# 37. Organization Claims

Keycloak Organization claims MAY be consumed for identity-oriented purposes.

They SHALL NOT replace:

```text
canonical entity mapping
tenant resolution
buyer authorization
supplier approval
```

---

# 38. Canonical Identity Claim

Baobab MAY introduce a canonical identity claim in tokens issued after canonical resolution, but this SHALL be done cautiously.

The baseline profile SHOULD prefer:

```text
iss + sub
```

at the authentication boundary and resolve canonical identity through `baobab-cp`.

If a canonical identity claim is later added, it SHALL be treated as a Baobab extension and documented in Shared contracts.

---

# 39. Access Token Lifetime

Human Access Tokens SHALL be short-lived.

The precise lifetime SHOULD be environment-configurable within centrally governed bounds.

A production starting point SHOULD generally be measured in minutes rather than hours.

The existing Control Plane security model already expects short-lived tokens and currently caps accepted token lifetime at approximately 15 minutes; IAM integration SHOULD preserve or tighten that security posture rather than silently increasing it.

---

# 40. Workload Access Token Lifetime

Workload Access Tokens SHOULD be similarly short-lived.

Because workloads can automatically obtain replacement tokens, there is little justification for very long-lived bearer credentials.

---

# 41. Refresh Token Lifetime

Refresh-token lifetime MAY be longer than Access Token lifetime but SHALL be bounded.

The policy SHALL account for:

- workforce sensitivity;
- B2B buyer risk;
- supplier administration;
- B2C convenience;
- device/browser trust;
- inactivity.

The same refresh lifetime need not apply to every client class.

---

# 42. Offline Tokens

Offline/long-lived tokens SHALL be disabled by default.

Any use of offline access SHALL require explicit justification because it materially increases credential persistence.

---

# 43. Long-Lived API Tokens

Static long-lived bearer API keys SHALL not be the default workload-authentication mechanism.

Prefer:

```text
short-lived OAuth token
```

obtained using securely managed workload credentials.

---

# 44. Token Renewal

Applications SHALL renew tokens before expiry using the mechanism appropriate to their architecture.

They SHALL not simply extend access by ignoring `exp`.

---

# 45. Clock Skew

Resource servers MAY permit a small configured clock skew for:

```text
exp
nbf
iat
```

validation.

The Control Plane's existing approximately 30-second skew policy SHOULD remain the platform baseline unless operational evidence requires change.

Large skew tolerances SHALL be avoided.

---

# 46. Signing Algorithms

Baobab SHALL use asymmetric signing for production tokens.

The existing Control Plane verifier accepts:

```text
RS256
ES256
```

The IAM token profile SHALL remain compatible with the relying-service security model.

The exact primary signing algorithm SHALL be configured centrally and documented.

---

# 47. Symmetric Token Signing

Shared symmetric signing secrets across multiple resource servers SHALL NOT be the normal production architecture.

Asymmetric signing is preferred because resource servers can verify tokens without holding the issuer's signing secret.

---

# 48. Algorithm Allow-List

Every resource server SHALL maintain an explicit algorithm allow-list.

The incoming token header SHALL not unilaterally decide which algorithm is trusted.

---

# 49. JWKS

Baobab IAM SHALL expose OIDC discovery and JWKS according to standard OIDC behaviour.

Relying services SHALL use discovery/JWKS only from preconfigured trusted issuer locations.

---

# 50. JWKS Cache

Resource servers SHOULD cache signing keys.

They SHALL refresh appropriately when:

- unknown `kid` encountered;
- cache expires;
- issuer rotates signing keys.

Failure to retrieve a replacement key SHALL fail closed for tokens that cannot be verified.

---

# 51. Key Rotation

Signing keys SHALL be rotatable without requiring simultaneous deployment of every relying service.

Expected flow:

```text
Old key active
      │
      ▼
New key published
      │
      ▼
New key begins signing
      │
      ▼
Old tokens expire
      │
      ▼
Old key retired
```

Rotation SHALL preserve overlap sufficient for outstanding valid tokens.

---

# 52. Key Compromise

A suspected signing-key compromise SHALL trigger an emergency process that may include:

- key replacement;
- token/session revocation;
- shortened session validity;
- incident investigation;
- client notification;
- audit review.

This process SHALL be tested operationally.

---

# 53. Token Storage

Tokens SHALL not be persisted casually.

Forbidden locations include:

```text
application logs
analytics events
error traces
URLs
source code
repository files
browser localStorage by default for high-risk apps
```

Architecture-specific secure storage SHALL be documented.

---

# 54. Token in URL

Access or refresh tokens SHALL never intentionally be transported through:

```text
query strings
URL fragments
redirect parameters
```

except where a standards-defined protocol artifact requires a different temporary value such as an authorization code.

---

# 55. Token Logging

Services SHALL redact:

```text
Authorization
access_token
refresh_token
id_token
client_secret
```

from logs and traces.

---

# 56. Bearer Token Replay

Because bearer tokens can be replayed if stolen, Baobab SHALL minimize:

- token lifetime;
- exposure;
- unnecessary propagation;
- persistence.

Sender-constrained access tokens MAY be considered in a future ADR if threat/risk warrants them.

---

# 57. Token Forwarding

Services SHALL NOT forward incoming user tokens indiscriminately to every downstream service.

Token forwarding SHALL occur only where:

- audience is appropriate;
- delegation semantics are valid;
- receiving service is authorized to consume the token.

---

# 58. Token Exchange

OAuth token exchange MAY be used in future where a service must obtain a downstream token representing delegated identity or workload authority.

It SHALL NOT be introduced merely to avoid defining proper audience boundaries.

Token exchange SHALL require explicit policy for:

```text
subject
actor
audience
scope
delegation chain
```

and SHALL be addressed by implementation-specific security review.

---

# 59. User Token Versus Workload Token

Baobab SHALL distinguish:

```text
user-authenticated request
```

from:

```text
service-owned operation
```

A service SHALL not impersonate a human simply by presenting its workload token.

Where “on behalf of” semantics are needed, actor and subject MUST remain distinguishable.

---

# 60. Delegated Call Model

Future delegated flows SHOULD preserve:

```text
human subject
       │
       ▼
service actor
       │
       ▼
target service
```

rather than losing the initiating subject.

---

# 61. Service-Owned Call Model

For background jobs:

```text
baobab-trade
     │
     ▼
workload token
     │
     ▼
baobab-erp
```

there may be no human subject at all.

The audit record SHALL clearly identify the workload actor.

---

# 62. Resource Server Validation

Every resource server SHALL independently validate access tokens unless an explicitly designed trusted token-validation architecture supersedes this rule.

Validation SHALL include at least:

```text
signature
issuer
audience
expiration
not-before
algorithm
required scope
expected actor/client semantics
```

---

# 63. Gateway Validation

The gateway MAY reject obviously invalid tokens early.

This is defense in depth.

Gateway validation SHALL NOT remove the requirement for security-sensitive downstream services to enforce their own trust contract.

---

# 64. Introspection

Token introspection MAY be used for specific token profiles or high-risk revocation-sensitive operations.

However, the baseline SHALL remain locally verifiable signed JWT access tokens where appropriate.

Introspection SHALL not be required for every request unless architecture/risk justifies the additional runtime dependency.

---

# 65. Revocation

Baobab SHALL distinguish:

```text
session revocation
refresh-token revocation
client credential revocation
external identity disablement
canonical identity suspension
membership revocation
domain authorization revocation
```

Revoking one does not necessarily represent all others.

---

# 66. Access Token Revocation Limitation

A previously issued self-contained Access Token may remain cryptographically valid until expiry unless:

- introspection is required;
- key/session strategy invalidates it;
- a resource server performs additional lifecycle checks.

Therefore short Access Token lifetimes are important.

---

# 67. Logout

Logout MAY involve multiple layers:

```text
Application session
        │
        ▼
IAM session
        │
        ▼
Refresh token invalidation
```

Single Logout behavior SHALL be tested per client.

Logging out of one Digital Estate need not automatically destroy every active business session unless policy requires global logout.

---

# 68. Global Logout

Baobab IAM SHOULD support administrative global session revocation for:

- compromised account;
- employee termination;
- privileged identity incident;
- suspected credential theft.

---

# 69. Password Change

A password change MAY trigger session revocation according to client/security class.

Sensitive workforce accounts SHOULD receive stricter behavior than low-risk consumer accounts.

---

# 70. MFA State and Tokens

Tokens MAY indicate authentication assurance information where useful.

However downstream business permissions SHALL not infer MFA solely from a generic role.

For step-up-sensitive operations, the application SHOULD verify authentication assurance through a defined claim/profile.

---

# 71. Authentication Context

Baobab MAY use standard OIDC concepts such as:

```text
acr
amr
auth_time
```

where needed for step-up decisions.

Exact values SHALL be centrally documented if relied upon.

---

# 72. Step-Up Authentication

Sensitive operations MAY require stronger recent authentication.

Examples:

```text
IAM administration
ERP financial posting
high-value B2B approval
supplier bank-account change
security setting modification
```

The application SHALL request or verify the required assurance level rather than inventing local password prompts.

---

# 73. Token Profile Versioning

Baobab-specific claims SHALL be versioned through Shared contracts where evolution could break consumers.

Avoid uncontrolled custom-claim proliferation.

---

# 74. Custom Claim Namespace

Custom claims SHOULD use names that clearly identify Baobab semantics and avoid collisions with standard claims.

Example conceptual naming:

```text
baobab_actor_type
baobab_context
```

The precise naming convention SHALL follow Shared contract standards.

---

# 75. Standard Claims First

Where a standard claim exists, Baobab SHOULD use it rather than invent an equivalent.

Examples:

```text
iss
sub
aud
exp
iat
nbf
azp
scope
acr
amr
auth_time
```

---

# 76. Token Claim Ownership Matrix

| Claim/data | Authority |
|---|---|
| `iss` | IAM |
| `sub` | IAM provider subject |
| `aud` | IAM/client configuration |
| `azp` | IAM |
| `scope` | IAM authorization grant |
| actor type | IAM/contract |
| canonical identity | CP if represented |
| tenant status | CP |
| engine entitlement | CP |
| buyer role | Trade |
| ERP role | ERP |
| supplier approval | supplier domain |

This table prevents claim inflation.

---

# 77. Recommended Baseline Token Shape

Illustrative human Access Token:

```json
{
  "iss": "https://identity.baobab.example/realms/baobab",
  "sub": "4b8f...",
  "aud": "baobab-control-plane",
  "azp": "zuribeans-web",
  "actor_type": "human",
  "scope": "openid profile context:resolve",
  "iat": 1788900000,
  "exp": 1788900900
}
```

Illustrative workload token:

```json
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

These are conceptual examples, not mandates for literal Keycloak internals.

---

# 78. What Shall Not Be in the Token

By default, do not embed:

```text
password hashes
MFA secrets
tax numbers
supplier bank data
purchase limits
full ERP roles
complete customer profile
full tenant membership graph
commercial terms
personal addresses
```

JWTs are security artifacts, not portable databases.

---

# 79. Control Plane Administrative Token

Administrative Control Plane calls SHALL require:

```text
valid human token
correct audience
actor_type = human
explicit privileged scope
```

consistent with the Control Plane's existing OIDC security foundation.

The previous bootstrap-admin-secret model SHALL not be reintroduced.

---

# 80. Control Plane Workload Token

Internal context resolution SHALL require:

```text
valid workload token
correct audience
actor_type = workload
authorized client
context:resolve
```

plus any transport requirements defined by infrastructure.

---

# 81. Medusa Integration

Medusa SHALL consume Baobab identity through an approved OIDC/Auth Module integration.

It SHALL not require duplicating the Baobab master password credential.

Trade MAY maintain local actor/customer mappings, but Baobab IAM remains authentication authority.

---

# 82. iDempiere Integration

iDempiere SHALL use Keycloak OIDC SSO where the supported integration path permits.

The ERP SHALL validate its intended authentication context while retaining ERP-native authorization.

IAM tokens SHALL not embed complete `AD_Role` permission sets.

---

# 83. CMS Integration

Payload CMS administrative authentication SHOULD use Baobab IAM where feasible.

CMS roles remain CMS-owned.

---

# 84. Pulse Integration

Baobab Pulse service APIs SHALL use workload or user access tokens appropriate to the operation.

Pulse SHALL not trust tenant context solely from query parameters.

---

# 85. Client Registration

Every client SHALL define:

```text
client ID
client type
redirect URIs
allowed origins where relevant
grant types
scopes
audiences
token policy
logout URIs
```

as configuration-as-code.

---

# 86. Client Secret Policy

Confidential client secrets SHALL:

- be unique per client;
- be secret-managed;
- be rotatable;
- not be committed;
- not be shared across applications.

---

# 87. Stronger Client Authentication

For high-value workloads, Baobab MAY later adopt stronger client authentication than static shared secret where supported, such as certificate- or key-based mechanisms.

This is not required by this ADR for all clients.

---

# 88. CORS

CORS SHALL be explicitly configured per browser-facing resource.

CORS SHALL NOT be treated as an authorization control.

A permissive CORS configuration does not grant API permission, and a restrictive one does not replace token validation.

---

# 89. CSRF

Cookie-authenticated application architectures SHALL implement CSRF protection for state-changing operations.

Bearer-token APIs that do not rely on browser ambient credentials have a different CSRF profile, but XSS/token-theft risk remains.

---

# 90. Replay and `jti`

Baobab MAY use `jti` where useful for audit or replay-sensitive profiles.

The platform SHALL not maintain global replay-state for every ordinary short-lived bearer JWT unless risk warrants it.

---

# 91. Token Cache Policy

Applications MAY cache validated token metadata for performance where safe.

Cache duration SHALL never exceed token validity.

Security-sensitive lifecycle state may still require fresh context checks.

---

# 92. Failure Behavior

The following SHALL fail closed:

| Condition | Result |
|---|---|
| signature invalid | deny |
| issuer mismatch | deny |
| audience mismatch | deny |
| expired token | deny |
| unsupported algorithm | deny |
| missing required scope | deny |
| wrong actor type | deny |
| workload client mismatch | deny |
| JWKS unavailable and key unknown | deny |
| malformed token | deny |

---

# 93. Token Validation Errors

External responses SHOULD remain generic:

```text
401 Unauthorized
403 Forbidden
```

as appropriate.

Detailed validation failure reasons SHOULD remain in protected telemetry/audit systems.

---

# 94. Authentication Versus Authorization Status

As a guideline:

```text
invalid/missing authentication
        │
        ▼
401

authenticated but insufficient permission
        │
        ▼
403
```

Resource APIs SHOULD follow consistent HTTP semantics.

---

# 95. Discovery

Clients SHOULD obtain protocol endpoints from OIDC discovery rather than hard-code numerous endpoint URLs independently.

The trusted issuer itself SHALL remain explicitly configured.

---

# 96. Development Environments

Local development MAY use localhost callback URIs and development clients.

Production and development clients SHALL remain separated sufficiently to prevent:

```text
development redirect URI
development secret
development origin
```

from becoming production trust paths.

---

# 97. Test Tokens

Tests SHALL not depend on production signing keys or production IAM accounts.

Integration tests SHOULD provision dedicated test clients and identities.

---

# 98. Negative Security Tests

Automated tests SHALL cover at least:

```text
expired token
wrong issuer
wrong audience
missing audience
unsupported algorithm
tampered signature
missing scope
wrong actor_type
wrong azp
PKCE missing
PKCE wrong verifier
redirect URI mismatch
authorization-code replay
refresh-token misuse
ID Token used as API Access Token
cross-service token forwarding
tenant claim tampering
```

---

# 99. Browser Tests

Browser/E2E tests SHOULD cover:

- Authorization Code + PKCE;
- logout;
- session expiry;
- login cancellation;
- callback integrity;
- state/nonce handling;
- expired session;
- multi-tab behavior where relevant.

---

# 100. Workload Tests

Workload integration tests SHALL demonstrate:

```text
valid client obtains token
invalid secret rejected
revoked client rejected
correct audience accepted
wrong audience rejected
required scope enforced
expired token rejected
```

---

# 101. Key-Rotation Test

A staging test SHALL prove that:

```text
old token
     +
new signing key
```

continues working during intended overlap, and that old keys can later be retired without permanent outage.

---

# 102. Interoperability Tests

At minimum, IAM integration SHALL be validated against:

```text
baobab-cp
baobab-trade
baobab-erp
```

before customer-facing rollout.

CMS and Pulse SHALL follow the same profile as integration reaches them.

---

# 103. Rejected Alternative — Implicit Flow

### Decision

Rejected.

Authorization Code + PKCE provides the preferred browser security model.

---

# 104. Rejected Alternative — Resource Owner Password Grant

### Decision

Rejected.

Digital Estates SHALL not collect user credentials merely to exchange them for tokens.

Credentials remain IAM-owned.

---

# 105. Rejected Alternative — One Token for Every Baobab API

A universal token with:

```text
aud = everything
```

would weaken audience isolation.

### Decision

Rejected as default.

---

# 106. Rejected Alternative — Full Authorization Graph in JWT

### Advantages

Fewer API lookups.

### Disadvantages

- stale policy;
- large tokens;
- poor revocation;
- tight IAM/domain coupling.

### Decision

Rejected.

---

# 107. Rejected Alternative — Very Long-Lived Access Tokens

### Advantages

Operational simplicity.

### Disadvantages

- larger replay window;
- poor revocation;
- increased compromise impact.

### Decision

Rejected.

---

# 108. Rejected Alternative — ID Token as API Token

ID Tokens are intended for the OIDC relying client, not as general API bearer credentials.

### Decision

Rejected.

---

# 109. Consequences

## Positive

This decision provides:

- consistent authentication protocols;
- strong browser security;
- audience isolation;
- short-lived credentials;
- consistent claims;
- clear token semantics;
- workload identity;
- reduced domain leakage into JWTs;
- easier interoperability across polyglot repositories.

## Negative

It requires:

- careful client registration;
- scope management;
- token validation libraries;
- JWKS handling;
- session/lifetime design;
- additional integration testing.

These costs are accepted.

---

# 110. Implementation Ownership

| Concern | Owner |
|---|---|
| Token issuance | `baobab-iam` |
| Realm/client configuration | `baobab-iam` |
| Claim contracts | `shared` |
| Access-token validation | each resource service |
| Canonical identity resolution | `baobab-cp` |
| Platform context | `baobab-cp` |
| Gateway pre-validation | `infrastructure` |
| Domain authorization | authoritative engine |
| Secret provisioning | `infrastructure` |

---

# 111. Shared Contract Requirements

`baobab-platform/shared` SHOULD define:

```text
identity claim profile
actor_type values
scope registry
context claim schema if used
token audience conventions
security event contracts
```

These SHALL be versioned.

---

# 112. Architectural Invariants

The following become binding:

```text
Authorization Code + PKCE for public browser clients

Implicit Grant is prohibited for new Baobab clients

ID Token ≠ API Access Token

Access Token ≠ Refresh Token

iss + sub ≠ CanonicalIdentity directly

Valid Token ≠ Valid Platform Context

Valid Scope ≠ Domain Business Permission

Audience must be explicit

Actor type must be explicit where required

Access Tokens must be short-lived

JWT ≠ Authorization Database

Client secret must never reside in public frontend code

Tokens must never be logged intentionally
```

---

# 113. Target Security Flow

```text
                     HUMAN
                       │
                       ▼
             Authorization Code + PKCE
                       │
                       ▼
                  BAOBAB IAM
                       │
                  Access Token
                       │
                       ▼
                 RESOURCE API
                       │
               validate token
                       │
                       ▼
                  BAOBAB CP
                       │
               resolve context
                       │
                       ▼
                 DOMAIN ENGINE
                       │
               authorize action
```

and:

```text
                   WORKLOAD
                       │
                       ▼
              OAuth client identity
                       │
                       ▼
                  BAOBAB IAM
                       │
                short-lived token
                       │
                       ▼
                  BAOBAB CP
                       │
                context policy
                       │
                       ▼
                  TARGET API
```

---

# 114. Decision Summary

Baobab adopts a strict, standards-based OIDC/OAuth token profile built around:

```text
Authorization Code + PKCE
explicit issuers
explicit audiences
short-lived access tokens
separate refresh tokens
workload client authentication
minimal claims
explicit scopes
asymmetric signatures
JWKS-based verification
server-side context resolution
domain-owned authorization
```

The governing principle is:

> **Tokens shall prove only what must travel with the request; mutable Baobab business authority shall remain in the systems that actually own it.**

This keeps the IAM layer secure, compact and portable while preserving the Control Plane and domain engines as authoritative decision-makers.