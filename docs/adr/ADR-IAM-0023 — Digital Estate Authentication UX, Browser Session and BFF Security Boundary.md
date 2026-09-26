# ADR-IAM-0023 — Digital Estate Authentication UX, Browser Session and BFF Security Boundary

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture  
**Primary Repositories:** `baobab-platform/baobab-iam`, Digital Estate repositories  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold, and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0022  
**Extends:** ADR-IAM-0003, ADR-IAM-0005, ADR-IAM-0006, ADR-IAM-0008, ADR-IAM-0009, ADR-IAM-0010, ADR-IAM-0011, ADR-IAM-0012, ADR-IAM-0013, ADR-IAM-0015, ADR-IAM-0016, ADR-IAM-0017, ADR-IAM-0019, ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022  
**Decision Type:** Authentication UX / Browser Security / Session Architecture / BFF / Digital Estate Integration  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Browser Architecture:** Server-mediated authentication with Backend-for-Frontend where applicable  
**Primary Security Principle:** Authentication credentials and OAuth tokens SHOULD remain outside browser JavaScript wherever architecture permits.

---

# 1. Decision

Baobab Digital Estates SHALL own their **authentication user experience**, while Ory and Baobab IAM retain responsibility for the underlying identity and authentication mechanics.

For first-party browser-based Digital Estates, Baobab SHALL prefer a **Backend-for-Frontend (BFF)** architecture in which:

1. the browser receives an opaque, strongly protected estate session cookie;
2. OAuth authorization codes are exchanged server-side;
3. OAuth access and refresh tokens remain server-side;
4. browser JavaScript does not require direct access to long-lived authentication credentials or OAuth tokens;
5. the BFF acts as the browser's trusted server-side security intermediary;
6. the BFF does not become the canonical identity authority;
7. the BFF does not become the platform authorization authority;
8. the BFF does not own domain authorization;
9. Ory Kratos remains responsible for human authentication mechanics;
10. Ory Hydra remains responsible for OAuth/OIDC;
11. Baobab Control Plane remains responsible for canonical identity and platform context;
12. domain engines remain responsible for domain authorization.

The target model is:

```text
Browser
   │
   │ opaque estate session cookie
   ▼
Digital Estate BFF
   │
   ├── server-side OAuth tokens
   ├── session state
   ├── CSRF enforcement
   ├── OAuth callback handling
   └── trusted API mediation
   │
   ▼
Ory / Baobab APIs
   │
   ▼
CanonicalIdentity + Context
   │
   ▼
Domain Authorization
```

The browser SHALL NOT become Baobab's token vault.

---

# 2. Why This ADR Exists

Moving from Keycloak to Ory deliberately gives Baobab greater control over identity UX.

That is valuable.

It is also dangerous if interpreted as:

> "Every frontend now implements authentication."

That is explicitly **not** the decision.

The platform requires a boundary between:

```text
Authentication presentation
Authentication protocol
Browser session
OAuth tokens
Canonical identity
Platform context
Business authorization
```

Without such a boundary, each Digital Estate could independently develop:

- token storage;
- refresh handling;
- callback handling;
- logout;
- CSRF defenses;
- recovery flows;
- MFA handling;
- passkey flows;
- tenant selection;
- organization switching;
- error semantics.

That would reproduce precisely the fragmentation the Baobab platform architecture is designed to avoid.

This ADR therefore defines a common security architecture while allowing ZuriBeans, Thamani, Nabhold and future Digital Estates to retain distinct user experiences.

---

# 3. Research Basis

This ADR is aligned with current browser OAuth security guidance.

RFC 10017, published in August 2026 as the Best Current Practice for OAuth 2.0 browser-based applications, explicitly discusses BFF architectures. It requires BFF session cookies to use `Secure` and `HttpOnly`, recommends `SameSite=Strict`, recommends `/` as the cookie path, and recommends not setting a `Domain` attribute.

RFC 9700 requires strong protections for redirect-based OAuth flows, including exact redirect URI matching and PKCE for public clients; PKCE is also recommended for confidential clients. It further recommends modern client authentication and discourages insecure legacy OAuth patterns.

OWASP recommends protecting session identifiers with TLS, `Secure`, `HttpOnly`, appropriate `SameSite` restrictions, and tightly scoped cookie domains. OWASP also warns against storing authentication tokens, session IDs, JWTs or refresh tokens in `localStorage` or `sessionStorage`.

These standards support, rather than replace, Baobab's existing IAM architectural decisions.

---

# 4. Architectural Principle

The authentication stack SHALL be understood as five distinct layers:

```text
┌─────────────────────────────────────┐
│ 1. DIGITAL ESTATE UX                │
│    "What does login look like?"     │
├─────────────────────────────────────┤
│ 2. BROWSER/BFF SESSION              │
│    "How is browser state secured?"  │
├─────────────────────────────────────┤
│ 3. IDENTITY PROVIDER                │
│    "Who authenticated?"             │
│    Kratos + Hydra                   │
├─────────────────────────────────────┤
│ 4. CONTROL PLANE                    │
│    "Who is this canonically and     │
│     in which context?"              │
├─────────────────────────────────────┤
│ 5. DOMAIN ENGINE                    │
│    "May they perform this action?"  │
└─────────────────────────────────────┘
```

No layer SHALL silently absorb the responsibilities of another.

---

# 5. Responsibility Model

| Concern | Estate UI | BFF | Ory | IAM Adapter | CP | Domain |
|---|---:|---:|---:|---:|---:|---:|
| Login presentation | ✓ | — | mechanics | — | — | — |
| Registration UX | ✓ | mediation | ✓ | lifecycle | — | — |
| Password authentication | presentation | mediation | ✓ | — | — | — |
| Passkeys | presentation | mediation | ✓ | policy integration | — | — |
| MFA | presentation | mediation | ✓ | policy integration | assurance use | — |
| Recovery | presentation | mediation | ✓ | lifecycle | — | — |
| OAuth authorization | redirect | callback | Hydra | — | — | — |
| OAuth tokens | ✕ preferred | ✓ | Hydra | — | validation/context | resource use |
| Browser session | cookie | ✓ | provider session | — | — | — |
| CanonicalIdentity | — | — | — | mapping | ✓ | reference |
| Tenant | display/context request | relay | — | — | ✓ | consume |
| LegalEntity | display/context request | relay | — | — | ✓ | consume |
| Organization membership | display | relay | — | — | contextual | domain/CP |
| Business role | display | relay | — | — | platform only | ✓ |
| Purchase authority | display | relay | — | — | — | Trade |
| ERP role | display | relay | — | — | mapping | iDempiere |

---

# 6. Estate-Owned Authentication UX

Each Digital Estate SHALL own the presentation of:

```text
sign in
sign out
registration
verification
recovery
passkey enrolment
MFA challenge
account-security settings
organization selection
context selection
authentication errors
```

where those experiences are relevant.

This allows:

```text
ZuriBeans
    → professional B2B trade identity UX

Thamani
    → B2C + B2B logistics identity UX

Nabhold
    → corporate/workforce-oriented UX
```

without forcing all estates into a generic identity-provider theme.

---

# 7. Estate Ownership Does Not Mean Identity Ownership

A Digital Estate MAY decide:

```text
layout
copy
branding
interaction sequence
accessibility treatment
responsive behavior
help content
```

It SHALL NOT independently decide:

```text
password hashing
credential storage
passkey cryptography
token signing
OIDC semantics
canonical identity IDs
tenant membership
business authorization
```

---

# 8. Shared UX, Not Shared Branding

Baobab SHOULD provide reusable authentication primitives and contracts.

For example:

```text
AuthenticationError
LoginState
VerificationState
RecoveryState
MFAChallenge
PasskeyChallenge
AuthenticatedPrincipal
ContextSummary
```

Digital Estates MAY render these differently.

---

# 9. Headless Identity Principle

Ory is selected partly because authentication mechanics can remain headless.

Therefore:

```text
Ory mechanics
      │
      ▼
Baobab security integration
      │
      ▼
Estate-owned UI
```

is preferred over:

```text
Ory-hosted generic page
      │
      ▼
all Baobab brands
```

where Baobab can safely own the UX.

---

# 10. Default Browser Architecture

For first-party Digital Estates, the preferred architecture is:

```text
                         BROWSER
                            │
                     HTTPS │
                            ▼
               ┌───────────────────────┐
               │ Digital Estate        │
               │                       │
               │ UI + BFF              │
               └──────────┬────────────┘
                          │
              server-side│ OAuth/OIDC
                          ▼
               ┌───────────────────────┐
               │ Ory                   │
               │ Kratos + Hydra        │
               └──────────┬────────────┘
                          │
                          ▼
               ┌───────────────────────┐
               │ Baobab Control Plane  │
               └──────────┬────────────┘
                          │
                  ┌───────┼───────┐
                  ▼       ▼       ▼
                Trade    ERP     CMS
```

---

# 11. Why BFF Is Preferred

The BFF reduces exposure of bearer credentials to browser JavaScript.

Instead of:

```text
Browser JavaScript
      │
      ├── access token
      ├── refresh token
      └── API calls
```

prefer:

```text
Browser
   │
   │ HttpOnly session cookie
   ▼
BFF
   │
   ├── access token
   ├── refresh token
   └── API calls
```

This does not eliminate browser security risk.

It changes the risk profile and substantially reduces direct JavaScript access to OAuth credentials.

RFC 10017 explicitly recognizes BFF as a browser application architecture and defines security requirements for its cookie-based session.

---

# 12. BFF Is Not an API Gateway

The BFF SHALL be scoped to the Digital Estate.

```text
ZuriBeans BFF
      ≠
Baobab API Gateway

Thamani BFF
      ≠
Baobab Control Plane

Nabhold BFF
      ≠
IAM
```

The BFF adapts browser interactions.

The gateway controls platform ingress.

CP resolves platform context.

These are distinct responsibilities.

---

# 13. BFF Is Not an Authorization Server

The BFF SHALL NOT issue Baobab OAuth access tokens.

Hydra remains the OAuth/OIDC authorization server.

---

# 14. BFF Is Not Identity Authority

The BFF SHALL NOT maintain an independent authoritative user table.

It MAY maintain application session state associated with:

```text
provider subject
CanonicalIdentity reference
session metadata
selected context
OAuth token references
```

but identity authority remains outside it.

---

# 15. BFF Is Not Business Authorization

Prohibited:

```text
if session.role == "buyer_admin":
    approve_purchase()
```

where `session.role` is treated as the ultimate authority.

Required:

```text
authenticated principal
      │
      ▼
resolved context
      │
      ▼
Trade authorization
      │
      ▼
ALLOW / DENY
```

---

# 16. BFF Session

The browser SHALL normally receive only an opaque session identifier.

Conceptually:

```text
Cookie:
__Host-Http-zuribeans-session=<opaque>
```

The value SHALL NOT encode:

```text
access token
refresh token
password
tenant authority
purchase limits
ERP role
```

---

# 17. Cookie Security

Production BFF session cookies SHALL use:

```text
Secure
HttpOnly
Path=/
```

and SHOULD use:

```text
SameSite=Strict
```

where the required navigation/federation behavior permits it.

A `Domain` attribute SHOULD NOT be set for host-bound estate sessions.

This follows the current browser-app BCP and OWASP session guidance.

---

# 18. SameSite Exceptions

Some federated identity journeys may require a less restrictive cookie configuration.

Any exception such as:

```text
SameSite=Lax
```

SHALL be:

- deliberate;
- documented;
- tested;
- scoped to the required cookie;
- protected by independent CSRF defenses.

`SameSite=None` SHALL require `Secure` and explicit architectural justification.

---

# 19. Cookie Domain Isolation

ZuriBeans and Thamani SHALL NOT share authentication session cookies merely because both belong to the Baobab ecosystem.

Prefer:

```text
zuribeans.example
   └── ZuriBeans session

thamani.example
   └── Thamani session
```

not:

```text
*.example
   └── universal Baobab browser session
```

---

# 20. One Identity Does Not Require One Cookie

A person may have:

```text
one CanonicalIdentity
```

while simultaneously holding:

```text
ZuriBeans estate session
Thamani estate session
Nabhold estate session
```

These concepts are independent.

---

# 21. Browser Storage

OAuth access tokens, refresh tokens and session secrets SHALL NOT be stored in:

```text
localStorage
sessionStorage
IndexedDB
```

for normal Baobab first-party BFF applications.

OWASP specifically warns against storing authentication tokens and session identifiers in web storage because JavaScript executing in the origin can access them.

---

# 22. Browser Memory

Short-lived protocol values MAY transiently exist in browser memory where required by standards-based flows.

This SHALL not become persistent token storage.

---

# 23. Server-Side Session Store

The BFF MAY maintain server-side session state.

Conceptually:

```text
session_id
principal_reference
provider_session_reference
CanonicalIdentity reference
OAuth token material/reference
selected_context
assurance metadata
created_at
last_activity
expires_at
revocation_state
```

Sensitive values SHALL be protected appropriately.

---

# 24. Session Store Is Not Canonical State

A session record may cache:

```text
CanonicalIdentity ID
selected Context ID
```

but SHALL NOT become the source of truth for either.

---

# 25. Session Fixation

Authentication SHALL establish or rotate the estate session identifier.

An anonymous/pre-authentication session identifier SHALL NOT simply become the authenticated session without appropriate regeneration.

---

# 26. Session Expiry

BFF sessions SHALL have:

```text
absolute expiry
idle expiry where appropriate
provider/token expiry awareness
revocation handling
```

Session duration SHALL reflect the risk of the estate and user population.

---

# 27. Privilege Change

Security-significant changes SHOULD cause:

```text
session rotation
context revalidation
step-up authentication
or session termination
```

as appropriate.

Examples:

```text
buyer approver privilege granted
finance role granted
password changed
MFA reset
identity recovery
account compromise
```

---

# 28. OAuth Flow

Baobab browser applications SHALL use Authorization Code flow.

PKCE SHALL be used where required and SHOULD be used broadly in accordance with current OAuth security guidance. RFC 9700 requires PKCE for public clients and recommends it for confidential clients.

---

# 29. Implicit Grant

The OAuth Implicit Grant SHALL NOT be used.

---

# 30. Resource Owner Password Credentials

ROPC SHALL NOT be used.

The Digital Estate SHALL not collect a password and exchange it directly for an OAuth token as an OAuth password grant.

---

# 31. Redirect URI Validation

Redirect URIs SHALL be explicitly registered.

Exact matching SHALL be used in accordance with OAuth security best practice.

Prohibited:

```text
https://*.zuribeans.example/callback
```

unless a standards-compliant mechanism explicitly requires and safely supports such behavior.

Prefer:

```text
https://portal.zuribeans.example/auth/callback
```

---

# 32. Open Redirectors

Authentication endpoints SHALL NOT provide arbitrary redirect behavior such as:

```text
/auth/callback?next=https://attacker.example
```

without strict validation.

RFC 9700 explicitly prohibits open redirector patterns in OAuth clients and authorization servers.

---

# 33. Return-To URLs

Estate UX may preserve the user's intended destination.

The destination SHALL be represented through:

```text
validated internal route
signed/opaque state
allow-listed destination
```

rather than arbitrary URLs.

---

# 34. OAuth State

OAuth `state` SHALL be:

- unpredictable;
- transaction-specific;
- integrity protected;
- bound to the initiating browser session;
- single-use or appropriately replay protected.

---

# 35. OIDC Nonce

Where OIDC ID Tokens participate in the flow, `nonce` SHALL be used according to the applicable OIDC security model.

It SHALL be transaction-specific.

---

# 36. PKCE

PKCE values SHALL be generated per authorization transaction.

Constant or reusable code verifiers are prohibited.

---

# 37. Callback Handling

The OAuth callback SHALL be handled server-side by the BFF for the preferred architecture.

```text
Hydra
  │
  │ authorization code
  ▼
BFF callback
  │
  │ server-to-server token exchange
  ▼
Hydra token endpoint
```

---

# 38. Browser Does Not Exchange Confidential Credentials

A confidential client secret SHALL never be shipped to browser JavaScript.

---

# 39. Token Storage

For the preferred BFF model:

```text
Access token  → server side
Refresh token → server side
ID token      → server side where retained
Session ID    → browser cookie
```

---

# 40. Access Token Lifetime

Access tokens SHALL remain short-lived according to ADR-IAM-0006 and the Ory token profile.

A long BFF session SHALL not imply a long-lived access token.

---

# 41. Refresh Tokens

Where used, refresh tokens SHALL:

- remain server-side;
- be encrypted/protected at rest where persisted;
- support rotation where available;
- detect/reject reuse where supported;
- be revoked when the session is terminated where practical.

---

# 42. Token Refresh

The BFF MAY transparently refresh OAuth credentials.

However:

```text
refresh succeeded
```

does not override:

```text
CanonicalIdentity suspended
Context invalid
domain permission revoked
```

---

# 43. Token Audience

The BFF SHALL request and use tokens only for appropriate audiences.

A Trade token SHALL not automatically be valid for ERP.

---

# 44. Token Forwarding

The BFF SHALL not blindly forward the same bearer token to every backend.

Each downstream audience SHALL be explicitly considered.

---

# 45. Token Exchange

Where a downstream service requires a different audience or delegated identity, standards-based token exchange MAY be used if explicitly adopted.

Ad hoc token rewriting is prohibited.

---

# 46. Browser API Pattern

Preferred:

```text
Browser
   │
   │ cookie
   ▼
Estate BFF
   │
   │ bearer/service credentials
   ▼
Baobab API
```

rather than:

```text
Browser
   │
   │ bearer token
   ▼
every Baobab engine
```

---

# 47. CSRF Boundary

Because browsers automatically attach cookies, BFF endpoints that mutate state SHALL implement CSRF protections.

`SameSite` is defense in depth, not a complete replacement for explicit CSRF protections. OWASP makes this distinction explicitly.

---

# 48. CSRF Controls

Depending on framework and route type, protections MAY include:

```text
synchronizer token
signed double-submit token
origin verification
Fetch Metadata validation
SameSite cookie restrictions
```

Security-sensitive mutation endpoints SHOULD combine appropriate defenses.

---

# 49. Origin Validation

Sensitive browser requests SHOULD validate:

```text
Origin
```

and where appropriate:

```text
Referer
Sec-Fetch-Site
```

against expected origins.

---

# 50. CORS

CORS SHALL be explicit and minimal.

Credential-bearing endpoints SHALL NOT use:

```text
Access-Control-Allow-Origin: *
```

---

# 51. Same-Origin Preference

Where practical:

```text
estate UI
+
estate BFF
```

SHOULD share an origin or otherwise use a tightly controlled first-party architecture.

This simplifies the security boundary.

---

# 52. XSS Remains Critical

HttpOnly cookies reduce direct session-secret extraction by JavaScript.

They do not make XSS harmless.

An attacker executing JavaScript in an authenticated origin may still initiate actions using the victim's browser.

Therefore estates SHALL maintain:

```text
strong CSP
output encoding
safe templating
dependency hygiene
Trusted Types where appropriate
minimal dangerous HTML injection
```

---

# 53. Content Security Policy

Authentication surfaces SHOULD receive particularly strict CSP configuration.

Exceptions for analytics, third-party widgets or tag managers SHALL be minimized.

Login and recovery pages are not appropriate places for broad third-party script execution.

---

# 54. Third-Party Scripts

Authentication pages SHOULD avoid unnecessary:

```text
advertising scripts
tracking scripts
chat widgets
marketing tags
```

because compromise expands credential/session attack surface.

---

# 55. Authentication UX and Accessibility

Security UX SHALL remain accessible.

Authentication surfaces SHALL support:

- keyboard operation;
- clear focus;
- semantic labels;
- error association;
- screen readers;
- sufficient contrast;
- understandable recovery instructions;
- non-color-only state communication.

Security SHALL not depend on inaccessible interaction patterns.

---

# 56. Error Messages

Authentication errors SHALL be useful without enabling identity enumeration.

Avoid:

```text
That email exists but the password is wrong.
```

where the context requires enumeration resistance.

Prefer a controlled generic response while providing recovery paths.

---

# 57. Registration UX

Registration SHALL be estate-specific while using provider-managed identity mechanics.

Conceptually:

```text
Estate registration UI
       │
       ▼
Kratos registration flow
       │
       ▼
identity established
       │
       ▼
Baobab lifecycle integration
       │
       ▼
CanonicalIdentity mapping
```

---

# 58. Registration Is Not Business Approval

For ZuriBeans:

```text
successful identity registration
       ≠
approved buyer company
```

For suppliers:

```text
successful identity registration
       ≠
approved supplier
```

For Thamani B2B:

```text
successful identity registration
       ≠
authorized representative of Company A
```

---

# 59. B2C Registration

Thamani may allow a person to establish a personal customer relationship.

Conceptually:

```text
Person
   │
   ▼
Ory identity
   │
   ▼
CanonicalIdentity
   │
   ▼
Thamani personal/B2C relationship
```

---

# 60. B2B Registration

For B2B journeys:

```text
Person
   │
   ▼
Ory identity
   │
   ▼
CanonicalIdentity
   │
   ▼
Business relationship/application/invitation
   │
   ▼
domain verification/approval
```

The identity provider SHALL NOT determine business representation merely because the user entered a company name.

---

# 61. One Person, Multiple Relationships

Example:

```text
                 Jane
                  │
                  ▼
          CanonicalIdentity
            /      |       \
           /       |        \
          ▼        ▼         ▼
     Personal   Company A   Company B
     Thamani    Logistics   Logistics
     Customer   Manager     Approver
```

One Ory identity can authenticate Jane.

CP/domain state determines the relationships.

---

# 62. Context Selection

After authentication, a user with multiple valid contexts MAY need to choose one.

Example:

```text
Authenticated Jane
       │
       ▼
CP resolves valid contexts
       │
       ├── Personal
       ├── Company A
       └── Company B
       │
       ▼
Estate presents selector
```

The selector displays valid contexts.

It does not invent them.

---

# 63. Client Context Is a Request

When the browser/BFF submits:

```text
context = Company B
```

this means:

> "Please resolve/activate Company B if this actor is entitled to it."

It does not mean:

> "The browser has proven Jane belongs to Company B."

---

# 64. Context Resolution

Required:

```text
Browser selection
      │
      ▼
BFF
      │
      ▼
CP
      │
      ▼
validate membership/context
      │
   ┌──┴───┐
   ▼      ▼
ALLOW    DENY
```

---

# 65. Context in Session

A BFF session MAY cache the currently selected:

```text
Context ID
```

for UX convenience.

The cached context SHALL be revalidated according to security policy.

---

# 66. Context Switching

Switching context SHALL:

1. request a new/validated CP context;
2. update server-side session state;
3. invalidate inappropriate cached data;
4. ensure downstream requests use the new context;
5. never mutate canonical membership.

---

# 67. Context Leakage

A browser session for:

```text
Company A
```

must not expose data cached while acting in:

```text
Company B
```

Context-aware cache boundaries are mandatory.

---

# 68. Public and Private Caching

Public estate content MAY use broad caching.

Authenticated/private content SHALL not share cache entries across:

```text
users
organizations
tenants
contexts
```

without an explicitly safe cache-key design.

---

# 69. Authentication State Model

Digital Estates SHOULD expose a common conceptual state model:

```text
ANONYMOUS
    │
    ▼
AUTHENTICATING
    │
    ▼
AUTHENTICATED
    │
    ▼
CONTEXT_REQUIRED
    │
    ▼
CONTEXT_ACTIVE
```

Domain states may extend this.

---

# 70. ZuriBeans State Model

ZuriBeans may expose:

```text
ANONYMOUS
   │
   ▼
AUTHENTICATED
   │
   ├── No Trading Account
   │
   ├── Trading Account Pending
   │
   └── Trading Account Approved
               │
               ▼
         Buyer Context
```

These are not all identity-provider states.

---

# 71. Thamani State Model

Thamani may expose:

```text
ANONYMOUS
   │
   ▼
AUTHENTICATED
   │
   ├── Personal Customer
   │
   ├── Business Applicant
   │
   ├── Business Member
   │
   └── Partner/Agent Context
```

Again, Ory authenticates the human; Thamani/CP own the relationships.

---

# 72. Supplier State Model

Supplier UX may expose:

```text
AUTHENTICATED
      │
      ▼
SUPPLIER_APPLICATION
      │
      ├── Draft
      ├── Submitted
      ├── Under Review
      ├── Approved
      └── Rejected
```

Kratos SHALL not encode this lifecycle as identity traits.

---

# 73. Login Flow

Preferred human login:

```text
Browser
   │
   ▼
Estate /login
   │
   ▼
BFF starts OAuth transaction
   │
   ▼
Hydra authorization
   │
   ▼
Kratos authentication
   │
   ▼
Hydra authorization code
   │
   ▼
BFF callback
   │
   ▼
server-side token exchange
   │
   ▼
resolve CanonicalIdentity/context
   │
   ▼
create/rotate estate session
   │
   ▼
Browser authenticated
```

---

# 74. Registration Flow

```text
Browser
   │
   ▼
Estate registration UX
   │
   ▼
Kratos registration
   │
   ▼
verification where required
   │
   ▼
IAM lifecycle integration
   │
   ▼
CanonicalIdentity mapping
   │
   ▼
estate/domain onboarding
```

---

# 75. Recovery Flow

```text
Browser
   │
   ▼
Estate recovery UX
   │
   ▼
Kratos recovery mechanics
   │
   ▼
identity recovered
   │
   ▼
existing sessions reviewed/revoked
   │
   ▼
assurance/context re-established
```

Recovery restores identity access.

It does not restore revoked business privileges.

---

# 76. Password Change

A password change SHOULD trigger appropriate security consequences, potentially including:

```text
session review
other-session revocation
security event
notification
risk evaluation
```

according to policy.

---

# 77. MFA

MFA challenge UX MAY be estate-owned.

Credential verification remains provider-managed.

```text
Estate UX
    │
    ▼
Kratos MFA flow
```

The estate SHALL not implement TOTP verification itself merely to customize UI.

---

# 78. Passkeys

Passkey UX MAY be integrated into estate-owned pages while relying on Kratos/WebAuthn mechanics.

The estate SHALL not create its own parallel passkey credential database.

---

# 79. Step-Up Authentication

Sensitive operations MAY require stronger authentication.

Examples:

```text
high-value purchase approval
banking detail change
supplier banking change
privileged administration
ERP finance operation
credential recovery
```

---

# 80. Step-Up Flow

```text
Domain operation
      │
      ▼
assurance insufficient
      │
      ▼
STEP_UP_REQUIRED
      │
      ▼
BFF redirects to authentication
      │
      ▼
Kratos stronger authentication
      │
      ▼
updated assurance evidence
      │
      ▼
operation retried
```

---

# 81. Step-Up Does Not Grant Permission

Passing MFA does not grant a business privilege.

```text
MFA success
    ≠
purchase approval authority
```

It proves stronger authentication assurance.

Domain authorization still applies.

---

# 82. Assurance Metadata

Where available and trustworthy, assurance information such as:

```text
acr
amr
auth_time
```

MAY participate in CP/domain security decisions.

The BFF SHALL not fabricate these values.

---

# 83. Logout

Logout SHALL distinguish:

```text
estate session logout
provider session logout
global/session-family logout
security revocation
```

They are not identical.

---

# 84. Estate Logout

At minimum:

```text
Browser
   │
   ▼
POST /logout
   │
   ▼
CSRF validation
   │
   ▼
BFF session invalidated
   │
   ▼
tokens revoked/discarded where applicable
   │
   ▼
cookie expired
```

---

# 85. Provider Logout

Where appropriate, logout MAY also terminate/revoke the corresponding Ory session.

The exact behavior depends on whether Baobab intends:

```text
logout from this estate
```

or:

```text
logout from identity provider/session family
```

---

# 86. Global Logout

A security-driven global logout SHALL be orchestrated through IAM lifecycle/revocation mechanisms, not merely by clearing a browser cookie.

---

# 87. Session Revocation

If:

```text
CanonicalIdentity = DISABLED
```

existing BFF sessions SHALL cease granting useful access as quickly as the security model requires.

The BFF SHALL not continue indefinitely because its local session cookie remains valid.

---

# 88. Revocation Strategy

This may require combinations of:

```text
short session validation intervals
CP security-state checks
revocation events
session invalidation
token expiry
token revocation
```

The exact performance/security balance SHALL be measured.

---

# 89. Provider Outage

If Kratos is unavailable:

```text
new authentication → unavailable/degraded
recovery → unavailable/degraded
registration → unavailable/degraded
```

Existing BFF sessions MAY continue where:

- their session remains valid;
- OAuth credentials remain valid;
- CP authorization remains valid;
- domain authorization remains valid.

---

# 90. Hydra Outage

If Hydra is unavailable:

```text
new OAuth authorization → impaired
token refresh/issuance → impaired
```

Existing usable short-lived credentials MAY continue until expiry according to the security architecture.

---

# 91. BFF Outage

An estate BFF outage affects that estate's authenticated browser experience.

It SHALL NOT imply that:

```text
CP
Trade
ERP
Ory
```

are unavailable platform-wide.

---

# 92. CP Outage

If a sensitive request requires CP context resolution and CP is unavailable:

```text
FAIL CLOSED
```

where no safe cached authorization/context decision exists.

The browser/BFF SHALL not invent context.

---

# 93. Session Cache During CP Outage

Bounded cached context MAY be used only where explicitly permitted by CP authorization architecture.

Security-sensitive invalidation requirements SHALL govern TTL.

---

# 94. API Error Semantics

The BFF SHOULD normalize platform security responses into useful estate-level outcomes such as:

```text
AUTHENTICATION_REQUIRED
SESSION_EXPIRED
STEP_UP_REQUIRED
CONTEXT_REQUIRED
CONTEXT_FORBIDDEN
ACCOUNT_SUSPENDED
DOMAIN_FORBIDDEN
SERVICE_UNAVAILABLE
```

without leaking unnecessary internal security details.

---

# 95. 401 and 403

General interpretation:

```text
401
→ authentication credentials absent/invalid/expired

403
→ authenticated but operation/context forbidden
```

Applications SHALL not convert every authorization failure into "please log in again."

---

# 96. Redirect Loops

Authentication middleware SHALL detect/prevent loops such as:

```text
/login
  ↓
callback
  ↓
context failure
  ↓
/login
  ↓
callback
  ↓
...
```

Context denial is not necessarily authentication failure.

---

# 97. BFF API Surface

The BFF SHOULD expose a narrow browser-oriented surface.

Example:

```text
/api/session
/api/context
/api/context/switch
/api/logout
/api/me
/api/trade/...
```

Exact routes remain estate-specific.

---

# 98. `/api/me`

A browser-facing identity summary MAY return:

```json
{
  "authenticated": true,
  "displayName": "Jane Doe",
  "contexts": [],
  "activeContext": {}
}
```

It SHALL not expose unnecessary provider internals such as:

```text
Kratos administrative ID
Hydra internals
provider secrets
raw refresh token
```

---

# 99. Provider-Neutral Browser Contract

The browser SHOULD not care whether the current provider is:

```text
Ory
Keycloak during migration
future standards-compatible provider
```

The estate contract should expose:

```text
authenticated
identity summary
assurance
available contexts
active context
required next action
```

---

# 100. Provider-Neutral Environment Variables

Estate/BFF configuration SHOULD use:

```text
BAOBAB_IAM_ISSUER
BAOBAB_IAM_DISCOVERY_URL
BAOBAB_IAM_CLIENT_ID
BAOBAB_IAM_AUDIENCE
BAOBAB_CP_URL
```

rather than:

```text
ORY_HYDRA_URL
KRATOS_ADMIN_URL
```

except inside the appropriate IAM/provider integration layer.

---

# 101. Kratos Public Integration

Where an estate must interact with Kratos browser flows, it SHALL use the supported public/self-service interface.

It SHALL NOT expose Kratos administrative APIs to the browser.

---

# 102. Hydra Integration

The BFF SHALL interact with Hydra using standards-based OAuth/OIDC interfaces wherever possible.

Provider administrative APIs SHALL not be required for ordinary browser authentication.

---

# 103. Administrative Separation

```text
Browser
   ✕
Kratos Admin

Browser
   ✕
Hydra Admin
```

No exceptions for frontend convenience.

---

# 104. SSR / Server Components

Server-rendered Digital Estates MAY use authenticated server-side rendering.

Authentication/session resolution SHALL occur server-side.

Sensitive credentials SHALL not be serialized into client component payloads.

---

# 105. React Server Components

Where a Digital Estate uses React Server Components, server components MAY call authenticated backend services through the BFF/server security context.

Tokens SHALL not be passed into client components.

---

# 106. Client Components

Client components SHOULD receive only the minimum data necessary for interaction.

For example:

```text
isAuthenticated
displayName
activeContextName
capability-derived UI hints
```

UI hints SHALL not substitute for server-side authorization.

---

# 107. Authorization-Aware UI

The UI MAY hide unavailable actions.

Example:

```text
Approve Purchase button
```

may be omitted if the current user lacks apparent authority.

However:

> Hidden UI is not authorization.

The backend SHALL enforce the operation independently.

---

# 108. Server Actions

Where framework server actions are used, they SHALL be treated as authenticated server endpoints.

They require:

- session validation;
- CSRF/origin protections as applicable;
- context resolution;
- domain authorization;
- input validation.

---

# 109. Middleware

Frontend middleware MAY enforce broad UX routing such as:

```text
anonymous → login
authenticated/no-context → context selection
```

It SHALL not become the sole enforcement point for domain authorization.

---

# 110. Edge Runtime

Authentication logic deployed to edge runtimes SHALL not assume access to secrets, cryptographic libraries, network routes or session stores unavailable in that runtime.

Security architecture SHALL determine runtime placement, not fashion.

---

# 111. Public Pages

Public pages SHALL not require authentication merely because an estate also has private functionality.

ZuriBeans public catalogue/content and authenticated buyer portal can coexist under separate cache/security boundaries.

---

# 112. Guest Journeys

Where supported, guest B2C flows SHALL remain distinct from authenticated identity.

Example:

```text
Thamani quote/tracking
```

MAY permit controlled anonymous access where domain policy permits it.

Authentication SHALL be introduced only when required.

---

# 113. Guest-to-Authenticated Transition

If guest state is attached to an authenticated identity:

```text
guest session
      │
      ▼
authentication
      │
      ▼
validated merge/claim
      │
      ▼
authenticated session
```

The merge SHALL not permit a user to claim another person's resources merely by knowing an identifier.

---

# 114. Deep Links

Authentication SHOULD preserve legitimate deep links.

Example:

```text
/order/123
    │
    ▼
login
    │
    ▼
context resolution
    │
    ▼
authorization
    │
    ▼
/order/123
```

If authorization fails, the estate SHALL show an appropriate denial rather than leaking the resource.

---

# 115. Multi-Tab Behavior

Session architecture SHOULD behave predictably across browser tabs.

Logout/revocation SHOULD eventually invalidate all tabs using the same estate session.

---

# 116. Concurrent Sessions

Baobab MAY allow multiple sessions per identity.

Privileged identities MAY have stricter limits or monitoring.

Concurrent session policy belongs to IAM security policy, not arbitrary frontend implementation.

---

# 117. Device Metadata

Device/browser metadata MAY be captured for security and session management where privacy policy permits.

It SHALL not be treated as a cryptographic identity proof.

---

# 118. Remember-Me

A "remember me" capability SHALL not simply create an unbounded session.

If implemented, it SHALL have:

- explicit lifetime;
- secure persistent cookie;
- revocation;
- risk assessment;
- appropriate refresh-token handling.

Privileged contexts MAY prohibit it.

---

# 119. High-Risk Operations

Operations such as:

```text
bank account change
supplier payment details
high-value approval
role administration
credential reset
API credential generation
```

SHOULD require recent authentication and/or step-up assurance.

---

# 120. Session Age

For high-risk operations, the system MAY require:

```text
auth_time >= threshold
```

or equivalent trusted assurance.

---

# 121. B2B Enterprise Federation

Future enterprise customers may authenticate using their corporate IdP.

Example:

```text
Employee
   │
   ▼
Microsoft Entra ID
   │
   ▼
Federation
   │
   ▼
Ory
   │
   ▼
CanonicalIdentity
   │
   ▼
Company membership
```

The estate UX SHOULD remain substantially consistent regardless of credential source.

---

# 122. Federation Does Not Bypass BFF

Federated authentication still returns to the estate's normal secure session boundary.

```text
Enterprise IdP
     │
     ▼
Ory
     │
     ▼
BFF callback
     │
     ▼
estate session
```

---

# 123. Federation Does Not Grant Company Membership

Successful authentication through Company A's IdP MAY be evidence used by onboarding policy.

It SHALL not automatically imply every possible Company A permission.

Domain membership/authority remains explicit.

---

# 124. Keycloak Migration Compatibility

During ADR-IAM-0022 migration, the estate/BFF MAY temporarily receive authentication from:

```text
Keycloak
or
Ory/Hydra
```

The browser-facing session contract SHOULD remain stable.

---

# 125. Migration Architecture

```text
                    Browser
                       │
                       ▼
                  Estate BFF
                   /      \
                  /        \
                 ▼          ▼
            Keycloak       Ory
              │             │
              └──────┬──────┘
                     ▼
             ExternalIdentity
                     │
                     ▼
             CanonicalIdentity
```

Provider migration SHALL not require redesigning the browser session contract.

---

# 126. Post-Migration Architecture

After ADR-IAM-0022 completes:

```text
Browser
   │
   ▼
Estate BFF
   │
   ▼
Ory
   │
   ▼
CanonicalIdentity
```

Keycloak-specific browser logic SHALL be removed.

---

# 127. Authentication Component Reuse

Baobab SHOULD maintain reusable frontend primitives where they provide value.

Potential examples:

```text
SignInForm
RegistrationForm
RecoveryForm
VerificationPrompt
PasskeyPrompt
MFAChallenge
ContextSelector
SessionExpiredDialog
AccessDenied
```

These MAY live in a shared UI package where appropriate.

---

# 128. Shared Components Must Remain Themeable

Shared security primitives SHALL not force:

```text
ZuriBeans branding
```

onto:

```text
Thamani
```

or vice versa.

The shared layer should own:

```text
security behavior
accessibility
state contracts
validation patterns
```

while estates own visual composition.

---

# 129. Shared Package Boundary

`baobab-platform/shared` MAY define contracts and reusable standards.

It SHALL NOT become a runtime identity service.

---

# 130. BFF Technology

This ADR does not mandate a single BFF programming language.

Each estate MAY use its natural server framework where it satisfies the security contract.

The architectural contract matters more than implementation language.

---

# 131. BFF Security Contract

Every estate BFF SHALL provide equivalent guarantees for:

```text
secure sessions
CSRF
OAuth callback
token protection
context handling
logout
revocation
observability
error handling
```

regardless of framework.

---

# 132. Secrets

BFF confidential-client credentials SHALL be held in the approved secrets system.

They SHALL NOT exist in:

```text
NEXT_PUBLIC_*
browser bundles
Git
static config files
client-side environment variables
```

---

# 133. Public Environment Variables

Only non-secret configuration MAY be exposed to the browser.

A value being called an "environment variable" does not make it secret if bundled into frontend JavaScript.

---

# 134. Logs

BFF logs SHALL NOT contain:

```text
password
access token
refresh token
authorization code
session cookie
client secret
recovery code
MFA secret
```

---

# 135. Audit

Security-significant browser/BFF operations SHOULD generate canonical or operational audit events as appropriate.

Examples:

```text
session.created
session.terminated
context.switched
step_up.required
step_up.completed
authentication.callback.failed
csrf.rejected
```

Canonical event naming SHALL follow the shared IAM event architecture.

---

# 136. Correlation

Authentication transactions SHOULD support correlation across:

```text
Browser
   │
   ▼
BFF
   │
   ▼
Ory
   │
   ▼
IAM
   │
   ▼
CP
   │
   ▼
Domain
```

without exposing sensitive identifiers unnecessarily to the browser.

---

# 137. Observability

Each estate SHOULD monitor:

```text
login starts
login success
login failure
callback failure
registration
recovery
verification
MFA challenge
passkey flows
session creation
session expiry
logout
context resolution failures
CSRF failures
OAuth refresh failures
```

---

# 138. Security Alerts

Alert candidates include:

```text
callback failure spike
CSRF rejection spike
recovery abuse
credential attack spike
unexpected redirect URI attempts
refresh-token reuse
session anomalies
provider outage
context-denial anomaly
```

---

# 139. Rate Limiting

Authentication-related BFF endpoints SHALL be appropriately rate limited.

Examples:

```text
/login
/register
/recover
/verify
/auth/callback
```

Rate limits SHALL account for distributed attacks and legitimate shared networks.

---

# 140. DoS Considerations

The BFF SHALL not create unlimited server-side session state from unauthenticated requests.

Pre-authentication state SHOULD be bounded and short-lived.

---

# 141. Session Store Failure

If the session store becomes unavailable:

```text
authenticated requests
       │
       ▼
cannot safely resolve session
       │
       ▼
FAIL CLOSED
```

unless the chosen session architecture provides an independently secure alternative.

---

# 142. Session Storage Availability

The session store is therefore production-critical for an estate using stateful BFF sessions.

It requires:

```text
HA
backup where appropriate
capacity planning
monitoring
secure connectivity
```

---

# 143. Session Data Minimization

The BFF session SHALL contain only what is needed.

Do not duplicate entire:

```text
user profile
organization graph
permission graph
ERP role graph
```

into session state.

---

# 144. Authorization Freshness

Highly dynamic authorization SHALL not rely on session creation-time snapshots.

Example:

```text
purchase authority removed at 10:00
```

must not remain effective until:

```text
session expires tomorrow
```

merely because a BFF cached it.

---

# 145. Session and Token Distinction

```text
Browser Session
      ≠
OAuth Access Token
      ≠
Kratos Session
      ≠
CanonicalIdentity
      ≠
CP Context
```

These distinctions SHALL remain visible in implementation and documentation.

---

# 146. Session Identifier Distinction

Names SHOULD avoid ambiguous generic fields such as:

```text
user_session
```

where several session types exist.

Prefer explicit concepts:

```text
estate_session_id
provider_session_reference
oauth_grant_reference
```

---

# 147. Authentication vs Authorization UX

Authentication errors:

```text
please sign in
session expired
MFA required
```

shall be distinguished from authorization errors:

```text
you do not have access to this organization
purchase approval unavailable
ERP operation forbidden
```

---

# 148. No Login Loop on 403

A `403` SHALL not automatically cause reauthentication.

The user may be perfectly authenticated but unauthorized.

---

# 149. Security Headers

Authenticated estates SHALL deploy appropriate:

```text
HSTS
CSP
X-Content-Type-Options
Referrer-Policy
frame-ancestors
Permissions-Policy
```

as applicable.

---

# 150. Referrer Leakage

Authentication URLs SHALL avoid placing sensitive information in query parameters where it may leak through:

```text
history
logs
Referer
analytics
```

Authorization codes SHALL be consumed promptly and callback URLs cleaned where appropriate.

---

# 151. HTTPS

Production authentication flows SHALL use HTTPS end-to-end.

RFC 9700 requires authorization responses to use encrypted connections except for narrowly defined native loopback exceptions.

---

# 152. Development Exceptions

Local development MAY use carefully constrained exceptions required by tooling.

Development exceptions SHALL not propagate to production configuration.

---

# 153. Codespaces

Codespaces callback URLs SHALL be explicitly managed.

The platform SHALL not introduce production wildcard callbacks simply to accommodate ephemeral development URLs.

---

# 154. Preview Deployments

Preview environments require separate OAuth clients or controlled redirect configuration.

A pull request SHALL not gain access to production OAuth credentials.

---

# 155. Environment Isolation

At minimum:

```text
development client
integration client
staging client
production client
```

SHOULD remain logically distinct.

Production cookies and sessions SHALL not be valid in development.

---

# 156. Testing Strategy

Authentication tests SHALL cover more than happy paths.

Required categories:

```text
protocol
browser
session
CSRF
XSS-resilience assumptions
context
authorization
revocation
migration
accessibility
failure
```

---

# 157. OAuth Tests

Test:

```text
authorization code
PKCE
state
nonce where applicable
redirect URI validation
wrong issuer
wrong audience
expired code
replayed code
invalid callback
logout
refresh
```

---

# 158. Cookie Tests

Verify:

```text
Secure
HttpOnly
SameSite
Path
absence of unsafe Domain
expiry
rotation
logout deletion
```

automatically where practical.

---

# 159. CSRF Tests

Test:

```text
missing token
invalid token
cross-origin POST
malicious Origin
SameSite boundary
logout CSRF
context-switch CSRF
```

---

# 160. Context Tests

Test:

```text
valid context
invalid context
context belonging to another user
revoked membership
multi-company switching
personal → business switch
business A → business B switch
```

---

# 161. Cache Isolation Tests

Test:

```text
User A response
    ✕
User B cache

Company A response
    ✕
Company B cache

Anonymous cache
    ✕
private authenticated response
```

---

# 162. Revocation Tests

At minimum:

```text
disable identity
revoke workload
remove membership
remove domain role
terminate provider session
terminate estate session
```

and verify expected propagation.

---

# 163. BFF Compromise Threat Model

A compromised BFF is high impact because it may possess:

```text
OAuth tokens
client credentials
session state
trusted backend access
```

Therefore BFF workloads SHALL receive strong:

```text
least privilege
secret isolation
network isolation
dependency security
runtime hardening
monitoring
```

---

# 164. Browser Compromise Threat Model

BFF reduces token theft from browser JavaScript but does not eliminate:

```text
XSS-driven authenticated actions
malicious extensions
device compromise
phishing
session riding
```

Defense therefore remains layered.

---

# 165. CSRF Threat Model

Because BFF authentication relies on cookies:

```text
cookie confidentiality
```

and:

```text
request authenticity
```

are separate concerns.

`HttpOnly` protects against direct JavaScript reading.

CSRF protections defend against unauthorized browser-initiated requests.

Both are required.

---

# 166. Session Theft

If an estate session cookie is stolen, the attacker may impersonate that estate session.

Mitigations include:

```text
Secure
HttpOnly
SameSite
short/bounded lifetime
session rotation
revocation
TLS
XSS prevention
risk monitoring
```

---

# 167. BFF-to-API Authentication

The BFF SHALL authenticate to downstream APIs using the appropriate OAuth/delegated identity model.

It SHALL not rely on:

```text
X-User-ID
X-Tenant-ID
```

from the browser as authoritative authentication.

---

# 168. Trusted Headers

The gateway/BFF MAY generate internal headers for routing/observability.

Such headers SHALL not substitute for cryptographically verifiable identity and CP context unless an explicitly trusted internal protocol defines them.

---

# 169. API Gateway

Conceptually:

```text
Browser
   │
   ▼
Estate BFF
   │
   ▼
APISIX
   │
   ▼
Baobab APIs
```

The gateway may validate infrastructure-level requirements.

It SHALL not infer business authorization.

---

# 170. Service-to-Service Boundary

Once a request leaves the browser/BFF boundary, ADR-IAM-0007 workload/delegation rules apply.

The BFF is itself a workload.

---

# 171. Actor Preservation

Where the BFF performs an operation on behalf of a human:

```text
human subject
+
BFF actor
```

SHOULD remain distinguishable where the downstream authorization/audit architecture requires it.

---

# 172. Delegated Audit

Audit SHOULD be able to answer:

```text
Who initiated the operation?
Which BFF acted?
Which CanonicalIdentity was represented?
Which Context was active?
Which domain authorized it?
```

---

# 173. API Responses

Sensitive APIs SHOULD return only data needed by the estate.

The BFF MAY adapt internal domain models into browser-safe response models.

---

# 174. BFF Data Validation

The BFF SHALL validate browser input.

Domain services SHALL independently validate domain invariants.

BFF validation improves UX/security but is not the final domain boundary.

---

# 175. File Uploads

Authenticated file-upload flows SHALL preserve:

```text
session authentication
context authorization
file size/type policy
malware/security scanning where required
domain ownership
```

Signed upload URLs SHALL be short-lived and narrowly scoped.

---

# 176. WebSockets and Streaming

Authenticated WebSockets/SSE SHALL use an explicit session/authentication design.

Do not place long-lived bearer tokens in URLs.

Context and revocation semantics SHALL remain defined for long-lived connections.

---

# 177. Mobile and Native Apps

This ADR primarily governs browser-based Digital Estates.

Native mobile applications MAY require a different OAuth architecture.

They SHALL use appropriate public-client patterns such as Authorization Code + PKCE and secure OS facilities.

They SHALL NOT imitate BFF cookies blindly.

---

# 178. Third-Party API Clients

Third-party machine/API integrations are outside the browser session boundary.

They SHALL use workload/client OAuth architecture rather than browser sessions.

---

# 179. Progressive Enhancement

Core authentication flows SHOULD remain robust under realistic browser conditions.

Security-critical state SHALL not depend entirely on fragile client-side JavaScript state.

---

# 180. User Experience Principle

Authentication should feel like part of the Digital Estate, not an unrelated infrastructure console.

But visual integration SHALL not obscure important security transitions.

Users SHOULD understand when they are:

```text
signing in
switching company
approving a sensitive operation
recovering identity
enrolling MFA/passkey
logging out
```

---

# 181. ZuriBeans Example

```text
Buyer visits ZuriBeans
       │
       ▼
Browse public catalogue
       │
       ▼
Sign in
       │
       ▼
ZuriBeans authentication UX
       │
       ▼
Ory authentication
       │
       ▼
ZuriBeans BFF session
       │
       ▼
CP resolves buyer contexts
       │
       ▼
ACME Uganda
ACME South Africa
       │
       ▼
Buyer selects ACME Uganda
       │
       ▼
Trade validates commercial authority
```

---

# 182. Thamani B2C Example

```text
Jane
 │
 ▼
Thamani
 │
 ▼
Sign in
 │
 ▼
Ory
 │
 ▼
Thamani BFF
 │
 ▼
CanonicalIdentity
 │
 ▼
Personal customer context
 │
 ▼
Create/track shipment
```

---

# 183. Thamani B2B Example

```text
Jane
 │
 ▼
same Ory identity
 │
 ▼
same CanonicalIdentity
 │
 ▼
CP contexts
 ├── Personal
 ├── Company A
 └── Company B
 │
 ▼
Jane selects Company A
 │
 ▼
Thamani domain
 │
 ▼
Logistics Manager authority
```

No second identity is required.

---

# 184. Step-Up Example

```text
Jane requests:
Change company payment details
        │
        ▼
domain requires recent strong auth
        │
        ▼
STEP_UP_REQUIRED
        │
        ▼
BFF → Ory
        │
        ▼
passkey/MFA
        │
        ▼
assurance updated
        │
        ▼
domain authorization checked again
        │
        ▼
operation allowed/denied
```

---

# 185. Security Boundary Diagram

```text
┌──────────────────────────────────────────────────────────────┐
│                       UNTRUSTED BROWSER                      │
│                                                              │
│  UI                                                          │
│  └── opaque HttpOnly session cookie                          │
│                                                              │
└──────────────────────────────┬───────────────────────────────┘
                               │ HTTPS
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    DIGITAL ESTATE BFF                        │
│                                                              │
│  session validation                                          │
│  CSRF                                                        │
│  OAuth callback                                              │
│  token protection                                            │
│  context mediation                                           │
│  browser-safe API                                            │
│                                                              │
│  NOT canonical identity authority                            │
│  NOT platform authorization authority                        │
│  NOT domain authorization authority                          │
└──────────────┬──────────────────────────┬────────────────────┘
               │                          │
               ▼                          ▼
       ┌───────────────┐           ┌──────────────┐
       │ Ory           │           │ baobab-cp    │
       │               │           │              │
       │ Kratos        │           │ identity     │
       │ Hydra         │           │ context      │
       └───────────────┘           └──────┬───────┘
                                         │
                              ┌──────────┼──────────┐
                              ▼          ▼          ▼
                            Trade       ERP        CMS
                              │          │          │
                              └──── domain authz ───┘
```

---

# 186. Provider-Neutrality

The estate security architecture SHALL survive another standards-compatible provider migration.

Desired:

```text
Estate UX
   │
Estate BFF
   │
OIDC/OAuth + Baobab contracts
   │
Provider
```

not:

```text
Estate components
   │
hundreds of Ory-specific assumptions
```

---

# 187. Appropriate Ory Coupling

Provider-specific behavior is appropriate inside:

```text
baobab-iam provider adapter
Ory deployment/configuration
Kratos flow integration boundary
migration tooling
```

It should not spread unnecessarily into domain UI and business services.

---

# 188. Implementation Gates

Implementation SHOULD proceed through the following gates.

## IAM-W0 — Existing Estate Audit

Audit each estate for:

```text
token storage
cookies
OAuth libraries
auth middleware
login routes
logout
callback routes
session management
Keycloak coupling
context handling
authorization checks
```

No replacement before discovery.

---

## IAM-W1 — Browser Security Contract

Define canonical:

```text
session semantics
cookie policy
CSRF policy
OAuth callback contract
error model
context model
```

in shared documentation/contracts.

---

## IAM-W2 — BFF Foundation

Implement estate BFF security foundation.

Verify:

```text
server-side token handling
opaque sessions
secure cookies
CSRF
logout
```

---

## IAM-W3 — Ory Authentication UX

Implement:

```text
login
registration
verification
recovery
```

against Ory.

---

## IAM-W4 — MFA and Passkeys

Implement provider-backed:

```text
MFA
passkey enrolment
step-up
```

with estate-owned UX.

---

## IAM-W5 — CP Context Integration

Implement:

```text
CanonicalIdentity resolution
context discovery
context selection
context switching
```

---

## IAM-W6 — ZuriBeans B2B Integration

Verify:

```text
buyer account
buyer membership
multi-company
purchase authority
RFQ/order access
```

---

## IAM-W7 — Thamani B2C Integration

Verify:

```text
personal customer
shipping journey
tracking
account
history
```

---

## IAM-W8 — Thamani B2B Integration

Verify:

```text
business accounts
representatives
context switching
approvals
finance/logistics roles
```

---

## IAM-W9 — Supplier UX

Verify:

```text
supplier registration
representative identity
application lifecycle
approval separation
```

---

## IAM-W10 — Security Hardening

Execute:

```text
CSRF tests
XSS review
CSP
cookie tests
redirect tests
session fixation tests
cache isolation tests
revocation tests
```

---

## IAM-W11 — Keycloak Migration Compatibility

Ensure ADR-IAM-0022 dual-provider migration does not break the estate session contract.

---

## IAM-W12 — Provider-Neutrality Cleanup

Remove inappropriate:

```text
KEYCLOAK_*
ORY_* from generic estate layers
provider role assumptions
provider identity IDs
```

---

# 189. Required Automated Security Tests

At minimum:

```text
cookie Secure
cookie HttpOnly
cookie SameSite
no unsafe Domain
CSRF rejection
invalid Origin rejection
OAuth state mismatch
PKCE failure
wrong redirect
wrong issuer
wrong audience
expired token
revoked identity
invalid context
cross-organization access
session fixation
logout invalidation
cache isolation
```

---

# 190. Production Checklist

### Authentication UX

- [ ] Estate owns presentation
- [ ] Ory owns credential mechanics
- [ ] no duplicate credential implementation
- [ ] errors resist enumeration
- [ ] accessibility verified

### Browser Session

- [ ] opaque session identifier
- [ ] `Secure`
- [ ] `HttpOnly`
- [ ] appropriate `SameSite`
- [ ] no unsafe `Domain`
- [ ] session rotation after authentication
- [ ] idle/absolute expiry defined
- [ ] logout invalidates session

### OAuth

- [ ] Authorization Code flow
- [ ] PKCE
- [ ] state validation
- [ ] nonce where applicable
- [ ] exact redirect URI
- [ ] no Implicit Grant
- [ ] no ROPC
- [ ] confidential secrets server-side

### Tokens

- [ ] access tokens server-side
- [ ] refresh tokens server-side
- [ ] no tokens in `localStorage`
- [ ] no tokens in `sessionStorage`
- [ ] audiences constrained
- [ ] refresh/revocation tested

### CSRF

- [ ] mutation endpoints protected
- [ ] Origin policy verified
- [ ] logout protected
- [ ] context switching protected
- [ ] SameSite treated as defense in depth

### Context

- [ ] browser context is a request, not authority
- [ ] CP validates context
- [ ] multi-context tested
- [ ] cross-company denial tested
- [ ] cache isolation tested

### Authorization

- [ ] BFF not authoritative
- [ ] backend authorization enforced
- [ ] UI hiding not treated as authorization
- [ ] step-up separate from permission
- [ ] 401/403 semantics correct

### Operations

- [ ] logs exclude secrets
- [ ] metrics implemented
- [ ] alerts configured
- [ ] BFF HA configured
- [ ] session-store failure tested
- [ ] Ory outage tested
- [ ] CP outage tested

### Migration

- [ ] Keycloak/Ory coexistence tested
- [ ] estate session contract provider-neutral
- [ ] Keycloak-specific UI coupling identified
- [ ] post-migration cleanup planned

---

# 191. Architectural Invariants

The following SHALL remain true:

```text
Estate UI ≠ Identity Provider

BFF ≠ Identity Provider

BFF ≠ Control Plane

BFF ≠ API Gateway

BFF ≠ Domain Authorization

Browser Session ≠ OAuth Token

Browser Session ≠ Kratos Session

Kratos Session ≠ CanonicalIdentity

CanonicalIdentity ≠ Context

Authentication ≠ Authorization

MFA Success ≠ Business Permission

Context Selection ≠ Context Authority

UI Role Hint ≠ Authorization

Hidden Button ≠ Authorization

Ory Identity ≠ Tenant

Ory Identity ≠ Buyer Organization

Ory Identity ≠ Supplier Organization

Estate Cookie ≠ Cross-Platform Identity

One CanonicalIdentity ≠ One Browser Session
```

---

# 192. Final Target Architecture

```text
                          USER
                           │
                           ▼
                ┌────────────────────┐
                │     Browser        │
                │                    │
                │ Estate UX          │
                │ opaque session     │
                └─────────┬──────────┘
                          │ HTTPS
                          ▼
                ┌────────────────────┐
                │   Estate BFF       │
                │                    │
                │ session            │
                │ CSRF               │
                │ OAuth callback     │
                │ token protection   │
                │ context mediation  │
                └─────┬────────┬─────┘
                      │        │
              OAuth   │        │ identity/context
                      ▼        ▼
             ┌────────────┐ ┌─────────────────┐
             │    Ory     │ │   baobab-cp     │
             │            │ │                 │
             │ Kratos     │ │ CanonicalID     │
             │ Hydra      │ │ Context         │
             └────────────┘ │ Capability      │
                            └────────┬────────┘
                                     │
                         authenticated/contextual
                                     │
                   ┌─────────────────┼─────────────────┐
                   ▼                 ▼                 ▼
                Trade              ERP                CMS
                   │                 │                 │
                   └────── domain authorization ──────┘
```

---

# 193. Consequences

## Positive

Baobab gains:

- full control over Digital Estate authentication UX;
- reduced exposure of OAuth tokens to browser JavaScript;
- consistent browser security architecture;
- estate-specific branding without duplicating IAM mechanics;
- clear B2B/B2C context switching;
- cleaner Ory adoption;
- provider-neutral application boundaries;
- stronger isolation between Digital Estates;
- clearer session, identity, context and authorization semantics;
- an architecture aligned with current browser OAuth security guidance.

## Costs

Baobab must now maintain:

- BFF session infrastructure;
- CSRF defenses;
- secure callback handling;
- estate authentication components;
- server-side token lifecycle;
- context integration;
- additional security tests;
- session-store operational infrastructure where stateful sessions are used.

These are deliberate product/security responsibilities rather than accidental frontend code.

## Risks

Poor BFF implementation could create a high-value attack surface.

Mitigation is:

```text
shared security contract
+
minimal BFF responsibility
+
provider-neutral integration
+
automated security tests
+
least privilege
+
observability
+
independent domain authorization
```

---

# 194. Final Decision Principle

Baobab SHALL use Ory to provide identity and authentication capabilities **without surrendering Digital Estate experience to the identity provider and without pushing OAuth credential management into browser JavaScript**.

The intended separation is:

```text
Digital Estate
    owns
    EXPERIENCE

BFF
    owns
    BROWSER SECURITY BOUNDARY

Ory
    owns
    AUTHENTICATION MECHANICS + OAUTH/OIDC

Baobab IAM
    owns
    PROVIDER INTEGRATION + LIFECYCLE NORMALIZATION

Control Plane
    owns
    CANONICAL IDENTITY + PLATFORM CONTEXT

Domain Engine
    owns
    BUSINESS AUTHORIZATION
```

This preserves the central provider-neutral architecture introduced by ADR-IAM-0020.

Ory is therefore intentionally **behind** Baobab's identity and UX boundaries rather than embedded throughout them.

The browser sees the Digital Estate.

The Digital Estate sees Baobab's authentication contract.

The provider supplies identity mechanics.

The Control Plane supplies canonical meaning and context.

The domain determines what the actor may actually do.

> **Own the experience. Protect the browser. Hide the tokens. Preserve the identity boundary. Keep authorization where it belongs.**