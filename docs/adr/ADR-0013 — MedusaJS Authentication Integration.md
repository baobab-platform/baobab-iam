# ADR-0013: MedusaJS Authentication Integration

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-trade`  
**Primary Runtime Owners:** `baobab-platform/baobab-trade`, `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** MedusaJS v2 authentication integration, Keycloak OIDC provider, customer and admin actor types, AuthIdentity mapping, callback handling, JIT provisioning, sessions, bearer-token validation, guest compatibility, workforce SSO, credential migration, account linking, logout, revocation and Medusa extension boundaries  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:**  
- ADR-0001 — Baobab Identity and Access Management Architecture  
- ADR-0002 — Keycloak as the Baobab Identity Provider  
- ADR-0003 — Identity Authority and Trust Boundaries  
- ADR-0004 — Canonical Identity and External Identity Mapping  
- ADR-0005 — Realm, Organization, Tenant and Legal-Entity Model  
- ADR-0006 — OIDC, OAuth and Token Profile  
- ADR-0007 — Workload Identity and Service-to-Service Authentication  
- ADR-0008 — Platform Authorization Architecture  
- ADR-0009 — Workforce SSO and Privileged Access  
- ADR-0010 — Zuribeans B2B Identity and Organization Access  
- ADR-0011 — Thamani B2C Customer Identity  
- ADR-0012 — Supplier Identity and Representative Access  

---

# 1. Context

Baobab Trade runs MedusaJS v2.

Medusa owns important commerce-domain actors including:

```text
customer
user
```

and can additionally support custom actor types.

Baobab, however, has established Keycloak through `baobab-iam` as the platform credential authority.

The architecture must therefore reconcile:

```text
Baobab Identity
       │
       ▼
Keycloak / OIDC

with

Medusa Authentication
       │
       ▼
Auth Module / AuthIdentity / Actor
```

without:

- forking Medusa;
- duplicating passwords;
- creating separate admin credentials;
- making Medusa the canonical identity authority;
- bypassing Medusa route authentication;
- allowing customer identities to become admin users;
- treating OIDC authentication as commerce authorization.

---

# 2. Decision

Baobab SHALL integrate Baobab IAM into Medusa using Medusa's supported Auth Module provider mechanism.

A dedicated provider SHALL authenticate Baobab OIDC identities and bind them to appropriate Medusa actors.

Conceptually:

```text
                    BAOBAB IAM
                     Keycloak
                        │
                       OIDC
                        │
                        ▼
              Medusa Baobab OIDC
                 Auth Provider
                        │
                 ┌──────┴──────┐
                 ▼             ▼
              customer        user
                actor          actor
```

No Medusa core fork SHALL be required.

---

# 3. Governing Principle

> **Keycloak authenticates Baobab identities; the Medusa Auth Module adapts those identities into Medusa actors; Medusa remains authoritative for commerce authorization.**

---

# 4. Medusa Auth Module as Integration Boundary

Medusa's Auth Module SHALL be the supported integration boundary.

The Baobab provider SHOULD extend or implement the relevant Medusa authentication-provider interfaces rather than modifying:

```text
@medusajs/medusa
```

core internals.

---

# 5. Provider Identifier

The custom authentication provider SHOULD use a stable identifier such as:

```text
baobab-oidc
```

or another explicitly versioned name.

The identifier SHALL be treated as configuration, not as canonical identity.

---

# 6. Provider Responsibilities

The Baobab OIDC provider SHALL be responsible for:

- initiating or completing the OIDC authentication interaction where appropriate;
- validating expected authentication responses;
- resolving `issuer + subject`;
- establishing or locating a Medusa `AuthIdentity`;
- binding that auth identity to the appropriate Medusa actor;
- returning Medusa-compatible authentication outcomes;
- propagating safe identity metadata needed by Baobab integrations.

It SHALL NOT:

- determine customer order ownership;
- grant buyer purchasing authority;
- approve suppliers;
- assign ERP roles;
- determine tenant context independently.

---

# 7. Provider Shall Not Store Passwords

The Baobab OIDC provider SHALL NOT store or validate Baobab customer/admin passwords.

Credentials remain in:

```text
baobab-iam
```

---

# 8. Medusa Actor Model

The integration SHALL preserve Medusa's distinction between authentication identity and actor.

Conceptually:

```text
AuthIdentity
    │
    ▼
app_metadata
    │
    ▼
customer_id
```

or:

```text
AuthIdentity
    │
    ▼
app_metadata
    │
    ▼
user_id
```

depending on actor type.

---

# 9. Customer Actor

Thamani B2C customers SHALL use:

```text
actor_type = customer
```

within Medusa.

The Baobab OIDC provider SHALL map the authenticated Baobab identity to the corresponding Medusa Customer actor.

---

# 10. Admin Actor

Trade administrative users SHALL use:

```text
actor_type = user
```

unless a future custom administrative actor is intentionally introduced.

These users SHALL authenticate through Baobab workforce SSO.

---

# 11. Customer and Admin Separation

The same OIDC provider MAY technically serve multiple actor types, but Baobab SHALL configure actor access explicitly.

For example:

```text
customer:
  - baobab-oidc

user:
  - baobab-oidc
```

only where both are intentionally enabled.

---

# 12. `authMethodsPerActor`

Medusa's:

```text
http.authMethodsPerActor
```

SHALL be configured explicitly in production.

Baobab SHALL NOT rely on Medusa's broad provider availability defaults for security-sensitive actors.

---

# 13. Recommended Initial Configuration

Conceptually:

```typescript
authMethodsPerActor: {
  customer: ["baobab-oidc"],
  user: ["baobab-oidc"]
}
```

for a fully migrated environment.

During migration, a temporary configuration MAY retain another provider for selected actor classes.

---

# 14. Migration Configuration

During credential migration, a temporary state MAY look like:

```typescript
authMethodsPerActor: {
  customer: ["baobab-oidc", "emailpass"],
  user: ["baobab-oidc"]
}
```

if customer migration requires a limited coexistence period.

This SHALL be transitional, documented and time-bounded.

---

# 15. Admin Email/Password

Medusa-local `emailpass` authentication SHOULD NOT remain the normal administrative login once Baobab workforce SSO is production-ready.

Administrative authentication SHALL converge on:

```text
Baobab IAM
```

---

# 16. Customer Email/Password

Thamani customer passwords SHOULD likewise migrate to Baobab IAM.

Medusa SHALL not remain a second authoritative customer password database.

---

# 17. OIDC Flow

Browser-facing authentication SHALL use:

```text
Authorization Code
+
PKCE
```

according to ADR-0006.

The Baobab/Medusa integration SHALL not introduce:

- implicit flow;
- resource-owner password credentials;
- credentials passed through Medusa merely to be forwarded to Keycloak.

---

# 18. Thamani Login Flow

Target:

```text
Customer
   │
   ▼
Thamani
   │
   ▼
Baobab IAM
   │
 Authorization Code + PKCE
   │
   ▼
Thamani/BFF
   │
   ▼
Medusa Baobab OIDC integration
   │
   ▼
customer actor
```

---

# 19. Admin Login Flow

Target:

```text
Trade Administrator
       │
       ▼
Medusa Admin
       │
       ▼
Baobab IAM
       │
       ▼
MFA / workforce SSO
       │
       ▼
Medusa Baobab OIDC Provider
       │
       ▼
Medusa User actor
       │
       ▼
Medusa domain authorization
```

---

# 20. Separate OIDC Clients

Customer-facing and administrative login SHOULD use distinct Keycloak clients.

Example:

```text
thamani-web
baobab-trade-admin
```

This permits different:

- redirect URIs;
- assurance requirements;
- session policies;
- audiences;
- MFA policy.

---

# 21. Redirect URIs

OIDC redirect URIs SHALL be explicitly configured and exact.

Wildcard redirect URIs SHOULD be avoided in production except where narrowly justified by framework constraints.

---

# 22. State

Authorization flows SHALL use:

```text
state
```

to bind the authentication response to the initiating browser transaction.

---

# 23. Nonce

OIDC flows using ID Tokens SHALL use:

```text
nonce
```

where required by the chosen integration pattern.

---

# 24. PKCE

Public browser clients SHALL require:

```text
S256
```

PKCE.

The integration SHALL NOT support downgrade to plain PKCE in production.

---

# 25. Callback Security

OIDC callback processing SHALL validate:

- expected state;
- expected authorization response;
- token endpoint result;
- issuer;
- audience/client;
- expiration;
- nonce where applicable;
- allowed algorithm.

---

# 26. No Callback Identity From Query Parameters

This SHALL be prohibited:

```text
?email=user@example.com
&customer_id=cus_123
```

as identity authority.

Identity SHALL come from validated OIDC evidence.

---

# 27. External Identity Key

The stable external identity key SHALL be:

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

# 28. Canonical Resolution

On successful authentication:

```text
iss + sub
    │
    ▼
ExternalIdentity
    │
    ▼
CanonicalIdentity
```

SHALL be resolved through the Baobab identity architecture.

---

# 29. Medusa AuthIdentity

Medusa's `AuthIdentity` SHALL represent the Medusa-side authentication-provider identity.

Conceptually:

```text
Medusa AuthIdentity
provider = baobab-oidc
provider_identity = stable external reference
```

Exact Medusa storage mechanics SHALL follow supported APIs.

---

# 30. AuthIdentity Is Not Canonical Identity

This invariant SHALL remain:

```text
Medusa AuthIdentity ≠ CanonicalIdentity
```

It is a Medusa authentication adapter record.

---

# 31. Actor Binding

The Medusa AuthIdentity SHALL be linked to its actor using Medusa's supported actor metadata.

For example:

```text
app_metadata.customer_id
```

or:

```text
app_metadata.user_id
```

rather than inventing unsupported joins.

---

# 32. Customer JIT Provisioning

For Thamani:

```text
OIDC identity authenticated
       │
       ▼
CanonicalIdentity resolved
       │
       ▼
Medusa customer mapping?
    ┌──┴───┐
   YES     NO
    │       │
    │       ▼
    │    create customer
    │       │
    │    bind AuthIdentity
    └───────┤
            ▼
      authenticated actor
```

Controlled JIT provisioning MAY therefore be used.

---

# 33. Admin JIT Provisioning

Administrative JIT provisioning SHALL be more restrictive.

A successfully authenticated workforce identity SHALL NOT automatically become a Medusa admin user.

Admin provisioning SHALL require explicit authorization.

---

# 34. Admin Provisioning Requirement

Before creating or binding:

```text
Medusa user
```

the integration SHALL verify appropriate workforce/domain entitlement.

Conceptually:

```text
IAM authenticated
       │
       ▼
CP workforce context valid
       │
       ▼
Trade admin entitlement exists
       │
       ▼
Medusa User mapping
```

---

# 35. No Login-Equals-Admin

This SHALL be prohibited:

```text
valid Keycloak identity
      =
Medusa admin
```

---

# 36. JIT Idempotency

Customer and approved admin provisioning SHALL be idempotent.

Repeated callbacks SHALL not create duplicate actors.

---

# 37. Mapping Uniqueness

At minimum, mappings SHOULD enforce:

```text
one Medusa actor
per canonical identity
per actor type
per relevant engine context
```

unless explicit requirements dictate otherwise.

---

# 38. Concurrent First Login

The implementation SHALL handle concurrent authentication attempts without creating duplicate:

- AuthIdentity records;
- Customer actors;
- User actors;
- canonical mappings.

---

# 39. Transaction Boundaries

Where Medusa actor creation and AuthIdentity binding require multiple operations, the implementation SHOULD use Medusa workflows/transactional primitives to obtain consistent failure behavior.

---

# 40. Mapping Failure

If:

```text
OIDC authentication succeeds
```

but:

```text
actor mapping fails
```

the system SHALL fail authentication into the commerce actor safely.

It SHALL NOT fall back to an arbitrary actor.

---

# 41. Orphan Detection

Operational tooling SHOULD detect:

```text
AuthIdentity without actor
actor expected to have Baobab identity but unmapped
duplicate identity mappings
```

for repair.

---

# 42. Medusa Token Boundary

If Medusa issues its own bearer/session token after provider authentication, that token SHALL represent a Medusa application session/actor.

It SHALL NOT become the canonical Baobab identity token for unrelated services.

---

# 43. Keycloak Token ≠ Medusa Token

This invariant SHALL be explicit:

```text
Keycloak Access Token
        ≠
Medusa Application Token
```

where both exist in the chosen integration.

---

# 44. Token Translation Boundary

Any conversion from an OIDC-authenticated user into a Medusa bearer/session token SHALL happen only through the trusted authentication-provider integration.

Clients SHALL not construct Medusa tokens themselves.

---

# 45. Token Audience

A Keycloak token intended for:

```text
baobab-control-plane
```

SHALL NOT be accepted as a Medusa Trade token simply because its signature is valid.

Audience validation remains mandatory.

---

# 46. Local Medusa Validation

Medusa SHALL independently validate any Baobab access token it accepts directly.

Gateway validation SHALL remain defense-in-depth only.

---

# 47. Supported Session Modes

Baobab MAY use:

```text
Medusa bearer authentication
```

or:

```text
Medusa session authentication
```

depending on frontend architecture.

The selected mode SHALL be documented per client.

---

# 48. Thamani BFF Preference

Where Thamani uses a Backend-for-Frontend, the BFF SHOULD keep sensitive OIDC credentials/tokens server-side and use secure session cookies toward the browser.

---

# 49. Cookie Security

Where cookies are used, production configuration SHALL include appropriate:

```text
Secure
HttpOnly
SameSite
```

settings according to the deployment topology.

---

# 50. CSRF

Cookie-authenticated mutation endpoints SHALL receive explicit CSRF protection.

CORS SHALL NOT be treated as CSRF protection.

---

# 51. CORS

Medusa CORS configuration SHALL be explicit per deployment environment.

Production SHALL not use unrestricted origins merely to simplify OIDC integration.

---

# 52. Guest Compatibility

The OIDC integration SHALL preserve Medusa guest commerce.

Anonymous customers SHALL be able to:

- browse;
- maintain permitted cart state;
- use guest checkout where enabled.

No IAM identity SHALL be required simply to interact anonymously with Trade.

---

# 53. Guest-to-Authenticated Transition

After login:

```text
Guest Cart
   │
   ▼
Authenticated Customer
```

Trade MAY attach or merge eligible cart state according to commerce policy.

This operation SHALL occur after secure actor resolution.

---

# 54. Guest Order Claim

Medusa authentication integration SHALL not attach historical guest orders to an actor based solely on email equality.

ADR-0011 remains authoritative.

---

# 55. Customer Registration

Where Medusa's authentication provider registration route is involved, Baobab SHALL ensure registration results in:

```text
Baobab IAM identity
+
CanonicalIdentity
+
Medusa actor mapping
```

rather than a parallel Medusa password identity.

---

# 56. Provider Redirect Flow

Where the Medusa provider advertises a redirect-style flow, frontend clients MAY discover the provider through Medusa's provider-list APIs and redirect accordingly.

This enables Thamani/Admin UI to avoid hard-coding provider behavior.

---

# 57. Provider Discovery

The frontend MAY obtain configured authentication providers by actor type.

It SHALL not display providers disabled for that actor.

---

# 58. Admin UI

Medusa Admin customization MAY be used to present:

```text
Continue with Baobab
```

or equivalent SSO UX.

The admin frontend SHALL NOT need to collect the administrator's Keycloak password directly.

---

# 59. Authentication Provider Restrictions

Baobab SHALL explicitly restrict provider availability per actor type.

Example transitional matrix:

| Actor | Baobab OIDC | EmailPass |
|---|---:|---:|
| customer | Yes | Temporary migration only |
| user/admin | Yes | No, except controlled emergency transition |
| custom supplier actor | If adopted | No |

---

# 60. Custom Actor Types

Medusa supports custom actor types.

Baobab MAY introduce them if Trade-native requirements justify actors such as:

```text
buyer_representative
supplier_representative
```

However, custom actors SHALL only be introduced when they improve domain correctness.

---

# 61. Do Not Duplicate Domain Membership Into Actor Types

Baobab SHALL avoid creating custom actor types merely to encode every role.

For example:

```text
buyer_approver
buyer_viewer
buyer_admin
```

SHOULD normally be domain roles/memberships, not separate authentication actor types.

---

# 62. Authentication Actor ≠ Authorization Role

This invariant SHALL remain:

```text
actor_type
   ≠
domain authorization role
```

---

# 63. Zuribeans Integration

For Zuribeans, the authenticated Medusa actor SHALL still be subject to:

```text
buyer organization membership
procurement role
resource ownership
commercial policy
```

Authentication alone SHALL not grant B2B purchasing authority.

---

# 64. Thamani Integration

For Thamani:

```text
customer actor
```

SHALL govern commerce identity.

Trade SHALL still validate order/address/cart ownership.

---

# 65. Supplier Integration

Supplier authentication SHOULD remain aligned with ADR-0012.

If Trade requires a Medusa actor for supplier-facing functionality, that actor SHALL map explicitly to the Canonical Identity and supplier membership.

---

# 66. Admin Authorization

Medusa administrative authorization remains a Trade/workforce concern.

The Baobab OIDC provider SHALL authenticate administrators but SHALL not treat Keycloak roles as the complete Trade authorization graph.

---

# 67. Role Mapping

Only coarse, intentional workforce claims MAY be used during Medusa admin bootstrap or entry checks.

Fine-grained Trade permissions SHOULD remain in Trade.

---

# 68. Do Not Mirror Every Trade Permission Into Keycloak

The following pattern SHALL be avoided:

```text
Keycloak:
trade_order_refund
trade_product_publish
trade_inventory_override
trade_price_modify
...
```

where Trade itself owns the permission model.

---

# 69. Account Linking

Medusa supports multiple AuthIdentity records linked to one actor.

Baobab MAY exploit this capability for approved multiple-provider authentication.

However canonical account linking SHALL be governed by ADR-0004.

---

# 70. Linking Flow

Conceptually:

```text
Existing Medusa Customer
        │
        ▼
existing Baobab identity
        │
        ▼
new external IdP securely linked
        │
        ▼
new AuthIdentity
        │
        ▼
same customer_id
```

---

# 71. No Automatic Same-Email Actor Linking

A new provider identity SHALL not be attached to an existing customer simply because:

```text
email matches
```

Additional proof is required.

---

# 72. Provider Unlinking

Removing an authentication provider SHALL not delete the underlying Medusa actor if another valid authentication method remains.

---

# 73. Prevent Lockout

Provider unlinking SHALL verify that the user will retain an approved authentication path unless the account is intentionally disabled.

---

# 74. Customer Credential Migration

If existing Medusa customers use EmailPass credentials, migration SHALL preserve their commerce actor and order history.

Target:

```text
existing Medusa Customer
        │
        ▼
Baobab IAM identity established
        │
        ▼
Baobab AuthIdentity linked
        │
        ▼
legacy EmailPass retired
```

The Customer ID SHOULD remain unchanged where practical.

---

# 75. Password Migration

Baobab SHALL NOT export plaintext Medusa passwords.

Where secure password-hash migration into Keycloak is unsupported or undesirable, users SHOULD complete:

```text
password reset / account activation
```

through Baobab IAM.

---

# 76. Admin Credential Migration

Existing Medusa admin users SHALL be mapped to workforce identities.

Migration SHALL verify:

- the human identity;
- current employment/authorization;
- expected Trade admin role;
- existing Medusa User mapping.

Legacy credentials SHOULD then be disabled.

---

# 77. Migration Safety

The system SHALL avoid:

```text
existing admin email matches Keycloak email
      │
      ▼
auto-link
```

without verified identity ownership.

---

# 78. Migration Audit

Migration records SHOULD capture:

```text
legacy actor
canonical identity
new provider identity
migration state
verified by
timestamp
```

without retaining obsolete secrets.

---

# 79. Migration States

A useful migration state model MAY include:

```text
UNMIGRATED
INVITED
LINKED
VERIFIED
LEGACY_AUTH_DISABLED
COMPLETE
```

---

# 80. Dual-Auth Window

If temporary dual authentication is required, it SHALL be:

- explicitly approved;
- observable;
- time-bounded;
- removable through configuration.

---

# 81. Legacy Credential Retirement

Migration SHALL not be considered complete while dormant Medusa passwords remain usable indefinitely.

---

# 82. Logout

Logout has potentially two layers:

```text
Medusa session
+
Baobab IAM session
```

Applications SHALL define whether logout is:

- local application logout;
- global IAM logout.

---

# 83. Local Logout

Local logout SHALL invalidate or remove the Medusa/browser application session.

It MAY leave another Baobab SSO session active according to UX policy.

---

# 84. Global Logout

Security-sensitive flows SHALL support terminating the corresponding Keycloak session where required.

---

# 85. Account Disablement

If a Canonical Identity or Keycloak identity is disabled:

```text
new Medusa authentication
```

SHALL fail.

Previously issued application sessions SHALL expire or be revoked according to defined revocation policy.

---

# 86. Customer Domain Suspension

A Trade customer MAY be suspended while IAM remains active.

In that case:

```text
authentication succeeds
commerce action denied
```

as required by ADR-0008.

---

# 87. Admin Role Revocation

If a Trade admin role is removed while the Keycloak session remains valid:

```text
authentication
```

may remain valid, but:

```text
administrative authorization
```

SHALL fail.

---

# 88. Session Revocation

Baobab SHALL document revocation behavior for:

- Keycloak user disabled;
- Keycloak session revoked;
- external identity unlinked;
- Medusa actor suspended;
- Medusa admin permission revoked.

---

# 89. Short-Lived Credentials

Any Baobab bearer token accepted directly by Medusa SHALL remain short-lived in accordance with ADR-0006.

---

# 90. No Permanent Customer API Tokens

Medusa customer access SHALL not be implemented using manually issued permanent API tokens.

---

# 91. Publishable API Keys

Medusa publishable API keys, where used for storefront/channel access, SHALL NOT be confused with authenticated customer identity.

They are distinct security mechanisms.

---

# 92. API Key ≠ User Authentication

This invariant SHALL be explicit:

```text
Medusa publishable API key
      ≠
customer identity
```

---

# 93. Admin API Keys

Administrative or secret API credentials SHALL be separately governed from human SSO.

They SHALL follow workload credential policies where machine-to-machine access is intended.

---

# 94. Service-to-Service Calls

Trade integrations calling CP, ERP, CMS or other services SHALL use workload identity under ADR-0007.

They SHALL NOT reuse a Medusa customer's session as service identity.

---

# 95. On-Behalf-Of Calls

Where a downstream action must preserve human provenance:

```text
human subject
+
Trade service actor
```

SHALL remain distinguishable.

ADR-0007 delegation rules apply.

---

# 96. Middleware

Medusa protected routes SHALL continue using supported authentication middleware or equivalent framework-supported controls.

Custom Baobab routes SHALL not bypass actor-type checks.

---

# 97. Customer Route Protection

Customer-specific routes SHALL require:

```text
actor_type = customer
```

or an explicitly designed equivalent.

---

# 98. Admin Route Protection

Admin routes SHALL require:

```text
actor_type = user
```

or another explicitly approved administrative actor.

---

# 99. Actor Confusion Protection

A token/session for:

```text
customer
```

SHALL not authorize:

```text
user/admin
```

routes.

---

# 100. Provider Confusion Protection

Authentication code SHALL explicitly identify:

```text
actor type
provider
```

rather than inferring them from arbitrary request input without validation.

---

# 101. Callback Replay

OIDC callback artifacts SHALL not be reusable indefinitely.

Authorization codes are single-use and the integration SHALL treat callback replay as invalid.

---

# 102. Token Replay

Bearer-token replay risk SHALL be bounded through:

- TLS;
- short lifetimes;
- audience restriction;
- secure browser/session architecture;
- no token logging.

Future sender-constrained token approaches MAY be evaluated separately.

---

# 103. Error Handling

Authentication errors SHALL avoid revealing:

- whether a particular admin exists;
- internal mapping IDs;
- Keycloak implementation details;
- sensitive token-validation information.

---

# 104. Customer Errors

Customer UX MAY distinguish actionable conditions such as:

```text
account needs verification
authentication failed
temporary service unavailable
```

without exposing internal security state unnecessarily.

---

# 105. Admin Errors

Administrative authentication errors SHOULD remain particularly cautious to reduce identity enumeration.

---

# 106. IAM Outage

If Baobab IAM is unavailable:

- new OIDC authentications cannot complete;
- existing valid application sessions MAY remain usable according to their expiry;
- Medusa SHALL NOT fall back automatically to a hidden shared admin password.

---

# 107. CP Outage

If authentication requires canonical/context provisioning that cannot be resolved because CP is unavailable:

```text
new context-dependent login/provisioning
```

SHALL fail closed.

Existing low-risk Medusa sessions may continue only according to explicitly designed resilience rules.

---

# 108. Mapping Service Outage

If the identity mapping authority is unavailable during first login, the system SHALL not create speculative mappings from email.

---

# 109. Key Rotation

Medusa components directly validating Keycloak JWTs SHALL:

- cache trusted JWKS;
- refresh safely on unknown `kid`;
- honor algorithm allowlists;
- support overlapping signing-key rotation.

---

# 110. Unknown Key

An unknown signing key that cannot be refreshed safely SHALL cause token validation failure.

---

# 111. Issuer Validation

Medusa SHALL require the configured exact Keycloak issuer.

A token from another realm/environment SHALL not be accepted merely because the signing algorithm is valid.

---

# 112. Environment Isolation

Development, staging and production SHALL use distinct identity client configuration.

Production Medusa SHALL not accept development IAM issuer/tokens.

---

# 113. Secret Management

OIDC client credentials for confidential Medusa/BFF components SHALL be:

- unique;
- externally injected;
- rotatable;
- excluded from Git;
- excluded from images;
- excluded from logs.

---

# 114. Frontend Secrets

No confidential Keycloak client secret SHALL be embedded in:

```text
Thamani browser bundle
Zuribeans browser bundle
Medusa Admin browser bundle
```

---

# 115. Observability

Authentication telemetry SHOULD distinguish:

```text
OIDC start
OIDC callback success
OIDC callback failure
canonical resolution failure
Medusa actor lookup
JIT actor creation
actor binding failure
legacy-provider login
admin login
customer login
```

---

# 116. Metrics

Useful metrics MAY include:

```text
auth_success_total
auth_failure_total
oidc_callback_failure_total
actor_mapping_failure_total
jit_customer_created_total
legacy_auth_usage_total
```

without high-cardinality or PII-heavy labels.

---

# 117. Audit

Security audit SHOULD capture:

```text
canonical identity
Medusa actor ID
actor type
auth provider
client
result
timestamp
correlation ID
```

where appropriate.

---

# 118. No Sensitive Audit Payload

Audit SHALL NOT include:

```text
authorization code
access token
refresh token
client secret
password
PKCE verifier
```

---

# 119. Migration Metrics

During migration, Baobab SHOULD measure:

```text
legacy EmailPass authentications
Baobab OIDC authentications
unmigrated actors
migration failures
```

so legacy authentication can be retired confidently.

---

# 120. Customer Integration Tests

At minimum:

```text
new OIDC customer
existing mapped customer
first-login JIT customer
concurrent first login
wrong issuer
wrong audience
expired token
invalid state
invalid nonce
actor mapping failure
disabled IAM identity
```

---

# 121. Admin Integration Tests

At minimum:

```text
approved workforce admin succeeds
ordinary customer cannot access admin
authenticated workforce without Trade admin role denied
revoked Trade admin role denied
MFA policy enforced
wrong actor type denied
legacy admin password disabled after migration
```

---

# 122. AuthIdentity Tests

Test:

```text
AuthIdentity created correctly
customer_id app metadata set
user_id app metadata set
wrong actor ID rejected
duplicate mapping prevented
identity unlink behaves correctly
```

---

# 123. Provider Restriction Tests

Test configuration to ensure:

```text
provider not enabled for actor
      =
authentication unavailable
```

rather than silently falling back to another provider.

---

# 124. Guest Regression Tests

Ensure IAM rollout does not break:

```text
anonymous product browsing
guest carts
guest checkout
guest-to-account cart merge
```

---

# 125. Migration Tests

Test:

```text
existing Medusa customer preserved
order history preserved
Baobab identity linked
legacy auth works only during approved window
legacy auth disabled
same-email attacker cannot auto-link
```

---

# 126. Session Tests

Test:

```text
local logout
global logout where enabled
session expiry
IAM session revocation
Medusa domain suspension
admin role revocation
```

---

# 127. Negative Security Tests

At minimum:

```text
customer token against admin route
admin token against unintended audience
forged customer_id
forged canonical_identity_id
callback replay
authorization-code replay
malicious redirect URI
state mismatch
cross-environment token
spoofed identity headers
```

---

# 128. Rejected Alternative — Medusa Owns All Credentials

### Advantages

Native Medusa simplicity.

### Disadvantages

- fragmented Baobab identity;
- duplicate SSO architecture;
- separate recovery;
- separate MFA;
- difficult cross-estate identity.

### Decision

Rejected.

---

# 129. Rejected Alternative — Fork Medusa Authentication

### Advantages

Complete control.

### Disadvantages

- upgrade burden;
- divergence from upstream;
- security maintenance risk;
- unnecessary because extension points exist.

### Decision

Rejected.

---

# 130. Rejected Alternative — Bypass Medusa Auth Module

### Advantages

Direct Keycloak integration.

### Disadvantages

- duplicated framework behavior;
- actor-type confusion;
- unsupported route assumptions;
- upgrade risk.

### Decision

Rejected.

---

# 131. Rejected Alternative — Email as Mapping Key

### Advantages

Simple.

### Disadvantages

- mutable;
- reusable;
- collision-prone;
- identity-takeover risk.

### Decision

Rejected.

---

# 132. Rejected Alternative — Keycloak Role Equals Medusa Business Role

### Advantages

Central authorization.

### Disadvantages

- stale claims;
- domain leakage;
- role duplication.

### Decision

Rejected.

---

# 133. Rejected Alternative — Automatic Admin JIT

### Advantages

Low administrative overhead.

### Disadvantages

- successful authentication could become privilege escalation.

### Decision

Rejected.

---

# 134. Rejected Alternative — Permanent Dual Authentication

### Advantages

Fallback convenience.

### Disadvantages

- duplicate credential authority;
- larger attack surface;
- unclear recovery source.

### Decision

Rejected.

Dual authentication may exist only as a migration condition.

---

# 135. Consequences

## Positive

This decision provides:

- standards-based Medusa/Keycloak integration;
- no Medusa fork;
- unified customer/workforce authentication;
- preserved Medusa actor semantics;
- guest commerce compatibility;
- controlled JIT customer provisioning;
- strong admin isolation;
- incremental credential migration;
- future external identity linking.

## Negative

It requires:

- custom Medusa Auth Module provider code;
- identity-mapping workflows;
- migration tooling;
- callback/session testing;
- actor-specific configuration;
- careful dual-auth retirement.

These costs are accepted.

---

# 136. Implementation Ownership

| Concern | Owner |
|---|---|
| Keycloak authentication | `baobab-iam` |
| OIDC client configuration | `baobab-iam` |
| Medusa OIDC provider | `baobab-trade` |
| Medusa AuthIdentity | `baobab-trade` |
| Customer/User actor mapping | `baobab-trade` |
| Canonical Identity | `baobab-cp` |
| ExternalIdentity mapping | `baobab-cp` |
| Tenant/estate/market context | `baobab-cp` |
| Commerce authorization | `baobab-trade` |
| Workforce authorization | CP + Trade |
| Shared claims/contracts | `baobab-platform/shared` |
| Browser/BFF UX | respective Digital Estate |

---

# 137. Suggested Repository Structure

Within `baobab-trade`, implementation SHOULD resemble the existing Medusa project structure and MAY include:

```text
src/
├── modules/
│   └── baobab-auth/
│       ├── index.ts
│       ├── service.ts
│       ├── types.ts
│       └── providers/
│           └── oidc.ts
├── workflows/
│   └── identity/
│       ├── resolve-baobab-identity.ts
│       ├── provision-customer.ts
│       └── provision-admin.ts
├── subscribers/
│   └── identity-events.ts
└── api/
    └── ...
```

Exact paths SHALL follow current Medusa conventions at implementation time.

---

# 138. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend:

```text
identity claims profile
canonical identity reference
Medusa actor reference
external identity reference
authentication event
actor mapping event
delegated actor metadata
```

Medusa-internal DTOs SHALL remain within `baobab-trade`.

---

# 139. Configuration Requirements

`baobab-trade` SHALL maintain environment-specific configuration for:

```text
OIDC issuer
client ID
allowed audience
provider ID
callback URI
allowed actor types
JWKS/discovery policy
migration provider enablement
```

Secrets SHALL be runtime-injected.

---

# 140. Production-Readiness Checklist

The Medusa IAM integration SHALL not be considered production-ready until:

- Baobab OIDC Auth Module provider exists;
- no Medusa core fork is required;
- customer actor authentication works;
- admin actor authentication works;
- provider availability is restricted per actor;
- Authorization Code + PKCE is enforced for browser clients;
- exact issuer/audience validation is implemented;
- canonical identity resolution is implemented;
- AuthIdentity mapping is explicit;
- JIT customer creation is idempotent;
- JIT admin creation requires explicit privilege;
- guest commerce remains functional;
- customer/admin route isolation tests pass;
- callback replay protection passes;
- wrong-audience tests pass;
- cross-environment token tests pass;
- legacy credentials have a documented migration plan;
- no same-email auto-link exists;
- account linking is secure;
- local/global logout semantics are defined;
- session revocation behavior is tested;
- no secrets/tokens appear in logs;
- migration telemetry exists;
- legacy auth can be disabled entirely after migration.

---

# 141. Architectural Invariants

The following become binding:

```text
Keycloak Identity ≠ Medusa Actor

Medusa AuthIdentity ≠ CanonicalIdentity

Customer Actor ≠ Admin Actor

Authentication Provider ≠ Domain Role

OIDC Authentication ≠ Commerce Authorization

Valid Keycloak Token ≠ Valid Medusa Actor Automatically

Email Match ≠ Actor Match

Customer Login ≠ Admin Login

Medusa Token ≠ Universal Baobab Token

Publishable API Key ≠ Customer Identity

Workload Identity ≠ Human Medusa Session

Guest Cart ≠ Canonical Identity

Legacy Credential ≠ Permanent Fallback

Medusa Extension ≠ Medusa Fork
```

---

# 142. Target Architecture

```text
                         KEYCLOAK
                      / BAOBAB IAM
                            │
                           OIDC
                            │
                            ▼
                  ┌───────────────────┐
                  │ BAOBAB OIDC AUTH  │
                  │ MEDUSA PROVIDER   │
                  └─────────┬─────────┘
                            │
                     Medusa AuthIdentity
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
          Customer                      User
           Actor                        Actor
              │                           │
              ▼                           ▼
       Thamani / B2C                Medusa Admin
       Zuribeans user*              Workforce SSO
              │                           │
              └──────────────┬────────────┘
                             ▼
                         BAOBAB TRADE
                             │
                Commerce Authorization
```

*Where Zuribeans requirements use the appropriate Trade actor/membership model.

---

# 143. Customer Login Flow

```text
THAMANI CUSTOMER
       │
       ▼
Select Login
       │
       ▼
Baobab IAM
       │
Authorization Code + PKCE
       │
       ▼
OIDC Callback
       │
       ▼
Validate:
state
nonce
issuer
audience
expiry
       │
       ▼
Resolve CanonicalIdentity
       │
       ▼
Find Medusa AuthIdentity
       │
   ┌───┴────┐
  FOUND   NOT FOUND
   │         │
   │         ▼
   │     find/create Customer
   │         │
   │     bind AuthIdentity
   └────┬────┘
        ▼
Medusa customer authentication
        │
        ▼
Trade resource authorization
```

---

# 144. Admin SSO Flow

```text
TRADE ADMINISTRATOR
        │
        ▼
Medusa Admin
        │
        ▼
Baobab IAM
        │
       MFA
        │
        ▼
OIDC authentication
        │
        ▼
CanonicalIdentity
        │
        ▼
CP workforce entitlement
        │
   ┌────┴────┐
  DENY      ALLOW
   │          │
   ▼          ▼
 STOP    Medusa User mapping
              │
              ▼
         Trade admin role
              │
              ▼
       Administrative action
```

---

# 145. Migration Flow

```text
LEGACY MEDUSA ACTOR
        │
        ▼
Verify existing human identity
        │
        ▼
Create/link Baobab IAM identity
        │
        ▼
Resolve CanonicalIdentity
        │
        ▼
Create Baobab AuthIdentity
        │
        ▼
Link existing Medusa actor
        │
        ▼
Verify OIDC login
        │
        ▼
Disable legacy authentication
```

The actor, orders and commerce history remain intact.

---

# 146. Decision Summary

Medusa SHALL remain Baobab Trade's commerce engine and shall continue using its native Auth Module abstractions.

Baobab SHALL add a standards-based authentication provider rather than replacing Medusa's authentication framework or forking the platform.

The integration hierarchy SHALL be:

```text
WHO AUTHENTICATED THIS PERSON?
        │
        ▼
Baobab IAM / Keycloak

WHO IS THIS PERSON ACROSS BAOBAB?
        │
        ▼
CanonicalIdentity

WHICH MEDUSA ACTOR REPRESENTS THEM?
        │
        ▼
AuthIdentity + Customer/User mapping

WHAT MAY THAT ACTOR DO?
        │
        ▼
Baobab Trade
```

Customer and workforce admin identities SHALL use the same Baobab identity authority while remaining distinct Medusa actor and authorization domains.

Guest commerce SHALL remain available without synthetic IAM identities.

Legacy Medusa credentials SHALL be treated as migration state, not a permanent parallel identity system.

The governing principle is:

> **Integrate Keycloak through Medusa's authentication abstractions, preserve Medusa's actor model, and never trade framework compatibility for identity shortcuts.**