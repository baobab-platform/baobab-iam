# ADR-0011: Thamani B2C Customer Identity

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture  
**Repository:** `baobab-platform/baobab-iam`  
**Primary Runtime Owners:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/thamani`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Thamani customer authentication, self-service registration, guest checkout, customer accounts, OIDC integration, Medusa customer mapping, account linking, verification, recovery, social/federated login, privacy, account deletion, order ownership and abuse controls  
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

---

# 1. Context

Thamani is Baobab's B2C commerce Digital Estate.

Unlike Zuribeans, its primary external users are individual consumers purchasing goods for personal or household use.

The primary customer journey therefore emphasizes:

- low-friction registration;
- guest browsing;
- guest checkout where commercially permitted;
- simple account creation;
- order history;
- address management;
- account recovery;
- optional stronger authentication;
- privacy;
- social or federated login where useful.

Despite the lower organizational complexity of B2C identity, the architecture must still prevent duplication of credentials between:

```text
Thamani
Baobab IAM
Medusa
```

and preserve the architectural rule established by ADR-0001:

> Baobab IAM is the authentication authority; Trade remains the commerce authority.

---

# 2. Decision

Thamani SHALL use Baobab IAM as its customer credential and authentication authority.

Thamani SHALL own the customer-facing login and account UX.

`baobab-trade` SHALL own the commerce-domain customer actor and all commerce resource authorization.

The canonical flow SHALL be:

```text
Customer
   │
   ▼
Thamani
   │
   ▼
Baobab IAM
   │
   ▼
OIDC identity
   │
   ▼
CanonicalIdentity
   │
   ▼
Baobab CP
   │
   ▼
Thamani / Trade context
   │
   ▼
Medusa Customer Actor
   │
   ▼
Orders / Cart / Addresses / Commerce
```

---

# 3. Governing Principle

> **Thamani owns the customer experience, Baobab IAM owns credentials and authentication, and Baobab Trade owns commerce identity and authorization.**

---

# 4. Customer Identity

A Thamani registered customer SHALL authenticate as an individual person.

The person's authentication identity SHALL remain separate from their Medusa customer record.

Conceptually:

```text
Baobab IAM Subject
       │
       ▼
CanonicalIdentity
       │
       ▼
ExternalReference / Mapping
       │
       ▼
Medusa Customer Actor
```

---

# 5. Customer Actor Is Not Canonical Identity

This invariant SHALL remain binding:

```text
CanonicalIdentity ≠ Medusa Customer
```

The Medusa customer actor represents the customer within the commerce domain.

The Canonical Identity represents the person across Baobab.

---

# 6. Customer Account Is Not Credential Authority

Medusa SHALL NOT become the authoritative store for the customer's Baobab password when Baobab IAM authentication is enabled.

The preferred model SHALL be:

```text
Thamani
   │
   ▼
Baobab IAM
   │
   ▼
OIDC
   │
   ▼
Medusa Baobab authentication provider
```

---

# 7. Medusa Authentication Integration

Baobab SHALL implement Thamani authentication using Medusa's supported extensibility mechanisms rather than modifying Medusa core.

Medusa's Auth Module supports custom authentication providers and configurable authentication providers by actor type, enabling Baobab to integrate an OIDC-backed provider for the `customer` actor.

The target shall therefore be a Baobab/Keycloak OIDC Auth Module provider or equivalent supported integration.

---

# 8. No Medusa Fork

Baobab SHALL NOT fork Medusa merely to introduce Baobab IAM.

Integration preference SHALL remain:

```text
supported Medusa extension
        >
custom Auth Module provider
        >
adapter
        >
Medusa core modification
```

A fork would require a separate ADR.

---

# 9. Authentication Flow

For account-based customers:

```text
Customer selects Login
       │
       ▼
Thamani initiates OIDC
       │
       ▼
Baobab IAM
       │
       ▼
Authorization Code + PKCE
       │
       ▼
Thamani / BFF
       │
       ▼
Baobab-authenticated customer
       │
       ▼
Medusa customer mapping
```

The protocol SHALL follow ADR-0006.

---

# 10. Thamani Login UX

Thamani SHALL control:

- login page entry points;
- registration UX;
- account settings UX;
- recovery entry points;
- verification instructions;
- checkout prompts.

It SHALL NOT itself validate customer passwords.

---

# 11. Self-Service Registration

Thamani SHALL support customer self-registration.

A typical flow SHALL be:

```text
Customer
   │
   ▼
Register
   │
   ▼
Baobab IAM identity created
   │
   ▼
contact verification
   │
   ▼
CanonicalIdentity resolved/created
   │
   ▼
Medusa Customer created/linked
   │
   ▼
Customer account available
```

---

# 12. Minimal Registration

Initial B2C registration SHOULD collect only what is necessary.

Prefer:

```text
email/contact identifier
name where required
authentication enrollment
```

over requiring extensive customer profile data before the customer can browse or transact.

---

# 13. Progressive Profiling

Additional customer data MAY be collected progressively when required for:

- checkout;
- delivery;
- tax;
- invoicing;
- loyalty;
- customer service.

IAM SHALL not become the storage location for this commerce profile.

---

# 14. Verification

Baobab SHOULD require verification of the primary contact mechanism used for account recovery and account ownership.

Where email is the primary contact, email verification SHOULD occur before granting sensitive account capabilities.

Medusa itself supports customer verification requirements, including configurable email verification, but because Baobab IAM is the credential authority, Baobab SHALL avoid duplicate verification workflows unless Medusa requires a mapped verification state for compatibility.

---

# 15. Verification Authority

The authoritative authentication verification state SHALL live in IAM.

Medusa MAY retain a derived or domain-local state where technically required.

---

# 16. Verification Does Not Equal Commerce Authorization

This remains false:

```text
email verified
      =
may access any order
```

Trade SHALL still enforce resource ownership.

---

# 17. Guest Browsing

Anonymous users SHOULD be permitted to browse public Thamani commerce content where appropriate.

Anonymous browsing SHALL not require customer identity creation.

---

# 18. Guest Cart

Thamani MAY allow anonymous carts.

A guest cart SHALL have:

- non-guessable identity;
- bounded lifetime;
- no authority over registered customer resources;
- protection against cart hijacking.

---

# 19. Guest Checkout

Thamani SHOULD support guest checkout where business, fraud and regulatory policy permit.

Guest checkout enables:

```text
browse
  │
  ▼
cart
  │
  ▼
checkout
  │
  ▼
order
```

without forcing account creation first.

---

# 20. Guest Checkout Does Not Mean Anonymous Fulfilment

Guest checkout may still require:

- email;
- delivery details;
- billing details;
- payment information;
- legal acknowledgements.

The distinction is:

```text
no persistent login account required
```

not:

```text
no customer information required
```

---

# 21. Guest Order

Guest orders SHALL be represented in Trade according to Medusa's commerce model.

They SHALL NOT require a fabricated Baobab IAM user solely to satisfy identity architecture.

---

# 22. No Synthetic IAM Accounts for Guests

The platform SHALL NOT create:

```text
guest-12345@synthetic.baobab
```

IAM accounts merely to represent every anonymous shopper.

Guest commerce state belongs in Trade.

---

# 23. Guest-to-Account Conversion

A guest customer MAY later create an account.

The platform SHOULD support safely associating eligible historical guest resources with the new registered identity.

---

# 24. Guest Order Claiming

Historical guest orders SHALL NOT be attached to an account merely because the new account provides the same email address.

Additional proof SHALL be required where needed.

Possible evidence includes:

- authenticated ownership of verified email;
- possession of a secure order claim secret;
- support-assisted verification;
- other approved proof.

---

# 25. No Automatic Linking by Email Alone

This invariant from ADR-0004 SHALL apply:

```text
same email
    ≠
same identity automatically
```

This is especially important where:

- email addresses are recycled;
- guest checkout records predate account creation;
- social login introduces another IdP subject.

---

# 26. Account Checkout

Registered customers MAY use account checkout.

Benefits MAY include:

- saved addresses;
- order history;
- faster checkout;
- preferences;
- loyalty features;
- saved commercial context where appropriate.

Trade owns those capabilities.

---

# 27. Cart Association

After authentication, a guest cart MAY be associated with the authenticated customer if security checks pass.

The system SHALL prevent:

```text
attacker authenticates
      │
      ▼
claims another browser's cart
```

---

# 28. Cart Merge

Where a customer has both:

```text
anonymous cart
+
existing account cart
```

Thamani/Trade MAY merge or prompt according to commerce UX.

Merge policy SHALL not reside in IAM.

---

# 29. Medusa Customer Mapping

The canonical mapping SHALL conceptually be:

```text
IAM:
issuer + subject
      │
      ▼
CanonicalIdentity
      │
      ▼
ExternalReference / Mapping
      │
      ▼
Medusa Customer ID
```

This mapping SHALL be explicit and immutable in identity relationship semantics.

---

# 30. First Login Provisioning

Where no Medusa customer mapping exists, Baobab MAY use controlled Just-In-Time provisioning.

Flow:

```text
OIDC authentication succeeds
       │
       ▼
CanonicalIdentity resolved
       │
       ▼
Medusa mapping exists?
    ┌──┴───┐
   YES     NO
    │       │
    │       ▼
    │   create customer
    │       │
    │       ▼
    │   create mapping
    └───────┤
            ▼
      customer session
```

---

# 31. JIT Idempotency

Customer provisioning SHALL be idempotent.

Repeated authentication callbacks SHALL not create duplicate Medusa customers.

---

# 32. Concurrency

The implementation SHALL handle simultaneous first-login attempts safely.

The mapping layer SHOULD enforce uniqueness so that:

```text
one canonical identity
       │
       ▼
one active Thamani customer mapping
```

unless a future domain requirement explicitly permits otherwise.

---

# 33. Customer Mapping Failure

If IAM authentication succeeds but Trade customer mapping fails:

```text
authentication = success
commerce provisioning = failure
```

The platform SHALL NOT fabricate authorization.

The user SHALL receive a safe recoverable error while the failure is logged.

---

# 34. Mapping Repair

Administrative repair tools SHOULD support resolving mapping failures without manually altering multiple databases inconsistently.

---

# 35. Order Ownership

Trade SHALL own order authorization.

A registered customer MAY access an order only if Trade establishes the relationship.

Example:

```text
CanonicalIdentity
       │
       ▼
Medusa Customer
       │
       ▼
Order
```

---

# 36. Valid IAM Token Does Not Grant All Orders

This is prohibited:

```text
valid Thamani login
      │
      ▼
GET /orders/{arbitrary-id}
      │
      ▼
allow
```

Trade SHALL verify ownership or another approved domain relationship.

---

# 37. Order Enumeration

Customer-facing order identifiers SHOULD not create an enumeration vulnerability.

Even with non-sequential IDs, authorization SHALL remain mandatory.

---

# 38. Address Ownership

Saved customer addresses SHALL be Trade/customer-domain resources.

A customer SHALL not modify another customer's saved address by changing an identifier.

---

# 39. Payment Instruments

Sensitive payment instrument storage SHOULD remain with the approved payment provider or commerce integration as architecture requires.

IAM SHALL never store payment credentials.

---

# 40. Authentication and Payment Are Separate

Successful IAM authentication SHALL not imply:

```text
payment authorized
```

Payment authorization remains part of commerce/payment processing.

---

# 41. Social Login

Thamani MAY support social or federated identity providers through Baobab IAM.

Examples may include:

```text
Google
Apple
other approved providers
```

Keycloak remains the broker/authentication boundary.

---

# 42. Social Provider Credentials

Thamani SHALL not independently integrate separate social-login identity stores when IAM can broker them centrally.

Target:

```text
Social IdP
    │
    ▼
Baobab IAM
    │
    ▼
CanonicalIdentity
    │
    ▼
Thamani
```

---

# 43. Social Login Is External Identity

A social identity SHALL map as:

```text
issuer + subject
       │
       ▼
ExternalIdentity
       │
       ▼
CanonicalIdentity
```

per ADR-0004.

---

# 44. Multiple Login Methods

One Canonical Identity MAY support multiple authentication methods or external identities.

Example:

```text
CanonicalIdentity
   │
   ├── Baobab credential
   ├── Google identity
   └── future enterprise identity
```

subject to secure linking.

---

# 45. Account Linking

Account linking SHALL be a security-sensitive operation.

The system SHALL NOT automatically link two identities solely because:

```text
email addresses match
```

---

# 46. Link Authorization

Linking SHOULD require proof that the authenticated user controls both identities or a securely governed recovery process.

---

# 47. Account Linking Audit

Identity-link events SHALL be audited because incorrect linking could expose:

- order history;
- addresses;
- personal profile;
- loyalty benefits.

---

# 48. Account Merge

Merging two Canonical Identities SHALL remain a controlled operation governed by ADR-0004.

Thamani SHALL not implement independent identity merge logic.

---

# 49. Account Recovery

Registered Thamani users SHALL use Baobab IAM account recovery.

Thamani MAY provide the UX entry point:

```text
Forgot password?
```

but the recovery authority remains IAM.

---

# 50. Recovery SHALL Not Be Implemented in Medusa

Medusa SHALL not maintain a parallel password-reset path for Baobab-authenticated customers.

Otherwise:

```text
IAM password
+
Medusa password
```

would create competing credential authorities.

---

# 51. Recovery Security

Recovery mechanisms SHALL resist:

- account enumeration;
- reset-link replay;
- token leakage;
- brute force;
- social-engineering takeover.

---

# 52. Recovery Token

Recovery tokens SHALL be:

- short-lived;
- single-purpose;
- difficult to guess;
- invalidated after successful use;
- excluded from logs.

---

# 53. Recovery Does Not Change Customer Mapping

Successful credential recovery SHALL restore access to the existing Canonical Identity.

It SHALL not create a new Medusa customer.

---

# 54. MFA Posture

MFA SHALL not necessarily be mandatory for every B2C customer at initial rollout.

The baseline MAY be:

```text
ordinary B2C customer:
MFA optional

high-risk customer action:
step-up possible
```

while privileged workforce MFA remains mandatory under ADR-0009.

---

# 55. Passkeys

Passkeys SHOULD be supported or introduced as a preferred customer authentication method when Baobab IAM deployment and UX are ready.

They offer an opportunity to reduce:

- password friction;
- password reuse;
- phishing exposure.

Exact credential requirements belong to ADR-0015.

---

# 56. Customer MFA

Customers MAY opt into MFA where supported.

Baobab SHALL prefer IAM-managed MFA instead of separately enrolling another factor in Medusa.

Medusa has its own MFA framework, including TOTP and recovery-code support, but Baobab SHOULD avoid duplicating MFA state because Keycloak is the designated credential authority.

---

# 57. Medusa MFA Capability

Medusa's native MFA capabilities MAY still be useful for:

- non-Baobab deployments;
- exceptional actor classes;
- defensive integration where IAM assurance cannot be propagated.

For Thamani's normal customer identity, IAM remains authoritative.

---

# 58. Step-Up Authentication

Potential high-risk B2C operations MAY trigger step-up authentication.

Examples:

```text
change primary email
change password/passkey
link external identity
view particularly sensitive account information
change security settings
high-risk payment/account action
```

---

# 59. Step-Up Decision Ownership

The business application MAY determine that stronger authentication is required.

IAM SHALL perform the authentication challenge.

The domain SHALL still authorize the requested action afterward.

---

# 60. Authentication Assurance

Where step-up is used, assurance SHOULD be represented using the common OIDC profile established by ADR-0006.

Applications SHALL not invent unrelated local MFA flags.

---

# 61. Session Architecture

Thamani MAY use either:

```text
BFF-managed session
```

or another approved OIDC architecture.

Higher-value deployments SHOULD prefer a BFF where it materially reduces browser token exposure.

---

# 62. Browser Token Storage

Thamani SHALL avoid unnecessarily persisting long-lived tokens in browser-accessible storage.

Security architecture SHALL follow ADR-0006.

---

# 63. Logout

Thamani SHALL support customer logout.

Logout SHALL clear the Thamani application session and SHOULD appropriately interact with IAM session logout according to the chosen client architecture.

---

# 64. Shared SSO Considerations

Because Baobab IAM may authenticate multiple Digital Estates, logout semantics SHALL be deliberate.

Logging out of Thamani does not necessarily require globally terminating every unrelated Baobab session unless policy demands it.

---

# 65. Session Revocation

A compromised Thamani customer account SHOULD support:

```text
revoke IAM sessions
       │
       ▼
secure identity
       │
       ▼
review sensitive commerce activity
```

---

# 66. Customer Lifecycle

A registered customer identity MAY support states conceptually such as:

```text
PENDING_VERIFICATION
ACTIVE
LOCKED
SUSPENDED
DISABLED
ARCHIVED
```

Credential lifecycle remains distinct from Trade customer lifecycle.

---

# 67. Customer Account Suspension

A customer may be unable to transact even while authentication remains valid.

For example:

```text
IAM identity ACTIVE
Trade customer SUSPENDED
```

Trade SHALL deny restricted commerce actions.

---

# 68. IAM Suspension

Conversely:

```text
IAM identity DISABLED
Trade customer ACTIVE
```

shall not permit authenticated account operations because authentication cannot succeed.

---

# 69. Customer Profile

Customer commerce-profile data SHALL primarily belong to Trade or the appropriate customer domain.

Examples:

- delivery addresses;
- billing preferences;
- order history;
- customer preferences;
- commerce metadata.

---

# 70. IAM Profile

IAM SHOULD retain the minimum identity profile required for:

- authentication;
- account recovery;
- identity display;
- federation;
- security.

---

# 71. Profile Synchronization

Where attributes exist in both IAM and Trade, the authoritative source SHALL be defined explicitly.

For example:

```text
primary authentication email → IAM authority

shipping address → Trade authority
```

---

# 72. Email Changes

Changing the primary authentication email SHALL be treated as a security-sensitive identity operation.

The process SHOULD include:

- authentication;
- appropriate step-up;
- new-address verification;
- audit.

Trade MAY receive the updated contact attribute through a controlled synchronization/event mechanism.

---

# 73. No Direct Cross-Database Update

Trade SHALL not update the Keycloak database directly to change an authentication identity.

Likewise IAM SHALL not directly modify Medusa customer tables.

---

# 74. Identity Events

Appropriate identity events MAY include:

```text
identity.created.v1
identity.verified.v1
identity.updated.v1
identity.disabled.v1
external-identity.linked.v1
```

subject to Shared event standards.

---

# 75. Customer Mapping Events

Integration MAY use events such as:

```text
customer.identity-linked.v1
customer.identity-unlinked.v1
```

if needed.

Exact event names SHALL align with Shared conventions.

---

# 76. Guest Identity Is Not Canonical Identity

Anonymous/guest commerce sessions SHALL NOT automatically become Canonical Identities.

Canonical identity creation SHOULD occur when a persistent Baobab identity is genuinely required.

---

# 77. Consumer Is Not Tenant

A Thamani consumer SHALL not become a Baobab Tenant.

The architecture is:

```text
Thamani Tenant
    │
    ▼
Trade
    │
    ├── Customer A
    ├── Customer B
    └── Customer C
```

---

# 78. Consumer Is Not Legal Entity

Ordinary customer identity SHALL not be forced into the LegalEntity model.

CanonicalEntity distinctions SHALL remain semantically correct.

---

# 79. Customer Context

A normal customer platform context may include:

```text
Tenant = Thamani
DigitalEstate = Thamani
Market = ZA
Capability = Trade
```

followed by Trade resolving the customer actor.

---

# 80. Multi-Market Customer

A customer MAY transact in multiple enabled Thamani markets where business rules permit.

This SHALL not create duplicate Canonical Identities merely because the market changes.

---

# 81. Market Context

Market selection SHALL be validated through platform and commerce rules.

A customer's browser-selected market does not independently establish authority or availability.

---

# 82. Cross-Market Orders

Trade SHALL determine whether historical orders remain visible across market contexts according to its business model.

This SHALL not be encoded as IAM identity policy.

---

# 83. Order Ownership Example

```text
Customer logs in
      │
      ▼
IAM authenticates
      │
      ▼
CP resolves Thamani Trade context
      │
      ▼
Trade maps canonical identity
      │
      ▼
Medusa Customer C123
      │
      ▼
Order O987 belongs to C123?
      │
   ┌──┴───┐
  YES     NO
   │       │
ALLOW    DENY
```

---

# 84. Customer Service Access

Thamani support staff SHALL authenticate as workforce users under ADR-0009.

They SHALL not log in using customer credentials.

---

# 85. Customer Impersonation

If support impersonation is introduced, it SHALL preserve:

```text
subject = customer
actor = support workforce identity
```

and be fully audited.

---

# 86. Customer Data Access by Support

Support access SHALL be limited to the minimum customer data required for support duties.

---

# 87. Privacy

Thamani identity architecture SHALL support privacy obligations by separating:

```text
authentication data
commerce profile
transaction records
marketing preferences
security audit
```

rather than placing everything into one identity profile.

---

# 88. Marketing Consent

Marketing consent SHALL NOT be inferred from:

```text
customer created account
```

Consent SHALL be separately recorded according to applicable business/privacy requirements.

---

# 89. Authentication Consent

Accepting IAM terms or authentication processing SHALL not substitute for commerce/marketing consent.

---

# 90. Account Deletion Request

A customer MAY request account deletion or closure according to applicable policy.

The process SHALL distinguish:

```text
disable authentication
remove optional profile data
retain legally required transaction records
retain security/audit records where permitted
```

---

# 91. Identity Deletion Is Not Order Deletion

This invariant SHALL remain binding:

```text
delete/close customer identity
      ≠
delete transaction history automatically
```

Orders may need retention for:

- accounting;
- tax;
- fraud;
- legal obligations;
- dispute handling.

---

# 92. Pseudonymization

Where deletion obligations require removal of personal association but transaction records must remain, Baobab SHOULD support pseudonymization/anonymization strategies appropriate to the data and applicable law.

---

# 93. Canonical Identity Deletion

Canonical identity deletion SHALL be governed carefully because the person may have other Baobab relationships.

Example:

```text
same person
   │
   ├── Thamani customer
   ├── Zuribeans buyer representative
   └── supplier representative
```

Closing a Thamani account SHALL not automatically delete the global Canonical Identity.

---

# 94. Thamani Account Closure

Prefer:

```text
remove/disable Thamani relationship
```

before:

```text
delete CanonicalIdentity
```

unless the latter is appropriate platform-wide.

---

# 95. Fraud and Abuse

Thamani SHALL implement B2C identity abuse controls for:

- credential stuffing;
- brute-force login;
- mass registration;
- verification abuse;
- password reset abuse;
- promo abuse;
- cart abuse;
- account takeover;
- enumeration.

---

# 96. Rate Limiting

At minimum, rate limits SHOULD apply to:

```text
login attempts
registration
verification resend
account recovery
identity linking
```

according to risk.

---

# 97. Account Enumeration

Registration and recovery UX SHOULD avoid unnecessarily revealing whether a specific account exists.

---

# 98. Credential Stuffing

Authentication infrastructure SHOULD support detection or throttling of anomalous repeated authentication attempts.

---

# 99. Registration Abuse

Customer registration MAY require additional anti-abuse controls when observed risk justifies them.

The initial architecture SHALL not require high-friction challenges for every legitimate customer by default.

---

# 100. Verification Resend Abuse

Verification/resend endpoints SHALL prevent:

- unlimited email sending;
- targeted harassment;
- resource exhaustion.

---

# 101. Social Identity Takeover

Social/federated login linking SHALL not trust user-controlled claims more than the upstream identity assurance permits.

Issuer and subject remain the external identity key.

---

# 102. Account Recovery Abuse

Recovery attempts SHOULD generate protected security telemetry sufficient to identify unusual activity.

---

# 103. Security Notifications

Customers SHOULD receive notifications for important security events where appropriate, such as:

- credential change;
- primary email change;
- new identity provider linked;
- account recovery;
- major account-security change.

---

# 104. Audit

Customer security events SHOULD answer:

```text
which canonical identity?
which external identity?
which client?
which event?
when?
success/failure?
```

without logging secrets.

---

# 105. Commerce Audit

Trade SHALL separately own events such as:

```text
order placed
address changed
refund requested
customer resource modified
```

---

# 106. Cross-System Correlation

Where feasible:

```text
IAM login
    │
    ▼
CP context decision
    │
    ▼
Trade customer action
```

SHOULD be correlatable through canonical identity and request/decision identifiers.

---

# 107. No Token Logging

Thamani, Trade and observability pipelines SHALL not log:

```text
ID tokens
access tokens
refresh tokens
authorization codes
recovery secrets
```

---

# 108. Registration Tests

At minimum test:

```text
new registration
verification required
duplicate callback
existing canonical identity
Medusa provisioning failure
concurrent first login
```

---

# 109. Login Tests

Test:

```text
successful OIDC login
invalid issuer
wrong audience
expired token
disabled IAM identity
missing customer mapping
customer mapping creation
```

---

# 110. Guest Tests

Test:

```text
anonymous browsing
guest cart
guest checkout
guest order
guest-to-account conversion
guest order claim rejection without sufficient proof
```

---

# 111. Resource Isolation Tests

At minimum:

```text
Customer A cannot:
- read Customer B order
- modify Customer B address
- access Customer B saved profile
- attach Customer B cart
```

---

# 112. Account Linking Tests

Test:

```text
secure link
email-match-only link rejected
unverified external identity rejected where required
duplicate mapping prevention
link audit
unlink behavior
```

---

# 113. Recovery Tests

Test:

```text
valid recovery
expired recovery token
reused recovery token
account enumeration resistance
recovered account retains same canonical identity
revoked commerce relationship not restored
```

---

# 114. Social Login Tests

Test:

```text
new social login
existing securely linked social identity
unlinked same-email identity
issuer mismatch
subject mismatch
provider removal
```

---

# 115. Privacy Tests

Test:

```text
close Thamani account
retain required orders
remove/disassociate removable customer data
do not delete unrelated Zuribeans/supplier relationships
```

---

# 116. Abuse Tests

Security testing SHALL include:

```text
credential stuffing simulation
recovery brute force
verification resend abuse
registration flood
order enumeration
customer-ID tampering
```

---

# 117. Rejected Alternative — Medusa Owns Customer Passwords

### Advantages

Native/simple Medusa authentication.

### Disadvantages

- duplicate credential authority;
- inconsistent SSO;
- duplicated MFA/recovery;
- weaker cross-estate identity strategy.

### Decision

Rejected.

Baobab IAM remains the credential authority.

---

# 118. Rejected Alternative — Mandatory Account Before Checkout

### Advantages

Every order has a persistent authenticated customer.

### Disadvantages

- unnecessary B2C friction;
- conversion impact;
- synthetic account pressure.

### Decision

Rejected as a universal rule.

Guest checkout MAY be supported where commercially appropriate.

---

# 119. Rejected Alternative — Create IAM Identity for Every Guest

### Advantages

Uniform identity model.

### Disadvantages

- unnecessary identity proliferation;
- poor semantics;
- privacy overhead;
- account pollution.

### Decision

Rejected.

---

# 120. Rejected Alternative — Automatically Link Same Email

### Advantages

Smooth UX.

### Disadvantages

- identity takeover risk;
- unsafe assumptions;
- conflicts with canonical identity rules.

### Decision

Rejected.

---

# 121. Rejected Alternative — Medusa MFA as Parallel Customer MFA

### Advantages

Native Medusa capability.

### Disadvantages

- duplicate MFA enrollment;
- inconsistent recovery;
- two assurance authorities;
- fragmented customer experience.

### Decision

Rejected as the normal Thamani model.

IAM owns MFA.

---

# 122. Rejected Alternative — Social Login Integrated Directly Into Thamani

### Advantages

Potentially simple frontend integration.

### Disadvantages

- fragmented identity brokering;
- duplicate external identity mappings;
- inconsistent cross-estate security.

### Decision

Rejected as the default.

Social providers SHOULD terminate through Baobab IAM.

---

# 123. Rejected Alternative — Customer Is Tenant

### Decision

Rejected.

A normal B2C customer is a domain customer within the Thamani tenant.

---

# 124. Consequences

## Positive

This decision provides:

- one customer credential authority;
- lower-friction B2C onboarding;
- optional guest checkout;
- explicit customer-to-Medusa mapping;
- safe social-login evolution;
- consistent recovery;
- strong order isolation;
- cleaner privacy boundaries;
- future passkey/MFA readiness.

## Negative

It requires:

- custom Medusa IAM integration;
- guest/account reconciliation;
- explicit mapping infrastructure;
- account-linking controls;
- additional privacy workflows;
- cross-system testing.

These costs are accepted.

---

# 125. Implementation Ownership

| Concern | Owner |
|---|---|
| Customer authentication | `baobab-iam` |
| Credentials | `baobab-iam` |
| MFA/passkeys | `baobab-iam` |
| Social identity brokering | `baobab-iam` |
| Canonical identity | `baobab-cp` |
| Thamani tenant/market context | `baobab-cp` |
| Medusa customer actor | `baobab-trade` |
| Customer mapping | `baobab-cp` / explicit mapping contract |
| Cart/order ownership | `baobab-trade` |
| Guest checkout | `baobab-trade` + `thamani` |
| Customer frontend UX | `baobab-platform/thamani` |
| Shared identity contracts | `baobab-platform/shared` |

---

# 126. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend versioned contracts for:

```text
customer identity mapping
external identity reference
customer actor reference
identity lifecycle events
account-link events
context resolution
delegation metadata
```

Trade-specific cart/order/customer contracts SHALL remain in Trade where appropriate.

---

# 127. Production-Readiness Checklist

Thamani B2C identity SHALL not be considered production-ready until:

- Thamani authentication uses Baobab IAM;
- browser login uses the approved OIDC flow;
- Medusa does not become a second customer password authority;
- custom/approved Medusa OIDC authentication integration works;
- canonical identity mapping is idempotent;
- Medusa customer mapping is explicit;
- first-login provisioning is concurrency-safe;
- customer order ownership is enforced server-side;
- guest browsing works without synthetic identities;
- guest checkout behavior is explicitly defined;
- guest-to-account conversion is safe;
- same-email auto-linking is prohibited;
- account recovery remains IAM-owned;
- social providers terminate through IAM where enabled;
- account linking requires sufficient proof;
- cross-customer isolation tests pass;
- privacy/account-closure workflow exists;
- unrelated canonical relationships survive Thamani account closure;
- authentication and recovery endpoints are rate-limited;
- tokens and recovery secrets are excluded from logs.

---

# 128. Architectural Invariants

The following become binding:

```text
Thamani UX ≠ Credential Authority

CanonicalIdentity ≠ Medusa Customer

Medusa Customer ≠ Baobab IAM User

Guest Session ≠ Canonical Identity

Guest Checkout ≠ Anonymous Fulfilment

Valid Login ≠ Access to Every Order

Email Match ≠ Identity Match

Account Recovery ≠ New Identity

Social Login ≠ Automatic Account Link

Customer ≠ Tenant

IAM Profile ≠ Commerce Profile

Account Closure ≠ Global Canonical Identity Deletion

IAM MFA ≠ Parallel Medusa MFA
```

---

# 129. Target Architecture

```text
                          BAOBAB IAM
                             │
                    Authentication / OIDC
                             │
                             ▼
                     CanonicalIdentity
                             │
                             ▼
                        BAOBAB CP
                             │
                 Thamani / Market / Trade
                             │
                             ▼
                       BAOBAB TRADE
                             │
                     Medusa Customer
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
         Cart              Orders            Addresses
```

For guest commerce:

```text
Anonymous Browser
       │
       ▼
Thamani / Trade
       │
       ▼
Guest Cart
       │
       ▼
Guest Checkout
       │
       ▼
Guest Order

No IAM identity is created solely because the guest shopped.
```

---

# 130. Registered Customer Flow

```text
CUSTOMER
   │
   ▼
Thamani Login
   │
   ▼
Baobab IAM
   │
   ▼
Authorization Code + PKCE
   │
   ▼
Canonical identity resolution
   │
   ▼
Medusa mapping exists?
  ┌────┴─────┐
 YES         NO
  │           │
  │           ▼
  │       create/link
  │       Medusa customer
  │           │
  └─────┬─────┘
        ▼
Resolve Thamani context
        │
        ▼
Trade resource authorization
        │
        ▼
Customer commerce session
```

---

# 131. Guest-to-Account Flow

```text
GUEST
  │
  ▼
Cart / Checkout / Order
  │
  ▼
Later chooses "Create Account"
  │
  ▼
Baobab IAM registration
  │
  ▼
CanonicalIdentity
  │
  ▼
Medusa Customer
  │
  ▼
Can historical guest resource be proven?
       ┌─────┴─────┐
      YES          NO
       │            │
       ▼            ▼
securely link     leave unlinked /
eligible data     support workflow
```

Email equality alone SHALL not satisfy the proof step.

---

# 132. Decision Summary

Thamani SHALL implement a low-friction but strongly bounded B2C identity architecture.

The decision chain is:

```text
WHO IS THE CUSTOMER?
        │
        ▼
Baobab IAM

WHICH PLATFORM CONTEXT?
        │
        ▼
Baobab Control Plane

WHICH COMMERCE CUSTOMER?
        │
        ▼
Baobab Trade / Medusa

WHICH CART, ORDER OR ADDRESS MAY THEY ACCESS?
        │
        ▼
Baobab Trade
```

Guest commerce SHALL remain possible without polluting IAM with synthetic identities.

Registered customers SHALL receive a persistent Canonical Identity and explicit Medusa customer mapping.

Social login, account recovery, MFA and future passkeys SHALL remain centralized through Baobab IAM.

The governing principle is:

> **Thamani should make identity nearly invisible to the customer while keeping authentication centralized, commerce ownership explicit, and account boundaries uncompromising.**