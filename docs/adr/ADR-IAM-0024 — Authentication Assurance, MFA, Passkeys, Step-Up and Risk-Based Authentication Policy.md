# ADR-IAM-0024 — Authentication Assurance, MFA, Passkeys, Step-Up and Risk-Based Authentication Policy

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold, and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0023  
**Extends:** ADR-IAM-0006, ADR-IAM-0008, ADR-IAM-0009, ADR-IAM-0010, ADR-IAM-0011, ADR-IAM-0012, ADR-IAM-0014, ADR-IAM-0015, ADR-IAM-0016, ADR-IAM-0017, ADR-IAM-0018, ADR-IAM-0019, ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022, ADR-IAM-0023  
**Decision Type:** Authentication Assurance / MFA / Passkeys / Step-Up / Adaptive Authentication / Security Policy  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Business Authorization Authorities:** Baobab Control Plane and respective domain engines

---

# 1. Decision

Baobab SHALL adopt an explicit **authentication assurance policy** rather than treating authentication as a binary condition.

The platform SHALL distinguish:

```text
identity authenticated
        │
        ▼
authentication assurance
        │
        ▼
current risk
        │
        ▼
required assurance for operation
        │
        ▼
step-up if necessary
        │
        ▼
business authorization
```

Authentication strength SHALL therefore be proportional to the risk of the requested operation.

Baobab SHALL:

1. support passwordless/passkey authentication;
2. prefer phishing-resistant authentication for privileged and high-impact operations;
3. require MFA for privileged identities;
4. support step-up authentication for sensitive operations;
5. support contextual/risk-based authentication;
6. distinguish authentication assurance from business authorization;
7. treat account recovery and authenticator replacement as high-risk security operations;
8. preserve authentication assurance across OIDC/OAuth using trustworthy protocol claims where available;
9. make assurance requirements centrally definable but domain-sensitive;
10. avoid forcing maximum authentication friction on every ordinary low-risk user action.

---

# 2. Core Principle

The platform SHALL answer two independent questions:

```text
QUESTION 1

How strongly do we know
that this is Jane?

        │
        ▼
AUTHENTICATION ASSURANCE


QUESTION 2

May Jane perform
this operation?

        │
        ▼
AUTHORIZATION
```

These questions SHALL never be collapsed.

---

# 3. Authentication Does Not Grant Authority

The following is prohibited:

```text
Jane passed MFA
      │
      ▼
Jane may approve purchase
```

Required:

```text
Jane passed MFA
      │
      ▼
required assurance satisfied
      │
      ▼
Trade evaluates Jane's
purchase authority
      │
   ┌──┴──┐
   ▼     ▼
ALLOW   DENY
```

MFA strengthens evidence about the actor.

It does not create business authority.

---

# 4. Standards Basis

Baobab's assurance model is informed by NIST SP 800-63B-4, finalized in 2025. NIST defines three Authenticator Assurance Levels and requires progressively stronger authentication characteristics. At AAL2, phishing-resistant authentication is recommended and must be available; AAL3 requires phishing resistance and stronger cryptographic authenticator characteristics.

Baobab SHALL use the NIST AAL framework as an architectural reference rather than falsely claiming formal NIST AAL compliance merely because similar controls are implemented.

WebAuthn Level 3 became a W3C Recommendation on 25 August 2026. It specifies public-key credentials scoped to relying parties and mediated through authenticators/user agents, making WebAuthn/passkeys an appropriate foundation for Baobab's phishing-resistant authentication strategy.

OWASP similarly recommends MFA for privileged users and sensitive operations, risk-based authentication when circumstances warrant stronger authentication, and phishing-resistant methods such as FIDO2/WebAuthn as the preferred defense against modern phishing attacks.

---

# 5. Baobab Assurance Levels

Baobab SHALL define its own application assurance classes.

These SHALL be conceptually aligned with NIST without claiming equivalence.

```text
BAOBAB-A0
    │
    ▼
Unauthenticated / Guest

BAOBAB-A1
    │
    ▼
Authenticated

BAOBAB-A2
    │
    ▼
Strong Multi-Factor Authentication

BAOBAB-A3
    │
    ▼
Phishing-Resistant Strong Authentication

BAOBAB-A4
    │
    ▼
Privileged / High-Assurance Session
```

These are **Baobab policy classifications**, not NIST certification labels.

---

# 6. BAOBAB-A0 — Anonymous

Examples:

```text
public catalogue
public corporate content
public shipment information where policy permits
public supplier information
public contact forms
anonymous quotation initiation where permitted
```

No authenticated identity is assumed.

---

# 7. BAOBAB-A1 — Authenticated

A1 means:

> A recognized identity has successfully authenticated using an accepted authentication mechanism.

Possible examples:

```text
password
federated enterprise authentication
single-factor passkey configuration
other approved provider authentication
```

depending on provider capability and policy.

A1 may be sufficient for ordinary low-risk customer operations.

---

# 8. BAOBAB-A2 — Strong MFA

A2 requires appropriate multi-factor authentication.

Examples may include:

```text
password
   +
TOTP

password
   +
cryptographic authenticator

approved multi-factor authenticator
```

The factors SHALL be sufficiently independent.

Two passwords do not constitute MFA.

OWASP similarly notes that multiple instances of the same factor do not provide genuine MFA.

---

# 9. BAOBAB-A3 — Phishing-Resistant Authentication

A3 requires an approved phishing-resistant cryptographic authentication mechanism.

The preferred mechanism is:

```text
WebAuthn / Passkey
```

with appropriate user verification.

Other phishing-resistant mechanisms MAY be approved through architecture/security review.

---

# 10. BAOBAB-A4 — Privileged High Assurance

A4 represents a **Baobab privileged-session policy**, not a new cryptographic factor type.

A4 requires:

```text
A3 authentication
+
recent authentication
+
privileged identity/context
+
risk evaluation
+
restricted session policy
```

and MAY additionally require:

```text
managed device
hardware-bound authenticator
approved network posture
administrative workstation
additional transaction confirmation
```

depending on the operation.

---

# 11. Assurance Is Not Permanent

A user SHALL NOT acquire A3 permanently because they once used a passkey.

Assurance is associated with an authentication event/session.

Conceptually:

```text
CanonicalIdentity
      │
      ├── may possess Passkey
      ├── may possess TOTP
      └── may possess Password

Current Session
      │
      ▼
actual authentication performed
      │
      ▼
Current Assurance
```

---

# 12. Authenticator Capability vs Session Assurance

These are distinct:

```text
Jane HAS a passkey
```

does not imply:

```text
Jane USED the passkey
for this session
```

Therefore the system SHALL distinguish:

```text
available_authenticators
```

from:

```text
session_assurance
```

---

# 13. Authentication Evidence

Where trustworthy and available, Baobab MAY use protocol/provider evidence such as:

```text
acr
amr
auth_time
```

to determine session assurance.

These values SHALL originate from trusted authentication infrastructure.

The browser SHALL not be permitted to assert them.

---

# 14. Assurance Evaluation

Conceptually:

```text
Authentication Evidence
        │
        ▼
baobab-iam assurance evaluator
        │
        ▼
Baobab Assurance Level
        │
        ▼
CP / Domain decision
```

---

# 15. Provider-Neutral Assurance

Domain engines SHALL NOT require:

```text
kratos_passkey == true
```

or:

```text
keycloak_otp == true
```

Instead:

```text
authentication_assurance >= BAOBAB-A3
```

SHOULD be the provider-neutral semantic contract.

---

# 16. Assurance Contract

`shared` SHOULD define a provider-neutral assurance representation.

Conceptually:

```json
{
  "level": "BAOBAB-A3",
  "authenticated_at": "2026-09-26T12:00:00Z",
  "methods": [
    "webauthn"
  ],
  "phishing_resistant": true,
  "user_verification": true
}
```

Provider-specific details MAY remain available for audit but SHALL not become domain policy.

---

# 17. Baseline Assurance vs Transaction Assurance

Baobab SHALL distinguish:

```text
SESSION ASSURANCE

"How strongly was this session authenticated?"
```

from:

```text
OPERATION ASSURANCE REQUIREMENT

"How strongly must this actor authenticate
to perform this operation now?"
```

---

# 18. Assurance Decision

```text
Current Assurance
        │
        ▼
Required Assurance
        │
    ┌───┴────┐
    │        │
 sufficient insufficient
    │        │
    ▼        ▼
continue   STEP-UP
```

---

# 19. Step-Up Authentication

Step-up SHALL allow a currently authenticated user to satisfy stronger assurance without unnecessarily restarting the entire application journey.

Example:

```text
Jane logged in
BAOBAB-A1
     │
     ▼
Jane opens catalogue
     │
     ▼
allowed
     │
     ▼
Jane attempts high-value approval
     │
     ▼
requires BAOBAB-A3
     │
     ▼
STEP-UP
     │
     ▼
Passkey
     │
     ▼
BAOBAB-A3
     │
     ▼
Trade evaluates purchase authority
```

---

# 20. Step-Up Is Operation Driven

Step-up SHALL be triggered because:

```text
operation requires stronger assurance
```

or:

```text
current risk requires stronger assurance
```

not because the frontend randomly decides to display MFA.

---

# 21. Step-Up Result

Successful step-up SHALL produce updated trustworthy assurance evidence.

It SHALL NOT produce:

```text
new buyer role
new ERP role
new supplier approval
new tenant membership
```

---

# 22. Step-Up Failure

If required assurance cannot be obtained:

```text
operation
    │
    ▼
STEP_UP_REQUIRED
    │
    ▼
step-up unsuccessful
    │
    ▼
operation DENIED
```

The existing lower-risk session MAY remain usable where appropriate.

---

# 23. Step-Up Cancellation

A user cancelling step-up SHALL not necessarily be logged out.

Example:

```text
Jane cancels purchase approval
```

may return Jane to her ordinary authenticated session.

---

# 24. Recent Authentication

Certain operations require not only a strong method but a sufficiently recent authentication event.

Conceptually:

```text
required:
BAOBAB-A3
AND
auth_age <= 10 minutes
```

The actual thresholds SHALL be policy-configurable.

---

# 25. Why Authentication Age Matters

A session authenticated strongly eight hours ago may not provide sufficient assurance for:

```text
banking change
privilege elevation
credential reset
large financial approval
```

even if the original authentication was strong.

---

# 26. Risk-Based Authentication

Baobab SHALL support contextual risk evaluation.

Risk signals MAY increase required authentication assurance.

OWASP identifies signals such as new devices, unusual locations, suspicious IP reputation and abnormal behavior as appropriate inputs for adaptive authentication.

---

# 27. Risk Does Not Replace Authentication

Risk analysis SHALL supplement authentication.

It SHALL NOT turn:

```text
familiar IP address
```

into:

```text
authenticated identity
```

---

# 28. Risk Signals

Potential signals include:

```text
new device
new browser
unusual IP
IP reputation
anonymous proxy/Tor
unexpected geography
impossible travel
unusual login time
credential stuffing indicators
failed authentication burst
new authenticator
recent recovery
recent password reset
recent MFA reset
unusual context switch
privileged operation
high transaction value
abnormal behavior
```

---

# 29. Risk Signal Classification

Signals SHALL be classified as:

```text
LOW_CONFIDENCE
MEDIUM_CONFIDENCE
HIGH_CONFIDENCE
```

and:

```text
INFORMATIONAL
RISK_INCREASING
RISK_REDUCING
```

where useful.

No single weak signal SHOULD automatically determine identity legitimacy.

---

# 30. Risk Score

Baobab MAY compute an internal risk score.

Conceptually:

```text
device
+
network
+
behavior
+
account state
+
operation
+
recent security events
        │
        ▼
Risk Evaluation
        │
        ▼
LOW / MEDIUM / HIGH / CRITICAL
```

The exact implementation need not be a numeric score.

---

# 31. Risk Outcomes

Risk evaluation MAY result in:

```text
ALLOW_CURRENT_ASSURANCE

REQUIRE_REAUTHENTICATION

REQUIRE_A2

REQUIRE_A3

REQUIRE_A4

DENY

MANUAL_REVIEW

SECURITY_HOLD
```

depending on operation and context.

---

# 32. Risk-Based Authentication Is Not Authorization

Example:

```text
Jane has no purchase authority
```

Risk engine:

```text
LOW RISK
```

Result:

```text
DENY
```

Low authentication risk cannot create missing business permission.

---

# 33. Risk Cannot Lower Hard Minimums

If policy states:

```text
ERP administrator
requires BAOBAB-A3
```

a "trusted device" or familiar location SHALL NOT lower that requirement to A1.

Risk signals may increase minimum assurance.

They SHALL not silently weaken mandatory assurance.

---

# 34. Assurance Policy Hierarchy

Conceptually:

```text
PLATFORM MINIMUM
       │
       ▼
IDENTITY CLASS MINIMUM
       │
       ▼
DOMAIN MINIMUM
       │
       ▼
OPERATION MINIMUM
       │
       ▼
RISK ADJUSTMENT
       │
       ▼
FINAL REQUIRED ASSURANCE
```

The strongest applicable requirement wins.

---

# 35. Assurance Policy Examples

| Scenario | Baseline | Operation Requirement | Possible Risk Elevation |
|---|---|---|---|
| Public browsing | A0 | A0 | — |
| Ordinary B2C account | A1 | A1 | A2/A3 |
| B2C profile edit | A1 | A1/A2 | A2/A3 |
| Buyer representative | A2 preferred | A2 | A3 |
| Purchase approval | A2 | A3 | A3/A4 |
| Supplier banking change | A2 | A3 | A4 |
| ERP finance | A3 | A3 | A4 |
| CP administrator | A3 | A4 session | deny/high assurance |
| IAM administrator | A3 | A4 | deny/high assurance |
| Break-glass | dedicated policy | A4 | dedicated controls |

These are baseline architectural defaults; exact operational policy SHALL be versioned and reviewed.

---

# 36. B2C Policy

Ordinary B2C interactions SHOULD avoid unnecessary authentication friction.

For Thamani personal customers:

```text
public quote
public information
        │
        ▼
A0 where permitted

personal account
ordinary shipment activity
        │
        ▼
A1 minimum

sensitive profile/security change
        │
        ▼
A2/A3 step-up
```

---

# 37. B2C Passkeys

Thamani SHOULD offer passkeys to personal customers.

Passkeys can improve both:

```text
security
+
usability
```

by reducing password dependence while providing phishing-resistant public-key authentication.

WebAuthn Level 3 standardizes this public-key authentication model.

---

# 38. B2B Baseline

B2B representatives generally carry greater commercial authority than ordinary consumer accounts.

Therefore:

```text
buyer representatives
business logistics representatives
supplier representatives
```

SHOULD enroll an MFA-capable authenticator.

High-authority B2B roles SHALL require MFA.

---

# 39. ZuriBeans Buyer Roles

Illustrative policy:

```text
BUYER_VIEWER
    → A1/A2

PURCHASER
    → A2

BUYER_APPROVER
    → A2 baseline
    → A3 for sensitive approval

BUYER_ADMIN
    → A3

FINANCE
    → A3 for sensitive financial operations
```

Trade remains authoritative for these roles.

---

# 40. Purchase Approval

Example:

```text
Purchase Order
USD-equivalent 500
       │
       ▼
normal purchase policy
       │
       ▼
A2 sufficient
```

versus:

```text
Purchase Order
high-value / exceptional
       │
       ▼
Trade risk policy
       │
       ▼
A3 + recent authentication
```

Authentication policy SHALL not itself decide the commercial approval threshold.

Trade provides the domain risk/operation classification.

---

# 41. Thamani B2B Roles

Illustrative:

```text
TRACKING_ONLY
    → A1

SHIPPING_CLERK
    → A2 preferred

LOGISTICS_MANAGER
    → A2

BUSINESS_APPROVER
    → A3 for sensitive approval

BUSINESS_ADMIN
    → A3

FINANCE
    → A3 for financial changes
```

---

# 42. One Human, Different Assurance Requirements

Jane may simultaneously be:

```text
Personal Thamani Customer
Company A Logistics Manager
Company B Approver
```

Her identity remains one CanonicalIdentity.

But:

```text
personal tracking
```

may require A1 while:

```text
Company B financial approval
```

may require A3.

---

# 43. Supplier Representatives

Supplier representatives SHOULD use MFA.

The following SHOULD require phishing-resistant step-up:

```text
bank account change
legal entity change
tax identifier change
ownership/control change
primary administrator change
high-impact certification change
```

where domain policy classifies them as high risk.

---

# 44. Supplier Approval

Again:

```text
A3 authenticated supplier representative
        ≠
approved supplier
```

Supplier approval remains domain state.

---

# 45. Workforce

Baobab workforce identities SHALL use MFA.

Privileged workforce identities SHALL use phishing-resistant authentication.

Examples:

```text
platform administrators
IAM administrators
ERP administrators
finance administrators
security operators
production operators
```

---

# 46. ERP

Sensitive ERP operations SHALL require strong authentication.

Examples include:

```text
finance
accounting
payment configuration
user/role administration
system administration
```

A3 SHOULD be the default target for privileged ERP users.

---

# 47. CMS

Ordinary content editing MAY require A2.

Sensitive CMS operations such as:

```text
administrator management
authentication configuration
production publishing policy
integration secrets
```

SHOULD require A3 where exposed through CMS administration.

---

# 48. Control Plane

CP privileged administration SHALL require phishing-resistant authentication.

A CP administrator SHOULD normally operate at:

```text
BAOBAB-A4
```

for privileged administration.

---

# 49. IAM Administration

IAM administration represents one of the highest-risk privilege domains.

Required baseline:

```text
phishing-resistant authentication
+
recent authentication
+
restricted privileged session
```

---

# 50. Passkey-First Strategy

Baobab SHALL move progressively toward:

```text
PASSKEY-FIRST
```

rather than:

```text
PASSWORD-FIRST FOREVER
```

for human authentication.

This does not require immediate elimination of passwords.

---

# 51. Why Passkeys

WebAuthn credentials are public-key credentials scoped to a relying party and mediated by authenticators, providing a strong foundation for phishing-resistant authentication.

Baobab therefore considers passkeys strategically preferable to:

```text
password-only
SMS OTP
email OTP
TOTP-only
push-only
```

for high-assurance authentication.

---

# 52. Passkey Types

Baobab SHALL distinguish, where provider/platform information permits:

```text
synced passkey
device-bound credential
hardware security key
```

rather than assuming all WebAuthn credentials have identical operational characteristics.

---

# 53. User Verification

For high-assurance passkey authentication, user verification SHOULD be required.

Examples:

```text
device PIN
biometric unlock
```

performed by the authenticator.

---

# 54. Biometrics

Baobab applications SHALL NOT receive or store raw biometric data used by platform authenticators.

Conceptually:

```text
fingerprint / face
      │
      ▼
local authenticator
      │
      ▼
unlock cryptographic credential
      │
      ▼
WebAuthn proof
```

Baobab receives the cryptographic authentication result, not the user's fingerprint.

---

# 55. Attestation

Authenticator attestation MAY be used for specific high-security workforce use cases if justified.

It SHALL NOT be universally required for ordinary customers because of:

```text
privacy
compatibility
operational complexity
```

unless a separate risk assessment requires it.

---

# 56. TOTP

TOTP SHALL remain an acceptable transitional/secondary MFA mechanism for appropriate A2 scenarios.

It SHALL not be Baobab's preferred long-term high-assurance method.

---

# 57. SMS

SMS SHALL NOT be the preferred MFA method for privileged identities.

If supported for limited recovery or lower-risk populations, it SHALL be treated as lower assurance than phishing-resistant cryptographic authentication.

---

# 58. Email OTP

Email verification and email OTP SHALL not automatically be treated as high-assurance MFA.

Security depends partly on the security of the user's email account.

---

# 59. Push Authentication

If push authentication is introduced, simple:

```text
Approve / Deny
```

push SHALL not be considered equivalent to phishing-resistant WebAuthn.

Controls against MFA fatigue, such as number matching and rate limits, SHOULD be required. OWASP explicitly identifies push fatigue as an attack pattern.

---

# 60. Password Policy

Passwords remain a possible authentication mechanism where needed.

Existing ADR-IAM-0015 requirements remain:

```text
sufficient length
compromised-password screening
no arbitrary periodic rotation
no security questions
secure hashing
rate limiting
```

Provider implementation SHALL conform to current supported Ory capabilities.

---

# 61. Password + Password Is Not MFA

```text
password
+
security PIN
```

does not automatically constitute independent multi-factor authentication.

Factor independence matters.

---

# 62. Authenticator Enrollment

Authenticator enrollment is a security-sensitive operation.

Adding a new authenticator SHALL require appropriate assurance.

---

# 63. Enrollment Flow

```text
Authenticated user
      │
      ▼
request add authenticator
      │
      ▼
reauthenticate / existing factor
      │
      ▼
risk evaluation
      │
      ▼
enrol new authenticator
      │
      ▼
verify
      │
      ▼
security event
      │
      ▼
notification
```

---

# 64. No Session-Only Authenticator Replacement

An existing browser session alone SHOULD NOT be sufficient to replace a strong authenticator for a high-value account.

OWASP recommends requiring reauthentication with an existing enrolled factor and treating MFA factor replacement as a high-risk action.

---

# 65. Authenticator Removal

Removing the last strong authenticator SHALL require enhanced controls.

For privileged identities, the operation MAY require:

```text
another strong authenticator
+
recent authentication
+
administrative recovery
```

depending on circumstances.

---

# 66. Authenticator Downgrade Prevention

A compromised session SHALL not be able to convert:

```text
passkey-protected account
```

into:

```text
password-only account
```

without satisfying appropriate high-assurance controls.

---

# 67. Recovery Is High Risk

Account recovery SHALL be treated as a potential account-takeover event.

It is not merely a usability workflow.

---

# 68. Recovery Does Not Restore Authorization

Recovery restores the ability to authenticate as the identity.

It SHALL NOT restore:

```text
revoked buyer membership
disabled supplier authority
removed ERP role
suspended CanonicalIdentity
revoked admin privilege
```

---

# 69. Post-Recovery Assurance

After account recovery, Baobab MAY temporarily restrict assurance-sensitive operations.

Example:

```text
RECOVERY COMPLETE
      │
      ▼
identity accessible
      │
      ▼
high-risk operations restricted
      │
      ▼
strong authenticator enrolled
      │
      ▼
normal assurance restored
```

---

# 70. Recovery Risk Signals

Recovery risk evaluation MAY consider:

```text
new device
new IP
recent password change
recent MFA reset
unusual geography
multiple recovery attempts
privileged account
recent sensitive transaction
```

---

# 71. Recovery Notification

Users SHOULD receive security notifications when:

```text
password changed
MFA reset
passkey added
passkey removed
recovery completed
new high-assurance authenticator enrolled
```

where suitable contact channels exist.

---

# 72. Break-Glass Authentication

Break-glass identities SHALL have a dedicated assurance policy.

They SHALL NOT depend entirely on the same authentication infrastructure whose failure they are intended to recover.

---

# 73. Break-Glass Requirements

Potential requirements include:

```text
hardware-bound cryptographic authenticator
offline recovery procedure
two-person control
sealed credential process
explicit activation
short session
comprehensive audit
post-use credential rotation
```

The exact implementation SHALL be covered by operational security procedures.

---

# 74. Break-Glass Is Not Convenience Admin

Break-glass accounts SHALL not be used for ordinary administration.

Every use SHALL be exceptional and auditable.

---

# 75. Machine Identities

Human MFA concepts SHALL NOT be applied mechanically to workloads.

Workload assurance comes from:

```text
strong client authentication
private keys/certificates
mTLS where appropriate
short-lived credentials
audience restrictions
rotation
revocation
```

as governed by ADR-IAM-0007.

---

# 76. Human vs Workload Assurance

```text
HUMAN

passkey
MFA
step-up
recent authentication
```

versus:

```text
WORKLOAD

private key
certificate
client authentication
mTLS
credential rotation
```

They solve related but distinct authentication problems.

---

# 77. Enterprise Federation

Federated enterprise authentication MAY satisfy Baobab assurance requirements if the federation assertion provides sufficient trustworthy evidence.

Baobab SHALL not assume:

```text
enterprise SSO
=
strong MFA
```

without assurance information or contractual/configuration guarantees.

---

# 78. Federation Assurance Mapping

Conceptually:

```text
Enterprise IdP assurance
        │
        ▼
federation assertion
        │
        ▼
Baobab assurance mapping
        │
        ▼
BAOBAB-A?
```

Mappings SHALL be explicit.

---

# 79. Federation Downgrade

If the upstream IdP cannot demonstrate required assurance:

```text
operation requires A3
```

Baobab MAY require local Ory step-up where technically appropriate.

---

# 80. Context Changes

Certain context changes MAY trigger step-up.

Example:

```text
Jane
Personal Thamani context
      │
      ▼
switches to
Company A Finance
```

The switch may require stronger authentication depending on the target context.

---

# 81. Context Does Not Automatically Elevate Assurance

Selecting:

```text
Company A Finance
```

does not convert an A1 session into A3.

---

# 82. Assurance-Aware Context Activation

CP MAY respond:

```json
{
  "context": "company-a-finance",
  "status": "STEP_UP_REQUIRED",
  "required_assurance": "BAOBAB-A3"
}
```

The estate/BFF then initiates step-up through IAM.

---

# 83. Domain-Initiated Step-Up

Domain engines MAY identify operation-specific assurance requirements.

Example:

```text
Trade
  │
  ▼
purchase approval requires A3
  │
  ▼
STEP_UP_REQUIRED
```

The domain SHALL not implement the authentication ceremony itself.

---

# 84. Standard Step-Up Response

`shared` SHOULD define a provider-neutral step-up result.

Conceptually:

```json
{
  "code": "STEP_UP_REQUIRED",
  "required_assurance": "BAOBAB-A3",
  "reason": "HIGH_VALUE_APPROVAL"
}
```

---

# 85. Reason Codes

Reason codes SHOULD be stable machine-readable values such as:

```text
PRIVILEGED_OPERATION
HIGH_VALUE_TRANSACTION
SENSITIVE_PROFILE_CHANGE
PAYMENT_DETAILS_CHANGE
AUTHENTICATOR_CHANGE
ACCOUNT_RECOVERY
NEW_DEVICE_RISK
ANOMALOUS_LOGIN
ADMINISTRATION
```

---

# 86. Do Not Leak Risk Internals

The browser SHALL not necessarily receive:

```text
IP reputation score = 91
fraud rule #73 triggered
device confidence = 0.27
```

Such detail could aid attackers.

---

# 87. Risk Decision Transparency

Users SHOULD receive useful explanations where appropriate:

```text
For your security, please verify your identity again.
```

rather than exposing internal detection logic.

---

# 88. Risk Engine Boundary

Baobab SHALL not initially create an unnecessarily complex standalone "AI authentication risk engine."

Initial policy MAY use deterministic rules and provider signals.

A dedicated risk service MAY be introduced later through ADR if scale and evidence justify it.

---

# 89. Pulse Boundary

Baobab Pulse SHALL NOT autonomously grant authentication assurance or authorization.

Future intelligence from Pulse MAY contribute advisory risk signals only through an explicitly governed interface.

---

# 90. No Black-Box Authorization

A machine-learning risk score SHALL not become:

```text
risk score says allow
      │
      ▼
bypass domain authorization
```

This is prohibited.

---

# 91. Privacy and Risk Signals

Risk-based authentication SHALL minimize unnecessary surveillance.

Collection SHALL be:

```text
purpose-limited
proportionate
secured
retained appropriately
```

Device fingerprinting and behavioral data require particular privacy scrutiny.

---

# 92. Geolocation

Approximate location or network geography MAY be a risk signal.

It SHALL NOT be treated as conclusive evidence of identity.

VPNs, mobile networks and travel make location inherently imperfect.

---

# 93. Impossible Travel

"Impossible travel" SHALL be a risk signal, not an automatic declaration of compromise.

False positives may occur because of:

```text
VPN
corporate proxies
mobile carrier routing
cloud access
```

---

# 94. Trusted Device

A trusted device MAY reduce unnecessary prompts within policy.

It SHALL not bypass hard A3/A4 requirements.

---

# 95. Trusted Network

Corporate network presence MAY contribute to risk evaluation.

It SHALL not itself constitute authentication.

---

# 96. Risk and Accessibility

Adaptive authentication SHALL account for accessibility and legitimate user circumstances.

A security system that repeatedly locks out legitimate users because of assistive technology or changing devices is not production-grade.

---

# 97. Risk and Emerging Markets

Baobab operates in markets where users may:

```text
change devices
share connectivity
use mobile networks
travel cross-border
experience unstable connectivity
```

Risk policy SHALL avoid naïvely treating such behavior as malicious.

---

# 98. Cross-Border Context

For ZuriBeans and Thamani, cross-border usage is expected.

Therefore:

```text
country changed
```

is not inherently suspicious.

Risk SHALL consider the business context.

---

# 99. Transaction Risk

Authentication risk and transaction risk MAY interact.

Example:

```text
known device
+
A2 session
+
ordinary shipment
       │
       ▼
proceed
```

versus:

```text
new device
+
recent recovery
+
supplier bank account change
       │
       ▼
A3/A4 + additional safeguards
```

---

# 100. High-Value Transactions

High-value transaction thresholds SHALL belong to the relevant domain.

IAM receives:

```text
required_assurance
```

rather than becoming the authority for commodity prices, purchase limits or payment policy.

---

# 101. Transaction Binding

For very high-risk operations, future implementations MAY bind strong authentication to transaction details.

Example:

```text
Approve:
PO-12345
USD 250,000
Supplier XYZ
```

rather than merely:

```text
Authenticate again
```

This SHOULD be considered where business risk justifies it.

---

# 102. Assurance Caching

A recently achieved step-up MAY be reused for a bounded interval.

Example:

```text
A3 achieved
at 14:00

sensitive operations
until 14:10
```

where policy permits.

---

# 103. Assurance Cache Must Expire

Step-up SHALL not silently elevate the user's session indefinitely.

---

# 104. Assurance Downgrade

A session MAY return from:

```text
A3
```

to its baseline assurance for high-risk operations once the step-up validity window expires.

This may be implemented as:

```text
current assurance evidence
+
authentication age
```

rather than literally changing a stored level.

---

# 105. Session Assurance and BFF

Following ADR-IAM-0023, the BFF MAY cache trusted assurance metadata.

It SHALL NOT manufacture assurance.

---

# 106. Browser Cannot Assert Assurance

Prohibited:

```json
{
  "assurance": "BAOBAB-A4"
}
```

from browser JavaScript as authoritative input.

---

# 107. CP Assurance Use

CP MAY use assurance to determine whether a context can be activated or a platform capability exercised.

Example:

```text
CP admin context
requires A4
```

---

# 108. Domain Assurance Use

Domain engines MAY require assurance for specific operations.

Example:

```text
Trade:
approve high-value PO
requires A3
```

---

# 109. IAM Remains Authentication Authority

IAM/provider infrastructure determines whether the authentication ceremony satisfied the required assurance.

Trade does not verify passkeys.

ERP does not verify TOTP.

CP does not store password hashes.

---

# 110. Assurance Decision Flow

```text
REQUEST
   │
   ▼
Authenticated?
   │
   ├── NO → AUTHENTICATION_REQUIRED
   │
   ▼
Current assurance?
   │
   ▼
Required assurance?
   │
   ▼
Risk adjustment
   │
   ▼
Sufficient?
   │
 ┌─┴───────────┐
 │             │
YES            NO
 │             │
 ▼             ▼
Domain      STEP_UP
AuthZ          │
 │             ▼
 ▼        Authenticate
ALLOW/DENY     │
               ▼
          Re-evaluate
               │
               ▼
          Domain AuthZ
```

---

# 111. Recovery Decision Flow

```text
Recovery requested
       │
       ▼
identity lookup safely performed
       │
       ▼
risk evaluation
       │
       ▼
recovery proof
       │
       ▼
identity access restored
       │
       ▼
old sessions reviewed/revoked
       │
       ▼
strong authenticator re-established
       │
       ▼
security hold expires
```

---

# 112. Authenticator Lifecycle

```text
AVAILABLE
   │
   ▼
ENROLLED
   │
   ▼
VERIFIED
   │
   ▼
ACTIVE
   │
   ├──► SUSPENDED
   │
   ├──► COMPROMISED
   │
   └──► RETIRED
```

Provider implementation details MAY differ, but Baobab lifecycle semantics SHOULD remain understandable.

---

# 113. Lost Authenticator

Loss of an authenticator SHALL not automatically require creation of a new CanonicalIdentity.

Recovery operates against the existing identity.

---

# 114. Compromised Authenticator

A compromised authenticator SHALL be revocable independently of the CanonicalIdentity where possible.

Example:

```text
Jane
 ├── Passkey A ← COMPROMISED
 └── Passkey B ← ACTIVE
```

Jane remains the same person.

---

# 115. Multiple Authenticators

Users SHOULD be encouraged to register more than one strong authenticator where appropriate.

This reduces recovery dependence.

---

# 116. Privileged Users

Privileged users SHOULD have at least two independently usable phishing-resistant authenticators where operationally practical.

Example:

```text
platform passkey
+
backup hardware security key
```

---

# 117. Shared Authenticators

Privileged authenticators SHALL not be shared among administrators.

Audit requires individual accountability.

---

# 118. Shared Accounts

Shared human administrative accounts are prohibited except explicitly governed emergency cases.

Normal administration SHALL use named identities.

---

# 119. Credential Recovery for Privileged Users

Privileged recovery SHALL require stronger procedures than ordinary consumer recovery.

Potentially:

```text
verified administrator
+
security review
+
strong new authenticator
+
session revocation
+
audit
```

---

# 120. Administrative Reset

Administrators SHALL NOT be able to discover a user's password or authenticator secret.

Reset means:

```text
invalidate / re-enrol
```

not:

```text
retrieve credential
```

---

# 121. Security Notifications

Authentication events worthy of notification MAY include:

```text
new passkey
new MFA factor
factor removed
recovery
password change
new privileged login
unusual login
```

Notifications themselves SHALL not leak sensitive data.

---

# 122. Rate Limiting

Authentication and MFA endpoints SHALL be protected against:

```text
brute force
credential stuffing
OTP guessing
MFA fatigue
recovery abuse
```

---

# 123. MFA Prompt Bombing

Repeated challenge generation SHALL be rate limited and monitored.

An attacker SHALL not be able to send unlimited prompts hoping the user eventually approves one.

---

# 124. TOTP Guessing

TOTP verification SHALL be rate limited.

Short OTP entropy makes unrestricted online guessing unacceptable.

---

# 125. Credential Stuffing

Password authentication SHALL be protected using combinations of:

```text
rate limiting
compromised-password checks
anomaly detection
MFA
passkeys
bot controls
```

appropriate to the estate.

---

# 126. Lockout

Account lockout SHALL be designed carefully to avoid turning authentication into a denial-of-service primitive.

Progressive throttling MAY be preferable to simple permanent lockout.

---

# 127. Risk Escalation

Repeated failed authentication MAY transition:

```text
LOW
 ↓
MEDIUM
 ↓
HIGH
 ↓
TEMPORARY HOLD
```

according to policy.

---

# 128. Security Events

Canonical events SHOULD include concepts such as:

```text
authentication.succeeded
authentication.failed
step_up.required
step_up.succeeded
step_up.failed
authenticator.enrolled
authenticator.removed
authenticator.compromised
recovery.started
recovery.completed
risk.elevated
session.revoked
```

Provider-native events SHALL be normalized through `baobab-iam`.

---

# 129. Audit Evidence

For sensitive authentication decisions, audit SHOULD capture:

```text
CanonicalIdentity
session
requested assurance
achieved assurance
authentication age
risk decision
operation/context
outcome
correlation ID
timestamp
```

without storing credential secrets.

---

# 130. No Raw Biometric Audit

Logs SHALL NOT contain:

```text
fingerprints
face images
biometric templates
```

from platform authenticator operations.

---

# 131. No MFA Secret Logging

Never log:

```text
TOTP seed
recovery code
WebAuthn private key
password
session secret
access token
refresh token
```

---

# 132. Metrics

Monitor:

```text
authentication success rate
authentication failure rate
MFA adoption
passkey adoption
step-up frequency
step-up success/failure
recovery frequency
factor reset frequency
risk escalation
privileged authentication
credential stuffing indicators
```

---

# 133. UX Metrics

Security policy SHOULD also monitor excessive friction:

```text
abandoned authentication
failed passkey enrollment
recovery abandonment
repeated false-positive step-up
```

Security that users cannot successfully operate creates new risk.

---

# 134. Passkey Rollout

Passkeys SHOULD be introduced progressively.

Suggested sequence:

```text
IAM/security administrators
        │
        ▼
platform administrators
        │
        ▼
ERP privileged workforce
        │
        ▼
B2B administrators/approvers
        │
        ▼
supplier administrators
        │
        ▼
general workforce
        │
        ▼
B2C customers
```

Actual rollout MAY overlap.

---

# 135. Passwordless Rollout

Passkey support does not require immediate mandatory passwordless authentication.

Stages may be:

```text
OPTIONAL
   │
   ▼
PREFERRED
   │
   ▼
REQUIRED FOR PRIVILEGED
   │
   ▼
PASSWORDLESS WHERE APPROPRIATE
```

---

# 136. Migration From Keycloak

ADR-IAM-0022 migration SHALL preserve or improve assurance.

A user SHALL NOT move from:

```text
strong MFA
```

to:

```text
password-only
```

merely because their identity moved to Ory.

---

# 137. Migration Inventory

Before migrating a user, record:

```text
credential types
MFA enrollment
passkeys/WebAuthn
federation
privilege class
required target assurance
```

---

# 138. Credential Migration

Where credential types cannot be safely imported:

```text
identity migration
      │
      ▼
controlled authenticator re-enrolment
```

SHALL be preferred to security downgrade.

---

# 139. Migration Cohorts

Privileged users SHALL not be migrated until the target Ory configuration supports their required assurance.

---

# 140. Dual Provider Assurance

During Keycloak/Ory coexistence, Baobab SHALL normalize authentication assurance from both providers into the same Baobab assurance model.

```text
Keycloak evidence ─┐
                   ├──► BAOBAB-A*
Ory evidence ──────┘
```

---

# 141. No Provider Privilege Bias

An Ory-authenticated user SHALL not automatically receive greater authority than a Keycloak-authenticated user during migration, or vice versa.

Authorization remains canonical/domain based.

---

# 142. Failure Mode — Risk Service Unavailable

If a required risk decision cannot be obtained:

```text
low-risk operation
```

MAY proceed under predefined fallback policy.

For:

```text
privileged/high-risk operation
```

the system SHOULD fail closed or require the strongest defined assurance.

---

# 143. Failure Mode — Step-Up Unavailable

If required step-up cannot be completed because IAM is unavailable:

```text
sensitive operation
      │
      ▼
DENY / DEFER
```

Do not silently fall back to weaker authentication.

---

# 144. Failure Mode — Passkey Unavailable

Where policy permits alternatives:

```text
Passkey unavailable
       │
       ▼
approved alternate A2/A3 method
```

may be used.

Where phishing resistance is mandatory, a non-phishing-resistant fallback SHALL not silently satisfy the requirement.

---

# 145. Recovery Must Not Defeat MFA

A system with strong MFA and weak recovery is a weak system.

Therefore:

```text
authentication assurance
```

and:

```text
recovery assurance
```

SHALL be designed together.

---

# 146. Helpdesk Boundary

Support staff SHALL not be able to bypass strong authentication merely because a caller claims device loss.

High-risk recovery requires defined identity verification procedures.

---

# 147. Social Engineering Resistance

Administrative recovery procedures SHALL assume attackers may:

```text
impersonate users
possess personal information
control email
pressure support staff
```

Support workflows SHALL therefore be auditable and policy-driven.

---

# 148. Risk Policy Versioning

Risk and assurance policy SHALL be versioned.

A decision SHOULD be explainable as:

```text
policy_version = IAM-ASSURANCE-3
```

rather than relying on undocumented code behavior.

---

# 149. Policy as Code

Where practical, assurance requirements SHOULD be represented as auditable configuration/policy.

Example conceptual rule:

```yaml
operation: supplier.bank_details.change
minimum_assurance: BAOBAB-A3
max_authentication_age: 10m
risk_escalation:
  high: BAOBAB-A4
```

The specific policy engine/format is not mandated by this ADR.

---

# 150. Do Not Build a New Authorization Engine Accidentally

Authentication assurance policy SHALL not become a general-purpose replacement for:

```text
CP authorization
Trade authorization
ERP authorization
supplier-domain authorization
```

It answers:

> "How strongly must the actor authenticate?"

not:

> "What may the actor do?"

---

# 151. Policy Ownership

Recommended ownership:

```text
Baobab Security Architecture
    → assurance classes

IAM
    → authentication mechanism capability

CP
    → platform/context assurance requirements

Domain
    → operation sensitivity

Risk policy
    → contextual escalation
```

---

# 152. Decision Composition

```text
Domain says:
operation sensitivity = HIGH

CP says:
context = FINANCE

IAM says:
session assurance = A2

Risk says:
risk = MEDIUM

Policy says:
required assurance = A3

Result:
STEP_UP_REQUIRED
```

---

# 153. Security Decision Record

For high-risk operations:

```json
{
  "current_assurance": "BAOBAB-A2",
  "required_assurance": "BAOBAB-A3",
  "risk": "MEDIUM",
  "decision": "STEP_UP_REQUIRED",
  "reason": "SENSITIVE_FINANCIAL_OPERATION"
}
```

---

# 154. UI Contract

The Digital Estate SHALL receive enough information to render the required authentication UX.

Example:

```json
{
  "code": "STEP_UP_REQUIRED",
  "required_assurance": "BAOBAB-A3",
  "supported_methods": [
    "passkey"
  ]
}
```

It SHALL not receive unnecessary risk internals.

---

# 155. UX Example

Instead of:

```text
Error 847:
ACR insufficient
```

show:

```text
Please verify your identity with your passkey
before approving this transaction.
```

---

# 156. Accessibility of MFA

Authentication SHALL provide accessible alternatives where technically and security-wise appropriate.

Users SHALL not be forced into inaccessible biometric or device interactions without a viable secure alternative.

---

# 157. Authentication Method Discovery

The estate SHOULD discover permitted authentication methods from IAM policy/provider capability rather than hard-coding:

```text
TOTP always exists
```

---

# 158. Capability Negotiation

Conceptually:

```text
required assurance
        │
        ▼
available authenticators
        │
        ▼
eligible methods
        │
        ▼
user chooses / policy selects
```

---

# 159. Preferred Method

If a passkey can satisfy the requirement:

```text
passkey
```

SHOULD generally be preferred over weaker methods for high-risk operations.

---

# 160. Authenticator Naming

Users SHOULD be able to distinguish their authenticators.

Example:

```text
MacBook Passkey
YubiKey Backup
Android Passkey
```

without exposing security-sensitive internal metadata.

---

# 161. Authenticator Inventory

Account security UX SHOULD show:

```text
active authenticators
enrollment date
last-used date where available
device/name
remove/revoke action
```

subject to provider capabilities.

---

# 162. Session Inventory

High-value accounts SHOULD be able to review active sessions where provider/session architecture supports it.

---

# 163. "Log Out Everywhere"

Users SHOULD have a mechanism to revoke other sessions where appropriate.

For compromised accounts this is a significant recovery control.

---

# 164. Privileged Session Duration

A4 sessions SHOULD have shorter validity than ordinary customer sessions.

NIST SP 800-63B-4 similarly applies tighter reauthentication expectations as assurance rises; its summary recommends shorter overall and inactivity windows for AAL3 than AAL2.

Baobab SHALL define its own thresholds rather than automatically copying NIST's federal-system values.

---

# 165. Default Session Policy

Illustrative defaults:

```text
A1
ordinary estate session
longer bounded duration

A2
business session
moderate duration

A3
strong authenticated session
shorter sensitive-operation window

A4
privileged session
short inactivity + recent-auth requirement
```

Exact durations SHALL be defined through policy configuration.

---

# 166. Production Assurance Matrix

| Actor/Operation | Minimum Target |
|---|---:|
| Anonymous visitor | A0 |
| Ordinary authenticated B2C | A1 |
| Personal security settings | A2 |
| B2B purchaser | A2 |
| Buyer approver sensitive action | A3 |
| Buyer administrator | A3 |
| Supplier administrator | A2/A3 |
| Supplier banking change | A3 |
| Thamani business admin | A3 |
| ERP finance | A3 |
| CMS administrator | A3 |
| CP administrator | A4 |
| IAM administrator | A4 |
| Break-glass | Dedicated A4+ controls |

---

# 167. Security Invariants

The following SHALL remain true:

```text
Authentication ≠ Authorization

MFA ≠ Business Permission

Passkey ≠ Tenant Membership

Passkey ≠ Buyer Approval

Passkey ≠ Supplier Approval

A3 ≠ Administrator

A4 ≠ Superuser

Risk Score ≠ Authorization

Trusted Device ≠ Identity

Trusted Network ≠ Identity

Location ≠ Identity

Recovery ≠ Privilege Restoration

Authenticator ≠ CanonicalIdentity

Provider Identity ≠ CanonicalIdentity

Session Assurance ≠ Permanent Identity Property

Strong Authentication ≠ Unlimited Session

Step-Up ≠ Privilege Elevation
```

---

# 168. Implementation Gates

## IAM-A0 — Assurance Inventory

Audit current:

```text
password policy
OTP
MFA
WebAuthn/passkeys
federation
recovery
session assurance
Keycloak implementation
Ory capabilities
```

Map current state against ADR-IAM-0015 and ADR-IAM-0019–0023.

---

## IAM-A1 — Shared Assurance Contract

Define:

```text
AssuranceLevel
AuthenticationEvidence
AuthenticationMethod
StepUpRequirement
RiskDecision
```

in provider-neutral shared contracts.

---

## IAM-A2 — Ory Assurance Mapping

Map supported Kratos/Hydra authentication evidence to:

```text
BAOBAB-A1
BAOBAB-A2
BAOBAB-A3
```

without leaking provider semantics into domains.

---

## IAM-A3 — MFA Foundation

Implement/test:

```text
TOTP
approved MFA combinations
factor enrollment
factor removal
factor recovery
```

---

## IAM-A4 — Passkey Foundation

Implement/test:

```text
WebAuthn
passkey registration
passkey authentication
user verification
multiple authenticators
revocation
```

---

## IAM-A5 — Step-Up Protocol

Implement:

```text
STEP_UP_REQUIRED
required_assurance
reason
authentication flow
post-step-up retry
```

---

## IAM-A6 — CP Assurance Integration

Enable CP to enforce assurance for:

```text
privileged context
sensitive capability
context activation
```

---

## IAM-A7 — Domain Assurance Integration

Integrate:

```text
Trade
ERP
CMS
supplier domain
Thamani domain
```

without moving business authorization into IAM.

---

## IAM-A8 — Risk-Based Authentication

Implement initial deterministic risk policy:

```text
new device
security events
recovery
failed authentication
network reputation where available
operation sensitivity
```

Avoid premature ML complexity.

---

## IAM-A9 — Recovery Hardening

Implement:

```text
secure recovery
factor reset
security notification
session revocation
post-recovery controls
```

---

## IAM-A10 — Privileged Authentication

Enforce phishing-resistant authentication for:

```text
IAM
CP
ERP privileged
production administration
security operations
```

---

## IAM-A11 — ZuriBeans

Implement/test:

```text
buyer MFA
approver step-up
buyer admin passkeys
high-risk purchasing
```

---

## IAM-A12 — Thamani

Implement/test both:

```text
B2C passkeys / adaptive auth
```

and:

```text
B2B MFA / step-up / context-sensitive assurance
```

---

## IAM-A13 — Supplier Assurance

Implement:

```text
supplier admin MFA
banking-change step-up
representative recovery
```

---

## IAM-A14 — Keycloak-to-Ory Migration

Verify no assurance downgrade during ADR-IAM-0022 migration.

---

## IAM-A15 — Observability and Security Testing

Implement:

```text
assurance audit
MFA attack tests
recovery abuse tests
step-up tests
risk-policy tests
passkey tests
```

---

## IAM-A16 — Production Hardening

Perform:

```text
penetration testing
phishing-resistance verification
recovery exercise
privileged-account exercise
break-glass exercise
policy review
```

---

# 169. Required Test Matrix

At minimum:

| Test | Expected |
|---|---|
| A1 user performs A1 operation | Allow if authorized |
| A1 user performs A3 operation | Step-up |
| A3 user lacks business permission | Deny |
| A3 session too old | Step-up |
| Passkey succeeds | Appropriate assurance |
| TOTP succeeds | Appropriate A2 assurance |
| MFA cancelled | Sensitive operation denied |
| Suspended identity passes authentication | Deny |
| High risk + A1 | Step-up/deny |
| Trusted device + mandatory A3 | Still A3 |
| Recovery succeeds | No automatic privilege restoration |
| New authenticator added | Audit + notification |
| Authenticator removed | Audit + appropriate reauth |
| Wrong context | Deny |
| Browser claims A4 | Ignore/reject |
| Risk service unavailable on privileged op | Fail safe |
| Keycloak/Ory equivalent auth | Same Baobab assurance semantics |

---

# 170. Production Readiness Checklist

### Assurance Model

- [ ] A0–A4 defined
- [ ] provider-neutral representation implemented
- [ ] assurance not confused with authorization
- [ ] authentication age supported
- [ ] assurance policy versioned

### MFA

- [ ] MFA available
- [ ] privileged MFA mandatory
- [ ] factor independence enforced
- [ ] factor enrollment protected
- [ ] factor replacement protected
- [ ] factor removal protected

### Passkeys

- [ ] WebAuthn supported
- [ ] user verification policy defined
- [ ] multiple authenticators supported
- [ ] authenticator revocation supported
- [ ] privileged passkey policy enforced

### Step-Up

- [ ] provider-neutral step-up contract
- [ ] recent-authentication requirements
- [ ] retry flow
- [ ] cancellation behavior
- [ ] no privilege elevation side effect

### Risk

- [ ] initial risk signals defined
- [ ] risk cannot reduce mandatory assurance
- [ ] high-risk fallback defined
- [ ] privacy review complete
- [ ] false-positive monitoring

### Recovery

- [ ] recovery treated as high risk
- [ ] no privilege restoration
- [ ] old sessions handled
- [ ] strong authenticator re-enrollment
- [ ] security notifications
- [ ] privileged recovery process

### Domains

- [ ] ZuriBeans buyer assurance
- [ ] purchase approval step-up
- [ ] Thamani B2C assurance
- [ ] Thamani B2B assurance
- [ ] supplier assurance
- [ ] ERP privileged assurance
- [ ] CMS privileged assurance
- [ ] CP/IAM privileged assurance

### Migration

- [ ] Keycloak assurance inventoried
- [ ] Ory equivalent mapped
- [ ] no MFA downgrade
- [ ] passkey migration/re-enrollment defined
- [ ] dual-provider assurance normalized

### Operations

- [ ] security events
- [ ] metrics
- [ ] alerting
- [ ] penetration tests
- [ ] recovery exercise
- [ ] break-glass exercise

---

# 171. Final Architecture

```text
                          HUMAN
                            │
                            ▼
                   Digital Estate UX
                            │
                            ▼
                     Estate BFF
                            │
                            ▼
                ┌─────────────────────┐
                │        ORY          │
                │                     │
                │ Password            │
                │ TOTP                │
                │ Passkey/WebAuthn    │
                │ Federation          │
                │ Recovery            │
                └──────────┬──────────┘
                           │
                   authentication
                     evidence
                           │
                           ▼
                ┌─────────────────────┐
                │     baobab-iam      │
                │                     │
                │ Assurance Mapping   │
                │ Risk Policy         │
                │ Lifecycle           │
                │ Events              │
                └──────────┬──────────┘
                           │
                   BAOBAB-A*
                           │
                           ▼
                ┌─────────────────────┐
                │     baobab-cp       │
                │                     │
                │ CanonicalIdentity   │
                │ Context             │
                │ Capability          │
                │ Assurance Policy    │
                └──────────┬──────────┘
                           │
                  ┌────────┼────────┐
                  ▼        ▼        ▼
                Trade     ERP      CMS
                  │        │        │
                  └── Domain AuthZ ─┘

If assurance insufficient:

Domain / CP
     │
     ▼
STEP_UP_REQUIRED
     │
     ▼
Estate BFF
     │
     ▼
Ory
     │
     ▼
Passkey / MFA
     │
     ▼
Higher Assurance
     │
     ▼
RE-EVALUATE AUTHORIZATION
```

---

# 172. Consequences

## Positive

This architecture gives Baobab:

- explicit authentication assurance semantics;
- phishing-resistant privileged authentication;
- a strategic path toward passkey-first identity;
- controlled MFA rather than indiscriminate MFA prompts;
- transaction-sensitive step-up;
- B2B and B2C policies appropriate to different risk profiles;
- provider-neutral assurance;
- stronger recovery security;
- consistent assurance across CP and domains;
- reduced dependence on passwords;
- a controlled path from Keycloak assurance to Ory assurance.

## Costs

Baobab must maintain:

- assurance policy;
- step-up contracts;
- provider assurance mappings;
- authenticator lifecycle;
- risk evaluation;
- recovery controls;
- security telemetry;
- domain assurance classifications.

This is justified because authentication assurance is a platform security capability rather than an incidental login-page concern.

## Risks

The largest architectural risks are:

```text
over-engineered risk scoring
under-secured recovery
MFA fatigue
provider-specific assurance coupling
false positives
excessive user friction
authorization accidentally moved into IAM
```

The controls in this ADR explicitly address these risks.

---

# 173. Final Decision Principle

Baobab SHALL no longer model authentication as:

```text
LOGGED IN
or
NOT LOGGED IN
```

The platform SHALL model:

```text
WHO?
    │
    ▼
CanonicalIdentity

HOW STRONGLY AUTHENTICATED?
    │
    ▼
Authentication Assurance

UNDER WHAT CONDITIONS?
    │
    ▼
Risk

IN WHICH CONTEXT?
    │
    ▼
Control Plane

WHAT ACTION IS REQUESTED?
    │
    ▼
Domain

IS CURRENT ASSURANCE SUFFICIENT?
    │
    ├── NO → STEP-UP
    │
    ▼
YES

IS THE ACTOR AUTHORIZED?
    │
    ├── NO → DENY
    │
    ▼
YES → ALLOW
```

Passkeys are the preferred strategic authentication mechanism for high-assurance human access.

MFA remains an important control.

Risk may increase authentication requirements.

Step-up provides stronger assurance when needed.

Recovery receives the same security seriousness as login.

But none of these mechanisms determine business authority.

> **Authenticate according to risk. Step up according to consequence. Prefer phishing resistance. Preserve usability. Never confuse assurance with authority.**