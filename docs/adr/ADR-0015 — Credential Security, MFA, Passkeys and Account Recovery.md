# ADR-0015: Credential Security, MFA, Passkeys and Account Recovery

**Status:** Proposed  
**Date:** 2026-09-08  
**Decision Owners:** NABHOLD / Baobab Platform Architecture and Security  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Related Repositories:** `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/shared`, `baobab-platform/infrastructure`, Digital Estate repositories  
**Primary Runtime Owner:** `baobab-platform/baobab-iam`  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** Passwords, passkeys, WebAuthn, MFA, authentication assurance, step-up authentication, authenticator enrollment, recovery codes, credential recovery, credential reset, lost-device handling, privileged recovery, service credentials, credential migration, compromise response and credential-related audit  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:** ADR-0001 through ADR-0014

---

# 1. Context

Baobab serves several materially different actor classes:

```text
Workforce
B2B buyer representatives
B2C customers
Supplier representatives
Privileged administrators
External professionals
Workloads/services
```

These identities do not have equal risk.

For example:

```text
Thamani customer
      ≠
ERP finance administrator
```

and:

```text
supplier catalog viewer
      ≠
supplier administrator changing bank details
```

Baobab therefore requires a platform-wide credential-security policy that centralizes authentication without imposing an unnecessarily rigid user experience.

The architecture must support:

- passwords;
- passwordless authentication;
- passkeys;
- WebAuthn;
- multifactor authentication;
- authentication assurance;
- step-up authentication;
- account recovery;
- credential compromise;
- recovery codes;
- credential migration;
- machine credentials;
- privileged emergency recovery.

---

# 2. Decision

Baobab IAM SHALL be the principal authority for human authentication credentials.

Keycloak SHALL manage, as applicable:

```text
passwords
passkeys
WebAuthn credentials
TOTP credentials
recovery codes
authentication sessions
credential reset
identity-provider federation
authentication assurance
```

Domain engines SHALL NOT independently become competing credential authorities for Baobab-managed human identities.

---

# 3. Governing Principle

> **Credential strength shall be proportional to risk, phishing-resistant authentication shall be preferred, recovery shall never become an authorization bypass, and no downstream engine shall recreate a second identity-security system.**

---

# 4. Credential Authority

The normal human credential hierarchy SHALL be:

```text
Human
  │
  ▼
Baobab IAM
  │
  ▼
Authentication
  │
  ▼
OIDC / OAuth assertion
  │
  ▼
Baobab services and engines
```

Passwords SHALL NOT be passed from a Digital Estate to an engine for independent validation.

---

# 5. Supported Human Authenticator Categories

Baobab MAY support:

| Authenticator | Intended Role |
|---|---|
| Password | Baseline/fallback authentication |
| Passkey | Preferred passwordless/phishing-resistant authentication |
| Security-key WebAuthn | High-assurance privileged authentication |
| Platform WebAuthn authenticator | Strong workforce/customer authentication |
| TOTP | MFA fallback where passkeys/WebAuthn are unavailable |
| Recovery codes | Controlled recovery fallback |
| Federated enterprise IdP | Workforce/B2B federation |
| Social IdP | Optional B2C authentication |

---

# 6. Phishing Resistance

Phishing-resistant authenticators SHOULD be preferred for:

```text
IAM administrators
Control Plane administrators
ERP administrators
finance users
production infrastructure administrators
security administrators
break-glass identities
```

Passkeys and WebAuthn security keys SHOULD therefore become the preferred privileged authentication mechanisms.

---

# 7. Passkeys

Baobab SHALL support a trajectory toward passkey-first authentication.

Passkeys MAY be:

```text
device-bound
```

or, where supported by the authenticator ecosystem:

```text
syncable
```

The chosen policy MAY differ according to assurance level.

---

# 8. Passkeys Are Public-Key Credentials

The authentication architecture SHALL treat passkeys as public-key credentials.

Private credential material SHALL remain under authenticator/platform control and SHALL NOT be stored in Baobab application databases.

---

# 9. Passwordless Login

Baobab SHOULD support passwordless login for actor classes where user experience and risk policy make it suitable.

Potential early candidates:

```text
workforce
privileged administrators
Thamani customers
supplier administrators
Zuribeans buyer administrators
```

---

# 10. Passkey-First Does Not Mean Password Elimination Immediately

Migration MAY initially support:

```text
passkey
OR
password + MFA
```

before passwordless authentication becomes broadly preferred.

---

# 11. Password Policy

Where passwords remain enabled, Baobab SHALL favor:

- sufficient length;
- password-manager compatibility;
- passphrases;
- breached/common-password blocking;
- secure hashing;
- no unnecessary complexity rituals.

Current NIST guidance requires at least 15 characters when a password is the sole factor, permits a lower minimum of eight characters when it is only one factor in MFA, recommends support for at least 64 characters, rejects mandatory composition rules, and rejects routine periodic password changes absent evidence of compromise.

Baobab SHOULD adopt the stronger practical baseline where compatible with Keycloak and user experience.

---

# 12. Password Length

Recommended Baobab baseline:

```text
single-factor capable password:
minimum 15 characters

password always combined with MFA:
minimum MAY be lower,
but SHOULD remain reasonably strong
```

The exact Keycloak configuration SHALL be documented as code/configuration.

---

# 13. Maximum Password Length

Baobab SHOULD support long passwords and passphrases.

Implementations SHOULD permit at least:

```text
64 characters
```

unless an unavoidable upstream limitation exists.

---

# 14. Password Composition Rules

Baobab SHALL NOT require arbitrary rules such as:

```text
one uppercase
one lowercase
one digit
one symbol
change every 30 days
```

merely as security theater.

---

# 15. Common and Compromised Password Blocking

Password enrollment and reset SHALL reject known weak or compromised choices using an approved password blocklist or equivalent mechanism.

---

# 16. Password Rotation

Routine mandatory password rotation SHALL NOT be the normal policy.

Password change SHALL instead be required when:

- compromise is suspected;
- credential exposure is detected;
- administrator-directed incident response requires it;
- credential migration requires reset.

---

# 17. Security Questions

Knowledge-based security questions SHALL NOT be used.

Examples prohibited:

```text
mother's maiden name
first school
first pet
birth city
```

They are unsuitable as authenticators or recovery mechanisms.

---

# 18. Password Hints

Baobab SHALL NOT expose password hints.

---

# 19. Password Storage

Passwords SHALL remain under Keycloak's credential-storage mechanisms.

Baobab applications SHALL NOT:

- persist plaintext passwords;
- log passwords;
- cache passwords;
- copy password hashes into application databases.

---

# 20. Password Transport

Credentials SHALL only traverse authenticated encrypted channels.

TLS SHALL be mandatory for production authentication traffic.

---

# 21. MFA Architecture

MFA requirements SHALL be risk-based.

Baobab SHALL define at least four assurance classes:

| Class | Example |
|---|---|
| Standard | Ordinary low-risk external users |
| Enhanced | Buyer/supplier admins, sensitive account holders |
| Privileged | Finance, platform admins, engine admins |
| Critical | IAM/security/break-glass access |

---

# 22. Standard Authentication

Standard users MAY initially authenticate with:

```text
password
```

or:

```text
passkey
```

depending on Digital Estate policy.

Examples include ordinary Thamani customers.

---

# 23. Enhanced Authentication

Enhanced users SHOULD require MFA or passkey-based strong authentication.

Examples:

```text
Zuribeans buyer administrator
purchase approver
supplier administrator
supplier finance contact
```

---

# 24. Privileged Authentication

Privileged interactive access SHALL require MFA.

Examples:

```text
CP admin
Medusa admin
iDempiere finance user
iDempiere administrator
CMS administrator/publisher
Pulse administrator
production operator
```

---

# 25. Critical Authentication

Critical identities SHOULD require phishing-resistant authentication wherever operationally feasible.

Examples:

```text
Keycloak realm administrator
IAM security administrator
highest-level production administrator
break-glass administrator
```

---

# 26. MFA Does Not Grant Authorization

This remains binding:

```text
MFA success
   ≠
authorization grant
```

MFA establishes authentication assurance.

Authorization remains with CP/domain engines.

---

# 27. Preferred MFA Order

Baobab SHOULD prefer:

```text
1. Passkey / WebAuthn
2. Hardware security key
3. TOTP
4. Recovery method
```

subject to actor class and operational needs.

---

# 28. SMS

SMS SHALL NOT be the preferred privileged MFA mechanism.

If introduced for specific low-risk consumer scenarios, it SHALL be treated as a weaker recovery/authentication factor and documented accordingly.

---

# 29. Email as MFA

Email access alone SHOULD NOT be considered a strong second authentication factor.

Email MAY be used for:

- verification;
- notifications;
- recovery initiation;

but SHALL not be confused with phishing-resistant MFA.

---

# 30. TOTP

TOTP MAY be supported as a fallback factor.

TOTP secrets SHALL:

- be generated securely;
- be displayed only during enrollment;
- be protected by IAM;
- never be logged;
- be revocable.

---

# 31. TOTP Enrollment

Enrollment SHALL require an already authenticated session.

Privileged users MAY be required to reauthenticate or step up before adding a new authenticator.

---

# 32. WebAuthn Enrollment

Adding a WebAuthn authenticator SHALL be treated as a sensitive security action.

The system SHOULD require:

```text
recent authentication
```

and, for privileged users:

```text
existing strong authenticator
```

where feasible.

---

# 33. Authenticator Naming

Users SHOULD be allowed to assign recognizable labels such as:

```text
MacBook passkey
Office security key
Android phone
```

without exposing sensitive device identifiers unnecessarily.

---

# 34. Multiple Authenticators

Users SHOULD be able to register multiple strong authenticators.

This reduces lockout risk.

Privileged users SHOULD be encouraged to maintain at least two viable strong authentication paths.

---

# 35. Authenticator Removal

Removing an authenticator SHALL require recent authentication.

Removing the final strong authenticator from a privileged account SHOULD require stronger verification or administrator workflow.

---

# 36. Last-Authenticator Protection

Baobab SHALL prevent accidental security downgrade.

Example:

```text
privileged account
has 1 security key
```

Deleting that key SHALL not silently leave a weak password-only account if policy requires MFA.

---

# 37. Step-Up Authentication

Baobab SHALL support step-up authentication for operations whose risk exceeds the assurance of the current session.

---

# 38. Step-Up Examples

Candidate actions include:

```text
grant privileged role
reset administrator MFA
change supplier bank details
approve high-value purchase
approve supplier
post journal
release payment
close accounting period
change authentication email
link external IdP
rotate client credential
suspend tenant
invoke impersonation
```

---

# 39. Step-Up Decision Flow

```text
User has active session
        │
        ▼
Requests sensitive operation
        │
        ▼
Required assurance satisfied?
     ┌──┴──┐
    YES    NO
     │      │
     │      ▼
     │   IAM step-up
     │      │
     └──┬───┘
        ▼
Domain authorization
        │
        ▼
ALLOW / DENY
```

---

# 40. Assurance Claims

Applications MAY use standardized identity information including:

```text
acr
amr
auth_time
```

to determine whether the session satisfies policy.

Custom claims SHALL be versioned through `baobab-platform/shared`.

---

# 41. Authentication Age

High-risk operations MAY require authentication within a maximum age.

For example:

```text
recent authentication required
```

rather than accepting a session created many hours earlier.

Exact limits SHALL be risk-based and centrally configurable.

---

# 42. Reauthentication

Reauthentication SHOULD occur through IAM.

Applications SHOULD NOT implement their own:

```text
enter your password again
```

mechanisms if standard IAM step-up can satisfy the requirement.

---

# 43. Session Strength

A successful stronger authentication event MAY elevate the assurance of a session.

It SHALL NOT expand business permissions.

---

# 44. MFA Enrollment Policy

MFA enrollment SHOULD occur:

```text
during workforce onboarding
```

for mandatory actor classes.

For consumer users, enrollment MAY be:

```text
optional but encouraged
```

until product/security policy changes.

---

# 45. Workforce MFA

MFA SHALL be mandatory for workforce users with privileged production or business access.

Ordinary workforce SHOULD also adopt MFA as the standard posture.

---

# 46. Supplier MFA

Supplier administrators SHOULD require MFA.

Other supplier representatives MAY initially use standard authentication unless their role exposes sensitive functionality.

---

# 47. Supplier Finance MFA

Supplier representatives permitted to modify financial or banking information SHALL require:

```text
MFA
+
step-up for sensitive change
```

---

# 48. Zuribeans B2B MFA

Buyer administrators and purchase approvers SHOULD use enhanced authentication.

High-value approval workflows MAY require fresh step-up.

---

# 49. Thamani B2C MFA

Thamani SHALL not initially require traditional MFA for every customer unless risk evidence justifies the friction.

Passkeys SHOULD provide a lower-friction path to stronger authentication.

---

# 50. B2C Risk-Based Step-Up

Thamani MAY require stronger authentication for:

- primary email changes;
- credential linking;
- high-risk account changes;
- abnormal account activity;
- unusually sensitive commerce operations.

---

# 51. Account Recovery

Account recovery SHALL restore control of the authentication identity.

It SHALL NOT restore independently revoked business authority.

---

# 52. Governing Recovery Invariant

```text
Credential Recovery
      ≠
Authorization Recovery
```

---

# 53. Recovery Entry Points

Recovery MAY begin through:

```text
Thamani
Zuribeans
supplier portal
workforce application
IAM account console
```

but SHALL converge on the Baobab IAM recovery authority.

---

# 54. Recovery Enumeration Resistance

Recovery endpoints SHOULD avoid revealing whether an account exists.

Prefer responses equivalent to:

```text
If an eligible account exists,
recovery instructions will be sent.
```

---

# 55. Recovery Tokens

Recovery links/tokens SHALL be:

- cryptographically strong;
- short-lived;
- single-purpose;
- single-use;
- securely transported;
- excluded from logs.

---

# 56. Recovery Token Replay

A used recovery token SHALL become invalid.

---

# 57. Recovery Token Scope

A password reset token SHALL NOT authorize:

```text
change tenant membership
grant buyer-admin
grant supplier-admin
grant ERP role
```

---

# 58. Recovery Codes

Where enabled, recovery codes SHALL be:

- high entropy;
- single-use;
- generated securely;
- shown only during issuance/regeneration;
- stored securely in derived/appropriate form;
- revocable.

---

# 59. Recovery-Code Regeneration

Generating new recovery codes SHALL invalidate the previous set.

---

# 60. Recovery Codes for Privileged Accounts

Recovery codes MAY be permitted for privileged identities, but storage and use SHALL receive stronger policy.

Security keys/passkeys plus a separately secured backup authenticator are preferable.

---

# 61. Lost Device

Lost-authenticator handling SHALL distinguish between:

```text
lost one authenticator
```

and:

```text
lost all authentication factors
```

---

# 62. Lost One Authenticator

If another enrolled strong authenticator remains:

```text
authenticate
   │
   ▼
remove lost authenticator
   │
   ▼
register replacement
```

---

# 63. Lost All Authenticators

Full recovery SHALL require stronger verification.

For ordinary consumers this may use verified recovery channels.

For privileged/workforce identities, helpdesk or security-assisted verification MAY be required.

---

# 64. Privileged Recovery

Privileged recovery SHALL be treated as a high-risk administrative event.

It SHOULD require:

- strong identity verification;
- named administrator involvement;
- reason;
- audit;
- user notification;
- session revocation;
- review of recent activity.

---

# 65. Helpdesk Recovery

Helpdesk staff SHALL NOT be able to bypass IAM controls through an undocumented override.

---

# 66. Helpdesk Role Separation

A helpdesk user permitted to initiate/reset recovery SHALL NOT automatically possess:

```text
IAM security admin
CP platform admin
ERP admin
```

authority.

---

# 67. MFA Reset

Resetting another person's MFA SHALL be a privileged action.

---

# 68. MFA Reset Effects

For privileged users, MFA reset SHOULD:

- revoke relevant sessions;
- generate a security alert;
- require reenrollment;
- create a security audit event.

---

# 69. Recovery Does Not Preserve Suspicious Sessions

After high-risk account recovery, active sessions SHOULD normally be revoked.

---

# 70. Primary Email Recovery

Changing a primary authentication email during recovery SHALL require careful proofing.

Email SHALL not become identity authority merely because it is the recovery channel.

---

# 71. External IdP Recovery

For identities authenticated solely by an upstream IdP:

```text
Baobab
```

may not own the credential recovery process.

Recovery should occur with that IdP unless Baobab manages additional authenticators.

---

# 72. Federated Workforce Recovery

Enterprise workforce federation MAY delegate password recovery upstream.

Baobab SHALL still control:

- Baobab memberships;
- application entitlements;
- local security sessions where applicable.

---

# 73. Social Login Recovery

For social-only Thamani accounts, recovery may depend on the social provider.

Baobab SHOULD encourage linking an additional approved authentication path where useful.

---

# 74. Identity Linking

Adding another login identity is security-sensitive.

It SHALL require:

- authenticated account;
- sufficient assurance;
- validation of new identity;
- explicit linking operation.

---

# 75. Same Email Does Not Authorize Linking

This remains binding:

```text
same email
    ≠
safe identity link
```

---

# 76. Credential Lifecycle

Human credentials SHOULD support lifecycle states such as:

```text
ENROLLED
ACTIVE
COMPROMISED
REVOKED
REPLACED
```

using native IAM semantics where possible.

---

# 77. Credential Compromise

If compromise is suspected:

```text
identify affected credential
       │
       ▼
revoke credential
       │
       ▼
revoke sessions as appropriate
       │
       ▼
require safe recovery
       │
       ▼
review recent activity
       │
       ▼
reenroll authenticator
```

---

# 78. Password Compromise

Known password exposure SHOULD trigger:

```text
credential invalidation / forced change
```

rather than waiting for the next scheduled rotation.

---

# 79. Passkey Compromise

If a device/passkey is believed compromised, the specific credential SHALL be revocable without necessarily deleting the entire identity.

---

# 80. Account Compromise

For suspected full account takeover:

```text
disable/restrict identity
revoke sessions
revoke suspicious authenticators
review linked identities
review privilege changes
review domain activity
```

---

# 81. Credential Stuffing

Authentication infrastructure SHALL defend against credential-stuffing attacks.

Controls MAY include:

- rate limiting;
- adaptive throttling;
- account lock protections;
- compromised password detection;
- security analytics.

---

# 82. Brute-Force Protection

Keycloak brute-force defenses SHALL be configured intentionally.

Permanent denial-of-service through attacker-triggered lockout SHOULD be avoided.

---

# 83. Progressive Delay

Progressive delay or similar risk controls SHOULD be preferred where they provide better resilience than simplistic permanent lockouts.

---

# 84. Rate Limiting

Rate limits SHALL apply appropriately to:

```text
login
password reset
verification resend
MFA challenge
authenticator enrollment
account linking
recovery
```

---

# 85. Enumeration

Authentication errors SHOULD avoid unnecessary disclosure of:

```text
valid username
valid email
registered authenticator
privileged account
```

---

# 86. Security Notifications

Users SHOULD receive notifications for important credential events.

Examples:

```text
password changed
new passkey enrolled
authenticator removed
MFA reset
external identity linked
account recovered
primary email changed
```

---

# 87. Security Notification Is Not Approval

Notifications inform.

They do not replace preventive authorization checks.

---

# 88. Suspicious Login Alerts

Baobab MAY add risk-driven notifications for unusual authentications.

Exact risk-engine architecture is outside this ADR.

---

# 89. Session Revocation

IAM SHALL support revoking:

```text
one session
multiple sessions
all sessions
```

where technically supported.

---

# 90. Credential Revocation vs Session Revocation

These SHALL remain separate concepts.

```text
credential revoked
```

may require:

```text
session revocation
```

depending on incident policy.

---

# 91. Password Change Sessions

High-risk password changes SHOULD invalidate other sessions unless policy explicitly preserves them.

---

# 92. Passkey Enrollment Sessions

Adding a new strong authenticator MAY trigger notification and session review.

---

# 93. Credential Downgrade

The system SHOULD detect or prevent a user from weakening a privileged account from:

```text
WebAuthn + MFA
```

to:

```text
password only
```

when policy requires stronger authentication.

---

# 94. Authentication Policy by Client

Different OIDC clients MAY require different assurance.

Examples:

```text
thamani-web
    → Standard

zuribeans-web
    → Standard/Enhanced

supplier-admin
    → Enhanced

baobab-trade-admin
    → Privileged

baobab-erp
    → Privileged

baobab-iam-admin
    → Critical
```

---

# 95. Client Assurance Does Not Replace Domain Step-Up

A client may generally require MFA while an individual high-risk action demands even more recent or stronger authentication.

Both mechanisms MAY coexist.

---

# 96. Keycloak Authentication Flows

Keycloak authentication flows SHALL be managed as controlled platform configuration.

Changes SHALL be:

- versioned;
- reviewed;
- tested;
- promoted through environments.

---

# 97. No Production Console Drift

Critical authentication policy SHOULD NOT exist solely as undocumented manual Keycloak Admin Console state.

---

# 98. IAM Configuration as Code

Where practical, repositories SHALL retain sanitized configuration or provisioning artifacts for:

```text
authentication flows
WebAuthn policy
password policy
required actions
client assurance
brute-force protection
```

Secrets SHALL remain external.

---

# 99. Environment Isolation

Development, staging and production SHALL have distinct authenticator/client/security configurations where required.

Development credential policy SHALL not silently weaken production policy.

---

# 100. Test Accounts

Production-like testing SHALL use dedicated test identities.

Real privileged workforce credentials SHALL NOT be copied into non-production.

---

# 101. Workload Credentials

Machine identities SHALL not use human password/MFA mechanisms.

Workload authentication is governed by ADR-0007.

---

# 102. Workload Credential Types

Baseline workload authentication MAY use:

```text
OAuth client credentials
+
client secret
```

with stronger forms such as:

```text
private-key client authentication
mTLS
```

where appropriate.

---

# 103. No Human Use of Workload Credentials

Humans SHALL NOT routinely authenticate interactively using:

```text
service client secret
```

---

# 104. No Workload Use of Human Passwords

Services SHALL NOT store a human user's password for background automation.

---

# 105. Workload Secret Storage

Service secrets SHALL be stored through approved secrets infrastructure.

They SHALL NOT be:

- committed to Git;
- baked into images;
- stored in frontend bundles;
- logged.

---

# 106. Workload Rotation

Machine credentials SHALL be rotatable without redeploying unrelated identities.

---

# 107. Workload Revocation

Compromised service credentials SHALL be individually revocable.

---

# 108. Client Secret Lifetime

Long-lived static client secrets SHOULD be progressively reduced where stronger deployment-integrated identity methods become practical.

---

# 109. Private-Key Client Authentication

Baobab SHOULD evaluate asymmetric client authentication for higher-risk workloads.

This reduces dependence on shared static secrets.

---

# 110. mTLS

mTLS MAY provide an additional workload authentication factor/binding.

It SHALL NOT replace application authorization.

---

# 111. Engine Credential Migration

Baobab SHALL progressively eliminate duplicate engine-managed human credentials.

Affected systems include:

```text
Medusa
iDempiere
Payload CMS
future engine admin surfaces
```

---

# 112. Migration Target

The target SHALL be:

```text
Engine local credential
       │
       ▼
Baobab IAM identity linked
       │
       ▼
SSO verified
       │
       ▼
local normal credential disabled
```

---

# 113. Password Import

Plaintext credential export SHALL never be used.

Existing password hashes SHALL only be migrated if:

- technically supported safely;
- hashing semantics are understood;
- migration does not weaken security.

Otherwise password-reset migration SHALL be preferred.

---

# 114. Medusa Migration

ADR-0013 remains authoritative for Medusa credential migration.

Legacy Medusa passwords SHALL become transitional only.

---

# 115. iDempiere Migration

ADR-0014 remains authoritative for ERP local credential migration.

Local passwords SHALL remain only where explicitly required for controlled emergency access.

---

# 116. CMS Migration

Payload CMS administrator/editor credentials SHOULD similarly converge on workforce SSO.

Domain roles remain Payload-owned.

---

# 117. Local Emergency Accounts

Some engines MAY require local emergency administrator credentials.

Such credentials SHALL be:

- exceptional;
- vaulted;
- strongly protected;
- not routine;
- tested;
- monitored;
- rotated after emergency use.

---

# 118. Break-Glass Credentials

Break-glass accounts SHALL preferably use strong phishing-resistant authentication where operationally feasible.

Where IAM itself is the failed component, the emergency mechanism MAY necessarily differ.

---

# 119. Break-Glass Storage

Emergency credentials SHALL be stored in an approved secure vault or equivalent control.

They SHALL NOT appear in:

```text
repository README
runbook plaintext
CI variable visible broadly
shared spreadsheet
```

---

# 120. Break-Glass Access

Emergency access SHOULD require:

```text
incident declaration
authorized retrieval
named human use
security alert
audit
post-use review
credential reseal/rotation
```

---

# 121. Shared Break-Glass Password

A generic shared emergency password SHOULD be avoided where technology allows named emergency identities.

If unavoidable, compensating controls SHALL be especially strong.

---

# 122. Recovery and Separation of Duties

The highest-risk recovery actions SHOULD use two-person control where practical.

Examples:

```text
recover IAM root-level admin
reset break-glass credential
replace critical administrator MFA
```

---

# 123. Authentication vs Identity Proofing

Credential recovery sometimes requires proving that the claimant is the legitimate person.

This is distinct from normal authentication.

A future identity-proofing policy MAY define stronger verification methods.

---

# 124. Recovery Shall Be Proportionate

Recovery assurance SHOULD correspond to the consequences of account takeover.

Example:

```text
ordinary consumer account
      ≠
production IAM administrator
```

---

# 125. No Recovery Through Business Data Alone

Knowledge of:

```text
company registration number
supplier bank account
order number
employee number
```

SHALL NOT alone be sufficient to recover an identity.

---

# 126. Delegated Organization Recovery

Buyer/supplier organization administration recovery SHALL remain separate from personal authentication recovery.

The user may recover their identity without automatically becoming:

```text
buyer_admin
supplier_admin
```

again.

---

# 127. Privilege Changes During Recovery

High-risk accounts SHOULD be checked for unauthorized role changes after recovery.

---

# 128. Authentication Event Audit

Audit SHOULD record:

```text
login success
login failure
MFA challenge
step-up
credential enrollment
credential removal
credential reset
account recovery
session revocation
external identity linking
```

where appropriate.

---

# 129. Audit Privacy

Authentication audit SHALL minimize personal and device data.

It SHOULD not capture secrets.

---

# 130. Secrets Never Logged

The following SHALL never be deliberately logged:

```text
passwords
TOTP seeds
WebAuthn private material
recovery codes
recovery tokens
authorization codes
PKCE verifiers
access tokens
refresh tokens
client secrets
private keys
```

---

# 131. Credential Metrics

Operational metrics SHOULD include:

```text
authentication success/failure rate
MFA adoption
passkey adoption
recovery rate
MFA reset rate
brute-force detections
credential lock events
step-up success/failure
```

without exposing secrets or excessive PII.

---

# 132. Privileged Authentication Alerts

Security monitoring SHOULD alert on events such as:

```text
new IAM administrator authenticator
privileged MFA reset
break-glass use
multiple failed privileged logins
unexpected identity linking
mass session revocation
```

---

# 133. Recovery Abuse Monitoring

Repeated recovery attempts against a user or organization SHOULD be detectable.

---

# 134. Credential Inventory

IAM SHOULD support visibility into registered authenticator types for account security administration.

The inventory SHALL not expose secret material.

---

# 135. Access Review vs Credential Review

Access review asks:

```text
What may this person do?
```

Credential review asks:

```text
How can this person authenticate?
```

They SHALL remain separate governance processes.

---

# 136. User Self-Service

Users SHOULD be able to self-manage safe credential functions such as:

- password change;
- passkey enrollment;
- authenticator removal where policy allows;
- recovery-code regeneration;
- session review.

They SHALL not self-grant privileges.

---

# 137. Privileged Self-Service Restrictions

Some credential operations for privileged identities MAY require stronger controls than customer self-service.

---

# 138. Authentication User Experience

Security controls SHOULD minimize needless friction.

Passkeys SHOULD be used to improve both:

```text
security
+
user experience
```

rather than requiring increasingly complex passwords.

---

# 139. Accessibility

Authentication flows SHALL account for accessibility requirements.

No actor should be forced into an unusable authentication mechanism if an equivalently secure approved alternative can be provided.

---

# 140. Device Loss and Geographic Reality

Baobab operates in markets where:

- device replacement may be difficult;
- phone numbers may change;
- roaming may be unreliable;
- users may use shared or low-cost devices.

Recovery architecture SHALL therefore avoid assuming permanent possession of a single telephone number.

---

# 141. Phone Number Is Not Canonical Identity

This SHALL remain binding:

```text
phone number
    ≠
CanonicalIdentity
```

---

# 142. Email Is Not Canonical Identity

Likewise:

```text
email
  ≠
CanonicalIdentity
```

---

# 143. Credential Is Not Canonical Identity

A passkey, password or upstream social identity is an authentication mechanism.

It is not the person themselves.

---

# 144. Multiple Credentials per Identity

One Canonical Identity MAY securely possess:

```text
password
passkey A
passkey B
TOTP
external IdP
```

according to policy.

---

# 145. Removing Credential Does Not Delete Identity

This remains binding:

```text
remove passkey
     ≠
delete CanonicalIdentity
```

---

# 146. Disabling Identity Overrides Valid Credential

If the Canonical/IAM identity is disabled, possession of a valid authenticator SHALL not restore access.

---

# 147. Domain Suspension Overrides Authentication

Likewise:

```text
valid authentication
+
supplier suspended
=
restricted/denied supplier actions
```

and equivalent domain cases remain governed by ADR-0008.

---

# 148. Fail-Closed Conditions

Authentication SHALL fail closed when:

- token validation fails;
- required MFA is absent;
- required step-up is stale;
- identity is disabled;
- authenticator is revoked;
- recovery token is invalid;
- authentication flow state is invalid;
- required security policy cannot be evaluated.

---

# 149. Availability

IAM is a Tier-0 platform service.

High availability SHALL be designed so stronger credential policy does not create a single-instance operational dependency.

---

# 150. Existing Session During IAM Outage

During an IAM outage:

```text
new authentication
```

cannot safely occur.

Existing valid sessions MAY remain usable according to TTL and downstream authorization policy.

---

# 151. No Outage Password Bypass

Applications SHALL NOT activate undocumented:

```text
emergency password login
```

merely because IAM is unavailable.

Only governed break-glass applies.

---

# 152. Backup and Restore

Keycloak backup/recovery SHALL preserve credential metadata safely.

Backup repositories SHALL receive security controls appropriate to credential data sensitivity.

---

# 153. Credential Backup Exposure

IAM backups SHALL be treated as highly sensitive security assets.

---

# 154. Key Material

Cryptographic signing keys and authentication secrets SHALL be stored and rotated through approved key/secret management.

---

# 155. Key Separation

OIDC signing keys, TLS keys, workload client keys and unrelated application secrets SHOULD remain separated by purpose.

---

# 156. Security Baseline Table

| Actor | Password Allowed | Passkey | MFA | Step-Up |
|---|---:|---:|---:|---:|
| Thamani customer | Yes | Preferred | Optional initially | Risk-based |
| Zuribeans buyer representative | Yes | Preferred | Recommended | Sensitive B2B actions |
| Buyer administrator/approver | Yes | Preferred | Strongly recommended/required by policy | Yes |
| Supplier representative | Yes | Preferred | Role-based | Sensitive changes |
| Supplier administrator/finance | Yes | Preferred | Required | Yes |
| Ordinary workforce | Yes | Preferred | Required target | Risk-based |
| ERP finance/admin | Yes | Strongly preferred | Required | Yes |
| CP/Trade/CMS admin | Yes | Strongly preferred | Required | Yes |
| IAM/security admin | Fallback only where possible | Strongly preferred | Required | Yes |
| Workload | No human password | N/A | Machine auth | N/A |

---

# 157. Recommended Authentication Evolution

Baobab SHOULD evolve through:

```text
PHASE 1
Password + MFA foundation
        │
        ▼
PHASE 2
Passkey enrollment
        │
        ▼
PHASE 3
Passkey preferred
        │
        ▼
PHASE 4
Passwordless for suitable populations
```

without waiting for passwordless maturity before implementing strong MFA for privileged users.

---

# 158. Required Unit Tests

Test:

```text
password policy
weak-password rejection
authenticator registration
authenticator removal
MFA enforcement
step-up requirement
recovery token expiry
recovery token replay
recovery-code single use
```

---

# 159. Required Integration Tests

At minimum:

```text
Thamani standard login
Thamani passkey login
Zuribeans enhanced login
supplier admin MFA
ERP finance MFA
CP admin MFA
IAM admin phishing-resistant authentication
```

where configured.

---

# 160. Recovery Tests

Test:

```text
valid recovery
expired token
reused token
invalid account
enumeration resistance
MFA reset
recovery session revocation
revoked domain role remains revoked
```

---

# 161. Passkey Tests

Test:

```text
new passkey enrollment
multiple passkeys
passkey login
credential revocation
lost-device replacement
wrong relying party
replayed assertion
```

---

# 162. Step-Up Tests

Test:

```text
normal session + low-risk action = allowed
normal session + high-risk action = challenge
fresh stronger auth + authorized action = allowed
fresh stronger auth + domain deny = denied
stale strong auth = challenge/deny
```

---

# 163. Privileged Recovery Tests

Staging SHALL prove:

```text
privileged user loses authenticators
       │
       ▼
controlled recovery
       │
       ▼
sessions revoked
       │
       ▼
MFA reenrolled
       │
       ▼
event audited
```

---

# 164. Credential Compromise Tests

Incident exercises SHOULD demonstrate:

```text
revoke one credential
revoke all sessions
disable identity
replace authenticator
review linked IdPs
restore safely
```

---

# 165. Engine Migration Tests

Each engine migration SHALL prove:

```text
SSO works
legacy credential disabled
engine role preserved
audit preserved
recovery handled by IAM
```

---

# 166. Workload Credential Tests

Test:

```text
valid workload credential
revoked workload credential
wrong audience
wrong environment
secret rotation
mTLS mismatch where applicable
human password rejected for workload auth
```

---

# 167. Rejected Alternative — Same MFA Policy for Everyone

### Advantages

Simple.

### Disadvantages

- unnecessary B2C friction;
- insufficient nuance;
- poor usability;
- mismatched risk.

### Decision

Rejected.

---

# 168. Rejected Alternative — Password Complexity Rules as Primary Control

### Decision

Rejected.

Long passwords, password blocking and stronger authenticators are preferred.

---

# 169. Rejected Alternative — Mandatory Routine Password Rotation

### Decision

Rejected.

Credential changes SHALL be driven by compromise or legitimate user action rather than arbitrary calendar intervals.

---

# 170. Rejected Alternative — Security Questions

### Decision

Rejected.

---

# 171. Rejected Alternative — SMS as Default Privileged MFA

### Decision

Rejected.

Phishing-resistant authentication is preferred.

---

# 172. Rejected Alternative — Email as Strong MFA

### Decision

Rejected.

Email verification/recovery may still be used according to policy.

---

# 173. Rejected Alternative — Engine-Specific MFA Everywhere

### Advantages

Native engine functionality.

### Disadvantages

- duplicated enrollment;
- fragmented recovery;
- conflicting assurance;
- poor SSO experience.

### Decision

Rejected as the platform baseline.

---

# 174. Rejected Alternative — Permanent Password-Only Administrators

### Decision

Rejected.

---

# 175. Rejected Alternative — Recovery Restores All Prior Roles

### Decision

Rejected.

Authentication recovery and authorization lifecycle remain separate.

---

# 176. Rejected Alternative — One Shared Service Secret

### Decision

Rejected.

Workload credentials remain independently revocable.

---

# 177. Consequences

## Positive

This decision provides:

- centralized credential security;
- consistent MFA;
- passkey readiness;
- phishing-resistant privileged access;
- simpler customer/workforce credential management;
- stronger recovery;
- reduced password duplication;
- explicit assurance semantics;
- safer engine migration.

## Negative

It requires:

- Keycloak flow engineering;
- authenticator policy management;
- recovery operations;
- user education;
- migration tooling;
- device-loss support;
- extensive security testing.

These costs are accepted.

---

# 178. Implementation Ownership

| Concern | Owner |
|---|---|
| Human credentials | `baobab-iam` |
| Password policy | `baobab-iam` |
| Passkeys/WebAuthn | `baobab-iam` |
| TOTP | `baobab-iam` |
| Recovery codes | `baobab-iam` |
| Human account recovery | `baobab-iam` |
| Authentication assurance | `baobab-iam` |
| Platform authorization | `baobab-cp` |
| Domain authorization | Domain engine |
| Workload credentials | IAM + infrastructure |
| Secrets infrastructure | `baobab-platform/infrastructure` |
| Shared assurance contracts | `baobab-platform/shared` |
| Digital Estate UX | Estate repository |

---

# 179. Shared Contract Requirements

`baobab-platform/shared` SHOULD define or extend versioned contracts for:

```text
authentication assurance
actor type
authentication method
step-up requirement
credential-security event
recovery event
session revocation event
identity-compromise event
```

Shared SHALL NOT store credential values.

---

# 180. Suggested Assurance Contract

Conceptually:

```text
AuthenticationAssurance
────────────────────────
actor_type
acr
amr[]
authenticated_at
step_up_at?
issuer
client_id
```

This is descriptive assurance information, not a business authorization grant.

---

# 181. Suggested Step-Up Requirement

Conceptually:

```text
AssuranceRequirement
────────────────────────
minimum_acr
accepted_methods[]
max_authentication_age?
phishing_resistant_required?
```

Exact schema SHALL be versioned.

---

# 182. Production-Readiness Checklist

Credential security SHALL not be considered production-ready until:

- Keycloak is the authoritative human credential service;
- engines no longer require parallel routine passwords where integration is complete;
- password policy follows modern guidance;
- weak/compromised passwords are blocked;
- routine forced rotation is disabled;
- passkey/WebAuthn support is configured;
- MFA is mandatory for privileged users;
- critical administrators have strong/phishing-resistant options;
- TOTP fallback is controlled;
- recovery codes are single-use;
- recovery tokens expire and cannot replay;
- MFA reset is audited;
- privileged recovery has stronger proof;
- recovery does not restore revoked domain roles;
- rate limiting/brute-force protection exists;
- account enumeration is mitigated;
- authenticator enrollment/removal is protected;
- step-up works for high-risk actions;
- security notifications exist for critical credential changes;
- service credentials are isolated from human credentials;
- credential migration plans exist for Medusa/iDempiere/CMS;
- no passwords/tokens/recovery secrets are logged;
- credential-compromise runbooks are tested;
- break-glass credentials are governed separately.

---

# 183. Architectural Invariants

The following become binding:

```text
Credential ≠ Identity

Authentication ≠ Authorization

MFA ≠ Business Permission

Passkey ≠ CanonicalIdentity

Email ≠ CanonicalIdentity

Phone Number ≠ CanonicalIdentity

Credential Recovery ≠ Authorization Recovery

Password Reset ≠ Role Restoration

MFA Reset ≠ Privilege Grant

Strong Authentication ≠ Domain Allow

Shared Service Secret ≠ Acceptable Workload Architecture

Human Password ≠ Workload Credential

Engine Password ≠ Independent Baobab Credential Authority

Break-Glass ≠ Routine Authentication

Security Question ≠ Acceptable Recovery Factor

Same Email ≠ Safe Identity Linking
```

---

# 184. Target Credential Architecture

```text
                         BAOBAB IAM
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
     Password             Passkeys             WebAuthn
        │                    │                    │
        └──────────────┬─────┴─────┬──────────────┘
                       │           │
                       ▼           ▼
                     TOTP       Recovery
                       │           │
                       └─────┬─────┘
                             ▼
                      Authentication
                             │
                             ▼
                  Authentication Assurance
                             │
                             ▼
                       OIDC / OAuth
                             │
                             ▼
                       BAOBAB CP
                             │
                             ▼
                     Domain Engines
```

Credentials prove identity.

They do not determine business authority.

---

# 185. Privileged Authentication Flow

```text
PRIVILEGED USER
      │
      ▼
Baobab IAM
      │
      ▼
Primary authentication
      │
      ▼
Phishing-resistant / MFA requirement
      │
   ┌──┴───┐
  FAIL   PASS
   │       │
   ▼       ▼
 DENY   Session
           │
           ▼
      Sensitive Action
           │
           ▼
     Is auth recent/strong enough?
        ┌──┴───┐
       NO     YES
        │       │
        ▼       │
    Step-Up     │
        └───┬───┘
            ▼
       Domain Authorization
            │
       ┌────┴────┐
      DENY      ALLOW
```

---

# 186. Account Recovery Flow

```text
USER CANNOT AUTHENTICATE
          │
          ▼
Initiate IAM Recovery
          │
          ▼
Enumeration-safe response
          │
          ▼
Verify approved recovery evidence
          │
          ▼
Is account privileged?
       ┌──┴───┐
      YES     NO
       │       │
       ▼       │
Stronger verification
       │       │
       └───┬───┘
           ▼
Reset / replace credential
           │
           ▼
Revoke affected sessions
           │
           ▼
Security notification + audit
           │
           ▼
Authentication restored
           │
           ▼
Existing authorization reevaluated

No revoked business role is recreated.
```

---

# 187. Credential Compromise Flow

```text
SUSPECTED COMPROMISE
        │
        ▼
Identify credential / account
        │
        ▼
Revoke credential
        │
        ▼
Revoke sessions
        │
        ▼
Disable identity if required
        │
        ▼
Review linked authenticators / IdPs
        │
        ▼
Review recent privileged/domain activity
        │
        ▼
Secure recovery
        │
        ▼
Enroll replacement authenticator
        │
        ▼
Incident closure
```

---

# 188. Decision Summary

Baobab SHALL centralize human credential management in Baobab IAM while applying stronger authentication requirements according to actor and action risk.

The security model SHALL evolve from:

```text
password-centered authentication
```

toward:

```text
passkey / WebAuthn-centered authentication
```

without delaying mandatory MFA for privileged users.

The credential decision hierarchy SHALL be:

```text
HOW DOES THIS PERSON PROVE IDENTITY?
              │
              ▼
          Baobab IAM

HOW STRONG WAS THAT AUTHENTICATION?
              │
              ▼
     Authentication Assurance

IS THIS ASSURANCE SUFFICIENT
FOR THE REQUESTED OPERATION?
              │
              ▼
       Step-Up if needed

MAY THIS PERSON OPERATE
IN THIS PLATFORM CONTEXT?
              │
              ▼
      Baobab Control Plane

MAY THEY PERFORM THIS
BUSINESS OPERATION?
              │
              ▼
          Domain Engine
```

Account recovery SHALL restore authentication only.

It SHALL never silently recreate buyer authority, supplier authority, workforce privilege, ERP roles or platform administration.

The governing principle is:

> **Baobab shall make strong authentication increasingly effortless through passkeys, make privileged authentication deliberately difficult to compromise, and ensure that recovery restores identity control without ever bypassing authorization.**