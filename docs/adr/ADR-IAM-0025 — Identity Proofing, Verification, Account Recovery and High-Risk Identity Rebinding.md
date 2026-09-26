# ADR-IAM-0025 — Identity Proofing, Verification, Account Recovery and High-Risk Identity Rebinding

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, ZuriBeans, Thamani, Nabhold, supplier-domain implementations, and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0024  
**Extends:** ADR-IAM-0004, ADR-IAM-0009, ADR-IAM-0010, ADR-IAM-0011, ADR-IAM-0012, ADR-IAM-0015, ADR-IAM-0016, ADR-IAM-0017, ADR-IAM-0019 through ADR-IAM-0024  
**Decision Type:** Identity Proofing / Verification / Enrollment / Recovery / Identity Rebinding / Privileged Identity Security  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Business Relationship Authorities:** Respective Baobab domain engines

---

# 1. Decision

Baobab SHALL distinguish four security concepts that are frequently and dangerously conflated:

```text
AUTHENTICATION
"Can this actor demonstrate control
of an enrolled authenticator?"

IDENTITY PROOFING
"Do we have sufficient evidence that
this digital identity corresponds to
the claimed real-world person?"

RELATIONSHIP VERIFICATION
"Is this person legitimately entitled
to represent this organization,
supplier, customer or legal entity?"

AUTHORIZATION
"May this actor perform this operation
in this context?"
```

Baobab SHALL therefore implement a **risk-proportionate identity proofing and rebinding architecture**.

Identity proofing SHALL NOT be universally required merely because a user creates an account.

Instead, proofing strength SHALL increase when Baobab binds an identity to relationships or privileges whose compromise would create material:

- financial risk;
- commercial risk;
- privacy risk;
- regulatory risk;
- organizational-control risk;
- platform-administration risk.

Particular protection SHALL apply to:

- B2B organization administrators;
- supplier representatives;
- finance users;
- purchasing approvers;
- workforce administrators;
- IAM and Control Plane administrators;
- legal representatives;
- sensitive business-account ownership changes;
- high-risk account recovery;
- replacement of strong authenticators;
- identity rebinding after loss of account control.

---

# 2. Why This ADR Exists

ADR-IAM-0024 answers:

> How strongly did Jane authenticate?

It does not fully answer:

> How did Baobab establish that the digital identity called Jane belongs to the intended Jane?

Nor:

> How did Baobab establish that Jane is legitimately entitled to administer Company A?

These are separate questions.

Consider:

```text
Attacker
   │
   ▼
creates account
   │
   ▼
enrols passkey
   │
   ▼
authenticates at BAOBAB-A3
```

The authentication may be cryptographically excellent.

But Baobab may still have authenticated the **wrong person extremely well**.

Therefore:

```text
Strong Authentication
        ≠
Strong Identity Proofing
```

and:

```text
Strong Identity Proofing
        ≠
Business Authority
```

---

# 3. Standards Basis

NIST SP 800-63A-4, finalized in July 2025, defines identity proofing as a process through which an applicant provides evidence that allows a credential service provider to establish their identity at a useful identity assurance level. It defines three Identity Assurance Levels.

Baobab SHALL use this framework as architectural guidance without claiming formal NIST certification merely because similar controls are implemented.

NIST SP 800-63B-4 separately treats account recovery as the process used when a subscriber loses control of authenticators required for authentication. Recovery can involve recovery codes, recovery contacts, existing authenticators, or repeated identity proofing. NIST also requires recovery notifications and recognizes that recovery can legitimately be more burdensome than ordinary authentication.

NIST further treats binding a new authenticator as a security-significant event and requires authentication appropriate to the strength of the authenticator being bound, together with independent notification.

These distinctions align closely with Baobab's existing separation of identity, credentials, relationships, contexts and authorization.

---

# 4. Baobab Identity Proofing Levels

Baobab SHALL define provider-neutral proofing classifications:

```text
BAOBAB-I0
    │
    ▼
Unproofed / self-asserted

BAOBAB-I1
    │
    ▼
Basic verified identity

BAOBAB-I2
    │
    ▼
Strong identity proofing

BAOBAB-I3
    │
    ▼
High-assurance identity proofing
```

These are Baobab classifications.

They SHALL NOT be represented externally as formal NIST IAL certification.

---

# 5. BAOBAB-I0 — Self-Asserted Identity

I0 means Baobab knows that an account exists and can authenticate, but has not established meaningful real-world identity evidence.

Examples:

```text
email registration
+
email verification
+
password/passkey
```

This can be entirely appropriate.

I0 SHOULD support many ordinary B2C scenarios.

---

# 6. I0 Is Not "Untrusted"

An I0 identity may still authenticate securely.

For example:

```text
Jane
  │
  ▼
Passkey
  │
  ▼
BAOBAB-A3 authentication
```

while remaining:

```text
BAOBAB-I0 proofing
```

because Baobab has not verified Jane's civil identity.

This distinction is intentional.

---

# 7. BAOBAB-I1 — Basic Verified Identity

I1 indicates that Baobab has validated additional evidence linking the digital identity to the claimed person.

Depending on business context, this MAY involve:

```text
verified contact channel
verified organizational invitation
verified enterprise federation
validated basic identity attributes
trusted business onboarding evidence
```

I1 SHALL not automatically imply government-document verification.

---

# 8. BAOBAB-I2 — Strong Identity Proofing

I2 applies where material business or financial authority requires stronger confidence.

Evidence MAY include combinations of:

```text
government-issued identity evidence
authoritative-source validation
trusted enterprise assertion
business registry evidence
verified corporate invitation
verified representative relationship
document validation
controlled manual review
```

The exact evidence SHALL be appropriate to jurisdiction and use case.

---

# 9. BAOBAB-I3 — High-Assurance Proofing

I3 is reserved for exceptional privilege/risk.

Potential use cases:

```text
IAM privileged recovery
Control Plane privileged recovery
break-glass enrollment
exceptional finance administration
high-impact identity rebinding
```

I3 MAY require:

```text
strong documentary evidence
+
independent validation
+
human review
+
existing organizational confirmation
+
enhanced fraud controls
```

depending on the case.

---

# 10. Proofing and Authentication Are Independent Axes

Baobab SHALL model:

```text
             AUTHENTICATION
                  A0 A1 A2 A3 A4
                 ───────────────►

PROOFING I0       •  •  •  •
         I1       •  •  •  •
         I2       •  •  •  •
         I3       •  •  •  •
         │
         ▼
```

Examples:

```text
I0 + A3
```

may represent a strongly authenticated ordinary customer whose legal identity was never proofed.

```text
I2 + A1
```

may represent a previously proofed person currently using insufficient authentication for a sensitive operation.

Neither axis replaces the other.

---

# 11. Proofing Is Not Authorization

The following remains prohibited:

```text
Identity proofed at I2
        │
        ▼
Automatically becomes
Company Administrator
```

Required:

```text
I2 identity
    │
    ▼
relationship verified
    │
    ▼
membership created
    │
    ▼
role assigned
    │
    ▼
domain authorization
```

---

# 12. Three Different Bindings

Baobab SHALL explicitly distinguish:

```text
PERSON ↔ DIGITAL IDENTITY
        Identity Proofing

PERSON ↔ ORGANIZATION
        Relationship Verification

IDENTITY ↔ AUTHENTICATOR
        Authenticator Binding
```

These are not interchangeable.

---

# 13. Canonical Identity Boundary

Proofing evidence SHALL attach to or reference:

```text
CanonicalIdentity
```

through controlled identity-proofing records.

It SHALL NOT cause unnecessary creation of additional CanonicalIdentity records.

---

# 14. Provider Identity Is Not Proofed Identity

Ory may know:

```text
identity_id = abc123
```

That alone does not mean:

```text
government identity verified
company representation verified
supplier authority verified
```

Ory remains the credential/authentication platform.

Baobab owns the business meaning of proofing.

---

# 15. Provider-Neutral Proofing

Domain code SHALL NOT ask:

```text
kratos_identity_verified == true
```

to determine high-level proofing.

It SHOULD consume a provider-neutral semantic result such as:

```json
{
  "proofing_level": "BAOBAB-I2",
  "status": "VERIFIED"
}
```

---

# 16. Proofing Record

Conceptually:

```text
IdentityProofingRecord
├── canonical_identity_id
├── proofing_level
├── status
├── method
├── evidence_references
├── verified_attributes
├── verifier
├── verified_at
├── expires_at
├── jurisdiction
├── policy_version
└── audit_reference
```

---

# 17. Evidence Minimization

Proofing does not mean copying every identity document into every engine.

Prefer:

```text
Domain
   │
   ▼
verified identity assertion/reference
```

over:

```text
Trade DB
ERP DB
CMS DB
CP DB
Supplier DB
   │
   ▼
five copies of passport
```

---

# 18. Evidence Storage Boundary

Sensitive identity evidence SHOULD be stored only in an explicitly approved proofing/evidence boundary.

Canonical and domain records SHOULD normally contain:

```text
verification result
evidence reference
verified attributes required
audit reference
```

rather than unnecessary raw evidence.

---

# 19. Data Minimization

Collect only identity evidence necessary for the intended assurance level and business purpose.

Do not collect passports merely because:

> "We might need them one day."

---

# 20. Purpose Limitation

Evidence collected for:

```text
supplier representative verification
```

SHALL not automatically become available for unrelated:

```text
marketing
analytics
employee monitoring
```

purposes.

---

# 21. Proofing State

Proofing SHOULD use an explicit lifecycle:

```text
NOT_REQUIRED
     │
     ▼
REQUIRED
     │
     ▼
IN_PROGRESS
     │
     ▼
VERIFIED
```

with alternative outcomes:

```text
REJECTED
EXPIRED
REVOKED
MANUAL_REVIEW
```

---

# 22. Proofing Expiry

Identity proofing need not always remain valid indefinitely.

Expiration MAY depend on:

```text
evidence type
jurisdiction
business relationship
regulatory requirement
risk
```

---

# 23. Proofing Revocation

Proofing status MAY be revoked where:

```text
fraud discovered
evidence invalidated
identity misbinding detected
legal identity materially changed
verification provider retracts result
```

Revocation SHALL generate security/audit events.

---

# 24. Attribute-Level Verification

Baobab SHALL avoid assuming:

```text
identity verified
```

means every identity attribute is verified.

Instead:

```text
name → verified
date_of_birth → verified
email → verified
phone → self-asserted
address → unverified
```

may coexist.

---

# 25. Verified Attributes

Where needed, proofing records SHOULD identify which attributes were verified and through which evidence.

---

# 26. Attribute Change

Changing a verified attribute SHALL not silently preserve its verified status.

Example:

```text
verified legal name
      │
      ▼
user edits name
      │
      ▼
new value
      │
      ▼
requires appropriate reverification
```

---

# 27. Ordinary B2C Accounts

Baobab SHALL NOT impose high-assurance identity proofing on ordinary consumers without business, regulatory or risk justification.

For example, an ordinary Thamani personal account may begin:

```text
I0
+
A1/A3
```

depending on authentication method.

---

# 28. Progressive Proofing

Baobab SHOULD use progressive proofing.

```text
Browse
  │
  ▼
I0

Create ordinary account
  │
  ▼
I0

Request sensitive service
  │
  ▼
I1/I2 if required

Obtain high-risk authority
  │
  ▼
I2/I3 if required
```

---

# 29. Do Not Front-Load Friction

The platform SHALL avoid:

```text
Create account
     │
     ▼
upload passport
     │
     ▼
selfie
     │
     ▼
manual review
```

when the user merely wants an ordinary low-risk account and no policy requires such proofing.

---

# 30. B2B Organization Membership

B2B introduces two distinct verification questions:

```text
Is this really Jane?
```

and:

```text
May Jane represent Company A?
```

Both may matter.

---

# 31. Organization Invitation

A trusted invitation MAY provide strong evidence of relationship membership.

Example:

```text
Verified Company A Admin
        │
        ▼
invites jane@company-a.example
        │
        ▼
Jane authenticates
        │
        ▼
invitation validated
        │
        ▼
Company A membership
```

This does not necessarily establish Jane's civil identity at I2.

---

# 32. Enterprise Federation

Corporate federation may provide useful identity and organizational evidence.

```text
Company A Entra ID
        │
        ▼
Ory federation
        │
        ▼
Jane
        │
        ▼
CanonicalIdentity
```

Baobab MAY map trusted enterprise assertions to proofing/relationship confidence according to an explicit federation policy.

---

# 33. Federation Is Not Unlimited Trust

A corporate IdP assertion SHALL NOT automatically authorize:

```text
purchase approval
finance authority
supplier banking changes
platform administration
```

Domain authorization remains explicit.

---

# 34. First Organization Administrator Problem

The first administrator of a B2B organization represents a special bootstrap risk.

There is no existing organization administrator to invite them.

Therefore:

```text
First Admin
   │
   ▼
stronger organization verification
   │
   ▼
representative verification
   │
   ▼
approval
   │
   ▼
organization-admin membership
```

SHALL be required according to business risk.

---

# 35. Subsequent Administrators

After a verified organization exists:

```text
existing authorized admin
       │
       ▼
invites additional admin
       │
       ▼
new admin identity verification
       │
       ▼
appropriate approval/step-up
```

may provide a simpler path.

---

# 36. Organization Control Must Be Hard to Seize

Changing:

```text
primary organization administrator
```

or:

```text
organization ownership/control
```

SHALL be treated as a high-risk identity/relationship rebinding operation.

---

# 37. ZuriBeans Buyer Example

```text
Applicant
   │
   ▼
creates identity
   │
   ▼
CanonicalIdentity
   │
   ▼
applies for ACME Ltd
   │
   ▼
ACME evidence verified
   │
   ▼
representative relationship verified
   │
   ▼
buyer organization approved
   │
   ▼
initial buyer admin assigned
```

No single step SHALL imply all subsequent steps.

---

# 38. Buyer Account State

Identity state:

```text
ACTIVE
```

Buyer organization state:

```text
PENDING
```

Buyer representative state:

```text
UNDER_REVIEW
```

may coexist.

This is valid.

---

# 39. Thamani B2B

Thamani business accounts SHALL use the same separation.

```text
Person
  │
  ▼
Identity
  │
  ▼
Business Application
  │
  ▼
Organization Verification
  │
  ▼
Representative Verification
  │
  ▼
Business Membership
```

---

# 40. Thamani B2C/B2B Transition

A person may begin as:

```text
Jane
└── Personal Thamani Customer
```

and later become:

```text
Jane
├── Personal Customer
└── Company A Logistics Manager
```

Baobab SHALL extend relationships around the same CanonicalIdentity.

It SHALL not create another Jane merely because she became a business representative.

---

# 41. Supplier Identity

Supplier onboarding requires especially careful separation.

```text
Supplier Company
        ≠
Supplier Representative
        ≠
Supplier Approval
        ≠
Supplier Product Approval
```

---

# 42. Supplier Representative Verification

A supplier representative MAY require stronger proofing than an ordinary buyer user because the representative may control:

```text
legal information
bank details
certifications
commercial documents
product submissions
```

---

# 43. Supplier Company Verification

Supplier organization verification MAY involve:

```text
company registry
tax registration
legal documents
physical/contact verification
banking evidence
certifications
```

depending on the sourcing domain.

These are organization-domain facts.

They SHALL not become Kratos identity traits.

---

# 44. Banking Details

Changing supplier banking details SHALL be treated as a high-risk operation.

Required controls SHOULD include:

```text
A3 step-up
+
verified representative authority
+
independent confirmation
+
audit
+
notification
```

and MAY require manual or dual approval.

---

# 45. Finance Users

Finance authority requires more than proof that the user controls an email address.

Finance-role onboarding SHOULD involve:

```text
strong identity confidence
+
verified organizational relationship
+
explicit role assignment
+
strong authentication
```

---

# 46. Workforce Proofing

Employees, contractors and privileged workforce SHALL be proofed according to their access risk.

The employment/contractor onboarding process MAY itself provide authoritative evidence.

---

# 47. Privileged Workforce

For:

```text
IAM administrators
CP administrators
production administrators
ERP finance administrators
security administrators
```

Baobab SHOULD require at least strong proofing and strong phishing-resistant authentication.

---

# 48. Identity Proofing Is Not Employment Verification

Proofing that:

```text
this is Jane Doe
```

does not prove:

```text
Jane currently works for Nabhold
```

Employment relationship remains separately governed.

---

# 49. Recovery Terminology

Baobab SHALL distinguish:

```text
AUTHENTICATOR REPLACEMENT
```

from:

```text
ACCOUNT RECOVERY
```

and:

```text
IDENTITY REBINDING
```

---

# 50. Authenticator Replacement

If Jane still controls another sufficient authenticator:

```text
Jane has Passkey A
Jane lost Passkey B
```

adding:

```text
Passkey C
```

is authenticator binding/replacement.

It need not become full account recovery.

This follows the distinction made in NIST SP 800-63B-4.

---

# 51. Account Recovery

Account recovery occurs when the subscriber no longer possesses sufficient authenticators to authenticate at the required assurance.

Conceptually:

```text
identity exists
+
authenticators unavailable
        │
        ▼
RECOVERY
```

---

# 52. Identity Rebinding

Identity rebinding is the higher-risk operation:

```text
existing CanonicalIdentity
        │
        ▼
new/recovered authentication identity
or authenticator set
        │
        ▼
bind back to existing person
```

Incorrect rebinding can hand the entire digital identity to an attacker.

---

# 53. Rebinding Principle

Baobab SHALL apply this rule:

> The authority required to regain control of an identity SHALL be proportionate to the authority that identity can exercise.

---

# 54. Recovery Strength

Recovery policy SHALL consider:

```text
proofing level
authentication capability
business relationships
privilege
financial authority
administrative authority
recent security events
risk
```

---

# 55. Recovery Classes

Baobab SHOULD classify recovery:

```text
R0 — ordinary low-risk recovery
R1 — enhanced recovery
R2 — high-risk recovery
R3 — privileged/exception recovery
```

---

# 56. R0 — Ordinary Recovery

Example:

```text
ordinary B2C account
no privileged relationships
no sensitive authority
```

Recovery MAY use standard provider-supported recovery mechanisms appropriate to the account.

---

# 57. R1 — Enhanced Recovery

May apply to:

```text
B2B ordinary representative
supplier ordinary representative
workforce non-privileged account
```

and SHOULD require stronger evidence or multiple recovery controls.

---

# 58. R2 — High-Risk Recovery

Applies to identities controlling:

```text
business administration
purchase approval
finance
supplier banking
sensitive organizational authority
```

Recovery SHOULD require stronger identity/relationship validation.

---

# 59. R3 — Privileged Recovery

Applies to:

```text
IAM administrator
CP administrator
break-glass controller
critical production administrator
```

Recovery SHALL use a dedicated privileged procedure.

Ordinary email recovery SHALL not be sufficient.

---

# 60. Recovery Inputs

Depending on class, recovery MAY use:

```text
existing authenticator
saved recovery code
issued recovery code
recovery contact
repeated identity proofing
enterprise administrator confirmation
organizational administrator confirmation
controlled manual review
```

NIST SP 800-63B-4 recognizes recovery codes, recovery contacts and repeated identity proofing as recovery mechanisms.

---

# 61. Recovery Codes

If Baobab/Ory supports recovery codes, they SHALL:

```text
have sufficient entropy
be securely generated
be single-use where appropriate
be securely stored
be revocable/reissuable
```

NIST SP 800-63B-4 requires saved recovery codes to contain at least 64 bits from an approved random source.

---

# 62. Recovery Contact

Recovery contacts MAY be used where policy permits.

A recovery contact SHALL NOT automatically gain access to the recovered account.

Their function is recovery evidence/authorization according to policy.

---

# 63. Recovery Contact Security

Changing a recovery contact is itself security-sensitive.

A compromised session SHALL not trivially replace:

```text
trusted recovery contact
```

with:

```text
attacker contact
```

---

# 64. Email Recovery

Email MAY participate in ordinary recovery.

Email alone SHOULD NOT be sufficient for privileged/high-impact identity rebinding.

---

# 65. SMS Recovery

SMS MAY participate in lower-risk recovery where justified.

It SHALL not be the sole high-assurance recovery mechanism for privileged identities.

---

# 66. Knowledge-Based Authentication

Security questions such as:

```text
mother's maiden name
first school
favorite color
```

SHALL NOT be used as identity-proofing or high-risk recovery controls.

---

# 67. Existing Authenticator

Possession of another enrolled strong authenticator SHOULD be preferred over weaker recovery channels.

---

# 68. Multiple Recovery Evidence

High-risk recovery SHOULD require multiple independent pieces of evidence.

Example:

```text
verified existing corporate channel
+
manual organizational confirmation
+
identity evidence
```

where appropriate.

---

# 69. Recovery Notification

Every completed account recovery SHALL generate notification through an independently maintained channel where possible.

NIST SP 800-63B-4 explicitly requires account-recovery notifications.

---

# 70. Notification Is Detection, Not Authorization

A notification saying:

```text
Your account was recovered.
```

does not make an insecure recovery process secure.

It is an additional detection control.

---

# 71. Recovery Hold

High-risk recovery MAY impose a temporary security hold.

Example:

```text
Recovery completed
      │
      ▼
ordinary access restored
      │
      ▼
24-hour sensitive-change hold
      │
      ▼
full privileges restored
```

Exact periods SHALL be risk/policy driven.

---

# 72. Hold Candidates

A recovery hold MAY temporarily restrict:

```text
bank-detail changes
new administrator creation
credential export
API key creation
large approvals
recovery-contact changes
```

---

# 73. Recovery Does Not Restore Revoked Relationships

Suppose Jane previously had:

```text
Company A Approver
```

but that membership was revoked before recovery.

Successful recovery SHALL NOT restore it.

---

# 74. Recovery Does Not Unsuspend Identity

If:

```text
CanonicalIdentity = SUSPENDED
```

account recovery SHALL not automatically change it to ACTIVE.

---

# 75. Recovery Does Not Reverse Fraud Controls

A fraud/security hold remains independent of credential recovery.

---

# 76. New Authenticator Binding

Binding a new authenticator SHALL require authentication appropriate to the new authenticator's intended assurance.

NIST SP 800-63B-4 requires binding to be protected by authentication at the relevant available/intended assurance level and requires independent notification when a new authenticator is added.

---

# 77. Binding Example

```text
Jane
 │
 ▼
A3 authentication using Passkey A
 │
 ▼
requests Passkey B
 │
 ▼
new WebAuthn ceremony
 │
 ▼
Passkey B bound
 │
 ▼
independent notification
```

---

# 78. Cross-Device Binding

Cross-device authenticator enrollment SHALL use secure, short-lived, single-use binding mechanisms.

NIST SP 800-63B-4 specifies protected-channel and single-use binding-code requirements for external authenticator binding.

---

# 79. No Email Binding Codes for High-Assurance Cross-Device Binding

Where Baobab implements explicit cross-device authenticator binding codes, insecure channels SHALL not be used to transfer them.

---

# 80. Authenticator Removal

Removing an authenticator SHALL:

```text
require appropriate authentication
generate an audit event
notify the subscriber
invalidate the authenticator
```

according to policy.

---

# 81. Last Strong Authenticator

Removing the last phishing-resistant authenticator from a privileged account SHALL require exceptional controls.

---

# 82. Identity Linking

ADR-IAM-0004 remains controlling:

```text
email equality
```

SHALL NOT automatically link external identities.

---

# 83. Provider Migration Linking

During Keycloak → Ory migration:

```text
Keycloak ExternalIdentity
             │
             ▼
      CanonicalIdentity
             ▲
             │
Ory ExternalIdentity
```

may coexist.

The migration process SHALL prove that both external identities correspond to the same canonical subject.

---

# 84. Migration Rebinding Must Be Idempotent

Repeated migration execution SHALL NOT create:

```text
duplicate CanonicalIdentity
duplicate memberships
duplicate privileges
```

---

# 85. Email Collision

If:

```text
Keycloak identity A
and
Ory identity B
```

share an email address but cannot be safely proven equivalent:

```text
DO NOT AUTO-LINK
```

Escalate to controlled resolution.

---

# 86. Identity Merge

Canonical identity merge is a high-risk administrative operation.

It SHALL require:

```text
explicit evidence
audit
reason
privileged authorization
reversibility strategy where feasible
```

---

# 87. Identity Split

Incorrectly linked identities may require separation.

Split operations SHALL preserve:

```text
audit history
relationship provenance
domain ownership
```

rather than deleting evidence of the mistake.

---

# 88. Identity Proofing Does Not Belong in JWTs

Detailed proofing evidence SHALL NOT be embedded in ordinary access tokens.

At most, narrowly scoped assurance indicators MAY be conveyed where justified.

---

# 89. Avoid Sensitive Claims

Do not place:

```text
passport number
national identity number
document images
date of birth unless required
```

into general OAuth access tokens.

---

# 90. Proofing Freshness

A domain MAY require proofing to be:

```text
at least I2
AND
verified within policy period
```

for especially sensitive operations.

---

# 91. Relationship Freshness

An identity may remain proofed while its organization relationship becomes stale.

Example:

```text
Jane is still Jane
```

but:

```text
Jane no longer works for Company A
```

Therefore identity proofing and relationship verification require independent lifecycle management.

---

# 92. Organizational Offboarding

When a person leaves Company A:

```text
Company A membership
      │
      ▼
REVOKED
```

Their CanonicalIdentity remains.

Their Thamani personal account may remain.

Their Company B relationship may remain.

---

# 93. Proofing Evidence Providers

Baobab MAY integrate external proofing/verification providers.

Such providers SHALL remain adapters behind Baobab's proofing contract.

---

# 94. Vendor Independence

Prohibited:

```text
if vendor_x_status == "GREEN":
    buyer_admin = true
```

Required:

```text
Vendor Result
      │
      ▼
Baobab Proofing Adapter
      │
      ▼
Proofing Decision
      │
      ▼
Relationship Workflow
      │
      ▼
Domain Authorization
```

---

# 95. Provider Failure

If an external proofing provider is unavailable:

```text
proofing-required operation
        │
        ▼
PENDING / DEFER
```

rather than silently lowering the proofing requirement.

---

# 96. Manual Review

Manual review SHALL be a first-class workflow where automated proofing is inconclusive.

```text
AUTOMATED
    │
    ├── VERIFIED
    ├── REJECTED
    └── MANUAL_REVIEW
```

---

# 97. Reviewer Separation

Where financial or organizational control is significant, the person requesting proofing SHOULD NOT approve their own proofing or relationship.

---

# 98. Four-Eyes Principle

High-risk changes MAY require:

```text
Reviewer A
    +
Reviewer B
```

before activation.

Examples:

```text
supplier bank account
primary organization administrator
privileged recovery
```

---

# 99. Evidence Provenance

Every proofing decision SHOULD record:

```text
what evidence was considered
where it came from
which policy applied
who/what evaluated it
when evaluation occurred
decision
reason
```

---

# 100. Auditability

A future auditor SHOULD be able to answer:

```text
Why was Jane accepted as Company A administrator?
```

without reverse-engineering application logs.

---

# 101. Decision Record

Conceptually:

```json
{
  "canonical_identity_id": "ci_...",
  "proofing_level": "BAOBAB-I2",
  "relationship": "company_a:administrator",
  "decision": "VERIFIED",
  "policy_version": "IAM-PROOFING-2",
  "decision_at": "2026-09-26T12:00:00Z",
  "audit_reference": "aud_..."
}
```

---

# 102. Evidence vs Decision

Domain services SHOULD consume:

```text
proofing decision
```

rather than raw identity documents.

---

# 103. Proofing Policy Ownership

Recommended ownership:

```text
Security Architecture
    → proofing classes

IAM
    → proofing orchestration

CP
    → canonical identity association

Domain
    → relationship requirement

Compliance/Operations
    → jurisdiction-specific evidence requirements
```

---

# 104. Domain Requests Proofing

A domain MAY say:

```text
To become SUPPLIER_ADMIN,
required proofing = I2
```

The domain SHALL not implement document-verification cryptography itself.

---

# 105. Standard Requirement Contract

`shared` SHOULD define:

```json
{
  "required_proofing": "BAOBAB-I2",
  "relationship": "SUPPLIER_ADMIN",
  "reason": "HIGH_IMPACT_BUSINESS_AUTHORITY"
}
```

---

# 106. Standard Result Contract

Conceptually:

```json
{
  "proofing_level": "BAOBAB-I2",
  "status": "VERIFIED",
  "verified_at": "2026-09-26T12:00:00Z",
  "policy_version": "IAM-PROOFING-2"
}
```

---

# 107. Proofing + Assurance + Authorization

The complete decision becomes:

```text
Identity Proofing
      │
      ▼
Is this sufficiently established
as the intended person?
      │
      ▼
Authentication Assurance
      │
      ▼
Is this sufficiently strong
authentication right now?
      │
      ▼
Relationship
      │
      ▼
May this person represent
this organization/context?
      │
      ▼
Domain Authorization
      │
      ▼
May this operation occur?
```

---

# 108. Example — ZuriBeans First Buyer Admin

```text
Applicant
   │
   ▼
Ory registration
   │
   ▼
CanonicalIdentity
   │
   ▼
I0 initially
   │
   ▼
Company application
   │
   ▼
organization verification
   │
   ▼
representative proofing
   │
   ▼
I2 where policy requires
   │
   ▼
buyer organization approved
   │
   ▼
buyer-admin relationship assigned
   │
   ▼
A3 authentication required
```

---

# 109. Example — Additional Buyer Purchaser

```text
Verified Buyer Admin
       │
       ▼
invites Jane
       │
       ▼
Jane authenticates
       │
       ▼
invitation accepted
       │
       ▼
membership established
       │
       ▼
PURCHASER role
```

The proofing burden may be lower than for the first organization administrator.

---

# 110. Example — Thamani Personal Customer

```text
Jane
 │
 ▼
creates account
 │
 ▼
email verified
 │
 ▼
passkey enrolled
 │
 ▼
I0 + A3
 │
 ▼
ordinary personal shipping
```

No passport is required merely to achieve A3 authentication.

---

# 111. Example — Thamani Business Admin

```text
Jane
 │
 ▼
existing personal identity
 │
 ▼
Company A onboarding
 │
 ▼
Company A verified
 │
 ▼
Jane's representative authority verified
 │
 ▼
I2 if policy requires
 │
 ▼
BUSINESS_ADMIN relationship
 │
 ▼
A3 authentication
```

Same CanonicalIdentity.

---

# 112. Example — Supplier Bank Change

```text
Supplier Admin
      │
      ▼
requests new bank details
      │
      ▼
A3 step-up
      │
      ▼
representative relationship checked
      │
      ▼
proofing freshness checked
      │
      ▼
independent confirmation
      │
      ▼
second approval if policy requires
      │
      ▼
change activated
      │
      ▼
security notification + audit
```

---

# 113. Example — Lost Passkey

```text
Jane has:
Passkey A
Passkey B

Passkey A lost
    │
    ▼
authenticate with B
    │
    ▼
revoke A
    │
    ▼
bind Passkey C
    │
    ▼
notification
```

This is authenticator maintenance, not necessarily full recovery.

---

# 114. Example — All Authenticators Lost

```text
Jane
 │
 ▼
no valid authenticator
 │
 ▼
Recovery Class evaluated
 │
 ▼
appropriate recovery evidence
 │
 ▼
identity rebound
 │
 ▼
new authenticator
 │
 ▼
old sessions revoked
 │
 ▼
security notification
```

---

# 115. Example — Privileged Recovery

```text
IAM Administrator
      │
      ▼
all authenticators lost
      │
      ▼
ordinary email reset
      │
      ╳
    DENIED

Instead:

privileged recovery procedure
      │
      ▼
strong proofing
      │
      ▼
independent administrator/security review
      │
      ▼
new phishing-resistant authenticator
      │
      ▼
all prior sessions revoked
      │
      ▼
audit + notification
      │
      ▼
restricted initial session
```

---

# 116. Recovery Abuse Detection

Monitor:

```text
repeated recovery attempts
recovery after password change
recovery after email change
new device + recovery
new geography + recovery
recovery of privileged identity
recovery followed by bank change
```

---

# 117. Rebinding Cooling Period

For sufficiently high-risk recovery, Baobab MAY impose a cooling period before selected operations become available.

---

# 118. Rebinding Notification

High-risk rebinding SHOULD notify:

```text
previous verified channel
current verified channel
organization security/admin contact
```

where appropriate.

---

# 119. Disputed Recovery

Baobab SHALL support escalation when a legitimate user reports:

```text
I did not recover this account.
```

The platform SHOULD be able to:

```text
suspend identity
revoke sessions
freeze sensitive operations
preserve evidence
begin investigation
```

---

# 120. Fraudulent Proofing

If proofing is later determined fraudulent:

```text
ProofingRecord → REVOKED
```

followed by appropriate relationship and authorization review.

---

# 121. Do Not Cascade Blindly

Revoking proofing SHALL not automatically delete every business record.

Instead:

```text
security event
     │
     ▼
affected relationships identified
     │
     ▼
domain-specific suspension/review
```

---

# 122. Legal Identity Change

Legitimate name or identity-document changes SHALL support controlled reverification without creating an unnecessary new CanonicalIdentity.

---

# 123. Duplicate Person Detection

Potential duplicate identities MAY be flagged.

They SHALL NOT be automatically merged based solely on:

```text
same name
same email
same phone
```

---

# 124. Sensitive Identifiers

Government identifiers SHOULD be:

```text
minimized
encrypted/protected
masked
access-controlled
excluded from ordinary logs
```

where collected.

---

# 125. Document Images

Identity-document images SHALL not be stored in ordinary application databases unless specifically justified.

---

# 126. Retention

Proofing evidence SHALL have explicit retention rules.

Retention SHALL consider:

```text
business need
regulatory obligations
fraud investigation
privacy
data minimization
```

---

# 127. Deletion

Where evidence may lawfully be deleted after verification, Baobab SHOULD prefer retaining:

```text
verification result
evidence type
audit proof
```

rather than raw evidence indefinitely.

---

# 128. Access Control

Raw proofing evidence SHALL be accessible only to narrowly authorized workflows/personnel.

Ordinary:

```text
buyer admin
supplier admin
developer
customer-support user
```

SHALL not automatically receive access.

---

# 129. Support Staff

Customer support SHALL see only information required to perform support functions.

Support access to proofing evidence SHALL be separately controlled and audited.

---

# 130. Developer Access

Production identity evidence SHALL not be routinely accessible to developers.

Debugging SHALL use redacted/synthetic data where practical.

---

# 131. Non-Production

Real production identity documents SHALL NOT be copied into development/test environments.

---

# 132. Test Data

Proofing workflows SHALL use synthetic fixtures in CI.

---

# 133. Audit Logs

Audit SHALL not duplicate raw identity evidence.

Log:

```text
evidence_reference
decision
method
reviewer
timestamp
reason
```

not full documents.

---

# 134. Proofing Events

Canonical events SHOULD include:

```text
identity.proofing.started
identity.proofing.verified
identity.proofing.rejected
identity.proofing.expired
identity.proofing.revoked

identity.rebinding.started
identity.rebinding.completed
identity.rebinding.rejected

recovery.started
recovery.completed
recovery.failed

authenticator.bound
authenticator.revoked
```

---

# 135. Relationship Events

Relationship systems SHOULD separately emit:

```text
organization.membership.requested
organization.membership.verified
organization.membership.revoked

supplier.representative.verified
buyer.representative.verified
```

Do not overload identity events with domain state.

---

# 136. Correlation

A high-risk onboarding/recovery operation SHOULD be traceable across:

```text
Digital Estate
      │
      ▼
BFF
      │
      ▼
Ory
      │
      ▼
baobab-iam
      │
      ▼
CP
      │
      ▼
Domain
```

using correlation identifiers.

---

# 137. Manual Reviewer Identity

Manual proofing decisions SHALL record the reviewer as a canonical workforce identity where possible.

---

# 138. No Anonymous Administrative Approval

Production identity proofing SHALL not be approved by:

```text
reviewer = admin
```

without an attributable identity.

---

# 139. Separation of Duties

High-impact recovery/proofing SHOULD prevent the same actor from:

```text
requesting
+
approving
+
executing
```

the complete privileged operation where practical.

---

# 140. Policy Versioning

Every proofing/recovery decision SHALL be associated with a policy version where practical.

Example:

```text
IAM-PROOFING-2026-02
```

---

# 141. Policy as Code

Requirements SHOULD become auditable configuration where practical.

Example:

```yaml
relationship: supplier_admin
minimum_proofing: BAOBAB-I2
minimum_authentication: BAOBAB-A3
recovery_class: R2
manual_review:
  conditional: true
```

---

# 142. Domain-Specific Policy

Different relationships may legitimately require different proofing.

Example:

```yaml
relationship: thamani_personal_customer
minimum_proofing: BAOBAB-I0
```

versus:

```yaml
relationship: supplier_primary_admin
minimum_proofing: BAOBAB-I2
```

---

# 143. Avoid Universal KYC

Baobab SHALL NOT implement:

```text
EVERY USER
    │
    ▼
KYC
```

as a generic platform rule.

Proofing must be justified by the service and risk.

---

# 144. Proofing vs Regulatory KYC

Identity proofing and regulatory KYC/AML are related but not synonymous.

A domain subject to KYC/AML requirements SHALL define those obligations separately.

This ADR SHALL not be interpreted as claiming regulatory KYC compliance.

---

# 145. Proofing vs Business Verification

Similarly:

```text
person identity proofing
```

is distinct from:

```text
business verification
```

such as company-registration validation.

---

# 146. Four Assurance Dimensions

Baobab therefore recognizes:

```text
PERSON IDENTITY
      │
      ▼
BAOBAB-I*

AUTHENTICATION
      │
      ▼
BAOBAB-A*

RELATIONSHIP
      │
      ▼
VERIFIED / UNVERIFIED / REVOKED

AUTHORIZATION
      │
      ▼
ALLOW / DENY
```

---

# 147. Full Decision Example

```text
Jane requests:
Change Supplier Bank Account
            │
            ▼
CanonicalIdentity valid?
            │
            ▼
I2 proofing current?
            │
            ▼
Supplier relationship verified?
            │
            ▼
A3 authentication current?
            │
            ▼
Supplier domain role permits change?
            │
            ▼
dual approval required?
            │
            ▼
ALLOW / DENY
```

---

# 148. Proofing Failure

If required proofing fails:

```text
identity
```

need not necessarily be deleted.

Instead:

```text
requested relationship/operation
        │
        ▼
DENIED / PENDING REVIEW
```

---

# 149. Recovery Failure

Failed recovery SHALL not reveal unnecessary information about whether a particular account exists.

---

# 150. Enumeration Resistance

Proofing and recovery endpoints SHALL resist account enumeration where applicable.

---

# 151. Rate Limiting

Protect:

```text
proofing initiation
document submission
recovery
recovery-code validation
identity linking
rebinding
```

against automated abuse.

---

# 152. Evidence Upload Security

Uploaded proofing evidence SHALL be subject to:

```text
size limits
content-type validation
malware scanning where appropriate
safe object storage
encryption
access control
retention
```

---

# 153. Signed Uploads

If direct object-storage uploads are used:

```text
signed upload URL
```

SHALL be:

```text
short-lived
single-purpose
identity/context bound
size constrained
```

where technically feasible.

---

# 154. Evidence Processing

Document processing services SHALL be treated as sensitive workloads.

They SHALL receive only necessary evidence and return bounded verification results.

---

# 155. AI/OCR Boundary

Automated extraction or AI-assisted document review MAY assist proofing.

It SHALL NOT become an unexplained autonomous source of high-risk authorization.

Human review SHOULD remain available for ambiguous/high-impact cases.

---

# 156. Bias and Error

Identity proofing systems can produce false rejection and false acceptance.

Baobab SHALL monitor:

```text
verification failures
manual-review rates
false-positive indicators
jurisdiction/device disparities
```

where possible.

---

# 157. Accessible Proofing

Proofing SHALL provide reasonable alternatives for users who cannot successfully complete a particular:

```text
camera
biometric
document
device
```

workflow where security requirements permit.

---

# 158. Cross-Border Considerations

Baobab operates across jurisdictions with different:

```text
identity documents
company registries
tax identifiers
languages
address systems
```

Proofing SHALL therefore be extensible rather than hard-coded around one country's evidence model.

---

# 159. Market Does Not Define Identity

A user moving between:

```text
Uganda
South Africa
Kenya
```

remains the same CanonicalIdentity where appropriate.

Market context SHALL not create duplicate persons.

---

# 160. Regional Data Residency

Identity evidence may be subject to stricter residency requirements than ordinary profile data.

Regional storage/routing SHALL therefore be evaluated explicitly under the multi-region IAM architecture.

---

# 161. CP Shall Not Become Document Repository

The Control Plane SHALL maintain canonical identity semantics.

It SHOULD NOT become the universal storage location for raw identity documents.

---

# 162. Ory Shall Not Become Business Evidence Repository

Kratos identity traits SHALL not be expanded into:

```text
supplier certificate archive
company registry
tax dossier
bank verification store
```

---

# 163. ERP Shall Not Become Identity Proofing Authority

iDempiere may contain business-party information.

It SHALL not become the canonical proofing authority merely because similar data exists there.

---

# 164. Trade Shall Not Become Identity Proofing Authority

Medusa/Trade may know buyer actors.

It SHALL consume verified relationships rather than inventing canonical identity proofing.

---

# 165. Provider-Neutral Architecture

```text
Proofing Provider A ─┐
Proofing Provider B ─┼──► baobab-iam proofing boundary
Manual Review ───────┘
                           │
                           ▼
                    Proofing Decision
                           │
                           ▼
                   CanonicalIdentity
                           │
                           ▼
                    Relationship
                           │
                           ▼
                       Domain
```

No downstream engine needs to know which vendor performed document verification unless required for audit.

---

# 166. Migration From Keycloak

Keycloak → Ory migration SHALL NOT reset proofing state.

Proofing belongs to Baobab's canonical identity architecture, not to the provider account.

---

# 167. Migration Example

Before:

```text
CanonicalIdentity Jane
├── Keycloak ExternalIdentity
└── Proofing I2
```

During:

```text
CanonicalIdentity Jane
├── Keycloak ExternalIdentity
├── Ory ExternalIdentity
└── Proofing I2
```

After:

```text
CanonicalIdentity Jane
├── Ory ExternalIdentity
└── Proofing I2
```

No re-proofing is required solely because the IdP changed, unless evidence/policy independently requires it.

---

# 168. Migration Exception

If old proofing provenance cannot be established reliably:

```text
proofing status = UNKNOWN
```

SHALL be safer than falsely asserting I2.

---

# 169. Security Invariants

The following SHALL remain true:

```text
Authentication ≠ Identity Proofing

Identity Proofing ≠ Authorization

Identity Proofing ≠ Organization Verification

Organization Verification ≠ Representative Authority

Representative Authority ≠ Domain Permission

Email Verification ≠ Civil Identity Verification

Passkey ≠ Identity Proofing

MFA ≠ Identity Proofing

Federation ≠ Unlimited Trust

Recovery ≠ Privilege Restoration

Recovery ≠ Unsuspension

Authenticator Binding ≠ Canonical Identity Creation

Same Email ≠ Same Person

Provider Identity ≠ CanonicalIdentity

Identity Provider Migration ≠ New Person

KYC ≠ Generic IAM

Proofing Vendor ≠ Authorization Authority

Document Upload ≠ Verification

Verified Person ≠ Verified Company

Verified Company ≠ Verified Representative
```

---

# 170. Implementation Gates

## IAM-P0 — Current-State Audit

Inventory:

```text
current verification fields
Keycloak verification state
Kratos identity schema
recovery mechanisms
business onboarding
supplier verification
buyer verification
workforce onboarding
manual processes
```

Identify accidental conflation of:

```text
email verification
identity proofing
business verification
authorization
```

---

## IAM-P1 — Shared Proofing Contracts

Define provider-neutral:

```text
ProofingLevel
ProofingStatus
IdentityProofingRecord
VerifiedAttribute
EvidenceReference
RecoveryClass
RebindingDecision
```

---

## IAM-P2 — Canonical Identity Integration

Add/validate CP references necessary to associate proofing outcomes with CanonicalIdentity without storing unnecessary raw evidence.

---

## IAM-P3 — Ory Verification Boundary

Map Ory:

```text
email verification
recovery
authenticator lifecycle
```

to Baobab semantics without misclassifying them as business identity proofing.

---

## IAM-P4 — Recovery Architecture

Implement:

```text
R0
R1
R2
R3
```

recovery policy and provider integration.

---

## IAM-P5 — Authenticator Rebinding

Implement:

```text
secure additional authenticator binding
replacement
revocation
notification
cross-device binding
```

---

## IAM-P6 — B2B Organization Proofing

Implement first-admin and organization-representative verification contracts for:

```text
ZuriBeans
Thamani B2B
future B2B estates
```

---

## IAM-P7 — Supplier Proofing

Implement:

```text
supplier representative
supplier organization
high-risk supplier changes
```

while preserving supplier-domain ownership.

---

## IAM-P8 — Workforce and Privileged Proofing

Implement:

```text
employee/contractor binding
privileged admin proofing
privileged recovery
break-glass proofing
```

---

## IAM-P9 — Manual Review

Implement controlled:

```text
review queue
review decision
reason
evidence reference
reviewer identity
audit
```

---

## IAM-P10 — Evidence Security

Implement:

```text
secure evidence storage
encryption
malware scanning
retention
access control
redaction
```

where raw evidence is actually required.

---

## IAM-P11 — Proofing Provider Adapters

Introduce provider-neutral adapters only when actual external proofing services are selected.

Do not prematurely bind canonical contracts to a vendor.

---

## IAM-P12 — Keycloak/Ory Migration

Preserve canonical proofing state through ADR-IAM-0022 migration.

Test identity-linking ambiguity and collision handling.

---

## IAM-P13 — Observability and Fraud Detection

Implement:

```text
proofing events
recovery events
rebinding events
abuse monitoring
alerts
```

---

## IAM-P14 — Production Hardening

Execute:

```text
account takeover tests
recovery abuse tests
identity-linking attacks
admin takeover tests
supplier bank-change attacks
evidence access tests
```

---

# 171. Required Test Matrix

| Scenario | Expected |
|---|---|
| Passkey user with no proofing | A3 may coexist with I0 |
| I2 user authenticates weakly | Step-up where A3 required |
| Same email on two identities | No automatic merge |
| First buyer admin | Enhanced organization/representative verification |
| Invited ordinary buyer | Policy-appropriate reduced proofing |
| Supplier admin changes bank | Strong authentication + relationship verification + high-risk controls |
| User loses one of two passkeys | Authenticator replacement, not necessarily recovery |
| User loses all authenticators | Recovery policy |
| Privileged admin requests email-only recovery | Deny |
| Recovery completed | No revoked privileges restored |
| Suspended identity recovered | Remains suspended |
| New authenticator bound | Notification generated |
| Proofing revoked | Affected relationships reviewed |
| Ory migration | Existing proofing preserved |
| Email collision during migration | Manual resolution |
| Raw evidence request by unauthorized service | Deny |
| Proofing provider unavailable | No assurance downgrade |
| Business relationship revoked | Identity remains |
| User changes market | No duplicate CanonicalIdentity |

---

# 172. Production Readiness Checklist

### Architecture

- [ ] authentication separated from proofing
- [ ] proofing separated from relationship verification
- [ ] relationship separated from authorization
- [ ] provider-neutral proofing model
- [ ] I0–I3 defined
- [ ] R0–R3 defined

### Canonical Identity

- [ ] proofing references CanonicalIdentity
- [ ] no email auto-linking
- [ ] identity merge controlled
- [ ] identity split supported operationally
- [ ] provider migration does not create new people

### B2B

- [ ] first-admin bootstrap protected
- [ ] invitation model defined
- [ ] representative verification defined
- [ ] organization-control changes protected
- [ ] multi-company identity preserved

### Suppliers

- [ ] supplier organization verification
- [ ] representative verification
- [ ] bank-change controls
- [ ] supplier approval separate from identity
- [ ] product approval separate from identity

### Recovery

- [ ] recovery classes
- [ ] ordinary recovery
- [ ] enhanced recovery
- [ ] privileged recovery
- [ ] security notifications
- [ ] old-session handling
- [ ] security holds where appropriate
- [ ] recovery cannot restore revoked authority

### Authenticators

- [ ] additional authenticator binding protected
- [ ] authenticator removal protected
- [ ] last-strong-factor removal protected
- [ ] cross-device binding secured
- [ ] notifications generated

### Evidence

- [ ] evidence minimization
- [ ] encrypted storage
- [ ] access controls
- [ ] retention policy
- [ ] non-production isolation
- [ ] no raw evidence in logs
- [ ] evidence provenance

### Operations

- [ ] manual review workflow
- [ ] reviewer attribution
- [ ] separation of duties
- [ ] policy versioning
- [ ] proofing events
- [ ] recovery events
- [ ] abuse alerts
- [ ] incident procedure

### Migration

- [ ] Keycloak proofing state inventoried
- [ ] Ory semantics mapped
- [ ] dual identity mapping tested
- [ ] collision handling tested
- [ ] no assurance/proofing downgrade

---

# 173. Final Architecture

```text
                           PERSON
                             │
                             ▼
                 ┌─────────────────────┐
                 │ IDENTITY PROOFING   │
                 │                     │
                 │ I0 / I1 / I2 / I3 │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ CanonicalIdentity   │
                 │     baobab-cp       │
                 └──────────┬──────────┘
                            │
             ┌──────────────┼───────────────┐
             │              │               │
             ▼              ▼               ▼
        Ory Identity    Organization    Supplier /
        Credentials     Relationship   Workforce
             │              │          Relationship
             ▼              │               │
      Authentication        │               │
      A0/A1/A2/A3/A4       │               │
             │              │               │
             └──────────────┼───────────────┘
                            │
                            ▼
                    ACTIVE CONTEXT
                            │
                            ▼
                  DOMAIN AUTHORIZATION
                            │
                     ┌──────┴──────┐
                     ▼             ▼
                   ALLOW          DENY
```

Recovery operates orthogonally:

```text
Lost Authenticators
        │
        ▼
Recovery Classification
 R0 / R1 / R2 / R3
        │
        ▼
Recovery Evidence
        │
        ▼
Identity Rebinding
        │
        ▼
New Authenticator
        │
        ▼
Session Revocation
        │
        ▼
Notification / Hold
        │
        ▼
Existing CanonicalIdentity
        │
        ▼
Relationships re-evaluated,
NOT recreated automatically
```

---

# 174. Consequences

## Positive

This architecture gives Baobab:

- explicit separation between authentication and identity proofing;
- proportional rather than universal proofing;
- safer B2B administrator onboarding;
- safer supplier onboarding;
- stronger finance and privileged-user binding;
- hardened account recovery;
- secure authenticator rebinding;
- provider-neutral proofing semantics;
- reduced identity duplication;
- stronger Keycloak-to-Ory migration safety;
- clear evidence provenance;
- stronger resistance to account takeover and social engineering.

## Costs

Baobab must maintain:

- proofing policies;
- evidence references;
- relationship verification workflows;
- recovery classes;
- manual-review capability;
- high-risk rebinding procedures;
- proofing audit and lifecycle.

These costs should be incurred only where the risk justifies them.

## Risks

The principal implementation risks are:

```text
unnecessary KYC friction
over-collection of personal data
weak account recovery
email-based identity merging
proofing vendor lock-in
identity/business verification conflation
manual-review abuse
excessive document retention
privileged recovery shortcuts
```

The controls in this ADR explicitly constrain these risks.

---

# 175. Final Decision Principle

Baobab SHALL recognize that there are progressively different questions:

```text
WHO DOES THIS ACCOUNT CLAIM TO BE?
             │
             ▼
Self-Asserted Identity

WHO HAVE WE ESTABLISHED THIS PERSON TO BE?
             │
             ▼
Identity Proofing

CAN THEY PROVE CONTROL OF THEIR AUTHENTICATOR?
             │
             ▼
Authentication Assurance

WHOM MAY THEY REPRESENT?
             │
             ▼
Relationship Verification

IN WHICH PLATFORM CONTEXT MAY THEY ACT?
             │
             ▼
Control Plane

WHAT MAY THEY DO?
             │
             ▼
Domain Authorization
```

No one layer may silently answer all six questions.

For ordinary users, Baobab SHALL keep proofing proportionate and unobtrusive.

For administrators, finance users, organizational controllers, supplier representatives and recovered privileged identities, Baobab SHALL demand stronger evidence before establishing or re-establishing consequential authority.

Most importantly:

> **Authenticate the credential. Proof the person when necessary. Verify the relationship separately. Rebind identities cautiously. Authorize only at the proper authority boundary.**