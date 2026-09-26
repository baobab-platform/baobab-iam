# ADR-IAM-0030 — Identity Privacy, Personal Information Governance, Retention, Erasure and Regulatory Compliance Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Privacy & Information Governance / Security Architecture  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/shared`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold and all future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0029  
**Extends:** ADR-IAM-0003, 0004, 0005, 0016, 0017, 0018, 0019, 0020, 0025, 0026, 0027, 0028, 0029  
**Decision Type:** Privacy / Personal Information Governance / Retention / Erasure / Regulatory Compliance  
**Primary Initial Regulatory Context:** South Africa / POPIA  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane

---

# 1. Decision

Baobab SHALL govern identity-related personal information according to:

```text
PURPOSE
   ↓
MINIMISATION
   ↓
AUTHORITY
   ↓
ACCESS CONTROL
   ↓
RETENTION
   ↓
RESTRICTION
   ↓
ERASURE / ANONYMISATION
   ↓
AUDITABLE COMPLETION
```

Identity information SHALL NOT be treated as one indivisible data object.

Baobab SHALL distinguish at least:

```text
Authentication Data
Canonical Identity Data
Identity Proofing Data
Contact / Profile Data
Business Relationship Data
Authorization Data
Transaction Data
Security Telemetry
Audit Evidence
Consent / Privacy Records
Support Records
Backup Copies
Derived / Analytical Data
```

Each class SHALL have its own:

```text
authority
purpose
lawful basis
sensitivity
storage boundary
access policy
retention rule
correction mechanism
restriction mechanism
erasure/anonymisation rule
residency requirements
audit requirements
```

The governing principle is:

> **Collect only what Baobab needs, keep it only for a justified purpose, disclose it only to an authorized consumer, and remove or de-identify it when that justification ends.**

---

# 2. Privacy Is an Architectural Boundary

Privacy SHALL NOT be implemented merely through:

```text
privacy policy page
cookie banner
terms and conditions
```

It SHALL influence:

```text
schemas
APIs
events
logs
backups
analytics
identity-provider configuration
cross-border replication
retention jobs
administrative tooling
data exports
deletion workflows
```

---

# 3. Privacy Is Not Authentication

```text
Authentication
     ≠
Privacy

Authorization
     ≠
Consent

Consent
     ≠
Business Authority

Deletion
     ≠
Revocation

Retention
     ≠
Active Processing
```

---

# 4. POPIA Baseline

For South African processing, Baobab SHALL design for the conditions for lawful processing established by the Protection of Personal Information Act 4 of 2013.

The architecture SHALL support:

```text
accountability
processing limitation
purpose specification
further-processing limitation
information quality
openness
security safeguards
data-subject participation
```

The architecture SHALL NOT assume that:

```text
consent
```

is the only possible lawful basis for every processing operation.

---

# 5. Responsible Party and Operator Must Be Explicit

For every material identity-processing flow, Baobab SHALL be capable of identifying:

```text
Responsible Party
Operator
Purpose
System of Record
Recipients
Processing Location
Retention Rule
```

Baobab Platform being technical infrastructure does not automatically make it the responsible party for every customer's processing.

---

# 6. Multi-Tenant Privacy Responsibility

For an external Baobab customer:

```text
Customer Organization
        │
        │ determines business purpose
        ▼
Baobab Platform
        │
        │ processes according to
        │ architecture + agreement
        ▼
Identity Infrastructure
```

the exact responsible-party/operator relationship SHALL be determined contractually and legally rather than inferred from technical tenancy.

---

# 7. Group Companies Remain Distinct

Nabhold Group Africa ownership does not mean:

```text
ZuriBeans personal information
       =
Thamani personal information
       =
Equator & Estate personal information
```

Each processing purpose and legal entity SHALL remain explicit.

---

# 8. Shared Platform Does Not Mean Shared Personal Data

Baobab MAY share:

```text
identity infrastructure
canonical contracts
security controls
technical capabilities
```

without automatically sharing:

```text
customer profiles
buyer records
supplier records
shipment records
ERP records
marketing profiles
```

between tenants or legal entities.

---

# 9. CanonicalIdentity

The CP `CanonicalIdentity` SHALL remain deliberately minimal.

It exists to establish stable identity continuity across Baobab.

It SHALL NOT become a universal customer profile.

Conceptually:

```text
CanonicalIdentity
├── canonical_identity_id
├── identity_type
├── lifecycle_state
├── created_at
├── updated_at
└── minimal governance metadata
```

---

# 10. Canonical Identity Minimisation

Avoid placing into CanonicalIdentity unless genuinely required:

```text
full address
marketing preferences
shipping addresses
bank details
tax numbers
passport scans
supplier documents
employment records
transaction history
behavioural analytics
```

---

# 11. ExternalIdentity

External identity mappings SHALL contain only what is needed to map:

```text
Issuer + Subject
        ↓
CanonicalIdentity
```

Provider-specific profile duplication SHOULD be minimized.

---

# 12. Ory Kratos Boundary

Kratos SHALL own authentication-oriented identity traits and credential lifecycle necessary for authentication.

Kratos SHALL NOT become Baobab's universal business-profile database.

---

# 13. Kratos Traits

A Kratos identity schema SHOULD contain only attributes required for:

```text
authentication
verification
recovery
authentication UX
identity lifecycle
```

where justified.

---

# 14. Business Data Does Not Belong in Kratos

Do not put into Kratos merely for convenience:

```text
buyer credit limit
supplier approval
purchase authority
ERP role
shipment authority
tenant ownership
pricing entitlement
banking details
commercial contracts
```

---

# 15. Credentials

Credential secrets remain under the identity runtime according to earlier IAM ADRs.

Baobab applications SHALL not duplicate:

```text
password hashes
TOTP secrets
recovery codes
passkey private keys
```

---

# 16. Passkey Privacy

Baobab stores or processes only server-side information required by WebAuthn/provider operation.

Private passkey key material remains with the authenticator.

---

# 17. Proofing Data

ADR-IAM-0025 identity-proofing evidence SHALL be treated as a separate high-sensitivity class.

Examples may include:

```text
identity documents
verification results
evidence references
proofing decisions
manual review records
```

---

# 18. Proofing Evidence Minimisation

Where possible, downstream systems SHOULD receive:

```text
proofing status
assurance result
verification reference
```

instead of copies of raw proofing documents.

---

# 19. Proofing Evidence Retention

Raw identity evidence SHOULD normally have a shorter and more restrictive lifecycle than the resulting proofing decision unless law or legitimate operational requirements justify otherwise.

---

# 20. Business Relationships

Business relationships remain in their authoritative systems.

Examples:

```text
CP
  → platform memberships/context

Trade
  → buyer/customer commercial relationships

Supplier domain
  → supplier representatives

ERP
  → workforce/finance/accounting roles

Thamani
  → shipping/logistics relationships
```

---

# 21. Identity Deletion Does Not Delete Accounting History

A request to erase an authentication identity SHALL NOT blindly destroy legally required:

```text
invoices
orders
accounting records
shipment records
tax records
contracts
fraud evidence
```

---

# 22. Personal Data May Remain Inside Business Records

Where transaction records must remain but direct identity is no longer required, systems SHOULD consider:

```text
anonymisation
pseudonymisation
restriction
minimal archival identity
```

subject to applicable legal requirements.

---

# 23. Purpose Registry

Baobab SHOULD maintain a versioned processing-purpose registry.

Conceptually:

```text
ProcessingPurpose
├── purpose_id
├── name
├── description
├── data_classes
├── lawful_basis
├── responsible_party
├── processors/operators
├── recipients
├── retention_policy
├── residency_policy
└── status
```

---

# 24. Purpose Binding

Personal information SHALL be collected for an identified purpose.

The fact that information exists in the platform SHALL NOT itself authorize unrelated reuse.

---

# 25. Further Processing

New uses of existing personal information SHALL be assessed for compatibility with the original purpose and applicable legal requirements.

---

# 26. No "Collect Now, Decide Later"

Prohibited pattern:

```text
collect everything
       ↓
store indefinitely
       ↓
perhaps use later
```

---

# 27. Data Classification

Baobab SHALL classify identity-related information.

Suggested classes:

```text
P0 — Public / Non-Personal
P1 — Ordinary Personal Information
P2 — Sensitive Authentication / Security Information
P3 — High-Sensitivity Proofing / Financial / Regulatory Information
P4 — Cryptographic Secrets / Credentials
```

Exact classification taxonomy MAY be refined by platform security governance.

---

# 28. Special Personal Information

Where Baobab processes legally defined special personal information, the processing SHALL receive additional review and safeguards appropriate to applicable law.

---

# 29. Children

Where a Digital Estate intentionally processes children's personal information, it SHALL not simply inherit ordinary adult identity-processing assumptions.

Specific lawful authority, safeguards and UX MAY be required.

---

# 30. Data Inventory

Baobab SHALL maintain sufficient inventory to answer:

```text
What personal information do we have?

Why do we have it?

Where is it?

Which system is authoritative?

Who can access it?

Where is it processed?

How long is it retained?

How is it deleted or restricted?
```

---

# 31. Data Lineage

For material personal information, Baobab SHOULD know:

```text
SOURCE
  ↓
AUTHORITATIVE STORE
  ↓
DERIVED STORES
  ↓
EVENTS
  ↓
CACHE
  ↓
ANALYTICS
  ↓
BACKUP
```

---

# 32. Copy Minimisation

The number of copies of personal information SHOULD be minimized.

---

# 33. Event Minimisation

Events SHOULD carry identifiers/references rather than entire identity profiles where possible.

Prefer:

```text
canonical_identity_id
supplier_id
context_id
```

over broadcasting:

```text
full name
email
phone
address
passport
bank details
```

to every subscriber.

---

# 34. Event Purpose

A consumer SHALL receive personal information only when necessary for its legitimate event-processing responsibility.

---

# 35. Logs

Application logs SHALL avoid personal information unless operationally required.

---

# 36. No Credential Logging

Existing prohibitions remain absolute for:

```text
passwords
access tokens
refresh tokens
session cookies
private keys
TOTP secrets
recovery codes
```

---

# 37. Identifier Logging

Where correlation requires an identity reference, prefer stable internal opaque identifiers over email/phone.

---

# 38. Telemetry

Security telemetry governed by ADR-IAM-0029 MAY contain personal information where necessary for security.

This does not authorize unrelated profiling.

---

# 39. Security Purpose Limitation

Security telemetry SHALL NOT silently become:

```text
marketing data
employee productivity analytics
customer scoring
commercial profiling
```

---

# 40. Data Quality

Where personal information influences identity or access decisions, Baobab SHALL provide mechanisms appropriate to maintaining:

```text
accuracy
completeness
currency
non-misleading state
```

---

# 41. Correction

Correcting profile data SHALL NOT rewrite immutable historical records where historical integrity must be preserved.

Example:

```text
current email changed
```

does not mean:

```text
rewrite old invoice
```

unless legally/operationally appropriate.

---

# 42. Identity Continuity

Changing:

```text
name
email
phone
address
```

SHALL NOT create a new CanonicalIdentity merely because mutable personal attributes changed.

---

# 43. Email Is Not Identity

This reinforces ADR-IAM-0004:

```text
email
≠
CanonicalIdentity
```

---

# 44. Access Rights

Baobab SHALL support workflows necessary to identify and retrieve personal information associated with a data subject where applicable.

---

# 45. Access Is Not Raw Database Access

A data-subject access process SHALL produce an appropriate disclosure/export.

It SHALL NOT grant the user direct access to:

```text
Kratos database
CP database
security telemetry database
ERP database
```

---

# 46. Privacy Request Model

Conceptually:

```text
PrivacyRequest
├── request_id
├── request_type
├── canonical_identity_reference?
├── requester
├── verification_state
├── received_at
├── jurisdiction
├── responsible_party
├── status
├── due_at?
├── disposition
└── completed_at
```

---

# 47. Privacy Request Types

At minimum architecture SHOULD accommodate:

```text
ACCESS
CORRECTION
ERASURE
RESTRICTION
OBJECTION
EXPORT
CONSENT_WITHDRAWAL
```

where legally applicable.

---

# 48. Request Authentication

Privacy requests SHALL require proportionate verification.

Baobab SHALL NOT disclose sensitive identity information merely because someone knows an email address.

---

# 49. High-Risk Requests

Requests involving:

```text
proofing records
security evidence
financial identity
large exports
```

MAY require stronger verification.

---

# 50. Requester ≠ Data Subject

Architecture SHALL support situations where an authorized:

```text
representative
guardian
legal authority
```

may legitimately act for another data subject, subject to verification.

---

# 51. Data Subject Discovery

Baobab SHALL use canonical mappings and authoritative system registries to discover relevant records.

It SHALL NOT rely solely on:

```text
SELECT * WHERE email = ...
```

---

# 52. Data Discovery

Conceptually:

```text
Verified Privacy Request
          │
          ▼
CanonicalIdentity
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
 Kratos   CP   Domains
                │
        ┌───────┼────────┐
        ▼       ▼        ▼
      Trade    ERP    Supplier/Other
        │
        ▼
Telemetry / Audit / Archive references
```

---

# 53. Privacy Orchestration

Baobab SHOULD provide a privacy orchestration mechanism rather than giving one database authority over all deletion.

---

# 54. Orchestrator Is Not Data Owner

The privacy orchestrator coordinates requests.

Each authoritative system decides how its records must be:

```text
corrected
restricted
erased
anonymised
retained
```

under governing policy.

---

# 55. Erasure Is a Saga

Identity erasure SHALL be implemented as an auditable distributed workflow.

```text
REQUEST
   ↓
VERIFY
   ↓
DISCOVER
   ↓
CLASSIFY
   ↓
CHECK RETENTION / LEGAL HOLDS
   ↓
REVOKE ACTIVE ACCESS
   ↓
ERASE / ANONYMISE / RESTRICT
   ↓
PROPAGATE
   ↓
VERIFY
   ↓
COMPLETE
```

---

# 56. Erasure State

Conceptually:

```text
ErasureCase
├── case_id
├── subject_reference
├── systems[]
├── legal_holds[]
├── started_at
├── actions[]
├── exceptions[]
├── verification_state
└── completed_at
```

---

# 57. Erasure Outcomes

A record MAY end as:

```text
DELETED
ANONYMISED
PSEUDONYMISED
RESTRICTED
RETAINED_WITH_JUSTIFICATION
NOT_FOUND
```

---

# 58. Deactivation Is Not Erasure

```text
account.disabled
```

does not mean:

```text
personal_information.erased
```

---

# 59. Erasure Is Not Immediate Credential Revocation Only

Credential revocation is normally an early step.

It is not the complete privacy workflow.

---

# 60. Erasure Must Not Resurrect Access

After erasure/deactivation:

```text
backup restore
DR
event replay
reconciliation
```

SHALL NOT accidentally recreate active authority.

---

# 61. Tombstones

Minimal tombstones MAY be retained where necessary to prevent:

```text
identity resurrection
duplicate processing
security-state rollback
```

provided they contain the minimum information necessary.

---

# 62. Tombstone ≠ Shadow Profile

A tombstone SHALL NOT become a hidden retained copy of the deleted profile.

---

# 63. Pseudonymisation

Pseudonymisation MAY reduce exposure but SHALL NOT automatically be treated as equivalent to anonymisation.

If data can reasonably be linked back to the individual, it remains governed personal information.

---

# 64. Anonymisation

Anonymised information SHOULD no longer permit reasonable re-identification using retained means.

---

# 65. Hashing Is Not Automatically Anonymisation

```text
SHA256(email)
```

is not automatically anonymous.

Low-entropy identifiers can often be recomputed or linked.

---

# 66. Analytics

Where analytics does not require identity, Baobab SHOULD use:

```text
aggregation
anonymisation
pseudonymisation
```

as appropriate.

---

# 67. Baobab Pulse

Pulse SHALL NOT receive unrestricted identity data merely because it is an intelligence engine.

---

# 68. Pulse Boundary

Pulse MAY receive:

```text
aggregated
anonymised
pseudonymised
purpose-approved
```

information according to explicit contracts.

---

# 69. AI / ML Training

Personal identity data SHALL NOT automatically become AI/ML training data.

Any such use requires explicit governance, purpose and legal assessment.

---

# 70. Derived Data

Derived:

```text
risk score
fraud signal
security classification
identity confidence
```

may itself constitute personal information where associated with an identifiable person.

It therefore requires lifecycle governance.

---

# 71. Risk Scores

ADR-IAM-0029 risk assessments SHALL expire or be reevaluated.

Baobab SHALL NOT retain indefinite behavioural labels without justification.

---

# 72. Retention Principle

Retention SHALL be purpose-specific.

There SHALL NOT be one universal:

```text
retain all identity data for seven years
```

policy.

---

# 73. Retention Policy

Conceptually:

```text
RetentionPolicy
├── policy_id
├── data_class
├── purpose
├── trigger
├── duration
├── disposition
├── legal_basis
├── jurisdiction
├── exceptions
└── policy_version
```

---

# 74. Retention Trigger

Retention MAY begin from:

```text
collection
last activity
account closure
relationship termination
transaction completion
contract termination
incident closure
legal hold release
```

depending on the record.

---

# 75. Retention Outcomes

At retention expiry:

```text
DELETE
ANONYMISE
ARCHIVE_RESTRICTED
REVIEW
```

SHALL occur according to policy.

---

# 76. Indefinite Retention Is Exceptional

`FOREVER` SHALL not be a casual default retention value.

---

# 77. Legal Holds

Baobab SHALL support:

```text
LegalHold
```

where deletion must temporarily stop.

---

# 78. Legal Hold Scope

A hold SHALL identify:

```text
reason
authority
scope
records
start
review
release
```

---

# 79. Legal Hold Is Not Global Freeze

A hold concerning:

```text
invoice records
```

does not automatically justify retaining unrelated:

```text
marketing preferences
old device fingerprints
raw proofing documents
```

---

# 80. Restriction

Where information must remain but ordinary processing should cease:

```text
RESTRICTED
```

state SHOULD be supported.

---

# 81. Restricted Data

Restricted data SHOULD be unavailable to normal operational processing except where the governing purpose permits.

---

# 82. Audit Evidence

Security/audit evidence MAY require retention after an operational identity has been deleted.

---

# 83. Audit Minimisation

Retained audit evidence SHOULD contain the minimum information necessary for:

```text
security
accountability
legal defence
regulatory obligations
forensics
```

---

# 84. Immutable Audit vs Correction

Historical audit records SHALL not be rewritten to pretend past events occurred under a person's current profile attributes.

---

# 85. Detached Historical References

Where appropriate:

```text
CanonicalIdentity UUID
```

may remain in restricted historical audit records even after profile attributes are removed, if justified by the audit purpose.

---

# 86. Audit Access

Historical security/audit identity information SHALL have narrower access than normal application profile information.

---

# 87. Backups

Backups are not exempt from privacy governance.

---

# 88. Backup Reality

Baobab SHALL NOT promise:

```text
every byte disappears from every immutable backup instantly
```

if the backup architecture cannot truthfully provide that behavior.

---

# 89. Backup Erasure Strategy

Instead:

```text
live data erased/restricted
        ↓
backup remains protected
        ↓
backup expires under retention
        ↓
if restored before expiry:
        ↓
erasure/restriction journal reapplied
```

---

# 90. Privacy Erasure Journal

Baobab SHALL maintain sufficient privacy-state information to prevent backup restoration from resurrecting erased identities.

---

# 91. Journal Minimisation

The erasure journal SHALL contain only what is necessary to reapply deletion/restriction.

---

# 92. DR Integration

ADR-IAM-0027 recovery procedures SHALL replay:

```text
security journal
+
privacy erasure/restriction state
```

before restored IAM becomes authoritative.

---

# 93. Backup Retention

Backup retention SHALL itself be defined and enforced.

---

# 94. Backup Access

Backup access SHALL be narrower than ordinary database access.

---

# 95. Cross-Border Processing

Baobab SHALL maintain awareness of:

```text
storage region
processing region
support-access region
backup region
subprocessor region
```

for personal information.

---

# 96. Market ≠ Data Residency

Reaffirm:

```text
Market
≠
Data Residency
```

A Ugandan commercial market does not automatically determine the storage region.

---

# 97. Tenant ≠ Jurisdiction

Likewise:

```text
Tenant
≠
Privacy Jurisdiction
```

A tenant may operate in multiple jurisdictions.

---

# 98. Cross-Border Transfer

Cross-border transfers SHALL be assessed according to applicable privacy law, contractual obligations and Baobab's residency architecture.

---

# 99. Regional Identity Domains

ADR-IAM-0027 IdentitySecurityDomains MAY provide stronger residency isolation where required.

---

# 100. Data Residency Metadata

Where needed, records/policies SHOULD carry residency classification rather than deriving it from mutable geography assumptions.

---

# 101. Subprocessors

Baobab SHALL maintain governance over third-party services that process personal information.

---

# 102. Subprocessor Registry

Conceptually:

```text
Subprocessor
├── provider
├── purpose
├── data_classes
├── processing_locations
├── contractual_status
├── security_review
└── status
```

---

# 103. Vendor Minimisation

A SaaS integration SHALL not receive the full identity profile if it only needs:

```text
opaque user reference
```

---

# 104. API Minimisation

API responses SHALL expose only the personal information needed by the caller.

---

# 105. Browser Minimisation

Server-rendered/BFF architectures from ADR-IAM-0023 SHOULD avoid unnecessarily placing sensitive identity data into:

```text
browser JavaScript
HTML hydration payloads
localStorage
analytics scripts
```

---

# 106. Browser Storage

Sensitive identity data SHALL NOT be persisted in browser storage merely for convenience.

---

# 107. Third-Party Scripts

Pages handling:

```text
login
proofing
recovery
financial identity
privacy requests
```

SHOULD minimize third-party scripts.

---

# 108. Cache Privacy

Private identity responses SHALL use appropriate private/no-store cache controls according to sensitivity.

---

# 109. CDN

Personalized identity responses SHALL NOT enter shared public CDN caches.

---

# 110. Search Indexes

Search indexes containing personal information SHALL participate in:

```text
correction
restriction
erasure
retention
```

workflows.

---

# 111. Caches

Cache expiry alone SHALL not be relied upon for high-risk erasure where explicit invalidation is feasible and required.

---

# 112. Event Consumers

Privacy orchestration SHALL account for downstream event consumers.

---

# 113. Event Replay

Historical event replay SHALL not recreate erased profile data into active stores contrary to current privacy state.

---

# 114. Outbox

Outbox tables containing personal information SHALL have explicit retention.

---

# 115. Dead-Letter Queues

DLQs MAY contain personal data.

They SHALL therefore have:

```text
access control
retention
redaction
reprocessing policy
```

---

# 116. Object Storage

Uploaded identity/proofing documents SHALL use:

```text
private access
encryption
purpose-specific access
retention
deletion
malware controls
```

---

# 117. URLs

Sensitive documents SHALL not be exposed through permanent public URLs.

---

# 118. Signed URLs

Time-limited signed access MAY be used where appropriate.

Possession of a signed URL SHALL not create broader authority.

---

# 119. Encryption

Sensitive identity information SHALL be encrypted:

```text
in transit
at rest
```

according to ADR-IAM-0028 and infrastructure policy.

---

# 120. Field-Level Protection

Particularly sensitive attributes MAY require application/field-level encryption where threat modelling justifies it.

---

# 121. Encryption Is Not Privacy Compliance

Encrypted information remains personal information if Baobab can decrypt and associate it with an individual.

---

# 122. Access Control

Access to personal information SHALL follow least privilege.

---

# 123. Administrative Views

Administrative UI SHOULD mask sensitive fields where full values are unnecessary.

Example:

```text
+27•••••1234
```

instead of exposing the full number to every support operator.

---

# 124. Support Access

Support personnel SHALL not automatically receive:

```text
proofing documents
full security history
financial identity
all tenant profiles
```

---

# 125. Privileged Privacy Access

Access to high-sensitivity identity data SHALL generate audit events.

---

# 126. Bulk Export

Bulk identity export SHALL be treated as a privileged operation.

---

# 127. Bulk Export Controls

Require:

```text
authorization
purpose
audit
secure delivery
expiry
```

and, where appropriate, stronger assurance.

---

# 128. Data Portability

Where applicable, exports SHOULD use interoperable machine-readable formats.

---

# 129. Export Does Not Include Secrets

A data export SHALL NOT include:

```text
password hash
TOTP seed
private key
session token
recovery code
other users' data
internal security secrets
```

---

# 130. Security Information Disclosure

Data-subject access SHALL balance transparency with protection against disclosing information that would compromise:

```text
security
other persons
fraud controls
protected investigations
```

according to applicable law.

---

# 131. Consent

Where consent is the appropriate lawful basis, consent SHALL be:

```text
specific
recorded
versioned
withdrawable
purpose-bound
```

as required by governing policy/law.

---

# 132. Consent Record

Conceptually:

```text
ConsentRecord
├── subject
├── purpose
├── policy_version
├── granted_at
├── source
├── status
└── withdrawn_at?
```

---

# 133. Consent Is Not Authentication

A successful login does not constitute blanket consent to every processing activity.

---

# 134. Consent Is Not Business Permission

A person consenting to receive communications does not gain authority to purchase on behalf of a business.

---

# 135. Withdrawal

Withdrawal of consent SHALL stop processing that depends on that consent, subject to other lawful retention/processing grounds.

---

# 136. Marketing Preferences

Marketing preferences SHOULD remain outside canonical authentication identity unless required for a specific estate workflow.

---

# 137. Digital Estate Privacy UX

ZuriBeans, Thamani and Nabhold SHALL present privacy interactions in estate-appropriate UX while using canonical privacy contracts where shared behavior is needed.

---

# 138. ZuriBeans

ZuriBeans identity processing SHALL distinguish:

```text
buyer representative
supplier representative
visitor/contact
workforce
```

and their different purposes.

---

# 139. B2B Contact Data

A business email address associated with an identifiable person may still be personal information.

B2B does not eliminate privacy obligations.

---

# 140. Buyer Relationship Termination

Removing Jane from:

```text
ACME buyer organization
```

SHALL terminate the relationship/context.

It need not erase Jane's CanonicalIdentity if she has another legitimate Baobab relationship.

---

# 141. Supplier Representative

Removing a supplier representative SHALL similarly not delete the supplier legal entity or its historical trade records.

---

# 142. Thamani

Thamani SHALL distinguish:

```text
individual customer
shipper
consignee
recipient
business representative
partner/agent
workforce
```

rather than forcing all into one "customer profile."

---

# 143. Recipient Data

A shipment recipient may have personal information processed without having a Baobab login.

Therefore:

```text
DataSubject
≠
AuthenticatedIdentity
```

---

# 144. Non-User Data Subjects

Privacy workflows SHALL support people whose information exists in domain systems but who have no CanonicalIdentity.

---

# 145. ERP

ERP personal information SHALL remain governed by:

```text
employment
finance
accounting
commercial
regulatory
```

purposes independent of authentication-profile deletion.

---

# 146. CMS

CMS SHALL avoid unnecessary publication of personal contact information.

Publicly published information has a fundamentally different disclosure boundary from private IAM profile data.

---

# 147. Public Information

Information becoming public does not automatically eliminate all governance responsibilities.

Publication must itself be purposeful and authorized.

---

# 148. Security Incidents

A personal-information security compromise SHALL enter the ADR-IAM-0029 incident process.

---

# 149. Privacy Incident Assessment

Incident handling SHALL determine:

```text
what personal information?
whose information?
how many subjects?
which tenants/legal entities?
which jurisdictions?
what exposure?
what safeguards existed?
what notification obligations?
```

---

# 150. Breach Notification

Baobab SHALL support workflows for notifying:

```text
responsible parties
regulators
affected data subjects
```

where legally required.

The architecture SHALL NOT hard-code one global notification deadline for all jurisdictions.

---

# 151. Incident Evidence vs Erasure

A pending security/privacy investigation MAY justify restricting erasure of relevant evidence where lawfully permitted.

This SHALL be recorded as an explicit hold, not an undocumented refusal.

---

# 152. Privacy Events

Canonical privacy events MAY include:

```text
privacy.request.received
privacy.request.verified
privacy.access.completed
privacy.correction.completed
privacy.restriction.applied
privacy.erasure.started
privacy.erasure.completed
privacy.erasure.exception
privacy.consent.granted
privacy.consent.withdrawn
privacy.hold.applied
privacy.hold.released
```

---

# 153. Event Payload Minimisation

Privacy events SHOULD carry references and outcomes rather than copying the data being erased.

---

# 154. Privacy Audit

Privacy operations SHALL themselves be auditable.

---

# 155. Audit Without Defeating Erasure

The audit record should say:

```text
erasure completed for canonical subject X
```

without retaining the erased:

```text
email
phone
address
documents
```

unless independently justified.

---

# 156. PostgreSQL

PostgreSQL SHALL use:

```text
role separation
least privilege
encrypted transport
encrypted storage where applicable
backup protection
```

according to infrastructure policy.

---

# 157. Row-Level Security

PostgreSQL RLS MAY provide defence-in-depth for appropriate privacy/tenant-sensitive tables.

It SHALL NOT replace Baobab's application/context authorization architecture.

---

# 158. RLS Boundary

Where RLS is used, remember that privileged database roles can bypass it.

RLS therefore does not make unrestricted database administration privacy-safe by itself.

---

# 159. Database Superusers

Application workloads SHALL not run as PostgreSQL superusers.

---

# 160. Database Dumps

Database dumps containing personal information SHALL be treated as protected copies of that information.

---

# 161. Developer Access

Production personal information SHOULD NOT routinely be copied into development environments.

---

# 162. Test Data

Prefer:

```text
synthetic data
anonymised data
purpose-built fixtures
```

for development and CI.

---

# 163. Production Debugging

Production debugging SHALL not justify unrestricted personal-data dumps.

---

# 164. Screenshots

Support/debug screenshots can contain personal information and SHALL be governed accordingly.

---

# 165. Data Masking

Operational tooling SHOULD support masking/redaction.

---

# 166. Secrets vs Personal Information

Some data is both:

```text
security-sensitive
+
personal
```

For example:

```text
recovery data
authentication factors
proofing evidence
```

The stronger applicable protections SHALL apply.

---

# 167. Privacy by Default

New IAM features SHOULD default to the least disclosure necessary.

---

# 168. Schema Review

New identity schema fields SHALL answer:

```text
Why is this required?
Who owns it?
Who consumes it?
Is it personal?
Is it sensitive?
How long is it kept?
How is it corrected?
How is it deleted?
```

before acceptance.

---

# 169. API Review

New identity APIs SHALL undergo equivalent data-minimisation review.

---

# 170. Event Review

New identity events SHALL undergo payload-minimisation review.

---

# 171. ADR Review

Architectural decisions introducing materially new personal-information processing SHOULD explicitly address privacy consequences.

---

# 172. Privacy Impact Assessment

High-risk processing SHOULD trigger a documented privacy impact assessment appropriate to applicable law and organizational policy.

---

# 173. High-Risk Examples

Examples include:

```text
large-scale identity proofing
biometrics
behavioural monitoring
automated fraud decisions
new cross-border processing
new sensitive-data analytics
children's information
large-scale federation
```

---

# 174. Automated Decisions

Where automated identity/risk processing materially affects individuals, Baobab SHALL maintain:

```text
explainability
reviewability
policy ownership
auditability
```

appropriate to applicable law.

---

# 175. Pulse and Automated Decisions

Pulse SHALL NOT silently become the final authority for identity eligibility, suspension or business authorization.

---

# 176. Data Protection Defaults

Default configuration SHOULD favour:

```text
minimal traits
private visibility
shorter retention
no unnecessary export
no unnecessary analytics
no unnecessary cross-border replication
```

---

# 177. Configuration Over Hard-Coding

Retention periods SHOULD be policy/configuration driven where appropriate.

---

# 178. Policy Versioning

A retention decision SHALL be traceable to the policy version that governed it.

---

# 179. Policy Change

Changing retention policy SHALL NOT silently destroy information subject to a legal hold.

---

# 180. Scheduled Retention Enforcement

Retention SHALL be actively enforced.

A policy document without deletion/restriction jobs is insufficient.

---

# 181. Retention Jobs

Retention jobs SHALL be:

```text
idempotent
observable
auditable
retryable
scope-limited
```

---

# 182. Failed Erasure

A failed downstream deletion SHALL not mark the entire erasure case complete.

---

# 183. Partial Completion

The orchestrator SHALL represent:

```text
COMPLETE
PARTIAL
BLOCKED
FAILED
```

states accurately.

---

# 184. Reconciliation

Periodic privacy reconciliation SHALL identify:

```text
expired records still active
erased identity recreated
restricted data still processed
expired proofing evidence
orphaned personal data
privacy request stuck
backup beyond retention
```

---

# 185. Orphaned Personal Data

Records that can no longer be associated with a valid purpose/owner SHALL be investigated rather than retained indefinitely.

---

# 186. Referential Integrity

Deletion workflows SHALL account for relational dependencies.

They SHALL NOT bypass business/accounting integrity merely to make deletion technically easy.

---

# 187. Domain-Specific Disposition

Each domain SHALL define how personal references are handled after identity erasure.

Example:

```text
Order
buyer_person_id → anonymised historical reference

Invoice
billing party → legally retained

Security event
subject → restricted pseudonymous reference

Marketing profile
→ deleted
```

---

# 188. Privacy Contract

`shared` MAY define provider-neutral contracts such as:

```text
PrivacyRequest
PrivacyDisposition
RetentionClass
RestrictionState
ErasureStatus
LegalHoldReference
```

where multiple repositories genuinely require them.

---

# 189. Shared Is Not Runtime

`baobab-platform/shared` SHALL NOT become:

```text
privacy database
erasure orchestrator
consent service
```

It remains contracts/standards.

---

# 190. CP Role

CP SHALL provide:

```text
canonical identity discovery
mapping discovery
context/relationship information
lifecycle authority
```

needed for privacy orchestration.

---

# 191. CP Is Not Universal Personal-Data Warehouse

CP SHALL NOT ingest domain personal information simply to make privacy searches easier.

---

# 192. IAM Role

`baobab-iam` owns:

```text
authentication identity privacy
credential lifecycle coordination
provider identity deletion/restriction
proofing-related identity governance
```

within its authority.

---

# 193. Domain Role

Each domain owns privacy disposition for records it authoritatively owns.

---

# 194. Infrastructure Role

Infrastructure owns:

```text
encryption
backup retention
regional storage
secret protection
access logging
secure destruction
```

for platform infrastructure.

---

# 195. Digital Estate Role

Digital Estates own:

```text
privacy UX
notices
request initiation
appropriate consent UX
user-facing status
```

but not arbitrary deletion of authoritative backend records.

---

# 196. Erasure Example

Jane leaves ACME and requests erasure.

```text
Jane
 │
 ▼
Privacy Request
 │
 ▼
Identity verification
 │
 ▼
CanonicalIdentity discovery
 │
 ├── Kratos identity
 ├── ACME membership
 ├── ZuriBeans Trade records
 ├── audit/security records
 └── historical invoices
```

Disposition might be:

```text
Kratos profile
    → DELETE after other relationships assessed

ACME membership
    → TERMINATE

Marketing profile
    → DELETE

Raw proofing evidence
    → DELETE when no longer justified

Historical order
    → RETAIN/ANONYMISE as policy requires

Invoice
    → RETAIN as legally required

Security audit
    → RESTRICT + MINIMISE

Backup
    → AGE OUT + erasure journal prevents resurrection
```

There is no single global SQL delete.

---

# 197. Multiple Relationships Example

If Jane is:

```text
ACME purchaser
+
Beta Ltd approver
+
personal Thamani customer
```

termination/erasure of the ACME relationship SHALL NOT automatically destroy Jane's other valid relationships.

---

# 198. Full Identity Erasure

Only when all applicable purposes/relationships have ended and no lawful retention requirement remains should the CanonicalIdentity itself become eligible for final disposition.

---

# 199. Canonical Identity Tombstone

Where necessary to preserve:

```text
security
non-resurrection
audit integrity
```

a minimal opaque tombstone MAY survive final profile erasure.

---

# 200. Identity Re-Registration

If a previously erased person later returns, Baobab SHALL NOT use hidden retained profile data to reconstruct their former identity unless a lawful retained mapping explicitly permits it.

---

# 201. Privacy Security Invariants

```text
CanonicalIdentity ≠ Universal Profile

Authentication Data ≠ Business Data

Business Relationship ≠ Identity

Consent ≠ Authentication

Consent ≠ Authorization

Account Disablement ≠ Erasure

Erasure ≠ Immediate Backup Destruction

Pseudonymisation ≠ Anonymisation

Hashing ≠ Automatic Anonymisation

Security Logging ≠ Unlimited Retention

Audit Retention ≠ Profile Retention

Legal Hold ≠ Keep Everything

Market ≠ Residency

Tenant ≠ Jurisdiction

Group Ownership ≠ Free Data Sharing

B2B ≠ Non-Personal

Data Subject ≠ Authenticated User

Encryption ≠ Anonymisation

SIEM ≠ Analytics Warehouse

Pulse ≠ Privacy Authority

Privacy Orchestrator ≠ Data Owner

Backup Restore ≠ Permission to Resurrect Erased Authority
```

---

# 202. Failure Behaviour

If privacy orchestration cannot determine whether a record may be erased:

```text
DO NOT SILENTLY DELETE
DO NOT SILENTLY RETAIN FOREVER
```

Instead:

```text
BLOCK
   ↓
record reason
   ↓
route for review
```

---

# 203. Implementation Gates

## IAM-P0 — Personal Information Inventory

Inventory personal information across:

```text
baobab-iam
baobab-cp
Trade
ERP
CMS
Pulse
Digital Estates
telemetry
object storage
backups
event infrastructure
```

---

## IAM-P1 — Data Classification and Purpose Registry

Define:

```text
data classes
processing purposes
authorities
responsible-party/operator mapping
sensitivity
lawful-basis metadata
```

---

## IAM-P2 — Canonical Identity Minimisation

Audit:

```text
CanonicalIdentity
ExternalIdentity
Mapping
Context
```

for unnecessary personal attributes.

---

## IAM-P3 — Ory Privacy Hardening

Audit Kratos schemas for:

```text
minimal traits
credential isolation
verification/recovery attributes
retention/deletion semantics
```

---

## IAM-P4 — Proofing Data Governance

Implement ADR-IAM-0025 proofing retention, restriction and evidence minimisation.

---

## IAM-P5 — Retention Policy Engine

Implement versioned retention policies and scheduled enforcement.

---

## IAM-P6 — Privacy Request Contract

Implement provider-neutral:

```text
PrivacyRequest
PrivacyDisposition
ErasureCase
RestrictionState
LegalHold
```

where required.

---

## IAM-P7 — Data Discovery

Implement canonical discovery across authoritative systems without creating a universal personal-data warehouse.

---

## IAM-P8 — Erasure Orchestration

Implement:

```text
verify
discover
classify
hold-check
revoke
erase/anonymise/restrict
verify
complete
```

workflow.

---

## IAM-P9 — Domain Privacy Integration

Implement domain disposition for:

```text
Trade
ERP
CMS
supplier data
Thamani logistics
ZuriBeans
```

---

## IAM-P10 — Backup and DR Privacy

Implement:

```text
backup retention
erasure journal
restore reconciliation
secure backup access
```

---

## IAM-P11 — Telemetry and Audit Privacy

Implement:

```text
PII minimisation
retention
access restrictions
redaction
audit disposition
```

---

## IAM-P12 — Cross-Border and Residency Governance

Map:

```text
processing regions
backup regions
support access
subprocessors
IdentitySecurityDomains
```

---

## IAM-P13 — Digital Estate Privacy UX

Implement appropriate:

```text
privacy notices
request initiation
correction
consent where applicable
request status
```

for ZuriBeans, Thamani and Nabhold.

---

## IAM-P14 — Privacy Security Testing

Test:

```text
cross-tenant disclosure
over-broad API responses
cache leakage
log leakage
event leakage
backup resurrection
failed erasure
unauthorized export
```

---

## IAM-P15 — Production Privacy Certification

Require:

```text
inventory complete
purposes documented
retention enforced
erasure tested
backups governed
privacy requests tested
cross-border processing mapped
security/privacy review complete
```

---

# 204. Required Test Matrix

| Scenario | Expected Result |
|---|---|
| User changes email | Same CanonicalIdentity |
| User leaves one buyer organization | Relationship ends; unrelated identities remain |
| Full erasure request | Distributed privacy workflow starts |
| Erasure while legal hold exists | Affected record restricted/retained with reason |
| Marketing data past retention | Deleted |
| Raw proofing evidence past retention | Deleted/restricted according to policy |
| Historical invoice under retention | Retained appropriately |
| Security evidence still justified | Restricted/minimised retention |
| Deleted identity restored from backup | Erasure journal reapplied |
| Event replay contains erased profile | Must not recreate active profile |
| User requests export | Only authorized subject data returned |
| Export contains another user's data | Test fails |
| Export contains credential secret | Test fails |
| PII written to prohibited log field | Test fails |
| Public CDN caches private profile | Test fails |
| Cross-tenant identity lookup | Denied |
| Developer requests production dump | Denied absent authorized process |
| Pulse requests unnecessary raw identity | Denied |
| Retention job fails | Alert + retry; record remains pending |
| Erasure incomplete in one domain | Case remains partial |
| Legal hold released | Retention workflow resumes |

---

# 205. Production Readiness Checklist

### Governance

- [ ] personal-information inventory
- [ ] purpose registry
- [ ] data classification
- [ ] authority mapping
- [ ] responsible-party/operator analysis
- [ ] lawful-processing assessment
- [ ] privacy-impact assessment process

### Identity

- [ ] minimal CanonicalIdentity
- [ ] minimal ExternalIdentity
- [ ] minimal Kratos traits
- [ ] no business authority in IAM profile
- [ ] proofing evidence isolated
- [ ] credentials isolated

### Retention

- [ ] per-class retention
- [ ] automated enforcement
- [ ] legal holds
- [ ] restriction
- [ ] anonymisation rules
- [ ] deletion rules
- [ ] policy versioning

### Privacy Requests

- [ ] request verification
- [ ] access
- [ ] correction
- [ ] restriction
- [ ] erasure
- [ ] objection where applicable
- [ ] consent withdrawal where applicable
- [ ] export

### Distributed Erasure

- [ ] Kratos
- [ ] CP
- [ ] Trade
- [ ] ERP
- [ ] CMS
- [ ] supplier domain
- [ ] Digital Estates
- [ ] telemetry
- [ ] search/cache
- [ ] event infrastructure
- [ ] object storage
- [ ] backups

### Infrastructure

- [ ] encryption
- [ ] least privilege
- [ ] production/test separation
- [ ] secure dumps
- [ ] backup retention
- [ ] restore privacy reconciliation
- [ ] cross-border processing inventory

### Observability

- [ ] PII-minimized logs
- [ ] no credential logging
- [ ] privacy operation audit
- [ ] retention metrics
- [ ] stuck-erasure alerts
- [ ] backup-expiry monitoring

---

# 206. Final Architecture

```text
                    DATA SUBJECT
                         │
                         ▼
                  Digital Estate
                         │
                         ▼
                 Privacy Request
                         │
                         ▼
             Verification / Proofing
                         │
                         ▼
              Privacy Orchestration
                         │
                         ▼
                 CanonicalIdentity
                         │
       ┌─────────────────┼──────────────────┐
       │                 │                  │
       ▼                 ▼                  ▼
     Kratos              CP              Domains
 Authentication      Identity/Context     Business
       │                 │                  │
       │           ┌─────┴─────┐      ┌─────┼─────┐
       │           ▼           ▼      ▼     ▼     ▼
       │       Relationships Mapping Trade ERP Supplier
       │                                  │
       └────────────────┬─────────────────┘
                        ▼
                  Classification
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
            Erase    Restrict    Retain
              │         │         │
              └─────────┼─────────┘
                        ▼
                    Verification
                        │
                        ▼
                  Privacy Audit
```

Backup processing runs alongside it:

```text
Operational Erasure
       │
       ▼
Erasure Journal
       │
       ├──────────────► Current Systems
       │
       └──────────────► DR / Restore
                              │
                              ▼
                       Reapply Erasure
                              │
                              ▼
                     Authority Restored
```

---

# 207. Consequences

## Positive

This architecture provides:

- POPIA-aware identity governance;
- data minimisation by architecture;
- separation of authentication and business information;
- purpose-specific retention;
- distributed erasure;
- preservation of legitimate financial/security records;
- privacy-safe backup restoration;
- better cross-border governance;
- tenant/legal-entity separation;
- support for non-user data subjects;
- controlled privacy requests;
- auditable retention and erasure;
- provider-neutral privacy semantics.

## Costs

Baobab must maintain:

```text
data inventories
purpose registries
retention policies
privacy workflows
legal holds
erasure orchestration
cross-repository integration
backup reconciliation
privacy audits
```

This complexity is preferable to uncontrolled duplication and indefinite retention of identity information.

---

# 208. Explicitly Deferred

This ADR does not prescribe:

```text
one global retention duration
one universal consent platform
one specific privacy-management vendor
automatic deletion of legally required records
a single jurisdiction's law for every tenant
customer-managed privacy policies without platform constraints
AI-based privacy decision making
```

Exact statutory retention periods and jurisdiction-specific rules SHALL be maintained in policy/compliance specifications rather than hard-coded into the foundational IAM architecture.

---

# 209. Final Decision Principle

Baobab SHALL treat privacy as a property of the entire identity lifecycle.

The architecture is:

```text
Person
   │
   ▼
Purpose
   │
   ▼
Minimum Necessary Data
   │
   ▼
Authoritative System
   │
   ▼
Controlled Processing
   │
   ▼
Purpose-Specific Retention
   │
   ▼
Erase / Anonymise / Restrict / Justifiably Retain
```

The most important distinction is:

```text
Who is Jane?
      │
      ▼
CanonicalIdentity

How does Jane authenticate?
      │
      ▼
Ory / IAM

Which organizations is Jane related to?
      │
      ▼
CP / Domains

What transactions involved Jane?
      │
      ▼
Trade / ERP / Logistics

What security events involved Jane?
      │
      ▼
Security Audit

Which of those records may still lawfully exist?
      │
      ▼
Privacy / Retention Policy
```

These questions SHALL NOT be collapsed into one identity record.

Therefore:

> **Deleting an account is not deleting a person from history, and retaining history is not permission to retain an operational profile forever.**

And:

> **Baobab shall know why personal information exists, where it exists, who controls it, how long it may remain, and what must happen when its purpose ends.**

The final privacy invariant is:

> **No identity data without purpose. No purpose without authority. No retention without justification. No erasure without reconciliation. No backup restore may resurrect privacy state that the authoritative platform has already extinguished.**