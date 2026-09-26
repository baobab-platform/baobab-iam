# ADR-IAM-0029 — IAM Security Operations, Threat Detection, Incident Response and Identity Compromise Containment Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture / Security Architecture / IAM Operations  
**Primary Repositories:** `baobab-platform/baobab-iam`, `baobab-platform/infrastructure`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0028  
**Extends:** ADR-IAM-0016, 0017, 0018, 0020, 0021, 0023, 0024, 0025, 0026, 0027, 0028  
**Decision Type:** Security Operations / Threat Detection / Incident Response / Containment / Recovery  
**Identity Runtime:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane  
**Security Telemetry Baseline:** OpenTelemetry-compatible structured telemetry  
**Incident-Response Reference:** NIST SP 800-61 Rev. 3

---

# 1. Decision

Baobab SHALL operate IAM as a **continuously monitored Tier-0 security system**.

IAM security operations SHALL provide:

```text
PREVENT
   │
   ▼
OBSERVE
   │
   ▼
DETECT
   │
   ▼
CORRELATE
   │
   ▼
ASSESS
   │
   ▼
CONTAIN
   │
   ▼
ERADICATE
   │
   ▼
RECOVER
   │
   ▼
LEARN
```

Baobab SHALL distinguish:

```text
security signal
    ≠
security finding
    ≠
risk assessment
    ≠
security incident
    ≠
containment action
    ≠
business authorization decision
```

The IAM security operations layer MAY detect risk and initiate approved security controls.

It SHALL NOT become:

- canonical identity authority;
- tenant authority;
- business-organization authority;
- business authorization engine;
- Trade authorization authority;
- ERP authorization authority;
- supplier approval authority;
- arbitrary behavioral-surveillance platform.

The governing principle is:

> **Detection observes identity behaviour. Containment restricts trust. Canonical identity and business authorization remain with their established authorities.**

---

# 2. Why This ADR Exists

Previous IAM ADRs define:

- identity;
- authentication;
- authorization;
- sessions;
- workloads;
- MFA and passkeys;
- federation;
- lifecycle;
- audit;
- migration;
- multi-region resilience;
- cryptographic trust.

Those controls are insufficient unless Baobab can determine when:

```text
valid credentials
```

are being used by:

```text
the wrong actor
```

or when:

```text
trusted infrastructure
```

has itself been compromised.

Identity attacks frequently operate through apparently valid authentication.

Examples include:

```text
stolen password
stolen session
stolen refresh token
compromised passkey device
MFA fatigue/social engineering
compromised workload secret
malicious enterprise federation
privileged administrator abuse
stolen signing key
account recovery abuse
credential stuffing
password spraying
bot registration
SCIM compromise
```

---

# 3. Threat Model

Baobab IAM SHALL explicitly detect and prepare for at least:

| Threat | Principal Target |
|---|---|
| Credential stuffing | Human |
| Password spraying | Humans |
| Brute force | Human |
| Session theft | Human |
| Refresh-token theft | Human/workload |
| Recovery abuse | Human |
| MFA abuse | Human |
| Passkey lifecycle abuse | Human |
| Federation compromise | Enterprise users |
| SCIM compromise | Enterprise lifecycle |
| Workload secret theft | Workload |
| OAuth client compromise | Workload/application |
| Signing-key compromise | Entire issuer |
| Admin compromise | Platform |
| Insider abuse | Human privileged user |
| Cross-tenant probing | Tenant isolation |
| Context manipulation | CP |
| Token replay | Human/workload |
| Invalid JWT attacks | APIs |
| Automated account creation | Public estates |
| Enumeration | Human identities |
| Supplier account takeover | Supplier |
| Buyer approver takeover | ZuriBeans |
| Finance-role takeover | ERP |
| Business-account takeover | Thamani |
| DR/security-state rollback | Platform |
| Identity-provider compromise | Entire IAM domain |

---

# 4. Security Operations Architecture

```text
                     DIGITAL ESTATES
                           │
                           ▼
                  ┌─────────────────┐
                  │ BFF / APISIX    │
                  └────────┬────────┘
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
          Kratos         Hydra       Federation
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                    baobab-iam
                           │
                           ▼
                    Baobab CP
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
           Trade          ERP          Domains
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                  SECURITY TELEMETRY
                           │
                           ▼
               Correlation / Detection
                           │
                           ▼
                    Security Finding
                           │
                           ▼
                  Incident Assessment
                           │
                 ┌─────────┴────────┐
                 ▼                  ▼
          automated safe       human-controlled
           containment          containment
                 │                  │
                 └─────────┬────────┘
                           ▼
                 Authoritative systems
                           │
                           ▼
                      Enforcement
```

---

# 5. Telemetry Is Evidence, Not Authority

A telemetry system MAY observe:

```text
Jane authenticated
from device D
at time T
through issuer I
```

It SHALL NOT independently conclude:

```text
Jane may approve
ZAR 5,000,000 purchase
```

That remains domain authorization.

---

# 6. Security Signal

A SecuritySignal represents an observation.

Conceptually:

```text
SecuritySignal
├── signal_id
├── signal_type
├── observed_at
├── source
├── subject_reference?
├── workload_reference?
├── session_reference?
├── tenant_reference?
├── context_reference?
├── federation_reference?
├── source_network?
├── device_reference?
├── correlation_id
├── confidence
└── metadata
```

---

# 7. Signals Are Not Facts About Intent

Examples:

```text
new device
new network
unusual request rate
repeated authentication failures
new country
unknown client
unexpected token audience
MFA failures
```

are signals.

They do not independently prove malicious intent.

---

# 8. Security Finding

Multiple signals MAY produce a:

```text
SecurityFinding
```

Conceptually:

```text
SecurityFinding
├── finding_id
├── category
├── severity
├── confidence
├── subjects
├── supporting_signals
├── detected_at
├── status
└── recommended_action
```

---

# 9. Incident

A SecurityIncident represents a governed security-response case.

```text
SecurityIncident
├── incident_id
├── severity
├── category
├── affected_scope
├── detected_at
├── declared_at
├── commander/owner
├── containment_status
├── evidence_references
├── recovery_status
└── closed_at
```

---

# 10. Incident Scope

An incident MAY affect:

```text
one session
one identity
one workload
one business organization
one tenant
one federation
one OAuth client
one Digital Estate
one IAM region
one issuer
entire Baobab IAM
```

Containment SHALL attempt to match that scope.

---

# 11. Least-Blast-Radius Containment

If:

```text
one session
```

is compromised, Baobab SHOULD NOT automatically disable:

```text
every identity
```

Likewise, if:

```text
one customer's federation
```

is compromised, Baobab SHOULD avoid shutting down unrelated customers.

---

# 12. Containment Hierarchy

```text
request
   │
session
   │
credential
   │
identity
   │
relationship/context
   │
OAuth client
   │
workload
   │
federation
   │
tenant
   │
issuer/security domain
   │
platform
```

Contain at the narrowest level that safely addresses the threat.

---

# 13. Deny Precedence

A containment decision MAY impose:

```text
DENY
SUSPEND
REVOKE
STEP_UP
REAUTHENTICATE
LIMIT
```

It SHALL NOT grant new business authority.

---

# 14. Risk Engine Boundary

Baobab MAY implement a provider-neutral:

```text
IdentityRiskAssessment
```

but this component SHALL NOT become a general-purpose authorization engine.

---

# 15. Risk Assessment

Conceptually:

```text
IdentityRiskAssessment
├── assessment_id
├── principal
├── session?
├── signals[]
├── risk_level
├── confidence
├── evaluated_at
├── expires_at
└── recommended_control
```

---

# 16. Risk Is Ephemeral

Risk assessments SHALL be:

```text
time-bound
context-bound
explainable
re-evaluable
```

They SHALL NOT permanently label a human as "risky."

---

# 17. Risk Levels

Baobab MAY normalize risk as:

```text
LOW
ELEVATED
HIGH
CRITICAL
```

These are security-operational classifications.

They SHALL NOT become business-user rankings.

---

# 18. Risk Signals

Possible signals include:

```text
authentication velocity
failure rate
new device
new browser
new ASN/network
known malicious network intelligence
credential-stuffing pattern
password-spraying pattern
bot behaviour
session anomalies
token replay
MFA failure patterns
recovery attempts
passkey changes
privileged-operation sequence
federation anomalies
SCIM anomalies
workload token anomalies
cross-tenant probing
```

---

# 19. Geolocation Is a Weak Signal

Geolocation SHALL NOT independently cause permanent account punishment.

VPNs, roaming, corporate gateways and mobile networks make location imperfect.

---

# 20. Device Fingerprinting

Device information MAY contribute to risk detection.

It SHALL NOT be treated as cryptographically authoritative identity.

---

# 21. Privacy-Minimizing Detection

Baobab SHALL collect only telemetry proportionate to security need.

Security monitoring SHALL NOT justify unrestricted behavioural profiling.

ADR-IAM-0030 will govern broader identity privacy and retention.

---

# 22. Authentication Attack Detection

Baobab SHALL detect patterns consistent with:

```text
credential stuffing
password spraying
brute force
enumeration
bot authentication
```

---

# 23. Distributed Attacks

Detection SHALL not rely solely on:

```text
requests per IP
```

because attackers may distribute attempts across large proxy networks.

Correlation SHOULD consider combinations of:

```text
account
network
device characteristics
failure pattern
velocity
credential pattern
time window
```

---

# 24. Rate Limiting

Rate limiting SHALL exist at appropriate layers:

```text
APISIX
Digital Estate/BFF
Kratos
Hydra
provider integration endpoints
```

according to endpoint semantics.

---

# 25. Rate Limit Is Not Account Lockout

Network throttling and identity lockout SHALL remain distinct controls.

---

# 26. Account Lockout

Account lockout SHALL be designed to avoid creating an easy denial-of-service mechanism against legitimate users.

---

# 27. Progressive Controls

Suspicious authentication MAY progressively trigger:

```text
rate limit
bot challenge
reauthentication
MFA
phishing-resistant step-up
temporary session restriction
security review
```

rather than immediately disabling an identity.

---

# 28. MFA Integration

ADR-IAM-0024 assurance policies SHALL integrate with risk detection.

Example:

```text
valid password
+
new suspicious device
+
high-risk operation
       │
       ▼
phishing-resistant step-up
```

---

# 29. Risk Cannot Downgrade Assurance

A low risk score SHALL never bypass a mandatory assurance requirement.

If policy requires phishing-resistant authentication:

```text
LOW risk
```

does not make password-only authentication sufficient.

---

# 30. High-Risk Authentication

High risk MAY require:

```text
step-up
recent authentication
passkey/security key
session revocation
manual verification
```

according to policy.

---

# 31. Account Takeover Detection

Potential account takeover indicators include:

```text
successful password followed by MFA failure
recovery immediately after unusual login
new credential registration after suspicious session
rapid device/network changes
session reuse anomalies
privileged operation after unusual authentication
```

---

# 32. Session Security

Baobab SHALL monitor:

```text
session creation
session rotation
session termination
concurrent-session anomalies
unexpected session reuse
revocation
```

without logging raw session secrets.

---

# 33. User Session Visibility

Where appropriate, users SHOULD be able to inspect meaningful active/recent sessions and terminate sessions they do not recognize.

---

# 34. Security Notifications

Users SHOULD receive meaningful security notifications for events such as:

```text
credential changed
new passkey added
MFA removed
recovery completed
suspicious successful login
session revoked for security
```

subject to anti-abuse and privacy rules.

---

# 35. Notification Fatigue

Baobab SHALL avoid sending security notifications for every trivial failed login.

Notifications must remain actionable.

---

# 36. Recovery Abuse

Recovery flows SHALL receive dedicated monitoring.

Repeated recovery attempts from unrelated sources MAY trigger:

```text
rate limiting
temporary recovery suspension
stronger proofing
security review
```

---

# 37. Credential Change Protection

Sensitive credential changes SHOULD require:

```text
recent authentication
appropriate assurance
```

and MAY trigger existing-session revocation according to ADR-IAM-0024.

---

# 38. MFA Downgrade Detection

Security operations SHALL detect attempts to:

```text
remove strong factor
add weaker recovery path
disable MFA
replace passkey
```

especially shortly after unusual authentication.

---

# 39. Passkey Incidents

A compromised/lost authenticator SHOULD permit revocation of the affected credential without necessarily destroying the CanonicalIdentity.

---

# 40. Workload Threat Detection

Workloads require separate behavioural detection.

Signals MAY include:

```text
unexpected token issuance
unexpected source workload
unexpected audience
unexpected region
unusual token volume
new certificate
failed mTLS
cross-tenant access
unusual capability use
```

---

# 41. Workload Containment

A compromised workload MAY require:

```text
credential revocation
client disablement
certificate revocation
CapabilityBinding suspension
network isolation
deployment quarantine
```

---

# 42. Workload Disablement

Disabling a workload credential SHALL not automatically delete historical mappings or audit evidence.

---

# 43. OAuth Client Compromise

A compromised OAuth client SHALL be treated separately from compromise of the entire issuer.

Containment SHOULD target:

```text
client credentials
client sessions/tokens
redirect configuration
associated workload
```

before escalating wider.

---

# 44. Signing-Key Compromise

ADR-IAM-0028 controls cryptographic response.

Security operations SHALL coordinate:

```text
key compromise declaration
emergency rotation
affected-token window
issuer impact
session impact
forensic analysis
consumer reconciliation
```

---

# 45. Issuer Compromise

If the integrity of the IAM issuer itself cannot be trusted:

```text
IssuerTrust → SUSPENDED/COMPROMISED
```

MAY be required.

---

# 46. Issuer Kill Switch

Baobab SHALL possess an emergency mechanism to stop accepting an issuer when compromise is credible.

This is a Tier-0 containment action.

---

# 47. Federation Monitoring

Enterprise federation SHALL monitor:

```text
unexpected issuer changes
signing-key changes
metadata changes
unusual login volumes
unexpected domain/user patterns
assertion validation failures
SCIM anomalies
```

---

# 48. Federation Containment

Compromised enterprise federation SHOULD be containable independently:

```text
FederationTrust
       │
       ▼
SUSPENDED
```

without disabling unrelated federations.

---

# 49. Federation Does Not Override CP

Even valid federation authentication remains subject to:

```text
ExternalIdentity
→ CanonicalIdentity
→ CP Context
→ Domain Authorization
```

This limits federation compromise blast radius.

---

# 50. SCIM Threat Model

SCIM compromise could allow attackers to:

```text
create identities
disable identities
alter lifecycle state
change projected attributes
```

Therefore SCIM activity SHALL be auditable and anomaly monitored.

---

# 51. SCIM Cannot Grant Business Authority

A compromised SCIM client SHALL NOT be capable of directly granting:

```text
purchase approval
ERP finance authority
supplier approval
tenant administration
```

unless a separately governed downstream authorization process explicitly permits it.

---

# 52. Privileged Identity Monitoring

Privileged identities SHALL receive enhanced monitoring.

Examples:

```text
IAM administrators
CP administrators
ERP finance/admin
platform operators
security operators
federation administrators
```

---

# 53. Privileged Signals

Monitor:

```text
privilege changes
credential changes
MFA changes
new administrator creation
break-glass activation
federation changes
issuer changes
trust-anchor changes
key rotation
secret access
mass revocation
```

---

# 54. Privileged Session Assurance

Sensitive privileged operations MAY require recent phishing-resistant authentication regardless of existing session validity.

---

# 55. Insider Threat

Security controls SHALL support detection of anomalous privileged actions without presuming malicious intent.

---

# 56. Break-Glass Monitoring

Every break-glass activation SHALL produce a high-severity security event.

---

# 57. Break-Glass Lifecycle

```text
REQUESTED
    │
    ▼
AUTHORIZED
    │
    ▼
ACTIVATED
    │
    ▼
USED
    │
    ▼
TERMINATED
    │
    ▼
REVIEWED
```

---

# 58. Break-Glass Does Not Mean Unlogged

Emergency access SHALL be more observable, not less.

---

# 59. Cross-Tenant Threat Detection

Baobab SHALL detect attempts by one principal/context to probe:

```text
another tenant
another buyer organization
another supplier
another business account
another legal entity
```

---

# 60. Isolation Incident

Confirmed cross-tenant unauthorized access SHALL be treated as a high-severity incident.

---

# 61. Context Manipulation

Repeated submission of invalid:

```text
Tenant ID
Context ID
LegalEntity ID
BusinessOrganization ID
```

MAY generate security signals.

Client-supplied identifiers remain requests, never authority.

---

# 62. ZuriBeans Threat Model

High-value ZuriBeans events include:

```text
buyer administrator takeover
purchaser takeover
approver takeover
purchase-authority manipulation
organization invitation abuse
quotation/order manipulation
cross-buyer access
```

IAM detects identity/security anomalies.

Trade remains authoritative for purchasing permissions.

---

# 63. Thamani B2C Threat Model

Monitor:

```text
consumer account takeover
shipment/account manipulation
recipient/consignee abuse
payment-related identity abuse
recovery abuse
```

---

# 64. Thamani B2B Threat Model

Monitor:

```text
business-account administrator takeover
logistics-manager takeover
shipping-clerk credential compromise
finance/approver compromise
cross-company context access
partner/agent credential abuse
```

---

# 65. Same Human, Multiple Contexts

A security incident involving Jane's:

```text
Company A session
```

does not necessarily imply compromise of Jane's:

```text
personal account
Company B relationship
```

Containment SHALL consider evidence and blast radius.

---

# 66. Supplier Threat Model

Monitor:

```text
supplier administrator takeover
bank-detail change
legal/tax information change
document replacement
representative invitation abuse
certification manipulation
```

Supplier approval remains supplier-domain authority.

---

# 67. ERP Threat Model

Enhanced monitoring SHALL cover:

```text
finance roles
accounting roles
payment-related operations
administrative roles
role assignment
client/org context
```

iDempiere remains authoritative for ERP permissions.

---

# 68. Security Event Taxonomy

Baobab SHOULD normalize provider/domain events into categories such as:

```text
authentication.*
session.*
credential.*
mfa.*
passkey.*
recovery.*
identity.*
workload.*
oauth_client.*
federation.*
scim.*
authorization.*
context.*
admin.*
crypto.*
dr.*
isolation.*
```

---

# 69. Example Events

```text
authentication.succeeded
authentication.failed

session.created
session.revoked
session.suspicious

credential.added
credential.removed

mfa.challenge.failed
passkey.registered

recovery.started
recovery.completed

identity.disabled

workload.authentication.failed
workload.revoked

federation.trust.changed

authorization.denied
context.forbidden

crypto.key.compromised
```

---

# 70. Canonical Event Envelope

Security events SHOULD use a provider-neutral envelope:

```text
SecurityEvent
├── event_id
├── event_type
├── occurred_at
├── observed_at
├── source
├── actor
├── subject
├── session_reference?
├── context_reference?
├── tenant_reference?
├── security_domain?
├── correlation_id
├── trace_id?
├── severity
├── outcome
└── metadata
```

---

# 71. Provider Events

Ory-native events SHALL be normalized before becoming Baobab canonical security events where normalization is needed.

Baobab SHALL not expose Ory-specific payload structures as permanent cross-platform contracts.

---

# 72. Domain Events

Domain engines MAY emit security-relevant events.

Examples:

```text
Trade → purchase authority denial
ERP → privileged access denial
Supplier → banking detail change
```

These enrich detection without transferring domain authority to IAM.

---

# 73. Correlation

Baobab SHALL correlate where available:

```text
request ID
correlation ID
trace ID
session reference
canonical identity reference
external identity reference
context reference
workload reference
```

---

# 74. Distributed Trace Correlation

Security telemetry SHOULD integrate with OpenTelemetry-compatible trace context.

This permits correlation across:

```text
Browser
→ BFF
→ APISIX
→ IAM
→ CP
→ Trade/ERP/domain
```

---

# 75. No Raw Credentials in Telemetry

Never include:

```text
password
access token
refresh token
session cookie
authorization code
client secret
private key
TOTP secret
recovery code
```

in security telemetry.

---

# 76. Sensitive Evidence

Security evidence MAY itself contain personal or commercially sensitive information.

Access SHALL be restricted.

---

# 77. Tamper Resistance

Security audit/event storage SHALL be protected from:

```text
unauthorized modification
deletion
retroactive rewriting
```

consistent with ADR-IAM-0017.

---

# 78. Detection Rules

Detection rules SHALL be:

```text
versioned
reviewable
testable
observable
reversible
```

---

# 79. Detection-as-Code

Where practical, security detection rules SHOULD be managed as version-controlled configuration/code.

---

# 80. Rule Deployment

Detection changes SHALL pass:

```text
review
test
staging/simulation
controlled deployment
monitoring
```

---

# 81. False Positives

Baobab SHALL measure false-positive rates.

A detection system that constantly blocks legitimate users becomes an availability vulnerability.

---

# 82. False Negatives

Security exercises SHALL test whether known attack patterns actually trigger expected detections.

---

# 83. Detection Quality

Measure:

```text
precision
false-positive rate
time to detect
time to triage
time to contain
coverage
```

where meaningful.

---

# 84. Risk Explainability

Containment should record:

```text
which signals
which rule/policy
which confidence
which action
```

caused it.

---

# 85. Automated Containment

Automation MAY perform reversible low-blast-radius controls such as:

```text
rate limiting
bot challenge
require reauthentication
require step-up
revoke suspicious session
temporarily throttle OAuth client
```

where policy authorizes it.

---

# 86. High-Blast-Radius Automation

Automation SHALL NOT casually perform:

```text
disable entire tenant
disable global issuer
revoke all users
destroy signing key
suspend all federation
```

without explicit emergency policy.

---

# 87. Human-Controlled Actions

High-impact containment SHOULD require authorized human confirmation unless a predefined emergency invariant mandates immediate action.

---

# 88. Emergency Automatic Actions

Automatic high-impact action MAY be appropriate for incontrovertible conditions such as:

```text
cryptographically confirmed revoked trust anchor
known compromised signing key under active emergency policy
```

but SHALL be predefined and auditable.

---

# 89. Containment Command Model

Conceptually:

```text
ContainmentCommand
├── command_id
├── target_type
├── target_id
├── action
├── reason_code
├── incident_id
├── requested_by
├── approved_by?
├── expires_at?
└── status
```

---

# 90. Idempotency

Containment commands SHALL be idempotent where possible.

Repeated:

```text
REVOKE SESSION X
```

must not create inconsistent state.

---

# 91. Temporary Containment

Some containment SHOULD expire automatically:

```text
rate limit
temporary block
temporary high-risk state
```

unless investigation extends it.

---

# 92. Permanent Security State

Permanent:

```text
identity disablement
credential revocation
trust revocation
```

requires authoritative lifecycle mutation.

---

# 93. Session Revocation

Baobab SHALL support:

```text
one session
all sessions for identity
sessions associated with credential
sessions associated with incident
```

where provider capabilities permit.

---

# 94. Credential Revocation

A compromised credential SHOULD be revocable without deleting the identity.

---

# 95. Identity Suspension

Where evidence indicates broader compromise:

```text
CanonicalIdentity → SUSPENDED/DISABLED
```

according to ADR-IAM-0016 lifecycle rules.

---

# 96. Restrictive State Wins

During disagreement:

```text
provider ACTIVE
CP DISABLED
```

results in:

```text
DENY
```

---

# 97. Mass Revocation

Baobab SHALL have tested capability for controlled bulk containment.

Examples:

```text
all sessions for issuer
all sessions signed by compromised key where technically possible
all workload credentials in compromised environment
all federation sessions from compromised trust
```

---

# 98. Mass Revocation Safety

Bulk operations SHALL require:

```text
scope preview
authorization
audit
progress visibility
failure handling
reconciliation
```

---

# 99. Kill Switches

Tier-0 kill switches SHALL exist for at least:

```text
identity
workload
OAuth client
federation trust
issuer trust
```

---

# 100. Kill Switch Governance

Kill switches SHALL not depend solely on the component being disabled.

Example:

If Ory is compromised, CP must still be able to deny the affected trust.

---

# 101. Security Journal

Critical containment SHALL integrate with ADR-IAM-0027's security recovery journal so disaster recovery cannot resurrect revoked authority.

---

# 102. Incident Severity

Baobab MAY classify:

```text
SEV-1 Critical
SEV-2 High
SEV-3 Moderate
SEV-4 Low
```

according to organizational incident policy.

---

# 103. Severity Factors

Consider:

```text
scope
privilege
tenant isolation
data exposure
credential type
persistence
issuer integrity
cryptographic integrity
customer impact
regulatory impact
recoverability
```

---

# 104. SEV-1 Examples

Potential examples:

```text
signing-key compromise
identity-provider compromise
confirmed cross-tenant access
widespread privileged account takeover
security journal compromise
uncontrolled IAM multi-region split brain
```

Final classification depends on actual incident facts.

---

# 105. Incident Lifecycle

```text
DETECTED
    │
    ▼
TRIAGED
    │
    ▼
DECLARED
    │
    ▼
CONTAINING
    │
    ▼
CONTAINED
    │
    ▼
ERADICATING
    │
    ▼
RECOVERING
    │
    ▼
MONITORING
    │
    ▼
CLOSED
    │
    ▼
POST-INCIDENT REVIEW
```

---

# 106. Incident Commander

Significant incidents SHALL have an identified response owner/commander.

---

# 107. Roles

Incident procedures SHOULD identify:

```text
Incident Commander
IAM Engineer
Security Engineer
Infrastructure/DB
Application/Domain Owner
Communications
Privacy/Legal where required
Executive escalation where required
```

---

# 108. Separation of Response Authority

An engineer investigating an incident SHALL not automatically possess unrestricted authority to alter every production security control.

---

# 109. Evidence Preservation

Incident response SHALL preserve evidence sufficient for:

```text
timeline reconstruction
root-cause analysis
scope determination
regulatory assessment
post-incident learning
```

---

# 110. Evidence Integrity

Evidence collection SHALL preserve:

```text
timestamp
source
integrity
chain of handling where required
```

---

# 111. Clock Synchronization

Security systems SHALL maintain reliable time synchronization.

Distributed incident reconstruction is unreliable when clocks materially disagree.

---

# 112. Timeline

Every significant incident SHALL produce a timeline.

Example:

```text
T0 suspicious authentication
T1 session created
T2 context selected
T3 privileged operation
T4 detection fired
T5 session revoked
T6 identity suspended
T7 investigation
T8 recovery
```

---

# 113. Incident Communications

Incident communications SHALL distinguish:

```text
confirmed fact
working hypothesis
unknown
remediation
```

---

# 114. Customer Notification

Customer/user notification requirements SHALL depend on:

```text
incident facts
contract
privacy law
regulation
risk
```

and SHALL not be automatically generated from a detection alert.

---

# 115. Recovery

Recovery SHALL not simply mean:

```text
service responds HTTP 200
```

It requires restored trust.

---

# 116. Recovery Criteria

Before closing significant identity incidents verify:

```text
attack vector contained
compromised credentials revoked
affected sessions handled
canonical state reconciled
CP state correct
domain state correct
keys/certificates handled
persistence verified
monitoring restored
no unauthorized authority resurrected
```

---

# 117. Recovery Authentication

Affected users MAY require:

```text
reauthentication
credential reset
passkey re-enrollment
MFA re-enrollment
identity proofing
```

depending on incident scope.

---

# 118. No Automatic Privilege Restoration

Recovery of identity access SHALL NOT automatically restore revoked business relationships.

---

# 119. Workload Recovery

Compromised workload recovery SHOULD use:

```text
new credential
new deployment
verified artifact
verified configuration
re-established CapabilityBinding
```

rather than simply re-enabling the compromised instance.

---

# 120. Federation Recovery

Federation recovery MAY require:

```text
new certificate/key
metadata verification
customer confirmation
test identity
mapping reconciliation
session revocation
```

before trust returns ACTIVE.

---

# 121. Cryptographic Recovery

Signing-key incidents follow ADR-IAM-0028 and SHALL verify all affected consumers.

---

# 122. Regional Recovery

Regional IAM incidents SHALL follow ADR-IAM-0027's fencing, promotion, security-journal and failback controls.

---

# 123. Post-Incident Review

Significant incidents SHALL produce a review covering:

```text
what happened
how detected
why possible
blast radius
containment
recovery
what worked
what failed
architectural change
control change
test change
runbook change
```

---

# 124. Blameless Technical Analysis

Post-incident analysis SHOULD focus on systemic causes and control improvement rather than substituting personal blame for technical analysis.

Malicious insider activity, where established, remains a separate security/personnel matter.

---

# 125. Detection Feedback Loop

```text
Incident
   │
   ▼
Finding
   │
   ▼
Root Cause
   │
   ▼
New/Changed Control
   │
   ▼
New Test
   │
   ▼
New Detection
```

---

# 126. Threat Intelligence

External threat intelligence MAY enrich:

```text
malicious IP
compromised credential indicators
known attack infrastructure
vulnerabilities
```

but SHALL not be accepted blindly as authoritative.

---

# 127. Intelligence Expiry

Threat indicators SHOULD expire or be revalidated.

Permanent blocklists accumulate errors.

---

# 128. SIEM

Baobab MAY use a SIEM/security analytics platform.

The SIEM SHALL be:

```text
detection/correlation system
```

not:

```text
canonical identity database
```

---

# 129. SIEM Failure

Failure of the SIEM SHALL not automatically disable authentication.

Critical local protections such as:

```text
signature validation
rate limiting
CP denial
domain authorization
```

must continue.

---

# 130. Security Event Pipeline

Conceptually:

```text
Ory ────────┐
APISIX ─────┤
BFF ────────┤
CP ─────────┤
Trade ──────┤
ERP ────────┼──► Event/Telemetry Pipeline
CMS ────────┤             │
Pulse ──────┤             ▼
Infra ──────┘      Security Analytics
                           │
                           ▼
                     Detection Rules
                           │
                           ▼
                       Findings
                           │
                           ▼
                       Incidents
```

---

# 131. OpenTelemetry

Baobab SHOULD continue using OpenTelemetry-compatible:

```text
logs
traces
metrics
```

and correlate them through trace/resource context where appropriate.

---

# 132. Security Events vs Application Logs

A critical event such as:

```text
identity.disabled
```

SHALL not exist only as an arbitrary text log message.

Important security state transitions SHOULD use structured security events.

---

# 133. Metrics

IAM security metrics SHOULD include:

```text
authentication failures
authentication success
MFA failure rate
step-up rate
recovery attempts
session revocations
credential changes
workload auth failures
federation failures
invalid JWT rate
unknown kid rate
cross-context denials
containment commands
time to detect
time to contain
```

---

# 134. Metrics Must Not Leak Identity Data

Prefer aggregation or pseudonymous references where identity-level detail is unnecessary.

---

# 135. Alert Quality

Every production alert SHOULD answer:

```text
what happened?
why does it matter?
what is affected?
what evidence exists?
what should responder do next?
```

---

# 136. No Alert Without Ownership

Every high-severity production alert SHALL have:

```text
owner
routing
runbook
escalation
```

---

# 137. Alarm Fatigue

Alerts SHALL be tuned.

Thousands of unactionable authentication-failure alerts are not a functioning security system.

---

# 138. Runbooks

Required IAM security runbooks SHALL include:

```text
account takeover
credential stuffing
password spraying
privileged identity compromise
workload compromise
OAuth client compromise
federation compromise
SCIM compromise
signing-key compromise
TLS/private-key compromise
database credential compromise
cross-tenant access
mass revocation
IAM provider compromise
regional IAM failure
security journal compromise
```

---

# 139. Runbook Structure

Each SHOULD contain:

```text
trigger
validation
scope
containment
evidence
eradication
recovery
communications
verification
rollback
post-incident requirements
```

---

# 140. Exercises

Baobab SHALL conduct security exercises.

---

# 141. Tabletop Exercises

Tabletops SHOULD include:

```text
signing key stolen
enterprise federation compromised
ZuriBeans approver takeover
Thamani enterprise admin takeover
ERP finance administrator compromise
Ory administrator compromise
regional IAM loss
```

---

# 142. Technical Exercises

Where safely possible, exercises SHALL verify actual:

```text
session revocation
client disablement
issuer suspension
credential rotation
federation suspension
mass revocation
DR recovery
```

---

# 143. Purple-Team Testing

Future mature operations MAY use controlled adversarial exercises to test:

```text
detection
telemetry
containment
response
```

---

# 144. Production Penetration Testing

IAM SHALL receive periodic security testing appropriate to its Tier-0 role.

Testing SHALL be authorized and controlled.

---

# 145. Dependency Vulnerabilities

Security operations SHALL monitor vulnerabilities affecting:

```text
Ory Kratos
Ory Hydra
PostgreSQL
APISIX
container base images
Go dependencies
Node dependencies
operating system packages
```

---

# 146. Vulnerability ≠ Incident

A vulnerability becomes an incident only when circumstances warrant.

Nevertheless critical exploitable vulnerabilities MAY require emergency remediation before exploitation is confirmed.

---

# 147. Supply-Chain Signals

Monitor:

```text
unexpected image digest
unsigned/untrusted artifact
dependency anomaly
CI credential misuse
unauthorized deployment
configuration drift
```

---

# 148. Deployment Correlation

Security events SHOULD correlate with deployment/change events.

A sudden authentication anomaly immediately after deployment may have a different cause from an attack.

---

# 149. Configuration Drift

Unexpected changes to:

```text
issuer
redirect URI
JWKS
federation
OAuth client
Kratos schema
Hydra configuration
network policy
```

SHALL be detectable.

---

# 150. Security Operations Access

Security responders SHALL receive only privileges required for their duties.

---

# 151. SOC Read Access

Security analysts MAY require broad visibility.

That does not imply broad mutation authority.

---

# 152. Containment Authority

Security operators MAY receive narrowly defined containment capabilities separate from general IAM administration.

---

# 153. Example Capability Separation

```text
iam.security.observe

iam.security.investigate

iam.session.revoke

iam.identity.suspend

iam.workload.suspend

iam.federation.suspend

iam.issuer.suspend
```

These SHOULD remain separately assignable.

---

# 154. Dual Control

High-blast-radius operations SHOULD support dual authorization where practical.

---

# 155. No Security Backdoor

Security operations SHALL not introduce hidden authentication bypasses.

---

# 156. Privacy Boundary

Security telemetry SHALL follow:

```text
purpose limitation
data minimization
access restriction
retention
deletion policy
```

to be expanded by ADR-IAM-0030.

---

# 157. No Secret Surveillance

Security telemetry SHALL not be repurposed casually for employee productivity monitoring, customer profiling or unrelated analytics.

---

# 158. Retention

Security telemetry retention SHALL reflect:

```text
investigation needs
security risk
privacy
regulatory requirements
storage cost
```

and SHALL not default to indefinite retention.

---

# 159. Development Environment

Development environments SHALL produce representative security events without transmitting production personal/security data into development.

---

# 160. Staging

Staging SHOULD exercise:

```text
detection rules
containment commands
alert routing
runbooks
```

before production deployment.

---

# 161. Synthetic Security Events

Baobab MAY generate synthetic security events to verify pipelines and alerts.

They SHALL be unmistakably marked as test events.

---

# 162. Security Pipeline Monitoring

Baobab SHALL detect when:

```text
security logs stop
event pipeline stalls
SIEM ingestion fails
alert delivery fails
```

A silent monitoring failure is itself security-relevant.

---

# 163. Backpressure

Telemetry failure SHALL not normally block authentication unless the event is required for a security-critical authoritative transaction.

Critical audit guarantees SHALL use durable patterns established by ADR-IAM-0017.

---

# 164. Outbox

Authoritative security state transitions SHOULD use transactional outbox/reconciliation patterns where appropriate.

---

# 165. Detection Cannot Depend Only on Events

Periodic reconciliation SHALL complement event-driven detection.

Events can be lost or delayed.

---

# 166. Reconciliation Examples

Check:

```text
disabled identity with active provider session
revoked workload with enabled OAuth client
suspended federation still accepting authentication
retired issuer still trusted
compromised key still published
```

---

# 167. Security Invariants

The following SHALL remain true:

```text
Signal ≠ Fact

Risk Score ≠ Identity

Risk Score ≠ Business Authorization

SIEM ≠ Canonical Identity Authority

Detection Engine ≠ Authorization Engine

Valid Credential ≠ Safe Session

Valid Session ≠ Current Authority

Low Risk ≠ Assurance Bypass

High Risk ≠ Automatic Permanent Guilt

Geolocation ≠ Identity

Device Fingerprint ≠ Credential

Federation Authentication ≠ Business Membership

SCIM Provisioning ≠ Business Authority

Containment ≠ Deletion

Recovery ≠ Privilege Restoration

Monitoring ≠ Surveillance

Availability ≠ Trust

Incident Closure ≠ Evidence Deletion

Security Automation ≠ Unlimited Authority
```

---

# 168. Failure Behaviour

If risk detection is unavailable:

```text
mandatory authentication
mandatory assurance
CP authorization
domain authorization
```

SHALL continue where safe.

High-risk operations MAY fail closed where policy explicitly requires a risk decision.

---

# 169. No Risk-Engine Single Point of Failure

Ordinary low-risk authentication SHALL not unnecessarily require a synchronous external risk engine if resilient local/provider controls can safely operate.

---

# 170. Detection Architecture Principle

Prefer:

```text
authoritative transaction
      │
      ├── immediate local controls
      │
      └── asynchronous rich correlation
```

over making every authentication request synchronously depend on the entire security analytics stack.

---

# 171. Implementation Gates

## IAM-SOC0 — Threat and Control Inventory

Inventory:

```text
human identities
workloads
privileged identities
federations
SCIM
sessions
OAuth clients
cryptographic trust
regional IAM
domain authorization
```

Map threats to existing controls and gaps.

---

## IAM-SOC1 — Canonical Security Event Model

Implement provider-neutral:

```text
SecurityEvent
SecuritySignal
SecurityFinding
SecurityIncident
ContainmentCommand
IdentityRiskAssessment
```

contracts where genuinely required.

`shared` SHALL contain contracts only, not a security runtime.

---

## IAM-SOC2 — Telemetry Foundation

Normalize telemetry from:

```text
Ory
APISIX
BFFs
CP
Trade
ERP
CMS
Pulse
Infrastructure
```

with correlation identifiers.

---

## IAM-SOC3 — Authentication Threat Detection

Implement detection for:

```text
credential stuffing
password spraying
brute force
enumeration
recovery abuse
MFA anomalies
```

---

## IAM-SOC4 — Session and Account-Takeover Detection

Implement:

```text
session monitoring
credential-change monitoring
new-device signals
suspicious-session containment
user security notifications
```

---

## IAM-SOC5 — Workload and OAuth Security

Implement detection and containment for:

```text
workload credentials
OAuth clients
mTLS identities
token anomalies
```

---

## IAM-SOC6 — Federation and SCIM Security

Implement:

```text
federation anomaly detection
trust suspension
SCIM anomaly detection
enterprise isolation
```

---

## IAM-SOC7 — Privileged Security Operations

Implement:

```text
privileged monitoring
break-glass monitoring
security operator capabilities
dual-control controls
```

---

## IAM-SOC8 — Cross-Tenant Isolation Detection

Instrument and test:

```text
Tenant
LegalEntity
BusinessOrganization
buyer
supplier
context
```

isolation failures.

---

## IAM-SOC9 — Automated Containment

Implement narrow reversible containment:

```text
rate limit
step-up
reauthenticate
session revoke
temporary workload/client restriction
```

with explicit policy.

---

## IAM-SOC10 — Kill Switches and Mass Revocation

Implement/test:

```text
identity kill switch
workload kill switch
OAuth client kill switch
federation kill switch
issuer kill switch
controlled mass revocation
```

---

## IAM-SOC11 — Incident Management

Establish:

```text
severity
incident lifecycle
ownership
evidence
communications
recovery criteria
post-incident review
```

---

## IAM-SOC12 — Runbooks

Create all Tier-0 IAM security runbooks defined by this ADR.

---

## IAM-SOC13 — Security Exercises

Execute:

```text
account takeover
workload compromise
federation compromise
signing-key compromise
cross-tenant incident
regional IAM incident
```

exercises.

---

## IAM-SOC14 — Production Certification

Production readiness requires:

```text
working telemetry
tested detections
tested containment
tested kill switches
working alert routing
runbooks
incident ownership
successful exercises
security approval
```

---

# 172. Required Automated Tests

At minimum:

| Scenario | Expected Result |
|---|---|
| Repeated failed login | Signal generated |
| Distributed credential stuffing simulation | Detection generated |
| Password spraying simulation | Detection generated |
| Suspicious login requiring step-up | Step-up enforced |
| Mandatory MFA + low risk | MFA still required |
| Suspicious session | Narrow containment possible |
| Revoked session reused | Denied |
| Disabled identity with provider session | CP denies |
| Revoked workload authenticates | Denied |
| Wrong audience token | Rejected and observable |
| Unknown issuer | Rejected |
| Cross-tenant context probe | Denied and observable |
| Compromised federation suspended | Authentication denied |
| SCIM client attempts business-role grant | No unauthorized authority |
| Signing key marked compromised | Incident path triggered |
| Security event pipeline fails | Monitoring alert |
| Raw access token in logging test | Test fails |
| Break-glass activation | High-severity event |
| Mass revocation dry run | Scope visible before execution |
| DR restores stale security state | Restrictive newer state wins |

---

# 173. Production Readiness Checklist

### Detection

- [ ] authentication monitoring
- [ ] credential-stuffing detection
- [ ] password-spraying detection
- [ ] account-takeover detection
- [ ] recovery monitoring
- [ ] MFA/passkey monitoring
- [ ] workload monitoring
- [ ] federation monitoring
- [ ] SCIM monitoring
- [ ] privileged monitoring
- [ ] cross-tenant monitoring

### Telemetry

- [ ] structured security events
- [ ] correlation IDs
- [ ] trace correlation
- [ ] no credential logging
- [ ] tamper-resistant audit
- [ ] pipeline health monitoring
- [ ] retention policy

### Containment

- [ ] session revocation
- [ ] credential revocation
- [ ] identity suspension
- [ ] workload suspension
- [ ] OAuth client suspension
- [ ] federation suspension
- [ ] issuer suspension
- [ ] mass-revocation capability
- [ ] security recovery journal integration

### Operations

- [ ] severity model
- [ ] incident commander process
- [ ] escalation paths
- [ ] evidence preservation
- [ ] communication process
- [ ] recovery criteria
- [ ] post-incident review

### Exercises

- [ ] account takeover drill
- [ ] workload compromise drill
- [ ] privileged compromise drill
- [ ] federation compromise drill
- [ ] signing-key compromise drill
- [ ] cross-tenant incident drill
- [ ] regional IAM incident drill

---

# 174. Final Architecture

```text
                    IDENTITY ACTIVITY
                           │
             ┌─────────────┼──────────────┐
             │             │              │
             ▼             ▼              ▼
          Human         Workload       Federation
             │             │              │
             └─────────────┼──────────────┘
                           ▼
                     Authentication
                           │
                           ▼
                     Security Events
                           │
                           ▼
                  Detection / Correlation
                           │
                           ▼
                     Risk Assessment
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
        NORMAL FLOW                SECURITY CONTROL
             │                           │
             ▼                           ▼
        CP Context                 Step-up / Revoke /
             │                     Suspend / Limit
             ▼                           │
      Domain Authorization              │
             │                           │
             └─────────────┬─────────────┘
                           ▼
                        AUDIT
                           │
                           ▼
                  Incident Response
                           │
                           ▼
                       Recovery
                           │
                           ▼
                     Improvement
```

The critical architectural separation remains:

```text
Detection:
"What appears to be happening?"

Authentication:
"Who or what proved possession
of an accepted credential?"

Control Plane:
"In which Baobab context may
this principal operate?"

Domain:
"What business action is allowed?"

Security Operations:
"What trust must be restricted
because of credible security risk?"
```

None replaces another.

---

# 175. Consequences

## Positive

This architecture gives Baobab:

- identity-centric threat detection;
- account-takeover response;
- credential-stuffing protection;
- workload compromise containment;
- federation incident isolation;
- controlled automated containment;
- issuer-level emergency controls;
- cross-tenant security monitoring;
- correlated security telemetry;
- tested mass revocation;
- measurable incident response;
- recovery tied to authoritative security state;
- a security feedback loop into architecture and testing.

## Costs

Baobab must operate:

- security telemetry pipelines;
- detection rules;
- alerting;
- incident management;
- containment tooling;
- security runbooks;
- exercises;
- on-call/escalation capability;
- evidence storage;
- tuning and reconciliation.

This is appropriate for a Tier-0 identity platform.

---

# 176. Explicitly Deferred

This ADR does not mandate:

```text
a specific SIEM vendor
a specific SOAR vendor
commercial threat intelligence
machine-learning behavioural scoring
biometric surveillance
permanent device fingerprinting
automatic global account shutdown
```

These require separate justification.

---

# 177. Final Decision Principle

Baobab SHALL assume that authentication controls can eventually be challenged, credentials can eventually be stolen, and infrastructure can eventually fail.

The security architecture therefore SHALL NOT stop at:

```text
"Was authentication successful?"
```

It must also be able to ask:

```text
"Does this activity remain trustworthy?"
```

When credible evidence says no, Baobab must be capable of reducing trust quickly.

But that capability SHALL remain bounded.

A risk engine does not own identity.

A SIEM does not own authorization.

A detection rule does not own a tenant.

An incident responder does not automatically own every business permission.

The complete security chain is:

```text
Observe
   ↓
Detect
   ↓
Correlate
   ↓
Assess
   ↓
Contain
   ↓
Reconcile authoritative state
   ↓
Recover
   ↓
Verify
   ↓
Learn
```

Therefore:

> **Baobab IAM must be able to lose trust faster than an attacker can exploit it, while restoring trust only through authoritative, auditable and verifiable processes.**

And the final containment rule is:

> **Restrict the smallest sufficient scope, preserve evidence, fail safely where trust is uncertain, and never let emergency security operations silently become a second authorization system.**