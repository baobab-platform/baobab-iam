# ADR-0017: IAM Audit, Security Events and Observability

**Status:** Proposed  
**Date:** 2026-09-09  
**Decision Owners:** NABHOLD / Baobab Platform Architecture and Security  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Related Repositories:** `baobab-platform/baobab-cp`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/shared`, `baobab-platform/infrastructure`, Digital Estate repositories  
**Contract Owner:** `baobab-platform/shared`  
**Scope:** IAM audit, security-event taxonomy, authentication events, authorization decisions, privileged-action logging, cross-system correlation, event provenance, operational telemetry, immutable/tamper-evident audit expectations, retention, redaction, SIEM integration, OpenTelemetry conventions, metrics, alerting, anomaly signals, incident investigation and observability governance  
**Supersedes:** None  
**Superseded by:** None  
**Depends on:** ADR-0001 through ADR-0016

---

# 1. Context

Baobab's identity architecture deliberately distributes authority across several systems.

For example:

```text
Baobab IAM
    → authentication

Baobab CP
    → platform context and entitlement

Trade
    → commerce authorization

ERP
    → ERP roles and financial authorization

CMS
    → editorial authorization

Pulse
    → intelligence/report access
```

A meaningful security investigation therefore cannot rely on one application log.

The platform must be able to reconstruct:

```text
Who authenticated?

Through which client?

Using what assurance?

Which Canonical Identity was resolved?

Which Tenant / LegalEntity / Estate / Market context was requested?

What did the Control Plane decide?

Which engine received the request?

What did that engine decide?

What business action occurred?

Who changed the user's access?

What was revoked?

When did the revocation become effective?
```

Without consistent security events and cross-system correlation, Baobab would have strong authorization boundaries but weak visibility into how those boundaries behaved.

---

# 2. Decision

Baobab SHALL implement a layered observability and audit architecture that distinguishes:

```text
Operational Logs
Security Audit Records
Canonical Security Events
Domain Audit Trails
Metrics
Distributed Traces
Alerts
```

These artifacts SHALL be related through standardized identifiers but SHALL not be collapsed into one undifferentiated logging stream.

---

# 3. Governing Principle

> **Every security-sensitive decision must be attributable, every privileged action must be reconstructable, every cross-system security flow must be correlatable, and secrets must never become observability data.**

---

# 4. Audit Layers

Baobab SHALL distinguish four primary audit layers.

| Layer | Purpose |
|---|---|
| Operational logs | Diagnose runtime behavior |
| Security audit | Record security-sensitive identity/access events |
| Domain audit | Record business-domain state changes |
| Canonical security events | Propagate significant security state changes cross-system |

---

# 5. Operational Logs

Operational logs MAY include:

- request failures;
- dependency errors;
- retries;
- cache behavior;
- latency;
- background jobs;
- startup/shutdown;
- integration failures.

Operational logs SHALL NOT automatically be treated as authoritative security audit.

---

# 6. Security Audit

Security audit SHALL record identity, access and privilege events requiring forensic accountability.

Examples:

```text
authentication success
authentication failure
MFA challenge
MFA reset
credential enrollment
credential revocation
session revocation
identity suspension
membership grant
membership revocation
entitlement grant
entitlement revocation
privileged role assignment
break-glass access
impersonation
```

---

# 7. Domain Audit

Domain engines SHALL preserve domain-specific business audit.

Examples:

```text
Trade:
order refund
price override
buyer approval
supplier approval

ERP:
journal posting
payment approval
role assignment
period close

CMS:
content publish
workflow approval

Pulse:
restricted report access
sensitive dataset export
```

---

# 8. Canonical Security Events

Canonical security events SHALL be versioned cross-system messages representing security-significant lifecycle changes.

Examples:

```text
identity.suspended.v1
identity.disabled.v1
membership.revoked.v1
entitlement.revoked.v1
credential.compromised.v1
session.revoked.v1
workload.revoked.v1
```

---

# 9. Security Event ≠ Operational Log

This SHALL remain binding:

```text
Security Event ≠ Log Line
```

A canonical event has:

- defined schema;
- source authority;
- semantics;
- version;
- provenance;
- lifecycle meaning.

---

# 10. Security Event ≠ Domain Audit

Likewise:

```text
identity.suspended.v1
```

is not equivalent to:

```text
ERP journal posted
```

They belong to different audit concerns.

---

# 11. Source-of-Truth Ownership

Each system SHALL emit events only for security properties it owns.

| Property | Authority |
|---|---|
| Authentication | IAM |
| Credential | IAM |
| Session | IAM/application |
| Canonical Identity | CP |
| Tenant membership | CP |
| Capability entitlement | CP |
| Buyer membership | Trade |
| Supplier approval/membership | Supplier domain |
| ERP roles | ERP |
| CMS roles | CMS |
| Pulse roles | Pulse |

---

# 12. No False Authority

Trade SHALL NOT emit:

```text
identity.disabled.v1
```

as if it were the global identity authority.

Instead it may emit:

```text
buyer.membership.revoked.v1
```

or a Trade-specific security event it owns.

---

# 13. Correlation Model

Baobab SHALL propagate consistent correlation metadata across services.

At minimum:

```text
trace_id
request_id
correlation_id
```

SHOULD be available where appropriate.

Security decisions SHOULD additionally carry:

```text
decision_id
```

---

# 14. Trace ID

`trace_id` SHALL correlate one distributed execution flow across participating services where tracing is active.

---

# 15. Request ID

`request_id` SHALL identify an individual inbound request.

---

# 16. Correlation ID

`correlation_id` MAY span:

- synchronous requests;
- asynchronous events;
- workflows;
- retries;
- downstream effects.

---

# 17. Decision ID

Security-sensitive authorization results SHOULD produce a:

```text
decision_id
```

that allows investigators to correlate:

```text
request
    │
    ▼
authorization decision
    │
    ▼
domain action
```

---

# 18. Canonical Identity ID

Where known and lawful, security audit SHOULD record:

```text
canonical_identity_id
```

rather than relying only on email or username.

---

# 19. External Identity

IAM authentication records SHOULD also preserve, where appropriate:

```text
issuer
subject
```

or a safe reference to them.

---

# 20. Actor and Subject

Delegated operations SHALL preserve the distinction between:

```text
subject
```

and:

```text
actor
```

Example:

```text
subject = human user
actor   = baobab-trade workload
```

---

# 21. Human-Initiated Service Action

A service acting for a human SHOULD make it possible to determine:

```text
who requested the action
which service performed it
```

---

# 22. Service-Owned Action

If no human is involved:

```text
subject = null / service-owned
actor   = workload identity
```

SHOULD be explicit.

---

# 23. Authentication Event Schema

A canonical authentication audit record SHOULD include fields conceptually similar to:

```text
event_id
occurred_at
event_type
issuer
subject
canonical_identity_id?
actor_type
client_id
authentication_method[]
assurance_level?
source_ip_metadata?
result
reason_code?
session_id?
trace_id?
correlation_id?
```

Sensitive fields SHALL be minimized.

---

# 24. Authentication Success

A successful authentication SHOULD capture enough information to establish:

- which identity;
- which client;
- authentication method;
- assurance level;
- timestamp;
- result.

---

# 25. Authentication Failure

Failure records SHOULD capture:

- failure category;
- client;
- timing;
- safe origin metadata.

They SHOULD NOT expose unnecessary credential-validation detail.

---

# 26. Failure Reason Codes

Prefer structured reasons such as:

```text
INVALID_CREDENTIAL
ACCOUNT_DISABLED
MFA_REQUIRED
MFA_FAILED
TOKEN_EXPIRED
INVALID_ISSUER
INVALID_AUDIENCE
INVALID_STATE
SESSION_REVOKED
```

Exact taxonomy SHALL be centrally governed.

---

# 27. Avoid Overly Detailed Client Errors

External error response:

```text
Authentication failed.
```

may be intentionally less detailed than internal audit:

```text
INVALID_CREDENTIAL
```

---

# 28. MFA Events

Audit SHALL capture:

```text
MFA enrollment
MFA successful
MFA failed
MFA reset
authenticator removed
recovery code generated
recovery code consumed
```

without capturing secrets.

---

# 29. Passkey/WebAuthn Events

Baobab SHOULD audit:

```text
credential registered
credential authenticated
credential revoked
credential renamed
```

using credential references rather than secret material.

---

# 30. Recovery Audit

Account recovery SHALL be auditable.

Record:

```text
recovery initiated
recovery verified
recovery completed
recovery failed
privileged recovery
MFA reset
session revocation triggered
```

---

# 31. Recovery Secrets

The following SHALL never enter logs:

```text
recovery token
recovery code
password
TOTP seed
WebAuthn private material
```

---

# 32. Authorization Decision Audit

Control Plane security-sensitive context decisions SHOULD emit structured decision telemetry.

Conceptually:

```text
decision_id
canonical_identity_id
actor_type
tenant_id
legal_entity_id
digital_estate_id
market_id
capability_id
engine_instance_id
result
reason_code
policy/version
occurred_at
trace_id
correlation_id
```

---

# 33. Authorization Data Minimization

Decision logs SHOULD record IDs and outcome, not unnecessary full resource payloads.

---

# 34. CP Denial Reasons

Reason codes MAY include:

```text
IDENTITY_DISABLED
TENANT_SUSPENDED
MEMBERSHIP_MISSING
MEMBERSHIP_REVOKED
CAPABILITY_NOT_ENTITLED
MARKET_NOT_ALLOWED
ENGINE_BINDING_MISSING
WORKLOAD_NOT_ALLOWED
CONTEXT_AMBIGUOUS
```

---

# 35. Domain Authorization Audit

Domain engines SHOULD emit their own structured authorization decisions for high-risk actions.

---

# 36. Trade Authorization Audit

Examples:

```text
buyer membership missing
purchase approval denied
cross-buyer resource access denied
supplier suspended
customer order ownership denied
```

---

# 37. ERP Authorization Audit

iDempiere SHALL remain authoritative for ERP permission/audit decisions.

Important ERP audit SHOULD preserve:

```text
AD_User
AD_Role
AD_Client
AD_Org
ERP operation
result
```

with Baobab correlation metadata where feasible.

---

# 38. CMS Authorization Audit

Payload SHOULD record meaningful changes such as:

```text
publish
unpublish
role change
workflow approval
privileged content access
```

---

# 39. Pulse Authorization Audit

Pulse SHOULD audit:

- restricted report access;
- sensitive dataset access;
- export;
- administrative changes;
- privileged query execution where appropriate.

---

# 40. Privileged Actions

Every privileged administrative operation SHALL produce security audit.

Examples:

```text
grant IAM administrator
grant CP administrator
assign ERP role
change tenant
suspend tenant
approve supplier
reset MFA
impersonate user
use break-glass
rotate critical credential
change production IAM configuration
```

---

# 41. Privilege Grant Audit

The audit record SHOULD answer:

```text
Who granted access?

To whom?

What was granted?

For which context?

When?

Why?

Was approval required?

Who approved?
```

---

# 42. Privilege Revocation Audit

Likewise:

```text
Who revoked access?

What authority disappeared?

When did it become effective?

Did propagation complete?
```

---

# 43. Before-and-After State

For high-risk administrative changes, audit SHOULD include safe before/after values.

Example:

```text
role:
  before: viewer
  after: finance_manager
```

---

# 44. Sensitive Values

Before/after audit SHALL NOT expose secrets or protected payment data.

---

# 45. Supplier Financial Changes

Supplier bank-detail changes SHOULD produce especially strong domain audit.

Record:

```text
supplier organization
requesting representative
approving workforce user
change reference
verification result
timestamp
```

Bank details themselves SHOULD be redacted or referenced securely.

---

# 46. ERP Financial Audit

Native iDempiere transaction/audit mechanisms SHALL remain authoritative for:

- journal posting;
- financial approvals;
- payments;
- accounting changes.

Baobab SHALL complement, not replace, these records.

---

# 47. Break-Glass Audit

Break-glass access SHALL always trigger:

```text
security audit
alert
incident reference
post-use review
```

---

# 48. Break-Glass Event

Audit SHOULD capture:

```text
identity
credential/path
target system
reason
incident_id
time started
time ended
actions taken
```

where feasible.

---

# 49. Impersonation

If impersonation is supported, it SHALL preserve:

```text
actor = support/admin
subject = impersonated user
```

Both identities SHALL be visible in audit.

---

# 50. Hidden Impersonation Prohibited

Baobab SHALL NOT implement support access that makes actions appear to originate only from the customer/supplier.

---

# 51. Security Event Envelope

Canonical events SHOULD use a common envelope.

Conceptually:

```text
event_id
event_type
schema_version
occurred_at
producer
subject
actor
context
reason_code
trace_id
correlation_id
payload
```

---

# 52. Event IDs

Every canonical security event SHALL have a globally unique event identifier.

---

# 53. Event Versioning

Security-event schemas SHALL be versioned.

Example:

```text
identity.disabled.v1
```

---

# 54. Event Provenance

Consumers SHALL know:

```text
who emitted the event
```

through authenticated workload identity and event metadata.

---

# 55. Event Integrity

Event transport SHALL protect:

- authenticity;
- integrity;
- ordering metadata where available;
- confidentiality where required.

---

# 56. Event Tampering

Consumers SHALL reject events failing authentication/integrity validation.

---

# 57. Event Payload Minimization

Canonical security events SHOULD contain:

```text
IDs
state changes
reason codes
timestamps
```

rather than whole user profiles.

---

# 58. No Credentials in Events

Canonical events SHALL never contain:

```text
password
access token
refresh token
authorization code
client secret
recovery token
TOTP seed
private key
```

---

# 59. Event Bus Authorization

Publishing security events SHALL require workload authorization.

---

# 60. Producer Restrictions

A workload SHALL be allowed to publish only event types it is authorized to produce.

---

# 61. Consumer Authorization

Access to security-event streams SHALL also be restricted.

---

# 62. Security Events Are Sensitive

IAM/security event streams SHALL not be treated as public integration feeds.

---

# 63. OpenTelemetry

Baobab SHOULD standardize distributed telemetry around OpenTelemetry-compatible conventions where practical.

---

# 64. Trace Propagation

Services SHOULD propagate standard trace context across:

```text
HTTP
internal APIs
event handlers
workflows
```

where supported.

---

# 65. Security Context in Traces

Traces MAY include safe identity references such as:

```text
actor.type
client.id
tenant.id
capability.id
decision.id
```

but SHALL avoid excessive PII.

---

# 66. Avoid Email as High-Cardinality Trace Attribute

Trace labels SHOULD prefer stable identifiers over:

```text
email
full name
phone
```

---

# 67. Cardinality

Metrics SHALL avoid uncontrolled high-cardinality labels.

Bad:

```text
auth_failures{email="every-user@example.com"}
```

Preferred:

```text
auth_failures{reason="INVALID_CREDENTIAL"}
```

---

# 68. Security Metrics

IAM SHOULD expose metrics such as:

```text
authentication_attempts_total
authentication_failures_total
mfa_challenges_total
mfa_failures_total
passkey_authentications_total
recovery_attempts_total
sessions_revoked_total
identities_suspended_total
```

---

# 69. CP Metrics

Useful metrics include:

```text
context_resolution_total
context_resolution_denied_total
entitlement_denied_total
cross_tenant_denied_total
authorization_latency
```

---

# 70. Lifecycle Metrics

ADR-0016 metrics remain relevant:

```text
revocation_event_lag
deprovisioning_duration
deprovisioning_failures_total
orphan_identities_total
```

---

# 71. Trade Security Metrics

Trade MAY expose:

```text
buyer_access_denied_total
cross_buyer_denied_total
customer_resource_denied_total
supplier_access_denied_total
```

---

# 72. ERP Security Metrics

ERP observability MAY include:

```text
sso_failures
erp_role_denials
privileged_financial_actions
erp_mapping_failures
```

without duplicating ERP's native audit model.

---

# 73. CMS Security Metrics

CMS MAY include:

```text
publish_denials
role_change_events
admin_login_failures
```

---

# 74. Pulse Security Metrics

Pulse MAY include:

```text
restricted_report_denials
sensitive_export_total
workspace_access_denied
```

---

# 75. Security SLOs

The platform SHOULD define operational SLOs for:

- IAM availability;
- authentication latency;
- token validation;
- CP context resolution;
- security-event propagation;
- revocation propagation;
- audit ingestion success.

---

# 76. Audit Ingestion SLO

Critical security audit ingestion SHOULD be monitored.

Missing audit SHALL be treated as an operational/security defect.

---

# 77. Audit Loss

The system SHALL NOT silently discard security audit because the primary analytics/logging backend is unavailable.

---

# 78. Buffered Delivery

Where practical, important security audit SHOULD be:

```text
buffered
retried
durably queued
```

before final archival/indexing.

---

# 79. Fail-Open vs Audit Availability

Most ordinary business operations SHOULD NOT necessarily fail solely because the SIEM is temporarily unavailable.

However, extremely sensitive operations MAY require durable audit capture before completion.

This SHALL be explicitly decided per operation.

---

# 80. Critical Audit Example

Candidate operations requiring stronger audit guarantees include:

```text
break-glass activation
IAM administrator assignment
tenant suspension
privileged MFA reset
```

---

# 81. Tamper Resistance

Security audit storage SHALL be protected against casual alteration by application administrators.

---

# 82. Tamper-Evident Expectations

High-value audit SHOULD use controls such as:

- append-oriented storage;
- restricted write paths;
- immutable/retention-locked storage where available;
- cryptographic integrity controls where justified;
- separate administrative roles.

---

# 83. Application Administrator ≠ Audit Administrator

An administrator of an application SHOULD NOT automatically be able to erase the audit trail of their own actions.

---

# 84. Audit Deletion

Security audit deletion SHALL follow controlled retention policy.

Ad-hoc operator deletion is prohibited.

---

# 85. Audit Export

Exporting security audit SHALL itself be auditable if the exported data is sensitive.

---

# 86. Retention Classes

Baobab SHALL define differentiated retention classes.

Suggested categories:

```text
operational
security
privileged-security
financial-domain
regulatory
```

---

# 87. Operational Retention

Operational logs MAY have relatively shorter retention.

---

# 88. Security Retention

Identity and access audit SHOULD receive longer retention appropriate to:

- investigation;
- compliance;
- legal requirements;
- risk.

---

# 89. Financial Retention

ERP/financial audit retention SHALL follow financial/legal requirements applicable to the relevant market/legal entity.

---

# 90. Retention Is Jurisdiction-Aware

Baobab SHALL not assume one global retention duration is valid for every market.

---

# 91. Data Residency

Security telemetry containing personal or regulated data SHALL follow Baobab's data-residency and privacy architecture.

---

# 92. PII Minimization

Audit SHALL collect only what is necessary for:

```text
security
operations
investigation
compliance
```

---

# 93. Identifier Preference

Prefer:

```text
canonical_identity_id
tenant_id
organization_id
actor_id
```

over repeated copies of:

```text
full name
email
phone
address
```

---

# 94. Redaction

Structured logging libraries and platform filters SHALL redact known secret fields.

---

# 95. Redaction Targets

At minimum:

```text
authorization
cookie
set-cookie
access_token
refresh_token
id_token
client_secret
password
authorization_code
pkce_verifier
recovery_token
totp_secret
```

---

# 96. HTTP Headers

Raw authentication headers SHALL not be logged.

---

# 97. Query Strings

Authentication/recovery secrets SHALL never be placed in URLs where they may appear in intermediary logs, unless required by a standards-based one-time callback mechanism and handled with strict sanitization.

---

# 98. Error Objects

Applications SHALL sanitize upstream OIDC/Keycloak error objects before logging if they may contain tokens or sensitive parameters.

---

# 99. Structured Logging

Security-relevant services SHOULD use structured logs.

Example:

```json
{
  "event": "authorization.denied",
  "decision_id": "dec_...",
  "tenant_id": "ten_...",
  "reason": "MEMBERSHIP_REVOKED"
}
```

---

# 100. Free-Text Logging

Free-text logs MAY supplement structured telemetry but SHALL not be the sole security audit mechanism.

---

# 101. Time Synchronization

All security-sensitive systems SHALL maintain reliable time synchronization.

---

# 102. Timestamp Standard

Security events SHALL use precise standardized timestamps.

UTC storage SHOULD be preferred, while display layers MAY localize timestamps.

---

# 103. Event Ordering

Consumers SHALL not assume ingestion time equals event occurrence time.

Both:

```text
occurred_at
received_at
```

MAY be useful.

---

# 104. Clock Skew

Investigative tooling SHOULD account for bounded system clock skew.

---

# 105. Environment Identification

All telemetry SHALL identify environment.

Example:

```text
environment = production
```

---

# 106. No Cross-Environment Confusion

Production and staging audit SHALL remain distinguishable and preferably segregated.

---

# 107. Service Identification

Audit/logging SHALL identify:

```text
service.name
service.version
deployment/environment
```

where practical.

---

# 108. Engine Instance Identification

Multi-instance engines SHOULD record:

```text
engine_instance_id
```

for correlation.

---

# 109. Tenant Context

Tenant-aware security events SHOULD include authoritative tenant context where known.

---

# 110. Digital Estate Context

Estate-facing flows SHOULD include:

```text
digital_estate_id
```

where meaningful.

---

# 111. Market Context

Market-aware authorization SHOULD include:

```text
market_id
```

when it affects the decision.

---

# 112. Legal Entity Context

Financial or entity-scoped actions SHOULD include:

```text
legal_entity_id
```

where relevant.

---

# 113. Business Organization Context

B2B/supplier audit SHOULD include organization references such as:

```text
buyer_organization_id
supplier_organization_id
```

where necessary.

---

# 114. No Ambiguous `organization_id`

Cross-platform security events SHOULD avoid one generic:

```text
organization_id
```

when the semantic type matters.

---

# 115. Security Alerting

Security monitoring SHALL support actionable alerts rather than alerting on every ordinary failure.

---

# 116. Critical Alert Candidates

Examples:

```text
break-glass use
critical admin MFA reset
IAM admin added
mass role grants
tenant suspension
high-volume account recovery
privileged credential compromise
cross-tenant access anomaly
unexpected signing-key failure
revocation propagation failure
```

---

# 117. Authentication Attack Signals

Useful signals include:

```text
credential stuffing
distributed brute force
MFA fatigue patterns
recovery abuse
account enumeration attempts
impossible authentication patterns
```

---

# 118. Anomaly ≠ Automatic Guilt

Anomaly signals SHALL trigger investigation or additional controls.

They SHALL not automatically become irreversible business sanctions without policy.

---

# 119. Adaptive Authentication Future

Risk signals MAY later inform:

```text
step-up authentication
temporary challenge
session review
```

through a separately governed risk architecture.

---

# 120. Privileged Behaviour Signals

Monitor unusual privileged behavior such as:

```text
admin creating another admin
mass role changes
unusual cross-tenant access
bulk data export
unexpected MFA resets
late-night break-glass use
```

according to policy and privacy constraints.

---

# 121. Cross-Tenant Monitoring

Cross-tenant access SHALL be especially observable.

Every legitimate privileged cross-tenant operation SHOULD carry:

```text
actor
source context
target tenant
reason
decision
```

where applicable.

---

# 122. Executive Visibility

Executive read-only cross-tenant access SHOULD be distinguishable from operational administrative access.

---

# 123. Service Abuse Signals

Workload monitoring SHOULD detect:

```text
wrong audience attempts
unusual token issuance
scope escalation attempts
unexpected tenant access
traffic from retired workload
```

---

# 124. Workload Credential Events

Audit SHOULD record:

```text
workload provisioned
credential issued
credential rotated
workload suspended
workload revoked
workload retired
```

---

# 125. Secret Rotation Audit

Rotation events SHALL identify the workload/client but SHALL never log the old/new secret.

---

# 126. OIDC Key Events

IAM operational/security monitoring SHOULD detect:

```text
signing key rotation
JWKS failures
unknown kid spikes
token validation anomalies
```

---

# 127. SIEM Integration

Baobab SHOULD integrate normalized security audit and selected domain events with a SIEM or equivalent centralized security analytics capability.

---

# 128. SIEM Is Not Source of Truth

The SIEM SHALL aggregate and analyze.

It SHALL not replace:

- IAM;
- CP;
- Trade;
- ERP;
- CMS;
- Pulse

as authoritative systems.

---

# 129. SIEM Event Normalization

Security events SHOULD be normalized into stable categories while retaining source-system semantics.

---

# 130. Raw vs Normalized

Where feasible:

```text
source audit record
+
normalized security event
```

SHOULD both be retained according to policy.

---

# 131. Detection Rules as Code

Important detection/alert rules SHOULD be version-controlled where tooling supports it.

---

# 132. Alert Ownership

Every production security alert SHOULD have:

```text
severity
owner
runbook
escalation path
```

---

# 133. Alert Fatigue

Baobab SHALL avoid alert rules that trigger continuously during legitimate routine activity.

---

# 134. Security Dashboards

Dashboards SHOULD expose trends such as:

```text
authentication failures
MFA adoption
passkey adoption
privileged changes
revocation lag
cross-tenant denials
workload failures
security-event ingestion health
```

---

# 135. Observability Health

The observability system itself SHALL be monitored.

Examples:

```text
collector unavailable
audit ingestion lag
event consumer backlog
trace exporter failures
storage quota
retention failure
```

---

# 136. Audit Pipeline Failure

Critical audit pipeline failure SHOULD trigger high-priority operational alerting.

---

# 137. Event Consumer Lag

Security-event consumer lag SHALL be measured because delayed consumption may become delayed revocation.

---

# 138. Investigation View

Incident responders SHOULD be able to search by:

```text
Canonical Identity
event ID
decision ID
trace ID
tenant
workload
engine actor
time window
```

---

# 139. Identity Timeline

Investigation tooling SHOULD enable a timeline such as:

```text
08:00 Login
08:01 MFA
08:02 CP context resolved
08:05 ERP role selected
08:10 Payment approved
08:17 IAM session revoked
```

---

# 140. Cross-System Timeline

Where a business action traverses multiple engines:

```text
Trade
  │
  ▼
CP
  │
  ▼
ERP
```

investigators SHOULD be able to correlate the complete flow.

---

# 141. Investigation Immutability

Incident evidence SHOULD be exportable/preservable under controlled evidence-handling processes.

---

# 142. Investigation Access

Security audit access SHALL itself be privileged.

---

# 143. Auditor Role

Auditors MAY receive read-only access to appropriate security and domain audit records.

Auditors SHALL not automatically gain operational administration privileges.

---

# 144. Security Team Access

Security personnel MAY require broader cross-platform audit visibility than ordinary administrators.

This SHALL be explicitly authorized.

---

# 145. Customer Access to Security History

B2C users MAY be given safe self-service visibility such as:

```text
recent sessions
new passkey
password changed
```

without exposing internal security intelligence.

---

# 146. Supplier Security Visibility

Supplier admins MAY view organization-relevant events such as:

```text
representative added
representative removed
bank-change request
supplier admin changed
```

subject to domain policy.

---

# 147. Buyer Security Visibility

Buyer admins MAY similarly view membership/invitation changes for their organization.

---

# 148. Internal Security Notes

Risk analyst notes and investigation details SHALL not automatically be exposed to external users.

---

# 149. Event Retention vs User Closure

Closing a user/customer account SHALL not automatically delete security audit required for legitimate security/compliance purposes.

---

# 150. Data Subject Requests

Privacy processes SHALL evaluate audit retention carefully.

Security audit may have lawful retention requirements distinct from product profile data.

---

# 151. No Secret in Support Tickets

Operational runbooks SHALL instruct teams not to paste tokens, passwords or recovery codes into incident/support systems.

---

# 152. Incident IDs

Security incidents SHOULD have identifiers that can be referenced from relevant audit events.

---

# 153. Reason Codes

Security event reason codes SHOULD be shared and versioned.

Examples:

```text
USER_REQUEST
ADMIN_ACTION
SECURITY_COMPROMISE
WORKFORCE_TERMINATION
CONTRACT_EXPIRY
POLICY_VIOLATION
TENANT_SUSPENSION
ROLE_CHANGE
AUTOMATED_SECURITY_RESPONSE
```

---

# 154. Security Event Severity

Canonical events MAY include severity classification where useful.

Example:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Severity SHALL not replace event semantics.

---

# 155. Security Event Categories

Recommended categories:

```text
AUTHENTICATION
CREDENTIAL
SESSION
IDENTITY
MEMBERSHIP
ENTITLEMENT
PRIVILEGE
WORKLOAD
TENANT
ADMINISTRATION
RECOVERY
IMPERSONATION
BREAK_GLASS
```

---

# 156. Detection Events

Derived anomaly events SHOULD be distinguishable from authoritative lifecycle events.

Example:

```text
security.anomaly.detected.v1
```

is not equivalent to:

```text
identity.disabled.v1
```

---

# 157. Automated Response

Where policy allows, severe detection may trigger automated:

```text
session revocation
step-up requirement
temporary suspension
```

Such automation SHALL itself be auditable.

---

# 158. Explainability

Automated security actions SHOULD include machine-readable reason/provenance so investigators can understand why they occurred.

---

# 159. Event Replay

Security-event systems MAY support replay for recovery/reconciliation.

Replay SHALL preserve original:

```text
event_id
occurred_at
```

and SHALL not make an old event appear newly authoritative.

---

# 160. Duplicate Event Handling

Consumers SHALL process security events idempotently.

---

# 161. Stale Event Handling

Consumers SHALL reject stale state transitions according to ADR-0016 lifecycle/versioning rules.

---

# 162. Logging Failures

Application code SHALL not crash merely because a best-effort debug log write fails.

Critical audit requirements MAY use stronger persistence semantics.

---

# 163. Audit Transaction Boundary

For highly sensitive operations, audit SHOULD be coupled closely enough to the state change that investigators cannot observe:

```text
privilege granted
```

with no corresponding audit due to an avoidable application bug.

---

# 164. Outbox Pattern

Where suitable, services SHOULD use transactional outbox or equivalent patterns for reliable security/domain event publication.

---

# 165. Audit Event Duplication

A domain action MAY legitimately produce:

```text
domain audit
+
canonical security event
+
operational log
+
trace span
```

These are complementary, not redundant errors.

---

# 166. No One Log to Rule Them All

Baobab SHALL NOT force all telemetry into one schema that destroys domain semantics.

---

# 167. OpenTelemetry Span Naming

Span names SHOULD be stable and operation-oriented.

Example:

```text
iam.authenticate
cp.context.resolve
trade.order.authorize
erp.role.resolve
```

Exact naming conventions SHALL be documented.

---

# 168. Security Span Attributes

Safe attributes MAY include:

```text
baobab.actor_type
baobab.tenant_id
baobab.capability_id
baobab.decision_id
```

Exact namespace SHALL be standardized.

---

# 169. Trace Sampling

General tracing MAY use sampling.

However, critical security audit SHALL NOT depend solely on sampled traces.

---

# 170. Audit Completeness

Security audit records requiring retention SHALL be recorded independently of trace sampling.

---

# 171. High-Volume Events

High-volume events such as ordinary successful customer login MAY require scalable storage/retention strategies.

Security-critical events SHALL receive higher durability/retention priority.

---

# 172. Debug Mode

Production debug logging SHALL not be casually enabled around authentication flows.

---

# 173. Development Redaction

Secret redaction SHOULD also apply outside production to prevent developers from normalizing insecure logging habits.

---

# 174. Test Assertions

Security tests SHOULD explicitly assert that secrets do not appear in captured logs.

---

# 175. Required IAM Tests

Test:

```text
successful login audited
failed login audited safely
MFA enrollment audited
MFA reset audited
credential revocation audited
recovery audited
session revocation audited
```

---

# 176. Required CP Tests

Test:

```text
context allow produces decision ID
context deny produces reason code
cross-tenant denial is observable
tenant suspension is observable
capability revocation is observable
```

---

# 177. Required Delegation Tests

Test:

```text
human → service → ERP
```

and verify:

```text
subject
actor
trace
decision
```

remain distinguishable.

---

# 178. Required Privileged Tests

Test:

```text
IAM admin grant
ERP role grant
tenant suspension
MFA reset
impersonation
break-glass
```

all generate appropriate audit.

---

# 179. Required Redaction Tests

Automated tests SHALL attempt to log payloads containing:

```text
access_token
refresh_token
password
client_secret
recovery_token
authorization header
```

and verify redaction.

---

# 180. Required Event Tests

Test:

```text
event authentication
event provenance
duplicate event
out-of-order event
event replay
consumer retry
dead-letter handling
```

---

# 181. Required Retention Tests

Where infrastructure supports it, validate:

- retention policy;
- write restrictions;
- audit deletion restrictions;
- archival.

---

# 182. Required Investigation Exercise

Staging/security exercises SHOULD prove investigators can reconstruct:

```text
login
context resolution
privilege grant
business action
session revocation
```

across multiple services.

---

# 183. Rejected Alternative — Plain Text Logs Only

### Advantages

Simple.

### Disadvantages

- poor queryability;
- weak correlation;
- inconsistent semantics;
- fragile investigation.

### Decision

Rejected.

---

# 184. Rejected Alternative — SIEM as Primary Audit Store

### Decision

Rejected.

Source systems retain authoritative audit responsibilities.

---

# 185. Rejected Alternative — Trace Data as Security Audit

### Decision

Rejected.

Tracing may be sampled and is optimized for performance diagnostics.

---

# 186. Rejected Alternative — Emails as Identity Correlation

### Decision

Rejected.

Canonical immutable identifiers SHALL be preferred.

---

# 187. Rejected Alternative — Log Full Tokens for Debugging

### Decision

Prohibited.

---

# 188. Rejected Alternative — Shared Generic Organization ID

### Decision

Rejected where semantics are ambiguous.

---

# 189. Rejected Alternative — Domain Engines Emit Global Identity State

### Decision

Rejected.

Authority boundaries remain explicit.

---

# 190. Rejected Alternative — Every Authentication Failure Is an Alert

### Decision

Rejected.

Alerting SHALL be risk- and pattern-based.

---

# 191. Rejected Alternative — Application Admin Can Delete Own Audit

### Decision

Rejected.

---

# 192. Rejected Alternative — Sampled Traces as Complete Audit

### Decision

Rejected.

---

# 193. Consequences

## Positive

This decision provides:

- strong forensic accountability;
- cross-system identity investigation;
- auditable privilege changes;
- safer incident response;
- measurable revocation;
- better tenant isolation monitoring;
- SIEM readiness;
- OpenTelemetry alignment;
- structured anomaly detection;
- reduced risk of secrets entering logs.

## Negative

It requires:

- event schemas;
- correlation conventions;
- audit pipelines;
- retention governance;
- central security analytics;
- storage capacity;
- redaction testing;
- operational ownership.

These costs are accepted.

---

# 194. Implementation Ownership

| Concern | Owner |
|---|---|
| Authentication audit | `baobab-iam` |
| Credential/session audit | `baobab-iam` |
| CP decision audit | `baobab-cp` |
| Buyer/customer domain audit | `baobab-trade` |
| Supplier security audit | supplier domain |
| ERP audit | `baobab-erp` |
| CMS audit | `baobab-cms` |
| Pulse audit | `baobab-pulse` |
| Canonical security contracts | `baobab-platform/shared` |
| Telemetry transport | `baobab-platform/infrastructure` |
| SIEM/security monitoring | Infrastructure/Security |
| Digital Estate frontend telemetry | respective estate |

---

# 195. Shared Contract Requirements

`baobab-platform/shared` SHOULD define versioned schemas for:

```text
security event envelope
authentication event
authorization decision event
identity lifecycle event
membership lifecycle event
entitlement event
credential event
session event
privileged action event
workload security event
security anomaly event
reason-code registry
correlation metadata
```

---

# 196. Suggested Security Event Envelope

Conceptually:

```text
SecurityEvent
────────────────────────
event_id
event_type
schema_version
occurred_at
producer
severity?
category
actor
subject?
context?
reason_code?
trace_id?
correlation_id?
payload
```

---

# 197. Suggested Actor Structure

```text
Actor
────────────────────────
actor_type
canonical_identity_id?
workload_id?
client_id?
external_subject_reference?
```

Only applicable fields SHALL be populated.

---

# 198. Suggested Security Context

```text
SecurityContext
────────────────────────
tenant_id?
legal_entity_id?
digital_estate_id?
market_id?
capability_id?
engine_instance_id?
buyer_organization_id?
supplier_organization_id?
```

---

# 199. Target Observability Architecture

```text
                         USERS / WORKLOADS
                                │
                                ▼
                           BAOBAB IAM
                                │
                 authentication/security events
                                │
                                ▼
                         BAOBAB CONTROL PLANE
                                │
                    context / decision events
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
           TRADE               ERP               CMS
              │                 │                 │
              └────────────┬────┴────┬────────────┘
                           ▼         ▼
                         PULSE     OTHER
                           │
                           ▼
                STRUCTURED TELEMETRY LAYER
                 ┌─────────┼─────────┐
                 ▼         ▼         ▼
               Logs      Traces    Metrics
                 │         │         │
                 └─────────┼─────────┘
                           ▼
                    SECURITY PIPELINE
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
            SIEM        Archive      Dashboards
              │
              ▼
         Detection / Alerts
              │
              ▼
       Incident Investigation
```

---

# 200. Cross-System Investigation Flow

```text
SECURITY INVESTIGATOR
        │
        ▼
CanonicalIdentity
        │
        ▼
IAM authentication history
        │
        ▼
CP decision_id / correlation_id
        │
        ▼
Engine activity
   ┌────┼────┬────┐
   ▼    ▼    ▼    ▼
Trade  ERP  CMS  Pulse
   │    │    │    │
   └────┴────┼────┘
             ▼
       Incident Timeline
             │
             ▼
     Cause / Scope / Response
```

---

# 201. Privileged Action Audit Flow

```text
PRIVILEGED USER
      │
      ▼
Strong authentication
      │
      ▼
CP context
      │
      ▼
Domain authorization
      │
      ▼
Privileged action
      │
      ├────────► domain audit
      │
      ├────────► security audit
      │
      ├────────► trace
      │
      └────────► metrics
                     │
                     ▼
                 SIEM / Alert
```

---

# 202. Security Event Flow

```text
AUTHORITATIVE SYSTEM
        │
        ▼
security state change
        │
        ▼
transaction/outbox
        │
        ▼
canonical security event
        │
        ▼
authenticated event transport
        │
   ┌────┼────┬────┐
   ▼    ▼    ▼    ▼
consumer consumer consumer archive
   │
   ▼
local restriction / reconciliation
```

---

# 203. Production-Readiness Checklist

IAM/security observability SHALL not be considered production-ready until:

- authentication success/failure is auditable;
- MFA and passkey lifecycle is auditable;
- account recovery is auditable;
- session revocation is auditable;
- CP context decisions have structured reason codes;
- decision IDs exist for sensitive authorization decisions;
- canonical identity can correlate cross-system events;
- actor and subject are distinguishable;
- workload actions are attributable;
- privileged actions are auditable;
- break-glass always alerts;
- impersonation preserves actor and subject;
- canonical security events are versioned;
- event producers are authenticated;
- security event streams are access-controlled;
- operational logs and security audit are separated;
- domain audit remains domain-owned;
- secrets are redacted;
- secret-redaction tests pass;
- distributed traces use stable correlation;
- critical security audit does not depend on trace sampling;
- audit retention classes are defined;
- security telemetry access is restricted;
- event ingestion health is monitored;
- revocation lag is measured;
- SIEM integration exists or has a defined implementation path;
- high-value detection rules have owners/runbooks;
- cross-tenant access is observable;
- audit survives application administrator actions;
- incident responders can reconstruct cross-system identity timelines.

---

# 204. Architectural Invariants

The following become binding:

```text
Operational Log ≠ Security Audit

Security Audit ≠ Domain Audit

Canonical Security Event ≠ Log Line

Trace ≠ Complete Audit Record

SIEM ≠ Source of Identity Truth

Email ≠ Canonical Correlation Identifier

Actor ≠ Subject

Application Admin ≠ Audit Admin

Authentication Success ≠ Authorization Success

Authorization Decision ≠ Business Action

Metric ≠ Audit Record

Alert ≠ Authoritative Security State

Anomaly ≠ Proven Compromise

Event Producer ≠ Universal Security Authority

Event Replay ≠ New Security Decision

Sampled Trace ≠ Retained Security Evidence

Secret ≠ Observability Data
```

---

# 205. Decision Summary

Baobab SHALL treat IAM observability as part of the security architecture, not merely an operational convenience.

The platform SHALL distinguish:

```text
WHAT HAPPENED TO THE APPLICATION?
        │
        ▼
Operational Logs

WHO AUTHENTICATED OR CHANGED ACCESS?
        │
        ▼
Security Audit

WHAT BUSINESS ACTION OCCURRED?
        │
        ▼
Domain Audit

WHAT SECURITY STATE MUST OTHER SYSTEMS KNOW?
        │
        ▼
Canonical Security Events

HOW DID THE REQUEST FLOW?
        │
        ▼
Distributed Trace

IS THE PLATFORM HEALTHY OR UNDER ATTACK?
        │
        ▼
Metrics + Detection + Alerts
```

Canonical identifiers, correlation IDs, trace IDs and decision IDs SHALL make cross-system investigations possible without relying on mutable attributes such as email.

Security events SHALL be versioned and emitted only by authoritative producers.

Secrets SHALL never become telemetry.

Privileged operations, break-glass use, identity lifecycle changes, credential changes, revocation and cross-tenant access SHALL receive particularly strong audit treatment.

The governing principle is:

> **Baobab shall make every important identity and authorization decision traceable across the platform, preserve authoritative audit close to the systems that own the action, centralize security visibility without centralizing domain truth, and ensure that observability increases accountability without becoming another source of credential exposure.**