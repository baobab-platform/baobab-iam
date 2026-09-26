# ADR-IAM-0022 — Keycloak-to-Ory Identity Migration, Dual-Issuer Trust and Cutover Architecture

**Status:** Accepted  
**Date:** 2026-09-26  
**Decision Owners:** Baobab Platform Architecture  
**Primary Repository:** `baobab-platform/baobab-iam`  
**Affected Repositories:** `baobab-platform/shared`, `baobab-platform/baobab-cp`, `baobab-platform/infrastructure`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, ZuriBeans, Thamani, Nabhold, and future Digital Estates  
**Depends On:** ADR-IAM-0001 through ADR-IAM-0021  
**Supersedes:** Keycloak-specific migration assumptions where inconsistent with this ADR  
**Extends:** ADR-IAM-0004, ADR-IAM-0006, ADR-IAM-0007, ADR-IAM-0016, ADR-IAM-0017, ADR-IAM-0018, ADR-IAM-0019, ADR-IAM-0020, ADR-IAM-0021  
**Decision Type:** Identity Migration / Security / Cutover / Continuity / Disaster Recovery  
**Source Provider:** Keycloak  
**Target Provider:** Ory Kratos + Ory Hydra  
**Canonical Identity Authority:** Baobab Control Plane

---

# 1. Decision

Baobab SHALL migrate from Keycloak to Ory using a **staged, reversible, identity-preserving migration** rather than a destructive replacement or "big bang" recreation of identities.

The migration SHALL preserve the existing Baobab canonical identity architecture.

The central migration invariant is:

```text
                 CanonicalIdentity
                    CI-000042
                    /       \
                   /         \
                  ▼           ▼
      ExternalIdentity    ExternalIdentity
          Keycloak              Ory
             │                   │
             ▼                   ▼
       issuer + sub        issuer + sub
```

During migration, a single `CanonicalIdentity` MAY therefore have both:

1. a legacy Keycloak `ExternalIdentity`; and
2. a target Ory `ExternalIdentity`.

This SHALL NOT create two people, two workload identities, two buyer representatives, two supplier representatives, or two ERP users.

The migration changes **authentication infrastructure**, not the canonical identity of the actor.

---

# 2. Primary Migration Principle

> **Migrate authentication bindings, credentials and provider state; preserve canonical identity and business state.**

Accordingly:

```text
MIGRATE / REPLACE
────────────────────────────
Keycloak authentication
Keycloak sessions
Keycloak credentials
Keycloak client configuration
Keycloak workload credentials
Keycloak federation configuration
Keycloak provider events
Keycloak-specific IAM configuration

PRESERVE
────────────────────────────
CanonicalIdentity
Tenant
LegalEntity
Market
DigitalEstate
Capability
CapabilityBinding
Context
IsolationProfile
BuyerOrganization
Buyer membership
SupplierOrganization
Supplier approval
Trade commercial authority
ERP AD_User mapping
ERP AD_Role
CMS authorization
canonical audit history
business transactions
```

---

# 3. Context

ADR-IAM-0019 selected Ory as the replacement for Keycloak.

ADR-IAM-0020 established a provider-neutral boundary.

ADR-IAM-0021 established the Ory runtime architecture.

The remaining problem is not simply:

```text
install Ory
```

It is:

```text
How does a production platform change its identity provider
without changing who people are,
without duplicating identities,
without granting unintended authority,
without losing credentials unnecessarily,
without invalidating business history,
without creating indefinite dual trust,
and without losing the ability to recover?
```

This ADR answers that question.

---

# 4. Existing Work Is an Asset

The existing IAM implementation SHALL be audited before migration code is written.

The migration SHALL preferentially reuse already-implemented:

- canonical identity models;
- `ExternalIdentity`;
- issuer/subject mapping;
- workload registry;
- client registry;
- scope registry;
- lifecycle states;
- revocation mechanisms;
- CP context resolution;
- engine mappings;
- audit contracts;
- canonical security events;
- IAM kill switches;
- reconciliation mechanisms;
- CI security controls;
- DR architecture.

Keycloak-specific code SHALL be distinguished from Baobab-owned architecture.

The migration SHALL NOT delete working provider-neutral functionality merely because it was first implemented while Keycloak was the provider.

---

# 5. Migration Boundary

The conceptual boundary is:

```text
                         BAOBAB STATE
                             │
                    CanonicalIdentity
                             │
                   ┌─────────┴─────────┐
                   │                   │
                   ▼                   ▼
           ExternalIdentity     ExternalIdentity
               LEGACY              TARGET
                   │                   │
                   ▼                   ▼
               Keycloak              Ory
                                    /   \
                                   ▼     ▼
                              Kratos    Hydra
```

Provider migration occurs below the canonical identity boundary.

---

# 6. Identity Continuity

A person SHALL retain the same `CanonicalIdentity` across the migration.

Example:

```text
Before
──────

CanonicalIdentity
CI-00125
   │
   ▼
ExternalIdentity
issuer=https://keycloak...
subject=76a...

After migration
───────────────

CanonicalIdentity
CI-00125
   │
   ├── Keycloak ExternalIdentity
   │       status = RETIRED
   │
   └── Ory ExternalIdentity
           status = ACTIVE
```

The canonical ID does not change.

---

# 7. Prohibition on Email-Based Identity Recreation

The migration SHALL NOT use email equality alone to determine canonical identity.

Prohibited:

```text
Keycloak:
alice@example.com
        │
        ▼
"same email"
        │
        ▼
automatically attach Ory identity
```

Email addresses may:

- change;
- be reused;
- be shared;
- differ by case/provider normalization;
- be incorrectly entered;
- represent organizational aliases.

Migration SHALL use an explicit migration mapping and controlled verification.

---

# 8. Migration Identity Mapping

The migration ledger SHALL associate:

```text
source issuer
source subject
        │
        ▼
CanonicalIdentity
        │
        ▼
target issuer
target subject
```

Conceptually:

```json
{
  "canonical_identity_id": "ci_00125",
  "source": {
    "provider": "keycloak",
    "issuer": "https://legacy-id.example/realms/baobab",
    "subject": "76a..."
  },
  "target": {
    "provider": "ory",
    "issuer": "https://identity.example",
    "subject": "9d2..."
  }
}
```

---

# 9. Migration Ledger

`baobab-iam` SHALL maintain an auditable migration ledger.

At minimum:

```text
migration_id
migration_batch_id
canonical_identity_id

source_provider
source_issuer
source_subject

target_provider
target_issuer
target_subject

identity_class
credential_strategy
migration_state
verification_state
cutover_state

source_snapshot_reference
attempt_count
last_error_code

created_at
started_at
verified_at
cutover_at
retired_at
```

Sensitive credential material SHALL NOT be persisted in this ledger.

---

# 10. Migration State Machine

Migration SHALL use explicit states.

```text
DISCOVERED
    │
    ▼
VALIDATED
    │
    ▼
READY
    │
    ▼
PROVISIONING
    │
    ▼
PROVISIONED
    │
    ▼
CREDENTIAL_PENDING
    │
    ▼
CREDENTIAL_READY
    │
    ▼
VERIFICATION_PENDING
    │
    ▼
VERIFIED
    │
    ▼
CUTOVER_READY
    │
    ▼
CUTOVER
    │
    ▼
LEGACY_RETIRED
```

Failure paths SHALL exist from every mutation stage.

---

# 11. Failure States

Examples:

```text
BLOCKED
FAILED_RETRYABLE
FAILED_MANUAL_REVIEW
ROLLED_BACK
QUARANTINED
```

A migration record SHALL never be silently skipped.

---

# 12. Migration Classes

Identities SHALL be classified before migration.

At minimum:

```text
HUMAN
WORKLOAD
PRIVILEGED_HUMAN
BREAK_GLASS
FEDERATED_HUMAN
SERVICE_INTEGRATION
TEST_OR_NONPRODUCTION
ORPHAN_CANDIDATE
```

Different classes require different migration procedures.

---

# 13. Human Identity Migration

For a normal human identity:

```text
Keycloak User
     │
     ▼
validate source identity
     │
     ▼
resolve CanonicalIdentity
     │
     ▼
create Kratos identity
     │
     ▼
migrate/re-enrol credential
     │
     ▼
create Ory ExternalIdentity mapping
     │
     ▼
verify login
     │
     ▼
cut over
```

No new CanonicalIdentity SHALL be created when an authoritative existing mapping exists.

---

# 14. Workload Migration

Workloads SHALL NOT be migrated by treating them as human identities.

The migration is:

```text
Baobab WorkloadIdentity
       │
       ▼
legacy Keycloak client/service identity
       │
       ▼
provision target Hydra OAuth client
       │
       ▼
issue new credential
       │
       ▼
deploy consumer
       │
       ▼
verify target authentication
       │
       ▼
revoke legacy credential
```

---

# 15. Credential Migration Is Separate From Identity Migration

Creating a target identity does not mean its credential is migrated.

Therefore:

```text
Identity provisioned
       ≠
Credential ready
```

and:

```text
Credential ready
       ≠
Migration verified
```

---

# 16. Human Credential Strategies

Each identity SHALL receive an explicit credential migration strategy.

Permitted strategies include:

```text
DIRECT_IMPORT
FIRST_LOGIN_MIGRATION
CONTROLLED_RE_ENROLMENT
FEDERATED_REBIND
PASSKEY_RE_ENROLMENT
MFA_RE_ENROLMENT
NO_CREDENTIAL_REQUIRED
```

The actual supported strategy SHALL be verified against the pinned Ory/Keycloak versions before execution.

---

# 17. Password Migration

Where source password hashes can be safely and correctly imported into Kratos using supported mechanisms, Baobab MAY perform direct password credential migration.

The implementation SHALL verify:

- source hash algorithm;
- parameters;
- encoding;
- salt representation;
- compatibility;
- successful authentication against test fixtures.

No password SHALL be converted to plaintext for migration.

---

# 18. Unsupported Password Credentials

If a credential cannot be safely migrated:

```text
DO NOT
──────
weaken hashing
export plaintext
invent password
share temporary universal password
```

Instead use controlled:

```text
recovery
re-enrolment
first-login migration
```

as supported by the target architecture.

---

# 19. Passkeys and WebAuthn

Passkey/WebAuthn migration SHALL be capability-tested rather than assumed.

Where safe credential import is supported and validated, it MAY be used.

Otherwise the user SHALL re-enrol the authenticator through a controlled flow.

Baobab SHALL prioritize identity continuity over preserving every provider credential object.

---

# 20. TOTP/MFA

Existing TOTP or other MFA credentials SHALL only be imported where:

1. supported by the target provider;
2. security semantics are understood;
3. interoperability is tested;
4. secrets can be handled safely.

Otherwise:

```text
identity migrates
      │
      ▼
MFA_RE_ENROLMENT_REQUIRED
```

---

# 21. Recovery State

Recovery configuration SHALL NOT be copied blindly.

Recovery channels SHALL be revalidated where security policy requires it.

Migration SHALL not allow:

```text
old untrusted recovery address
       │
       ▼
new privileged account recovery
```

without appropriate validation.

---

# 22. Privileged Identities

Privileged identities require stronger migration controls.

Examples:

- CP administrators;
- IAM administrators;
- ERP finance/admin users;
- Trade administrators;
- infrastructure administrators;
- security operators.

Their migration SHOULD require:

```text
source identity validation
+
target identity verification
+
strong MFA/passkey enrolment
+
privilege reconciliation
+
audit review
```

before cutover.

---

# 23. Break-Glass Identities

Break-glass identities SHALL have a separate migration procedure.

At no point SHALL migration eliminate all viable emergency administration.

Conceptually:

```text
Legacy break-glass operational
          │
          ▼
Target break-glass provisioned
          │
          ▼
Target access tested
          │
          ▼
Recovery procedure tested
          │
          ▼
Legacy break-glass retired
```

---

# 24. Federation

Federated identities require explicit migration of federation relationships.

Example:

```text
Enterprise Entra
      │
      ▼
Keycloak federation
```

becomes:

```text
Enterprise Entra
      │
      ▼
Ory-supported federation integration
```

The external enterprise identity is not itself "migrated" in the same sense as a locally credentialed user.

Its Baobab canonical mapping SHALL nevertheless remain continuous.

---

# 25. Provider Organization Data

Keycloak organization/group structures SHALL NOT be automatically recreated as Ory organizations and treated as canonical business relationships.

Before migration, each such object SHALL be classified:

```text
provider administration
identity federation grouping
business organization
tenant-like historical misuse
authorization role
obsolete configuration
```

Business semantics SHALL be migrated to their proper Baobab/domain authority where necessary.

---

# 26. Keycloak Roles

Keycloak roles SHALL be classified before migration.

```text
KEYCLOAK ROLE
     │
     ├── IAM/provider administration?
     │       └── recreate appropriately
     │
     ├── OAuth scope/protocol concern?
     │       └── map to Hydra configuration
     │
     ├── Baobab platform authority?
     │       └── reconcile with CP
     │
     ├── domain authority?
     │       └── reconcile with Trade/ERP/etc.
     │
     └── obsolete?
             └── retire
```

No mechanical "copy all roles to Ory" process is permitted.

---

# 27. Business Authorization Must Not Migrate Through Ory

Example:

```text
Keycloak role:
PURCHASE_APPROVER
```

If historically used for purchasing, migration SHALL NOT simply create an Ory equivalent.

Instead:

```text
CanonicalIdentity
       │
       ▼
BuyerOrganizationMembership
       │
       ▼
Trade Purchase Authority
```

shall be reconciled with Trade.

---

# 28. ERP Continuity

An ERP user's business mapping remains:

```text
CanonicalIdentity
      │
      ▼
ERP ExternalReference / Mapping
      │
      ▼
AD_User
      │
      ▼
AD_Role
```

The IdP migration changes the external authentication binding.

It SHALL NOT recreate `AD_User` merely because the provider subject changes.

---

# 29. ZuriBeans Continuity

Example:

```text
Before:

Keycloak Alice
      │
      ▼
CanonicalIdentity Alice
      │
      ▼
BuyerOrganization ACME
      │
      ▼
Purchaser

After:

Ory Alice
      │
      ▼
SAME CanonicalIdentity Alice
      │
      ▼
SAME BuyerOrganization ACME
      │
      ▼
SAME Purchaser relationship
```

---

# 30. Thamani Continuity

Thamani operates B2B and B2C shipping/logistics journeys.

One human may have:

```text
CanonicalIdentity
       │
       ├── personal/B2C shipping relationship
       │
       ├── Business A representative
       │
       └── Business B representative
```

Migration SHALL preserve those relationships.

The IdP SHALL not duplicate the person for each commercial context.

---

# 31. Supplier Continuity

Supplier representatives SHALL retain supplier-domain relationships independently of provider migration.

```text
Ory identity active
       ≠
supplier approved
```

and:

```text
provider migration
       ≠
supplier re-vetting
```

unless a separate business/security reason requires re-vetting.

---

# 32. Dual-Issuer Trust

During migration, selected resource servers MAY temporarily trust both:

```text
Legacy Keycloak issuer
+
Target Hydra issuer
```

This is **migration infrastructure**, not the steady-state architecture.

---

# 33. Trust Registry

Trusted issuers SHALL be represented explicitly.

Conceptually:

```text
IssuerTrust
├── issuer
├── provider
├── environment
├── status
├── allowed_audiences
├── allowed_clients
├── trust_started_at
├── migration_only
└── trust_expires_at
```

---

# 34. Issuer States

Recommended states:

```text
ACTIVE
MIGRATION_ONLY
SUSPENDED
RETIRED
COMPROMISED
```

Keycloak SHALL progress:

```text
ACTIVE
   │
   ▼
MIGRATION_ONLY
   │
   ▼
RETIRED
```

Ory SHALL progress:

```text
PREPARED
   │
   ▼
ACTIVE
```

---

# 35. Dual Trust Is Not Equal Trust

During migration, Keycloak and Ory SHALL NOT necessarily be permitted to issue tokens for every client/audience.

Example:

```text
Keycloak
   └── permitted legacy clients only

Hydra
   └── migrated/new clients
```

This progressively shrinks the legacy trust surface.

---

# 36. Dual-Issuer Authorization

Both issuers SHALL converge on the same canonical authorization path:

```text
Keycloak token ─┐
                │
                ▼
         issuer + subject
                │
                ▼
         ExternalIdentity
                │
                ▼
        CanonicalIdentity
                │
                ▼
        Context resolution
                │
                ▼
        Domain authorization

Hydra token ────┘
```

There SHALL NOT be:

```text
Keycloak authorization logic
```

versus:

```text
Ory authorization logic
```

for the same Baobab domain operation.

---

# 37. Exact Issuer Validation

Dual issuer support SHALL preserve:

- exact issuer matching;
- signature validation;
- audience validation;
- expiry validation;
- permitted algorithm policy;
- client/scope constraints.

"Accept either provider" SHALL NOT become:

```text
accept any JWT
```

---

# 38. Legacy Issuer Expiry

Every `MIGRATION_ONLY` issuer SHALL have a planned retirement condition and target deadline.

A CI or operational control SHOULD detect migration-only trust remaining beyond the approved window.

---

# 39. Dual Trust Must Be Removable

The architecture SHALL prove that removing Keycloak from trusted issuers does not require changing:

```text
CanonicalIdentity
Tenant
LegalEntity
Market
CapabilityBinding
BuyerOrganization
SupplierOrganization
ERP role mappings
```

---

# 40. Client Migration

OAuth/OIDC clients SHALL migrate individually.

For each client:

```text
discover
   │
   ▼
classify
   │
   ▼
create Hydra equivalent
   │
   ▼
verify redirect URIs/scopes/audiences
   │
   ▼
test
   │
   ▼
switch configuration
   │
   ▼
observe
   │
   ▼
disable Keycloak client
```

---

# 41. No Blind Client Export

Keycloak client configuration SHALL NOT be copied blindly.

Each client SHALL be reviewed for:

- current owner;
- active usage;
- redirect URIs;
- grant types;
- scopes;
- audiences;
- secret age;
- environment;
- legacy/unused callbacks;
- overbroad privileges.

Migration is also a cleanup opportunity.

---

# 42. Provider-Neutral Client Configuration

Applications SHOULD migrate from:

```text
KEYCLOAK_*
```

toward:

```text
BAOBAB_IAM_ISSUER
BAOBAB_IAM_DISCOVERY_URL
BAOBAB_IAM_CLIENT_ID
BAOBAB_IAM_AUDIENCE
```

Provider administrative variables remain confined to provider modules.

---

# 43. Client Secrets

Confidential clients SHALL receive new target-provider credentials.

Keycloak client secrets SHALL NOT be reused merely to reduce migration effort.

The transition is:

```text
legacy secret
     │
     ▼
new Hydra credential
     │
     ▼
deploy consumer
     │
     ▼
verify
     │
     ▼
revoke legacy secret
```

---

# 44. Workload Rotation Pattern

For workloads:

```text
Legacy credential active
         │
         ▼
Create Hydra credential
         │
         ▼
Deploy workload with target config
         │
         ▼
Verify authentication
         │
         ▼
Observe
         │
         ▼
Revoke legacy credential
```

This is a credential rotation/cutover, not merely data migration.

---

# 45. No Shared Migration Secret

There SHALL NOT be one universal migration client secret used by all Baobab services.

Each workload remains independently revocable.

---

# 46. Sessions Are Ephemeral Provider State

Baobab SHALL NOT require active Keycloak login sessions to become active Kratos sessions.

In general:

```text
Keycloak session
      ✕
Kratos session
```

Users MAY be required to authenticate with Ory after their cohort cutover.

This is preferable to attempting unsafe session transplantation.

---

# 47. User Experience

Migration SHOULD minimize unnecessary disruption, but security takes precedence over invisible migration.

Users MAY encounter:

- reauthentication;
- MFA re-enrolment;
- passkey re-enrolment;
- recovery verification.

Such steps SHALL be communicated clearly where applicable.

---

# 48. Cohort-Based Migration

Migration SHALL occur in cohorts.

Suggested order:

```text
0. synthetic/test identities
1. IAM engineering identities
2. non-privileged internal workforce
3. selected low-risk external identities
4. Digital Estate pilot cohorts
5. general B2C identities
6. B2B representatives
7. privileged business users
8. high-risk administrators
9. remaining workloads/integrations
10. legacy exceptions
```

Actual sequencing SHALL follow repository/state discovery and risk analysis.

---

# 49. Why Not Privileged Users First

Privileged users provide useful tests but also carry the highest blast radius.

A small IAM engineering cohort MAY migrate early.

Broad privileged migration SHALL occur only after lower-risk paths demonstrate stability.

---

# 50. B2C and B2B Need Different Validation

Thamani B2C migration should validate:

```text
registration
login
recovery
verification
passkey/MFA
personal shipping account continuity
order/shipment history
```

Thamani B2B should additionally validate:

```text
business representation
organization switching
business shipment authority
approval boundaries
```

ZuriBeans should validate:

```text
buyer organization membership
purchasing authority
RFQ/quotation access
order visibility
approval authority
```

---

# 51. Cohort Feature Flagging

Where appropriate, migration MAY use a controlled identity-provider routing decision.

Conceptually:

```text
User / client
      │
      ▼
Migration cohort?
   /       \
 NO        YES
 │          │
 ▼          ▼
Keycloak    Ory
```

This routing SHALL not become permanent business logic.

---

# 52. Routing Authority

Provider routing SHALL be determined by trusted migration configuration.

It SHALL NOT be accepted from an arbitrary browser parameter such as:

```text
?idp=keycloak
```

for protected production decisions.

---

# 53. Shadow Provisioning

Baobab MAY provision Ory identities before authentication cutover.

```text
Keycloak remains login authority
          │
          ▼
Ory identity pre-provisioned
          │
          ▼
ExternalIdentity prepared
          │
          ▼
not yet active for login
```

This can reduce cutover risk.

---

# 54. Shadow Provisioning Does Not Grant Authority

Pre-provisioning an Ory identity SHALL NOT create new business access.

Authority continues to derive from existing canonical/domain state.

---

# 55. Migration Validation

Before an identity is marked `VERIFIED`, the migration SHALL validate relevant invariants.

For humans:

```text
source mapping exists
target identity exists
same CanonicalIdentity
credential strategy complete
target authentication works
CP resolves target issuer+subject
context remains correct
domain authority remains correct
```

---

# 56. Workload Validation

For workloads:

```text
Hydra client exists
credential works
audience correct
scopes correct
CP resolves workload
capabilities correct
wrong audience denied
revoked credential denied
```

---

# 57. Verification Is End-to-End

This is insufficient:

```text
Ory login succeeded
```

Required:

```text
Ory login succeeded
       │
       ▼
token valid
       │
       ▼
ExternalIdentity resolves
       │
       ▼
CanonicalIdentity resolves
       │
       ▼
Context resolves
       │
       ▼
expected domain operation succeeds
       │
       ▼
forbidden operation still fails
```

---

# 58. Negative Verification

Every migration cohort SHALL test not only what users can do but what they **cannot** do.

Examples:

```text
wrong tenant → DENY
wrong buyer organization → DENY
wrong market context → DENY
wrong audience → DENY
suspended CanonicalIdentity → DENY
revoked workload → DENY
unauthorized ERP role → DENY
```

---

# 59. Authorization Diff Testing

Where feasible, Baobab SHOULD compare pre- and post-migration authorization outcomes.

Conceptually:

```text
Identity X + Context Y + Operation Z

Keycloak-era expected result
             │
             ▼
          ALLOW/DENY
             │
         compare
             │
             ▼
Ory-era result
```

Unexpected authorization expansion SHALL block migration.

---

# 60. Fail Closed on Ambiguous Mapping

If the migration discovers:

```text
one source identity
       │
       ├── possible CanonicalIdentity A
       └── possible CanonicalIdentity B
```

it SHALL NOT guess.

State:

```text
FAILED_MANUAL_REVIEW
```

or:

```text
QUARANTINED
```

shall be used.

---

# 61. Duplicate Detection

Migration SHALL detect:

```text
one Keycloak identity → multiple canonical identities
multiple Keycloak identities → unexpected same canonical identity
one canonical identity → conflicting target identities
duplicate provider subjects
duplicate migration ledger entries
```

before cutover.

---

# 62. Orphan Detection

An identity existing in Keycloak without a valid canonical mapping SHALL be classified.

It SHALL not automatically become a production Ory identity.

Possible outcomes:

```text
map
archive
quarantine
ignore nonproduction
manual review
```

---

# 63. Dormant Identities

Long-dormant identities SHOULD be reviewed before migration.

Migrating every historical identity indefinitely increases attack surface.

Dormant identities MAY require:

```text
reverification
recovery
manual reactivation
```

rather than automatic activation.

---

# 64. Disabled Identities

A disabled Keycloak identity SHALL NOT become an active Ory identity by default.

Migration must preserve restrictive state.

General security rule:

> When source and target state disagree during migration, do not silently choose the more permissive state.

---

# 65. Suspended CanonicalIdentity

If CP says:

```text
CanonicalIdentity = SUSPENDED
```

successful Ory authentication SHALL still result in Baobab denial.

This SHALL be explicitly tested.

---

# 66. Revocation Precedence

The most restrictive authoritative state SHALL prevail during migration.

Example:

```text
Keycloak user = ACTIVE
Ory identity = ACTIVE
CP identity = DISABLED

RESULT = DENY
```

---

# 67. Event Migration

During coexistence:

```text
Keycloak events ─┐
                 │
                 ▼
             baobab-iam
                 │
                 ▼
       canonical IAM events
                 ▲
                 │
Ory events ──────┘
```

Consumers SHALL remain provider-neutral.

---

# 68. Provider Event Deduplication

Equivalent events from two providers during migration SHALL not produce harmful duplicate effects.

Normalization SHALL use:

```text
provider event ID
canonical identity
event type
timestamp
migration state
idempotency controls
```

---

# 69. Event Provenance

Canonical events SHALL preserve provider provenance for audit:

```json
{
  "source": {
    "component": "baobab-iam",
    "provider": "ory"
  }
}
```

without making downstream behavior provider-specific.

---

# 70. Reconciliation During Migration

Migration requires three-way reconciliation:

```text
             Canonical State
                  /    \
                 /      \
                ▼        ▼
          Keycloak      Ory
```

Security-sensitive mismatches SHALL be surfaced.

---

# 71. Example Drift

```text
CP:
DISABLED

Keycloak:
DISABLED

Ory:
ACTIVE
```

Result:

```text
security drift
     │
     ▼
CP continues DENY
     │
     ▼
disable Ory identity
     │
     ▼
audit
```

---

# 72. Another Drift Example

```text
CP:
ACTIVE

Keycloak:
ACTIVE

Ory:
identity missing
```

If the cohort is not cut over:

```text
migration incomplete
```

If already cut over:

```text
production incident
```

Severity therefore depends on migration state.

---

# 73. Migration Source of Truth

The migration ledger records migration progress.

It does NOT become the source of truth for identity.

Authorities remain:

```text
Canonical identity       → CP
Provider credential      → current provider
Workload meaning         → Baobab workload registry
Trade authority          → Trade
ERP authority            → iDempiere
Supplier approval        → supplier domain
Migration progress       → migration ledger
```

---

# 74. Cutover Unit

Cutover SHALL be possible at several controlled units:

```text
identity
cohort
application/client
workload
Digital Estate
environment
```

Baobab SHALL avoid a single irreversible platform-wide switch.

---

# 75. Cutover Preconditions

A cohort SHALL not cut over until:

- target identities are provisioned;
- required credentials are ready;
- target login succeeds;
- canonical mappings resolve;
- positive tests pass;
- negative tests pass;
- audit/events function;
- observability is active;
- rollback remains available;
- no unresolved critical security drift exists.

---

# 76. Cutover Flow

```text
Migration cohort READY
        │
        ▼
freeze cohort mapping changes where necessary
        │
        ▼
final reconciliation
        │
        ▼
activate Ory routing
        │
        ▼
authenticate through Ory
        │
        ▼
verify CP/context/domain
        │
        ▼
observe
        │
    ┌───┴────┐
    ▼        ▼
 healthy   unhealthy
    │          │
    ▼          ▼
continue    rollback
```

---

# 77. Rollback Principle

Rollback SHALL be designed before cutover.

> A migration is not safely reversible merely because the old containers still exist.

Rollback requires:

- legacy provider availability;
- legacy issuer trust where required;
- legacy client configuration;
- source identity integrity;
- migration ledger state;
- credential implications understood;
- routing mechanism;
- audit.

---

# 78. Rollback Scope

Rollback SHOULD be scoped to the smallest safe unit.

Prefer:

```text
cohort rollback
```

over:

```text
entire platform rollback
```

where technically safe.

---

# 79. Rollback Does Not Delete Ory Identity

A rolled-back identity MAY retain its Ory mapping in a non-active migration state.

Example:

```text
CanonicalIdentity
├── Keycloak ExternalIdentity = ACTIVE/MIGRATION
└── Ory ExternalIdentity      = PREPARED/ROLLED_BACK
```

This preserves forensic and migration continuity.

---

# 80. Rollback Security

Rollback SHALL NOT reactivate:

- disabled identities;
- revoked workloads;
- removed memberships;
- expired privileges;
- compromised credentials.

Migration rollback is not security-state rollback.

---

# 81. Security State Is Monotonic Where Required

Certain security actions SHALL survive migration and rollback.

For example:

```text
identity revoked
workload revoked
privilege removed
issuer compromised
```

shall not be undone by restoring an older provider snapshot.

---

# 82. Database Backup Interaction

Migration SHALL coordinate with ADR-IAM-0018/0021 backup procedures.

Before material cutover:

```text
verify backups
      │
      ▼
record migration checkpoint
      │
      ▼
execute migration
```

But backups SHALL not be treated as the only rollback mechanism.

---

# 83. Provider Database Restoration

Restoring an Ory database to an earlier point SHALL trigger migration/security reconciliation before full service resumes.

Otherwise:

```text
revoked state
       │
       ▼
may be resurrected
```

---

# 84. Migration Checkpoints

Migration SHOULD create logical checkpoints such as:

```text
PRE_PROVISION
POST_PROVISION
POST_CREDENTIAL
PRE_CUTOVER
POST_CUTOVER
PRE_LEGACY_RETIREMENT
```

These support audit and recovery.

---

# 85. Audit Requirements

Every migration mutation SHALL be attributable.

Record:

```text
migration ID
batch/cohort
actor/workload
canonical identity
source provider
target provider
action
outcome
reason
correlation ID
timestamp
```

Do not record credential secrets.

---

# 86. Migration Metrics

Monitor:

```text
identities discovered
identities validated
identities provisioned
credentials migrated
re-enrolments required
verified identities
cutover identities
rollback count
failed migrations
quarantined identities
orphan identities
duplicate mappings
login failure rate
authorization-diff failures
```

---

# 87. Migration Dashboard

Operations SHOULD be able to answer:

```text
How many remain on Keycloak?

How many have Ory identities?

How many are verified?

How many are cut over?

How many failed?

How many need manual intervention?

Which legacy clients remain?

Which workloads still use Keycloak?

Can Keycloak be retired yet?
```

---

# 88. Privacy

Migration tooling SHALL minimize identity data.

Exports SHALL:

- contain only required fields;
- be encrypted;
- be access-controlled;
- have defined retention;
- be deleted after the migration retention requirement expires.

---

# 89. No Long-Lived Keycloak Dumps

Full Keycloak exports containing sensitive identity data SHALL NOT become permanent project artifacts.

They SHALL not be committed to Git.

---

# 90. Migration Environment

Migration SHALL first be rehearsed using non-production or appropriately sanitized representative data.

A production migration SHALL not be the first complete execution of the migration tooling.

---

# 91. Synthetic Test Identities

A permanent synthetic migration suite SHOULD include examples for:

```text
password user
passkey user
MFA user
federated user
disabled user
multi-context user
B2B representative
B2C customer
supplier representative
ERP user
privileged administrator
workload
revoked workload
```

---

# 92. Migration Dry Run

Tooling SHALL support a dry-run mode where practical.

Dry run SHOULD report:

```text
would create
would map
would skip
would quarantine
would require re-enrolment
would conflict
```

without mutating target production state.

---

# 93. Idempotency

Migration commands SHALL be safely restartable.

This sequence:

```text
migrate identity
      │
      ▼
Ory created
      │
      ▼
network failure
      │
      ▼
retry
```

must not create a second target identity.

---

# 94. Batch Resumption

Large migration jobs SHALL checkpoint progress.

A failure at identity 40,001 SHALL not require restarting 40,000 successful migrations.

---

# 95. Bounded Concurrency

Migration SHALL use bounded concurrency to avoid:

- provider rate exhaustion;
- database overload;
- excessive event storms;
- downstream reconciliation overload.

---

# 96. Migration APIs and Tools

Migration code SHOULD reside within the provider/migration boundary of `baobab-iam`.

Conceptually:

```text
baobab-iam/
└── internal/
    └── migration/
        ├── discovery/
        ├── mapping/
        ├── credentials/
        ├── workloads/
        ├── verification/
        ├── reconciliation/
        ├── cutover/
        └── rollback/
```

Provider-specific translation remains under provider-specific packages.

---

# 97. No Domain Migration Logic in Estates

ZuriBeans or Thamani SHALL NOT contain code such as:

```text
if keycloak_user:
    migrate_to_ory()
```

Digital Estates consume the configured identity architecture.

Migration belongs to IAM/control infrastructure.

---

# 98. No Migration Logic in Trade

Trade SHALL not own provider migration.

Trade participates only in:

- domain mapping verification;
- authorization verification;
- customer/buyer relationship continuity.

---

# 99. No Migration Logic in ERP

ERP SHALL not migrate Keycloak identities itself.

ERP verifies continuity from:

```text
CanonicalIdentity
     │
     ▼
existing ERP mapping
     │
     ▼
AD_User
```

---

# 100. API Compatibility

During dual-provider migration, APIs SHALL continue consuming provider-neutral principal/context contracts.

Provider-specific claims SHALL not become temporary dependencies.

Temporary dependencies have a habit of becoming permanent architecture.

---

# 101. Claim Normalization

Where Keycloak and Hydra emit different claims, the trusted authentication layer MAY normalize them into Baobab's principal contract.

Example:

```text
Keycloak claims ─┐
                 ├──► Principal v1
Hydra claims ────┘
```

But normalization SHALL not fabricate domain authority.

---

# 102. Scope Migration

Keycloak scopes SHALL be compared with the canonical Baobab scope registry.

Only approved scopes SHALL be recreated in Hydra.

Migration SHALL remove obsolete or overbroad scopes rather than perpetuate them.

---

# 103. Audience Migration

Audience semantics SHALL be explicitly tested.

A token that was accidentally accepted across several engines under Keycloak SHALL not be reproduced as a "compatibility requirement."

The migration SHALL preserve intended behavior, not security defects.

---

# 104. Configuration Compatibility

Applications SHALL progressively move to provider-neutral configuration established by ADR-IAM-0020.

Example:

```text
OLD

KEYCLOAK_URL
KEYCLOAK_REALM
KEYCLOAK_CLIENT_ID

TARGET

BAOBAB_IAM_ISSUER
BAOBAB_IAM_DISCOVERY_URL
BAOBAB_IAM_CLIENT_ID
BAOBAB_IAM_AUDIENCE
```

---

# 105. Compatibility Layer Lifetime

Any Keycloak compatibility adapter SHALL have:

- owner;
- purpose;
- consumers;
- deprecation status;
- removal criterion.

No compatibility shim SHALL remain indefinitely without review.

---

# 106. Keycloak Freeze

Before final migration, Keycloak configuration SHALL enter a controlled change state.

Nonessential changes to:

```text
clients
scopes
roles
federation
identity policies
```

SHOULD be frozen or synchronized through the migration process.

Otherwise source and target drift continuously.

---

# 107. Emergency Changes During Freeze

Security-critical Keycloak changes remain permitted.

They SHALL be:

```text
recorded
     │
     ▼
propagated/reconciled
     │
     ▼
verified in Ory
```

where relevant.

---

# 108. Final Reconciliation

Before Keycloak retirement, perform a final reconciliation of:

```text
human identities
privileged identities
workloads
OAuth clients
trusted issuers
active applications
federation
disabled identities
revoked workloads
unresolved mappings
migration exceptions
```

---

# 109. Keycloak Retirement Criteria

Keycloak SHALL NOT be retired merely because "most users migrated."

All mandatory retirement conditions SHALL be satisfied.

At minimum:

- no required application uses Keycloak for new authentication;
- no required workload uses Keycloak credentials;
- Ory login flows are production-proven;
- required credentials migrated or users re-enrolled;
- CP resolves Ory identities correctly;
- domain authorization tests pass;
- privileged identities migrated;
- break-glass tested;
- required federation migrated;
- Keycloak migration-only issuer trust removable;
- unresolved exceptions formally dispositioned;
- rollback window completed;
- security reconciliation clean;
- audit records retained;
- backups/archives handled under retention policy.

---

# 110. Retirement Decision Flow

```text
All cohorts migrated?
        │
       NO
        │
        └── continue migration

       YES
        │
        ▼
All workloads migrated?
        │
       NO
        └── continue

       YES
        │
        ▼
All privileged paths tested?
        │
       NO
        └── block retirement

       YES
        │
        ▼
Dual issuer removable?
        │
       NO
        └── investigate dependencies

       YES
        │
        ▼
Rollback observation period complete?
        │
       NO
        └── observe

       YES
        │
        ▼
Final reconciliation clean?
        │
       NO
        └── remediate

       YES
        │
        ▼
RETIRE KEYCLOAK
```

---

# 111. Retirement Is Staged

Keycloak retirement SHOULD progress:

```text
ACTIVE
  │
  ▼
MIGRATION_ONLY
  │
  ▼
NO_NEW_USERS
  │
  ▼
NO_NEW_SESSIONS
  │
  ▼
READ_ONLY / ARCHIVAL WINDOW
  │
  ▼
OFFLINE
  │
  ▼
DECOMMISSIONED
```

Exact operational modes depend on implementation capability.

---

# 112. Removal of Legacy Issuer

After retirement:

```text
trusted issuers:
    Ory/Hydra     ACTIVE
    Keycloak      RETIRED
```

Resource servers SHALL reject newly presented legacy Keycloak tokens once the approved validation window expires.

---

# 113. Remove Legacy Secrets

After the rollback/retention window:

- Keycloak client secrets SHALL be revoked;
- obsolete service credentials SHALL be destroyed;
- obsolete administrative credentials SHALL be revoked;
- secret-manager entries SHALL be retired according to policy.

---

# 114. Remove Legacy Network Paths

After decommissioning:

```text
Internet → Keycloak
internal services → Keycloak
migration tooling → Keycloak
```

SHALL be removed unless archival access is explicitly required.

---

# 115. Legacy Data Retention

Keycloak data required for:

- legal retention;
- audit;
- incident investigation;
- migration evidence

MAY be retained securely.

Retained data SHALL not imply an active authentication service.

---

# 116. Provider-Neutrality Proof

After retirement, run a repository-wide architectural check for:

```text
KEYCLOAK_
keycloak_user_id
keycloak_role
realm-specific business assumptions
Keycloak URLs
Keycloak libraries
Keycloak-specific claims
```

Each remaining occurrence SHALL be classified as:

```text
historical documentation
migration archive
intentional compatibility record
defect
```

Production runtime coupling SHALL be removed.

---

# 117. Ory Coupling Audit

The same exercise SHALL search for inappropriate new Ory coupling:

```text
ory_identity_id
kratos_identity_id
hydra_client_id
Ory organization used as Tenant
Ory role used as domain role
```

Migration succeeds architecturally only if Keycloak coupling is not replaced with Ory coupling.

---

# 118. CI Guardrails

CI SHOULD introduce architecture checks preventing reintroduction of prohibited provider-specific canonical fields.

Provider modules and migration tooling remain valid exceptions.

---

# 119. Migration Security Gates

A migration PR SHALL NOT merge merely because functional tests pass.

Relevant gates include:

```text
identity continuity
credential security
authorization non-expansion
issuer isolation
audience isolation
negative tests
event integrity
reconciliation
rollback
audit
secret scanning
```

---

# 120. Migration Gate Sequence

Implementation SHOULD proceed approximately as follows.

## IAM-M0 — Discovery and Inventory

Inventory:

```text
Keycloak users
credentials
clients
scopes
roles
groups/org structures
federation
workloads
sessions
provider-specific code
provider-specific configuration
```

Map each to its target authority.

---

## IAM-M1 — Canonical Mapping Audit

Verify:

```text
Keycloak issuer + subject
        │
        ▼
ExternalIdentity
        │
        ▼
CanonicalIdentity
```

Resolve duplicates/orphans before bulk migration.

---

## IAM-M2 — Migration Ledger

Implement:

- migration states;
- cohorts;
- idempotency;
- audit;
- checkpoints;
- dry run.

---

## IAM-M3 — Ory Provisioning

Provision target identities without changing authentication routing.

---

## IAM-M4 — Credential Strategy

Implement and test:

- password import where supported;
- re-enrolment;
- MFA migration;
- passkey strategy;
- recovery strategy.

---

## IAM-M5 — Workload Migration

Provision Hydra clients and rotate workloads.

---

## IAM-M6 — Dual-Issuer Trust

Introduce tightly constrained:

```text
Keycloak + Hydra
```

trust.

---

## IAM-M7 — End-to-End Verification

Test CP and domain continuity.

---

## IAM-M8 — Pilot Cohort

Cut over selected low-risk identities.

Observe and remediate.

---

## IAM-M9 — Digital Estate Cohorts

Progressively migrate ZuriBeans, Thamani and other estate populations.

---

## IAM-M10 — Privileged Cohorts

Migrate high-risk workforce and administrative identities under enhanced controls.

---

## IAM-M11 — Final Reconciliation

Resolve all remaining:

```text
orphans
duplicates
legacy clients
legacy workloads
federation
security drift
```

---

## IAM-M12 — Keycloak Retirement

Remove new authentication and legacy trust progressively.

---

## IAM-M13 — Post-Retirement Hardening

Remove:

```text
legacy libraries
legacy environment variables
legacy secrets
legacy routes
compatibility shims
obsolete documentation
```

and rerun provider-neutrality fitness tests.

---

# 121. Pull Request Discipline

Because the migration crosses repositories, implementation SHOULD use small coordinated PRs rather than one giant migration branch.

For example:

```text
PR 1  — migration inventory/ledger
PR 2  — CP dual external identity support
PR 3  — Ory human provisioning
PR 4  — credential migration
PR 5  — Hydra workload provisioning
PR 6  — issuer registry/dual trust
PR 7  — ZuriBeans integration
PR 8  — Thamani integration
PR 9  — ERP/CMS workforce integration
PR 10 — Keycloak retirement
```

Exact decomposition SHALL follow actual repository state.

Existing open PRs SHALL be audited before overlapping implementation begins.

---

# 122. Rollout Evidence

Every migration gate SHOULD produce evidence such as:

```text
test output
migration counts
security test results
authorization diffs
reconciliation report
rollback test
observability screenshot/report
ADR traceability
```

"PR merged" alone is not evidence that an identity migration is safe.

---

# 123. Migration Traceability

Implementation SHOULD maintain:

| Requirement | ADR | Repository | Implementation | Test | Status |
|---|---|---|---|---|---|
| Canonical identity continuity | 0022 | CP/IAM | mapping | migration test | — |
| Ory provisioning | 0020/0022 | IAM | adapter | contract test | — |
| dual issuer | 0006/0022 | CP/engines | trust registry | security test | — |
| workload migration | 0007/0022 | IAM | Hydra adapter | M2M test | — |
| rollback | 0018/0022 | IAM/infra | cutover controller | DR test | — |
| Keycloak retirement | 0019/0022 | polyrepo | cleanup | fitness test | — |

---

# 124. Production Acceptance Scenarios

At minimum, migration SHALL demonstrate:

### Scenario A — Existing B2C identity

```text
Keycloak user
   ↓
Ory migration
   ↓
same CanonicalIdentity
   ↓
Thamani login
   ↓
existing B2C shipping history accessible
```

---

### Scenario B — B2B representative

```text
Keycloak user
   ↓
Ory
   ↓
same CanonicalIdentity
   ↓
Company A
Company B
   ↓
correct company-context switching
```

---

### Scenario C — ZuriBeans purchaser

```text
Ory authentication
   ↓
CanonicalIdentity
   ↓
existing BuyerOrganization membership
   ↓
purchase authority unchanged
```

---

### Scenario D — Suspended identity

```text
valid Ory authentication
   ↓
CP CanonicalIdentity = SUSPENDED
   ↓
DENY
```

---

### Scenario E — Workload

```text
Trade
   ↓
Hydra client_credentials
   ↓
CP WorkloadIdentity
   ↓
expected capability
```

Wrong audience:

```text
DENY
```

---

### Scenario F — ERP workforce

```text
Ory authentication
   ↓
CanonicalIdentity
   ↓
existing ERP mapping
   ↓
same AD_User
   ↓
same permitted AD_Role
```

---

### Scenario G — Rollback

```text
cohort switched to Ory
   ↓
critical problem
   ↓
cohort routing rollback
   ↓
Keycloak available
   ↓
no canonical identity duplication
   ↓
no revoked privilege resurrected
```

---

### Scenario H — Provider retirement

```text
Keycloak token after retirement
        ↓
issuer = RETIRED
        ↓
DENY
```

---

# 125. Definition of Done

ADR-IAM-0022 is implemented when:

- all production Keycloak identities are inventoried or formally dispositioned;
- canonical mapping integrity is verified;
- migration ledger exists;
- migration is idempotent/resumable;
- Ory identities map to existing CanonicalIdentity records;
- credentials have supported migration/re-enrolment paths;
- workloads have been rotated to Hydra;
- dual-issuer trust is constrained and time-bound;
- positive and negative authorization tests pass;
- ZuriBeans continuity is verified;
- Thamani B2B and B2C continuity is verified;
- ERP/CMS workforce continuity is verified;
- supplier relationships remain intact;
- privileged identities are verified;
- break-glass access is tested;
- rollback is demonstrated;
- provider events normalize correctly;
- reconciliation detects migration drift;
- no security revocation is resurrected;
- Keycloak clients are retired;
- Keycloak issuer is retired;
- legacy secrets are revoked;
- provider-neutrality fitness tests pass.

---

# 126. Final Migration Architecture

```text
                         MIGRATION PERIOD
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│        KEYCLOAK                               ORY                  │
│     legacy provider                      target provider           │
│          │                               ┌─────┴─────┐             │
│          │                               ▼           ▼             │
│          │                            Kratos       Hydra            │
│          │                               │           │             │
│          └──────────────┬────────────────┴───────────┘             │
│                         │                                          │
│                         ▼                                          │
│                 ┌───────────────────┐                              │
│                 │    baobab-iam     │                              │
│                 │                   │                              │
│                 │ migration ledger  │                              │
│                 │ adapters          │                              │
│                 │ lifecycle         │                              │
│                 │ reconciliation    │                              │
│                 │ normalized events │                              │
│                 └─────────┬─────────┘                              │
│                           │                                        │
│                           ▼                                        │
│                 ┌───────────────────┐                              │
│                 │    baobab-cp      │                              │
│                 │                   │                              │
│                 │ CanonicalIdentity │                              │
│                 │ ExternalIdentity  │                              │
│                 │ Context           │                              │
│                 └─────────┬─────────┘                              │
│                           │                                        │
│             ┌─────────────┼─────────────┐                          │
│             ▼             ▼             ▼                          │
│           Trade          ERP           CMS                         │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘


                         STEADY STATE
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│                         ORY                                        │
│                   ┌──────┴──────┐                                 │
│                   ▼             ▼                                  │
│                Kratos         Hydra                                │
│                   └──────┬──────┘                                 │
│                          ▼                                         │
│                    baobab-iam                                     │
│                          │                                         │
│                          ▼                                         │
│                    baobab-cp                                      │
│                          │                                         │
│                 ┌────────┼────────┐                                │
│                 ▼        ▼        ▼                                │
│               Trade     ERP      CMS                               │
│                                                                    │
│ Keycloak: RETIRED                                                  │
│ Keycloak issuer: NOT TRUSTED                                       │
│ Keycloak credentials: REVOKED                                      │
│ Canonical identity: PRESERVED                                      │
│ Business authorization: PRESERVED                                  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

# 127. Final Invariants

Throughout migration and after cutover:

```text
Keycloak User ≠ CanonicalIdentity

Kratos Identity ≠ CanonicalIdentity

Provider Migration ≠ Identity Recreation

Provider Migration ≠ Business Relationship Migration

Provider Migration ≠ Authorization Migration

Email Equality ≠ Identity Equality

Successful Ory Login ≠ Baobab Authorization

Dual Issuer ≠ Unlimited Trust

Rollback ≠ Security-State Rollback

Provider Database Restore ≠ Authorization Restore

Keycloak Role ≠ Ory Role ≠ Domain Role

Hydra Client ≠ Canonical WorkloadIdentity

Migration Ledger ≠ Identity Authority

Ory Organization ≠ Tenant

Ory Organization ≠ BuyerOrganization

Ory Organization ≠ SupplierOrganization
```

---

# 128. Final Decision Principle

Baobab SHALL migrate from Keycloak to Ory by changing the **external authentication binding around an existing canonical identity**, not by rebuilding identity and authorization around Ory.

The desired transformation is:

```text
             BEFORE

        Keycloak Subject
               │
               ▼
        ExternalIdentity
               │
               ▼
       CanonicalIdentity
               │
               ▼
      Baobab Business State


             MIGRATION

        Keycloak Subject
               │
               ▼
       ExternalIdentity A
               │
               ▼
       CanonicalIdentity
               ▲
               │
       ExternalIdentity B
               ▲
               │
           Ory Subject


             AFTER

           Ory Subject
               │
               ▼
        ExternalIdentity
               │
               ▼
       CanonicalIdentity
               │
               ▼
      SAME Business State
```

The successful migration is therefore not measured merely by whether Ory can authenticate users.

It is measured by whether Baobab can replace its identity provider while preserving:

- who the actor is;
- which organization or organizations the actor represents;
- which tenant, legal entity, market and Digital Estate contexts are valid;
- which capabilities are granted;
- which business operations remain permitted or prohibited;
- existing ERP and Trade relationships;
- security revocations;
- audit continuity;
- workload isolation;
- recovery capability.

Keycloak SHALL remain available only for the bounded migration and rollback period required to establish those properties.

Once the retirement criteria are satisfied, Keycloak SHALL be removed from active trust.

> **We migrate the provider. We do not migrate the meaning of identity.**