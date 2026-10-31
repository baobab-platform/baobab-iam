# IAM-N05 — durable migration, reconciliation, disable/revoke and rollback

**Status:** implementation proposal; **development evidence and owner review
still required**. EA v2.3 / EA-DEV + accepted
ADR-IAM-0033, ADR-IAM-0022 (only where not superseded),
ADR-IAM-0020, ADR-0016. Source branch IAM #150. No production cutover,
Keycloak global retirement or protected approval.

## Authority and provider boundaries

- **CP** alone owns CanonicalIdentity/Principal and ExternalIdentity
  reconciliation, issuer trust and canonical resource authorization.
  A Keycloak `issuer+subject` may never be mapped to a different
  canonical actor using email, traits, role or a second tenant.
- **Kratos** owns native human identity disable, assurance/recovery and
  all human sessions; **Hydra** owns native OAuth/workload issuance.
  **Keycloak remains** the permanent initial enterprise SAML/OIDC
  federation provider under ADR-IAM-0033. Native migration does not
  globally disable Keycloak or erase federation configuration.
- The previous `internal/migration` Phase C model was **in-memory**.
  N05 adds a PostgreSQL 17 store and owner-side lifecycle safeguards.
  It does not automatically reconfigure legacy production IAM.

## One-time reviewed PostgreSQL 17 installation

DBA/infrastructure installs reviewed
`internal/migration/migrations/001_n05_ledger.sql` against an isolated
PostgreSQL 17 database. Creating `PostgresStore` verifies that schema
exists but never runs DDL itself. Use the approved protected migration
pipeline and independent backup approval for shared environments.
Development/CI runs only in `n05_ci`, loopback PostgreSQL, with
`IAM_N05_DISPOSABLE_PG=1` and the pinned dependency image.

The schema contains *columns*, not arbitrary JSONB credential payloads.
It has no place for passwords, hashes, TOTP, private JWKs, recovery
codes, cookies, access/refresh tokens or OAuth client secrets. It enforces
unique source `(provider,issuer,subject)`, distinct target binding,
immutable canonical id and exact source, revision increments,
append-only history, chronological containment progress and a
nondeletable revocation tombstone. Both the Go store and the SQL
trigger refuse CUTOVER and LEGACY_RETIRED before an independent M18
protected issuer-trust decision.

No migration requires decommissioning the Keycloak enterprise SSO
runtime or changing any CP Principal's tenant/Organisation permissions.

## Repeatable import and reconciliation

Source discovery MUST emit only exact source provider+issuer+subject,
a redacted source artifact reference, and an explicit identity class.
The `CanonicalResolver` must independently resolve that exact tuple
from governed CP ExternalIdentity/Principal—not caller-supplied email.
The `RegisterBatch` id includes the batch and tuple; the PostgreSQL
unique source binding prevents migration of the same external actor
into a second batch/canonical Principal. A rerun resolves CP again,
verifies the source tuple, batch and original snapshot reference, and
returns SKIPPED only for identical source/canonical identity. New CP
mapping, source evidence or duplicate target is a **conflict** requiring
manual review, not automatic remapping.

Crash/replay: a partially completed batch may be retried against the
same source snapshot/batch; committed rows remain intact, pending rows
register once. No transaction creates/revokes provider identities
without a source evidence record. `Service` state transitions use
`revision` optimistic compare and SQL `SELECT ... FOR UPDATE` within a
serializable transaction. Concurrent/stale writers cannot overwrite
each other or silently reset execution states.

Credential provisioning remains separately governed by the existing
`ProvisionBridge` and supported provider-native credential strategy,
not raw credential copies into this ledger.

## Human disable and session containment

`NativeContainment.Contain(ctx,migrationID,operationID)` accepts
one exact, stable operation id for a migrated native human and does the
following, in order:

1. Under serializable DB lock, read the exact legacy and target
   issuer+subject / original canonical Principal. Refuse orphans,
   missing targets, workload classes and legacy-retired rows. Add the
   durable immutable deny fence, create/resume the single operation,
   and quarantine the migration row **before** any provider call.
2. Call the existing real Ory adapter `DisableIdentity` for this exact
   native identity, then independently `GetIdentity` and require
   `StatusDisabled`, same issuer+subject.
3. Call `RevokeSessions` (Kratos Admin DELETE), then independently
   `ActiveSessionCount` via real Kratos Admin
   `GET /admin/identities/{id}/sessions?active=true&page_size=2`;
   exact JSON / identity binding required, and only an **empty**
   active-session page proves zero active sessions. Ambiguous 302,
   non-JSON, missing active/identity binding, failed TLS, incorrect
   issuer or surviving active sessions all block the operation.
4. Require an independent CP/resource `CurrentVetoReader` readback
   proving **both** legacy and native issuer current tokens denied
   for the *same* unchanged canonical Principal. A disabled IdP
   alone is insufficient for already-issued access tokens.
5. Only after all three witnesses report current denial may the
   journal move through `IDENTITY_DISABLED`,
   `SESSIONS_REVOKED`, `CURRENT_TOKENS_DENIED`, `VERIFIED`.
   Source tests use fakes and are explicitly **unattested**.
   The required CP adapter, original issuer/resource tests and
   external evidence custody are not yet demonstrated.

A failed provider call, unknown response or missing CP witness results
in `UNKNOWN`, leaving the deny fence in place. Retrying the **same
operation id** is allowed and never deletes prior history. A different
operation id may not steal that identity. Even if the journal
previously says VERIFIED, a restart/restore must re-read current
disabled status, zero sessions and both current-token denials—stale
VERIFIED evidence cannot resurrect access. The side-effecting disable
and revoke are not reissued on a clean verified readback.

N05 does **not** claim to erase native password, passkey, TOTP or
federated credential material. Those are separate credential-specific
lifecycle and N06 security/assurance processes. N05 containment
blocks authentication and sessions and requires real resource-token
denial independently.

## Reversible abort without resurrection

`RollbackPreCutover` requires the exact affected actor's source-provider fallback, 
the target actor's native binding denied, exact CP Principal unchanged, and preserved
legacy revocations, using an independently operated verifier.
The method does not call provider EnableIdentity, delete source/target
ExternalIdentity, delete migration history, or alter the retained
Keycloak federation runtime. After a containment fence exists,
rollback MUST refuse—restoring an old database image cannot erase
current revocation by mere state-machine transition.

Only Phase C pre-cutover `ROLLED_BACK` is implemented. Production
Keycloak/Ory dual-issuer trust cutover, M18 and legacy retirement
remain externally approved work.

## Original evidence and CI checklist

The new mandatory `iam-n05-postgres17-lifecycle` GitHub Actions job
uses a digest-pinned PostgreSQL 17 test container and runs the
source/SQL and race-negative tests. Required demonstrations include:
exact repeat import, drifted CP mapping denial, duplicate source
across batches, distinct Principals trying to own one native subject,
stale revision rejection, append-only SQL history, source immutability,
post-disable session readback, partial UNKNOWN/retry, same-operation
idempotency, stale VERIFIED after restored sessions/current tokens,
undeletable deny fence, and no authority-restoring rollback.

To certify real N05 development, supplement CI with **original**
private (not synthetic-mock) Keycloak legacy readback, actual Kratos
disable/revoke/list, Hydra/CP source-and-target token denial, two
distinct tenant/canonical Principals, exact source SHAs, original
PostgreSQL migrations and a restore/replay drill. The CP-side
`CurrentVetoReader` must be implemented by its owning authority;
this IAM PR deliberately does not fabricate that result.

**Held:** provider-signed and CP/resource readbacks, original
development run/evidence, independent review, final-head required
CI. Never merge this draft or promote N05/N04 support on source-only
evidence.
