# IAM Disaster Recovery Runbook

**Governing ADR:** `ADR-0018 — IAM Availability, Backup, Recovery and Disaster Resilience` §90-93, §215
**Current multi-provider recovery:** Restore the retained Keycloak broker, Kratos,
Hydra and IAM federation authority as separate failure domains. For PostgreSQL
shared federation state, follow [shared-state recovery](federation-shared-storage.md)
before serving traffic: externally advance the recovery epoch, invalidate
restored live authority and obtain fresh approvals. Local bbolt is bounded
staging storage. Cloud failover and measured RPO/RTO remain unaccepted.

**Owner of this document:** `baobab-platform/baobab-iam` (per §215's ownership table, jointly with `baobab-platform/infrastructure`)

This runbook exists because ADR-0018 §90 requires one ("`baobab-platform/baobab-iam` and/or
`baobab-platform/infrastructure` SHALL maintain a version-controlled DR runbook") and none
existed before Gate IAM-14. It documents the 17-step recovery sequence from §91
against what this repository actually owns today, not an aspirational full
recovery procedure — steps this repository does not own are marked as such and
point to `baobab-platform/infrastructure` rather than describing infrastructure this
repository has no visibility into.

Per §89, only authorized operations/security roles SHALL initiate production IAM
disaster recovery — this document assumes that decision has already been made
(§88, "DR Authority" / "Disaster Declaration") by the time anyone is executing it.

Per §92-93, **a successful Keycloak startup after restore is not the same as
"safe to serve production."** Every step below runs before traffic reopens.

---

## Recovery sequence

| # | Step (ADR-0018 §91) | Owner | What `baobab-iam` actually provides |
|---|---|---|---|
| 1 | Contain incident | Operations/Security | Not this repo. |
| 2 | Determine trusted recovery point | Infrastructure + Security | Not this repo — backup/PITR tooling is `baobab-platform/infrastructure`-owned (§215). |
| 3 | Restore infrastructure dependencies | Infrastructure | Not this repo. |
| 4 | Restore PostgreSQL | Infrastructure | Not this repo — database HA/backup/PITR is `baobab-platform/infrastructure`-owned (§215). |
| 5 | Restore cryptographic/secrets dependencies | Infrastructure | Not this repo — secret management is `baobab-platform/infrastructure`-owned (§215). |
| 6 | Deploy pinned runtimes | `baobab-iam` + Infrastructure | Retained Keycloak `26.7.5`, digest `sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85`, is pinned by `upstream.lock.yaml` and checked against the Dockerfile/registry by `scripts/keycloak-baseline.sh`. Kratos/Hydra pins remain in `provider.lock.yaml`. Verify the accepted release artifact before restore; a repository pin does not prove the deployed version. |
| 7 | Validate database/schema | Infrastructure | Not this repo. |
| 8 | Validate realm/client configuration | **`baobab-iam`** | `make bootstrap` re-applies `config/realm/baobab-realm.json` and `config/clients/*.json`/`config/scopes/*.json` to fill missing objects; existing objects require explicit drift comparison and correction (see procedure below). |
| 9 | Validate signing/JWKS | **`baobab-iam`** + Infrastructure | `tests/integration/run.sh` §2-3 (OIDC discovery + JWKS retrieval) prove the restored realm is issuing discoverable, verifiable tokens. Key material itself is Infrastructure-owned secrets/PKI. |
| 10 | Apply post-backup security changes | `baobab-cp` + `baobab-iam` | For federation authority, the [shared-state recovery procedure](federation-shared-storage.md) fences restored approvals/events and old processes; it does not reconcile all provider-native revocations. ADR-0018 §96-100's "security journal" (identities/credentials/sessions revoked *after* the restored backup's point-in-time) is not implemented anywhere in this session's scope yet — see [Gate IAM-14 scope](../governance/gate-iam-14-availability-dr-scope.md) §4. Until it exists, this step is manual: whoever declares the incident must independently know what was revoked between the backup and the disaster, and re-apply those revocations via the Admin API before reopening traffic. |
| 11 | Reconcile revocations | `baobab-cp` + `baobab-iam` | Same gap as step 10 — no automated reconciliation exists. `tests/integration/run.sh` §16 proves *how* to revoke (disable identity, revoke sessions) once the list of what to revoke is known. |
| 12 | Validate CP integration | `baobab-cp` | Not this repo's test suite — `baobab-cp` validates its own token acceptance and canonical-identity resolution against the restored realm. |
| 13 | Validate engine authentication | `baobab-trade`, `baobab-erp`, `baobab-cms`, `baobab-pulse` | Not this repo's test suite. |
| 14 | Run security smoke tests | **`baobab-iam`** | `BOOTSTRAP_WORKLOAD_CLIENT_SECRET=... ./tests/integration/run.sh` — see §18 below for exactly which of ADR-0018 §165's required checks this suite covers today. |
| 15 | Reopen traffic gradually | Infrastructure | Not this repo. |
| 16 | Monitor | Infrastructure + Security | Not this repo. |
| 17 | Complete incident review | Operations/Security | Not this repo. |

## What `baobab-iam`'s own recovery procedure is (steps 6, 8, 9, 14)

1. Deploy the image pinned by this repository's `Dockerfile` and `upstream.lock.yaml`
   (step 6) once Infrastructure confirms PostgreSQL and secrets are restored and
   reachable (steps 2-5).
2. Run `make bootstrap` against the restored, empty-or-partial realm to re-provision
   whatever the restore is missing. **This is idempotent only in the sense that it is
   safe to re-run — it does NOT reconcile drift on objects that already exist.**
   Reading `scripts/bootstrap.sh` directly: if the realm already exists, realm-level
   creation is skipped entirely (no attribute/flow/role reconciliation runs at all
   in that case); scopes and clients are only ever `kcadm create`d, and a create
   against an object that already exists is swallowed as "may already exist;
   skipping" rather than followed by an update. So bootstrap fills in objects a
   restore is missing; it does not correct stale configuration on objects a restore
   already produced. If a real restore leaves the realm with existing-but-incorrect
   objects (not just missing ones), someone SHALL diff the restored realm's actual
   configuration against `config/realm/baobab-realm.json`/`config/clients/*.json`/
   `config/scopes/*.json` and correct drift manually (or via `kcadm update`) before
   proceeding — this is a real, unimplemented gap in this repo's tooling, not a
   solved problem; see
   [Gate IAM-14 scope](../governance/gate-iam-14-availability-dr-scope.md) §7.
   In production, workload client secrets come from Infrastructure's
   secret-management boundary (ADR-0002 §25) at client-creation time — never from
   `BOOTSTRAP_WORKLOAD_CLIENT_SECRET`, which exists only for local/CI reproducibility
   and SHALL NOT be used in a real recovery.
3. Run `tests/integration/run.sh` against the restored instance (steps 9, 14), with
   `BOOTSTRAP_WORKLOAD_CLIENT_SECRET` set to whichever real secret the smoke test's
   workload client actually has in the restored realm (the same value step 2's client
   creation used, sourced from the same secret-management boundary — a mismatch here
   fails the workload-authentication checks on a secret mismatch, not a real defect).
   For a local/CI recovery **drill** (not a real production restore), set
   `BOOTSTRAP_WORKLOAD_CLIENT_SECRET` to the same value for both this step and step 2,
   exactly as [`README.md`](../../README.md)'s own verification instructions do. A
   clean pass proves discovery, JWKS, workload authentication, PKCE enforcement,
   workforce/role separation, MFA flow structure, and the identity-lifecycle kill
   switch all work on the restored instance — not just that Keycloak started.
4. Before declaring `baobab-iam` itself ready for step 12 (CP integration
   validation) to proceed, manually confirm (per step 10-11's known gap) that any
   identity, credential, session, or role revoked between the backup's point in
   time and the disaster has been re-applied. ADR-0018 §94-95's binding invariant
   is that **a restore SHALL NOT return previously revoked identity authority to
   service**. Federation PostgreSQL recovery provides automated epoch fencing and
   invalidation of restored live authority; provider-native revocation reconciliation
   remains a manual verification pending end-to-end DR certification. See
   [Gate IAM-14 scope](../governance/gate-iam-14-availability-dr-scope.md) §4 for
   why automating it (a "post-backup security journal") was deferred rather than
   built in this gate.

## DR exercises (ADR-0018 §119-123)

This repository does not yet run periodic DR exercises (§119 — that is Platform
Operations + Security's responsibility per §215). When one is run, ADR-0018 §121's
"Revocation Resurrection Test" is the mandatory minimum:

```text
1. create identity
2. create backup
3. revoke identity/credential
4. restore backup
5. reconcile
6. prove revoked access remains denied
```

`tests/integration/run.sh` §16 already proves step 6's mechanics in isolation
(disable an identity, confirm a new authentication attempt is denied) without a
real backup/restore cycle around it — a real exercise should wrap that same
assertion around an actual Infrastructure-driven backup and restore, once that
tooling exists to test against.


## ADR-IAM-0030: privacy restrictions during restored identity authority

The native IAM owner now has a separate *development implementation* of a
minimal monotonic restriction tombstone journal:
`internal/privacy/migrations/001_restriction_tombstone.sql` and
`internal/privacy.PostgresRepository`. Its identifier is the exact external
`issuer + subject`, never email. It carries only a decision reference and
timestamp; raw proofing documents, identity traits and credentials are not
stored. The journal must be kept **outside the provider backup under restore**
and must have separately protected custody, roles, retention and recovery.

`Service.RecordRestriction` requires a fresh current privacy authority
decision before writing a tombstone and independently reads the result.
`CheckReactivation` vetoes a restricted subject and fails closed on journal
unavailability; its successful return is **not** a grant of authority.
`RestoreReconciler.ReassertRestriction` re-disables the exact native subject,
revokes sessions, checks current provider state, requires fresh CP/resource
denial and rechecks privacy custody. `ReassertAll` requires a **separate
checkpoint verifier** before and after walking the restricted set and refuses
a changed checkpoint. A mock/verifier interface is not independent custody.

**Mandatory promotion hold:** Security and Privacy must independently prove
the live tombstone journal is complete, review legal holds, prove all provider
revocations/current CP denials, exercise event replay and backup restore, and
block every unauthorised reactivation/provision path. No unconnected JSON
receipt, source-level test or empty local tombstone list certifies global
erasure or a safe promotion. This increment is not an erasure saga and does
not implement Trade/ERP/CMS retention decisions, mandatory identity
reenablement-path enforcement, cross-border compliance or actual legal-hold
adjudication. Do not reopen production traffic based on it.

## ADR-IAM-0027 offline promotion preflight (development safeguard)

Before **any** candidate-region writer is enabled, collect an externally witnessed
JSON record and run:

```bash
python3 scripts/operations/check_dr_promotion.py /path/to/dr-evidence.json
python3 -m unittest discover -s tests/unit -p test_dr_promotion.py
```

The record identifies the identity security domain, stable HTTPS issuer, old and
candidate regions, backup/recovery checkpoints, explicit old-writer unreachable
and candidate read-only states, zero unresolved revocations and a reconciled
replication gap. It contains exact named attestations for incident declaration,
old-writer fencing, lease invalidation, replication position, security-journal
replay, provider/CP revocation reconciliation, issuer/JWKS verification and
negative security smoke. Every attestation requires a named role, independent
witness and evidence reference; the incident declarer and journal witness must
be distinct from the fencing witness.

**Security boundary:** This script only checks the *shape and internal
consistency of supplied assertions*. It cannot independently verify fencing,
WAL positions, witness identity, cryptographic receipts, CP decisions or journal
completeness. A JSON `verified: true` is not proof. Infrastructure and Security
must validate the original evidence against the real systems and authorize
promotion through protected controls. The tool neither promotes a database nor
changes routing or issues credentials. **No promotion may occur when the
security recovery journal is missing or unqualified.** A green preflight is
not an ADR-0027 acceptance receipt, production approval or measured RPO/RTO.
The ADR-IAM-0027 preflight rejects ambiguous issuer identifiers, duplicate
JSON members, non-integer revocation counts and padded witness identifiers.
It checks the submitted evidence structure. Infrastructure, Security and CP
verify the underlying receipts and remain responsible for promotion decisions.

### CTS v2 restriction approval freshness, 12 November 2026

Restriction authorization is validated after the authority call returns, at the
journal-write boundary. Slow or cancelled calls cannot persist a tombstone using
an approval that expired while waiting. Source tests assert no journal write on
late or cancelled approval. Independent privacy authority, journal completeness,
actual restored-provider denial and protected promotion remain separate gates.
