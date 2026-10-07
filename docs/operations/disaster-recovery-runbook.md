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
