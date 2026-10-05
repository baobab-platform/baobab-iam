# Federation shared state and recovery

The federation-authority service can use PostgreSQL 17 for approvals, immutable
native target material, trust revision history, OIDC requests/evidence/replay and
broker requests/captures/evidence/replay. Omitting `Storage` retains the bounded
local bbolt staging mode. Local files are not a multi-replica production backend.

Configure `Storage` with `DSNFile`, `Namespace` and `RecoveryEpoch`. The DSN is read
from an owner-only protected file. Runtime connections require verified TLS,
server identity and no plaintext fallback. Credentials must not be supplied in
command arguments, logs, Terraform values or source control. A private
`StateDirectory` is still required, but PostgreSQL mode writes no bbolt files.

Apply `internal/federation/migrations/001_shared_storage.sql` with the separate
migration administrator. Explicitly insert one control row with the namespace,
externally pinned recovery epoch and version 1. Runtime never creates/migrates
its schema or chooses an epoch. Restrict runtime grants to SELECT/UPDATE on the
control table (row-lock requirement) and SELECT/INSERT/UPDATE/DELETE on records;
no schema creation, recovery archive access, role administration or backup rights.
Revoke PUBLIC schema creation and lock down the database search path. Use a
separate IAM-owned database, not the CP or Keycloak application database.

Each storage transaction locks the shared namespace row: writers use FOR UPDATE,
readers FOR SHARE. It checks the pinned epoch and executes the unchanged domain
checks and writes in one transaction. Independent pools coordinate checker
choices and one-time evidence consumption. SQL failures cannot mean record
absence; uncertain commits are unavailable and are not automatically retried.
Logical ledger Close does not close other ledgers' shared pool. Readiness checks
storage identity and the epoch as well as the existing live authority sources.

This intentionally serializes short IAM state transactions within a deployment
namespace. Measure contention before raising replica count; connection pooling
is bounded. Network authority/protocol calls remain outside these transactions.
Database HA/synchronous replication, failover credentials and RPO/RTO must still
be provisioned and proved. Process replicas do not establish zero-loss durability.

## Backup and destructive-recovery procedure

Treat backups and the recovery archive as restricted identity security data;
event state includes correlation and PKCE material. Encrypt backups and keep an
independent immutable copy with a recorded source epoch, schema version, restore
point and integrity evidence. Do not put decrypted backups in CI artifacts.

1. Stop ingress and all IAM writers; verify that no active process remains.
2. Restore the encrypted database to an isolated database endpoint. Verify the
   backup integrity, schema and migrations using the recovery administrator.
3. Run `scripts/operations/federation-recovery.sql` against that isolated database
   using protected libpq service configuration and ON_ERROR_STOP. Supply only
   the non-secret namespace, old epoch and a distinct new epoch. The script
   locks the control row, archives restored records, invalidates all restored
   live governance/event/replay state and advances the epoch atomically. A
   missing or wrong old epoch aborts. Native immutable target bytes remain.
4. Update the recovery epoch in independently controlled service configuration;
   do not recover its pin from the database backup. Old processes retain the old
   pin and are denied by the database, including readiness and mutation paths.
5. Independently reconcile CP registration, containment/revocation, trust
   material, keys, certificates and compromised principals against current
   authoritative incident records. Obtain fresh maker/checker approvals and
   fresh trust IDs/revisions; never copy old approval authority back into live
   tables. Repeat broker/protocol verification with new authentication requests.
6. Prove denial of old requests, captures, approvals and stale processes before
   reopening ingress. Retain restricted audit evidence and recovery timings.

Clearing live authority is intentional: a database restore must not resurrect
revocations or replay consumption lost after the backup. The archive is audit
material, not an approval source. Existing event proofs cannot be recovered as
live authority. Backup restoration alone cannot declare service acceptance.

Migration from bbolt requires a separate reviewed cutover and reconciliation;
this increment provides no automatic file import or silent authority conversion.
Never run two independent storage backends for the same active binding. AWS
provisioning, real failover/restore drills, measured throughput and approved
RPO/RTO remain operational acceptance work.
