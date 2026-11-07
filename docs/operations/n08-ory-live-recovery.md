# N08 real Ory provider state recovery (development only)

**Status: candidate implementation; original CI receipt and independent
review outstanding. No whole-platform recovery certificate.**

`tests/operations/n08_ory_live_restore.sh` runs only inside a GitHub Actions
disposable `ory-foundation-ci` Compose project. It verifies project labels,
running provider containers, exact loopback-only public/admin URLs and actual
PostgreSQL **17** source versions before performing any database mutation.

1. `n08_ory_restore_state.py prepare` registers a unique real Kratos human,
   observes an actual session, disables the identity, revokes its sessions,
   and independently proves the original session denied. It provisions a real
   Hydra OAuth client, witnesses successful access-token issuance, disables
   its grants and proves issuance denied.
2. Stop the running Kratos/Hydra services; export their original, complete
   PG17 databases with `pg_dump -Fc` and validate private SHA-256 sidecars.
3. **Destroy and recreate** the two disposable databases. Import from their
   original dumps with `pg_restore --exit-on-error`, restart the same actual
   Kratos/Hydra services and wait for readiness.
4. `verify` rereads the identity as disabled and the client as grantless,
   proves the old Kratos session still fails and old Hydra credentials still
   cannot mint a token. The private fixture file and both DB dumps are
   erased via EXIT trap and **must never be uploaded**.

The workflow's final `docker compose down -v` must run even on failures.
This is genuine **two-provider** recovery rather than a pretend source-only
SQL restore. It still **does not** prove Redis/native-BFF vault restoration,
the separate IAM N06 security database, CP grant reconciliation,
a rotated key's old JWT verification, multi-node DR, or protected
environment recovery. Do not promote to full N08 or IAM completion on this
test alone. Independent original receipts and dedicated CP/consumer
recovery remain required.

## Same-run IAM security authority and recovery-hold restoration

The existing actual Kratos+Hydra database drill now creates a **third
synthetic IAM security database** in its own disposable PostgreSQL 17
container, applies the owner N06 migration and writes an append-only security
event and 24-hour recovery hold. All **three** databases are independently
snapshotted and original SHA256 checksums verified. After deleting and
recreating all three databases, the script verifies provider-issued session
and workload denials; independently reads back the original security event
and active hold; rejects mutation of immutable event history and an attempted
shortening of the restored hold. Its EXIT trap drops **only** the security DB
created by this specific run, verifies absence, and scrubs all private dumps.

This is a real, cohesive three-DB development recovery test, *not* a claim
that CP granted access is gone or that every Redis/BFF cache and enterprise
IdP session was successfully reconciled. That last cross-component recovery
boundary remains HELD until separate original witness and runtime readback.
