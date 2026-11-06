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
