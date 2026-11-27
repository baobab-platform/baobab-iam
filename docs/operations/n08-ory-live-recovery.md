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

The workflow's final `tests/ory-foundation/cleanup.sh` must run even on failures; it stops only the recorded helper processes and tears down the isolated Compose volumes.
This is genuine **two-provider** recovery rather than a pretend source-only
SQL restore. It still **does not** prove Redis/native-BFF vault restoration,
the separate IAM N06 security database, CP grant reconciliation,
a rotated key's old JWT verification, multi-node DR, or protected
environment recovery. Do not promote to full N08 or IAM completion on this
test alone. Independent original receipts and dedicated CP/consumer
recovery remain required.

## Disposable SMTP host-gateway contract

The Kratos courier sink is a host process bound only to the private isolated
Compose bridge gateway `172.30.146.1:1025`; its inspection API remains bound
to host loopback on `127.0.0.1:4457`. The base Compose file retains Docker's
`host-gateway` default for local development. The isolated Foundation runner
sets `BAOBAB_ORY_HOST_GATEWAY=172.30.146.1` before Compose starts and verifies
the running Kratos container's `HostConfig.ExtraHosts` entry. Do not change
the sink bind address, isolated subnet gateway, or host alias independently.
The source regression `test_smtp_sink_host_alias_matches_private_bridge_gateway`
guards this three-way contract. The Ory Foundation workflow installs Node/Chromium
before starting the provider fixture and runs the browser ceremony inside
`run.sh`, before its SMTP cleanup trap; do not move the browser step after that
process exits. `cleanup.sh` stops only the recorded relay/sink PIDs after
checking their command lines, then removes the isolated Compose volumes.

## Same-run IAM security authority and recovery-hold restoration

The existing actual Kratos+Hydra database drill now creates a **third
logical database**, `n08_security_ci`, inside the same disposable PostgreSQL 17
container that owns the Kratos database. Hydra remains in its own separate
PostgreSQL 17 container. The security database applies the owner N06 migration
and receives an append-only security event and 24-hour recovery hold. All
**three logical databases** (Kratos, Hydra and `n08_security_ci`) are
independently snapshotted and original SHA256 checksums verified. After
deleting and recreating all three databases, the script verifies provider-issued session
and workload denials; independently reads back the original security event
and active hold; rejects mutation of immutable event history and an attempted
shortening of the restored hold. Its EXIT trap drops **only** the security DB
created by this specific run, verifies absence, and scrubs all private dumps.

This is a real, cohesive three-DB development recovery test, *not* a claim
that CP granted access is gone or that every Redis/BFF cache and enterprise
IdP session was successfully reconciled. That last cross-component recovery
boundary remains HELD until separate original witness and runtime readback.
