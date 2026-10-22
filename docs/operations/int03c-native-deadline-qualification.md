# INT-03C native proof identities — supervised absolute run deadline

**Implementation status:** bounded source controls implemented on IAM PR #137.
**Actual Hydra/Kratos/CP qualification:** not yet executed. Neither a
source test nor a 60-second token lifetime proves complete client shutdown.

## Authority

The only authorised clients are the two exact development-only
`baobab-int03c-issuer-owner` and `baobab-int03c-issuer-verifier`
rows in Accepted Shared #366. The issuer owner has CP
`context:resolve`, and the verifier independently introspects the
owner token; neither is a CMS identity or a platform administrator.

## Independent deadline supervisor

Launch `int03c-native --action supervise` **before** any client
creation, with the exact run ID, private disposable Hydra admin endpoint,
Kratos endpoint, Hydra issuer, run CA and absolute RFC3339 deadline.
Set `BAOBAB_INT03C_NATIVE_DISPOSABLE=1`. Use the named owner as the
CLI name (the watchdog always destroys **both** owned clients).

Run this in a **separate, externally managed process/container** with
restart-on-failure and an independent absolute deadline/kill policy.
The separate supervisor MUST control the whole disposable stack's
lifetime and cannot be a child whose existence depends on the creator.
The `--lease-file` must have a 0700 private parent. The watchdog creates
an owner-private 0600 file with the run ID, absolute deadline, PID and
heartbeat, atomically fsyncing each refresh.

`--action create` checks that the watchdog is independently alive and
emitted a fresh heartbeat, and matches the exact run ID and deadline,
before the canonical Shared registry check and any native client POST.
An absent, stale, wrong-run or expired lease refuses creation.
Subsequent client creation uses the same lease and run.

On the deadline or normal SIGTERM/SIGINT, the watchdog uses IAM's
maintained Ory adapter to revoke and destroy both run-marked clients,
with a provider-native GET verifying absence. A failed cleanup leaves
the lease as an unreconciled recovery record; the next issuance must not
blindly retry creation. The 60-second token lifetime is a separate
upper bound, never an alternative to client removal and accepting-runtime
shutdown.

## Failure conditions requiring independent reconciliation

No ordinary users or production clients are created, and the code does
not claim that any of these situations are safe without a **real** host:

- A watchdog process killed by SIGKILL or a failed supervisor may leave
  issuer grants alive until the independent restarted worker is healthy.
  A heartbeat alone is not an issuer-enforced expiration mechanism.
- Loss of the disposable host's local disk requires issuer admin GET
  and revocation/readback; a missing lease cannot be treated as
  evidence that a client was never created.
- Deleting IAM clients does not deactivate the CP canonical Principal
  or purge CP-issued Contexts. CP and the accepting workload must be
  independently shut down and read back.

### Required runtime qualification before accepting INT-03C

1. Show the independent supervisor starts before any client creation,
   reaps both fresh Hydra native clients and independently verifies 404.
2. Demonstrate a late POST after the deadline or a stale heartbeat
   refuses every privileged create, including after a simulated
   creator crash.
3. Kill and restart the watchdog under an independent service manager;
   inspect the actual issuer state and any bearer that remains
   unexpired. Fail the run if any token is accepted past its bounded
   lifetime or if the client can issue again.
4. Retain original source/image/issuer/readback evidence in approved
   externally immutable storage and independently rehash it.
5. Complete the separate CP Maker/Checker Principal provenance and
   deactivation proof, all seven actual integration cases and full
   runtime teardown. Source tests do not substitute.

These controls do **not** activate Shared #354's CMS workloads. The
14 NAB-03 cases remain HELD.
