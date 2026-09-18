# Gate IAM-18 — Workload lifecycle status consistency (Gate ZB-03.9)

## Decision applied

`gate-iam-4-workload-identity-scope.md` §2 gap 5 identified workload lifecycle states
(ADR-0007 §45: `PROVISIONED | ACTIVE | SUSPENDED | REVOKED | RETIRED`) as a real gap and
explicitly deferred it, blocked on `baobab-cp`'s tenant-shortcut rebuild (§4 item 5, "blocked on
phase 4 for the same reason"). Phase 4 shipped in §8; item 5 itself was never picked back up until
now.

`nabhold/shared`'s `contracts/identity/v1/workload-registry.yaml` already carries a `status` field
per workload (all six entries currently `ACTIVE`, matching the six already-provisioned
`config/clients/*-workload.json` clients), and its own header comment already documents the
intended lifecycle discipline: *"Removing one: set status to RETIRED here before
disabling/deleting the Keycloak client, never the other order."* Nothing enforced that discipline.
`tests/integration/run.sh` §9 checked registry membership and scope allowlisting, but never
checked a client's live `enabled` flag against the registry's `status` at all — a registry entry
marked `SUSPENDED`/`REVOKED`/`RETIRED` and a Keycloak client left `enabled: true` would pass every
existing check. `gate-zb03-authority-contract-freeze.md` (`nabhold/baobab-cp`) independently names
this the same gap: workload lifecycle state is "unowned," and revocation today is binary Keycloak
client `enabled` toggling only.

§9 now additionally asserts, for every local `config/clients/*-workload.json` client matched to a
registry entry, that the client's `enabled` flag agrees with that entry's `status`:

- `status: ACTIVE` and `enabled: false` fails (availability defect — the registry expects this
  workload to be reachable and it isn't).
- any non-`ACTIVE` status with `enabled: true` fails (the security-relevant direction — a workload
  the registry says should no longer be trusted still holds a live credential). This is the actual
  enforcement mechanism for the registry's own documented "set status to RETIRED first" ordering:
  once a maintainer does that but forgets (or hasn't yet reached) the matching client-disable step,
  CI now catches the gap instead of silently allowing it to persist.

Verified against the real pinned registry and all six current client files (all `ACTIVE`/`enabled:
true`, so the new check passes today with no drift) and against a simulated `REVOKED`-but-enabled
case, confirmed to fail with the expected message.

## MFA and revocation: already shipped, not this gate's gap

Checked both other halves of this slice's title before scoping the above as the actual gap:

- **MFA** — Gate IAM-11 already ships a conditional-MFA browser flow requiring OTP for any role
  composited into `iam:mfa-required` (`config/realm/baobab-realm.json`), verified structurally
  against a live Keycloak in `tests/integration/run.sh` §15. Realm-wide via `browserFlow`; no
  domain-repository step-up wiring is in scope, and `baobab-trade`/`baobab-erp` need no changes
  (neither reads `acr`/`amr`/MFA claims today, and none of the workload-token flows this platform
  has built so far are human/browser-session flows that would need MFA in the first place).
- **Revocation (kill switch)** — Gate IAM-12 already ships `adminEventsEnabled`/
  `adminEventsDetailsEnabled` and an end-to-end disable-identity + revoke-sessions proof against a
  live Keycloak (`run.sh` §16-17). This is the human-identity kill switch; workload lifecycle
  status (this gate) is the separate, previously-unenforced gap.

## Explicitly out of scope

`baobab-cp` enforcing registry `status` at request time (rejecting a workload token whose
`client_id` maps to a non-`ACTIVE` registry entry) is real follow-on work, tracked in
`gate-zb03-authority-contract-freeze.md`, and is a separate `baobab-cp` change requiring its own
PR — not folded into this slice, matching how phase 4's `baobab-cp` enforcement work in
gate-iam-4 was its own separate PR (`nabhold/baobab-cp#102`) rather than bundled with the
`baobab-iam`-side registry work. The sync-vs-event question for how `baobab-cp` would learn about
a revocation (poll the registry, or consume `nabhold/shared`'s already-defined
`contracts/identity-events/v1/workload-revoked.schema.json`) is likewise left to that follow-on:
building an event producer/consumer nothing yet uses would be speculative here, and the registry
itself is already synchronously fetchable, so synchronous re-validation is the smaller, sufficient
mechanism until a real need for eventing is demonstrated.
