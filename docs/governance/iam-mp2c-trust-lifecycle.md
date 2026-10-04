# MP2-C durable IAM trust lifecycle increment

This increment adds the IAM-native trust lifecycle backend and private command
transport. It pins Shared #215 at
`6e9c6865de69b136db3de1b9f7cff72b4561243c`, including the federation governance
policy, permission vocabulary and reference-purpose ownership. It grants no
permissions, allocates no workload scopes and activates no workload or trust.
CP #258 supplies the mounted canonical identity source independently.

`OpenTrustLedger` requires current canonical actor authorization, authoritative
immutable target digests and current approved non-secret reference receipts.
These ports are mandatory. The library does not install a role-only authorizer,
manufacture reference registrations or infer approval from fetched configuration.
The authenticated authority handler exposes `/internal/federation/v1/trusts/`
`propose`, `decide` and `contain` commands; its access port remains mandatory.

Every revision binds the complete snapshot, provider instance, scope, lifetime
and policy references. This bounded increment supports exactly one organisation
and Digital Estate per trust. Provider/instance and organisation/estate ownership
are immutable in this increment; moving a trust requires a separately governed
migration instead of authorizing only its destination scope. Initial revisions must be REQUESTED. Independent
maker/checker approval and compare-and-swap against the preceding revision
prevent self-approval and competing decisions. ACTIVE changes require ROTATING
or suspension followed by VERIFYING; they cannot remain ACTIVE while changing
configuration. Activation requires all six current reference receipts tied to
that exact snapshot and sufficient lifetime. Consumers recheck receipts and the
current revision; source outages fail closed.

An explicitly authorized emergency suspension or terminal revocation does not
need the target or receipt service to be available. It advances the revision,
records the containment actor/time separately and preserves approval history.
Every committed revision, including suspension/revocation, is retained atomically
in append-only history independently of the current pointer; subsequent approvals
and additional containment cannot erase its actor, time or snapshot.
Re-entry from suspension still requires VERIFYING and an independent approval.
Revocation is terminal. A durable clock watermark prevents expired trust
windows reopening through clock rollback after restart.

This is a backend/transport increment, not completion of live MP2-C: production
composition still needs the canonical delegated human authorization transport,
CP-registered native targets, configuration/material/assurance sources and
current provider bindings. The tests use isolated synthetic authority ports.
The ledger retains the secure Linux file checks and local single-writer bbolt
limitations. Multi-replica fencing, retention policy, recovery and production
HA/DR evidence remain gates before deployment. MP3/MP4 registry/resolver,
Keycloak broker integration, upstream SAML verification and estate acceptance
are not implemented or certified by this change. Keycloak reduction remains
ineligible until those gates have their evidence.
