# Native and workload dispatch — C4 IAM composition increment

This increment provides fail-closed operation gates, not production activation
or completed C4 acceptance. All three canonical provider declarations remain
PARTIAL. It introduces no tenant membership, local provider registry, or new
Shared contract. The pinned Shared runtime vocabulary and canonical capability
resolution remain authoritative.

## Composition

`federation.NewRuntimeDispatch` receives an IAM-owned protected context source,
a CP capability resolver, a CP-owned `RuntimeBindingAuthority`, trusted
organisation/estate scope, and one exact executable provider/instance/service
reference. None of these values comes from login hints, email domains, token
claims, or estate-supplied CP contexts.

| Operation | Canonical capability | Required runtime facet |
| --- | --- | --- |
| Native human acceptance | identity.authentication.perform | HUMAN_AUTHENTICATION |
| Workload claim emission | identity.workload-token.issue | WORKLOAD_TOKEN_ISSUANCE |

Each check renews reads rather than caching readiness. It validates current
RESOLVED decisions, grant/binding identifiers, context and correlation equality,
version, expiry, protocol, and the exact composition target. It reads current
ACTIVE provider/instance/binding and VERIFIED runtime evidence for the exact
deployed artifact. It repeats resolution and profile reads, denying any grant,
binding, profile, artifact or context drift. CP must independently verify current
support, health, entitlement, scope, caller ownership and lifecycle.

`ory.NewGovernedCanonicalTokenProfileHook` invokes this capability-specific gate
only after sender authentication and canonical ACTIVE workload audience/scope
admission, immediately before emitting claims. Standard Hydra token endpoints
and credential verification stay direct. Local ACTIVE configuration is not CP
permission; issuance remains distinct from actual resource-server consumption.

`ory.NewGovernedNativeHumanHandoff` checks the human gate on every login/consent
operation and again after native session revalidation, before replay-fence
consumption and Hydra acceptance. Existing CSRF-bound intent, exact issuer and
subject, session and persistent challenge fences remain mandatory. Native
composition must additionally prove its Hydra OAuth runtime/profile and intended
client configuration: a Kratos HUMAN_AUTHENTICATION observation alone does not
certify a composed Kratos/Hydra journey. This wrapper does not perform canonical
mapping, grant membership, approve founding administrators or establish tenant
readiness.

## Remaining CP and executable integration

The new runtime authority port deliberately has no fixture-backed production
adapter. The existing `/internal/federation/v1/binding` projection is
federation-only: its SQL selects identity.authentication.perform and
federation_configuration references. Do not pass fake trust/configuration
references or reuse it for workload authorization.

Next: extend CP's authenticated current-runtime projection with approved native
and workload reference semantics and capability-specific support/binding
queries, then wire it into executable composition. The existing standalone
production hook retains its earlier canonical admission behavior; it does not
silently acquire this new authority. Deployment must not describe that command
as C4-complete. Production default wiring and composed CP/provider revocation
acceptance remain open.

Authority checks are read-time fences, not a cross-service atomic transaction.
Subsequent protected resource operations must independently enforce current CP
access and revocation. No unexpired token can substitute for membership.

## Evidence boundaries

Go tests use synthetic CP responses and TLS native/hook fixtures to demonstrate
repository construction, positive selection, fresh rechecks and denials. They
are not registration, deployed CP, staging or production evidence. Existing
real-provider CI tests remain required. Governed publication still needs real
allocated targets, reviewed support, artifacts and current scoped evidence.
