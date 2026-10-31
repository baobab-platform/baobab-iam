# Native and workload dispatch — C4 IAM composition increment

## IAM-N03 workload receiver, not issuer dispatch

[Receiver-side source implementation](n03-workload-resource-qualification.md) extends the existing governed Hydra issuance dispatch without replacing it. Resource consumers verify signed JWT, independent current issuer status, current CP Context/Principal through their registered `context:validate` caller and owner-native PEP, with no cached fallback, token-exchange proxy or local tenant authority. After issuer withdrawal, a still-unexpired bearer must be refused at the actual owner resource. The opt-in Hydra/CP source fixture is not protected C4-03B–E, provider support stays PARTIAL.


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

## Remaining executable integration

C4-01 supplies a production HTTP authority adapter and CP's separate native/
workload runtime projection (Shared #348, CP #417, IAM #120). Federation keeps
its original endpoint and trust/configuration rules. Native/workload authority
does not reuse federation grants or fabricate trust-material references.

C4-02's production hook requires `-runtime-config` in every environment and
calls `NewGovernedCanonicalTokenProfileHook`. There is no canonical-only or
PROVISIONED fallback in the executable. Provider-only CI uses its separate
`tests/ory-foundation/mechanics-hook` launcher. That launcher is not packaged
as an application service and supplies no C4 acceptance evidence.

`federation.StartRuntimeComposition` builds the C4-01 HTTP adapters, acquires a
caller-owned CP context and supervises renewal. `ory.StartNativeHumanRuntime`
is the native host factory: it composes Kratos human authentication, the current
Hydra workload issuer and Hydra's separate OAuth authorization-server evidence.
The native gate repeats both components and the OAuth observation before
acceptance, including the mechanics' final pre-fence check. End users gain no
workload scopes or resource audience. The host retains browser binding, approved
client configuration and persistent challenge-fence responsibilities. No new
public native-login endpoint is introduced.

C4-03 still requires actual CP/provider revocation, composed provider execution
and resource-consumption acceptance. Repository TLS wire fixtures are not that
qualification. Provider declarations remain PARTIAL.

Authority checks are read-time fences, not a cross-service atomic transaction.
Subsequent protected resource operations must independently enforce current CP
access and revocation. No unexpired token can substitute for membership.

## Evidence boundaries

Go tests use synthetic CP responses and TLS native/hook fixtures to demonstrate
repository construction, positive selection, fresh rechecks and denials. They
are not registration, deployed CP, staging or production evidence. Existing
real-provider CI tests remain required. Governed publication still needs real
allocated targets, reviewed support, artifacts and current scoped evidence.

## C4-01 production HTTP runtime authority

NewHTTPRuntimeAuthority now implements RuntimeBindingAuthority against CP's
separate /internal/identity-runtime/v1/binding projection. Each adapter binds
one reviewed provider, instance, organisation/estate, native/workload facet,
configuration reference and security-domain reference. Requests cannot retarget
it. Verified TLS, fixed destination, fresh credentials per call, strict bounded
JSON and no redirect/retry/proxy-env behavior reuse NewHTTPAuthority. Responses
must match the target, ACTIVE lifecycle, VERIFIED support, revision, exact
deployed artifact and current expiry; failure returns no proof.

CP requires the distinct identity-runtime:read scope and scoped
security.identity-runtime.view permission; neither is allocated here.
Reviewed configuration approval remains an independent composition input.
Reference existence is not approval. No fabricated FederationTrust is needed.
RuntimeDispatch still independently repeats caller-owned CP resolution.

C4-02 adopts these adapters in executable factories and supervises context
renewal. C4-03 must qualify the actual composition and resource consumption. Provider declarations remain PARTIAL; INT-02's named
Pulse proof-bootstrap exception grants no IAM authority.

## Production hook deployment and context renewal

The service accepts these protected, owner-controlled inputs:

- `-profiles`: strict private token-profile JSON from the pinned Shared registry.
- `-key-file`: a private regular file containing the Hydra hook authentication key.
- `-runtime-config`: strict private JSON with `cp_origin`,
  `resolution_token_file`, `runtime_token_file`, `context_target` (exact
  `tenant_id`, `organisation_id`, `country_code`), `provider_id`,
  `engine_instance_id`, `estate_id`, `service_reference`,
  `configuration_reference`, and `security_domain_reference`.
- `-cp-ca-file`: optional private-CA PEM; system roots apply when omitted.

CP origins require verified HTTPS. Reviewed configuration references must identify
exactly the deployed provider URLs/client configuration; references merely
existing is insufficient approval. Files/directories must satisfy the existing
protected-service-document rules. Do not substitute environment tokens, provider
hints or estate request values. The private hook listener retains sender-key
authentication and must only be reachable by Hydra on the protected deployment
network. Shutdown waits for request draining and joins context supervision before exit.
Listener/startup failures return a nonzero process status after cleanup. Each
hook operation has an eight-second overall budget, including renewal-lock waits,
below the ten-second response deadline; expiry denies issuance.

The resolution credential needs separately allocated `context:resolve` transport scope and
current canonical capability-resolution authority; runtime reads need `identity-runtime:read` plus
current scoped `security.identity-runtime.view`. This change allocates none.
Credentials are reread on every CP HTTP call. Deployment owns credential renewal;
it must establish an independently authorised bootstrap/renewal path rather than
requesting the very governed Hydra token whose issuance waits for this hook.
No INT-02 proof identity or exception is reused.

The supervisor calls `/v1/platform-context/resolve` using IAM's own credential.
It rejects substituted tenant/organisation/market, absent/expired/unbounded or
more-than-15-minute contexts. Every five seconds it checks the lease and renews
with a 15-second margin; a request reaching that margin also renews synchronously.
An initial acquisition failure prevents startup. A later uncertain renewal
clears the handle, denies the operation and permits fresh acquisition after CP
recovers. Cancellation, expiry and clock rollback deny use. No context is locally
extended, no capability/profile result is cached and no readiness result grants
issuance. Rotation during an operation may safely deny that operation; uncertain
provider acceptance must start a new transaction, never be retried blindly.

For native composition both components must share the exact CP origin,
resolution credential source, context target, estate and security-domain
reference, with distinct runtime instances. The Hydra OAuth and workload facets
must have the same current profile revision and deployed artifact. Both existing
canonical capabilities must be allocated to the IAM service caller. This is a
conservative composition prerequisite, not a replacement for human authority.
