# MP2-C live runtime plumbing and production dependencies

This increment adds executable authenticated authority transport, native
reference-approval storage/workflows and an actual OIDC signature verifier. It
stacks on IAM #65. Shared remains pinned to
`b10388460c23ac6d7d99bb8a22e2ee4821ad22f6`; CP #257's canonical reader remains a
dependency of the eventual CP source. Keycloak remains the SSO/federation
provider. No deployment, trust activation, workload scope allocation or
retirement is performed.

## Implemented boundary

`NewHTTPAuthority` owns a TLS-verifying, proxy-free, redirect-refusing transport
with a five-second deadline, per-read credentials and a 64 KiB strict JSON
limit. Each authority has independently configured origin/credentials; input
contains no caller-selected URL or provider product. Error details, response
bodies and credentials are never returned as errors. Unknown, duplicate, null,
trailing and oversized responses fail closed. Consumer independently checks
every fact; a 200 response alone never proves approval or activation.

`NewAuthorityHandler` implements the matching PRIVATE transport. It requires
request-time authentication before body parsing or proposal lookup, followed
by operation/target authorization. Access MUST verify the service audience,
current workload lifecycle and governed permission, or the current human
canonical actor for approval operations. There is no default authorizer. Missing
backends return unsupported; the handler neither manufactures facts nor reads
fixture data. CP and IAM must expose only the operations each owns. The handler
is not mounted in any deployed service in this increment.

The private wire structs are native port serialization (Go field names), not
new Shared canonical registries, public OpenAPI contracts or platform capability
keys. Receipts/reference purposes retain the MP2-C native semantics. If these
become public cross-repository APIs, publish their contract before enabling
consumers rather than treating private serialization as canonical Shared law.

| Private operation | Required authoritative backend |
| --- | --- |
| `trust`, `reference` | Current IAM approved trust snapshot and exact approved non-secret CP reference target |
| `binding` | CP platform association, scope, lifecycle, current approved profile/release/deployed artifact and support proof |
| `identity` | CP atomic ACTIVE human Principal + ExternalIdentity issuer/subject lookup, with independently approved relationship reference |
| `approval-authority` | Current canonical human administrative permission at exact target scope |
| `target` | Live CP ExternalReference plus immutable typed native target, current lifecycle/ownership and content digest |
| `oidc-configuration` | IAM approved client/algorithm configuration and public JWKS bound to the exact current trust snapshot |
| `map-assurance` | Approved policy applied to verified evidence, with an event/issuer/subject/evidence-bound mapping receipt |
| `approvals/propose`, `approvals/decide`, `approvals/revoke` | Durable native approval ledger + current approval authority and target resolver |

All paths are under `/internal/federation/v1/`; POST only, JSON, no query
credentials or redirects. Credentials come from trusted `AuthorityTokens` on
each call. Deployment's token source must rotate credentials, validate token
file ownership where applicable and use the incoming verified actor context for
human approval calls, never a shared service account as maker and checker.

`FileAuthorityTokens` rereads a rotated, private regular file on each call,
rejects symlinks, public permissions, multiline/oversized/padded credentials and
cancelled reads. The deployment must protect its parent directory and ownership.
The module moves from Go 1.22 to the tested CP-aligned Go 1.27 toolchain because
maintained protocol dependencies require at least Go 1.25. Protocol/ledger
libraries and transitive modules are pinned in `go.mod`/`go.sum`.

## Durable reference approvals

`ApprovalLedger` uses bbolt atomic transactions and exclusive writer locking.
Proposals are immutable: UUID, exact receipt expectation, current resolved target
digest, canonical maker and time. Approval requires a distinct canonical
checker, fresh authorisation before/after resolving target bytes, matching
digest, unexpired receipt and an undecided proposal. A concurrent decision has
one winner. Rejection is terminal. Revocation requires current explicit
authority, is terminal and retains the snapshot fence: it cannot be overwritten
by another approval for the same expectation.

Use re-resolves the typed target and digest, then rechecks approval/revocation.
Transport/storage errors are not absence. Native target existence, manual-import
reference registration, an email, IAM role or displayed effective authority
cannot approve a target. `ApprovalAuthority` and `ApprovalTargets` have no
permissive implementations. This ledger implements reference-target approvals;
it does NOT yet persist or enact FederationTrust's entire desired-lifecycle
workflow, activate provider configuration or mint canonical mappings.

## OIDC protocol wiring

`OpenOIDCEvents` and `NewLive` wire the protocol verifier into `Consumer`.
`Begin` generates cryptographically random event ID, state and nonce, bound to a
server-generated browser session, current trust snapshot and a five-minute
callback window. The BFF must supply its own secure browser-session binding;
the API is not an unauthenticated browser endpoint. Callbacks must come from
the BFF's server-side authorization-code/PKCE flow, not arbitrary caller token
submission.

`Complete` verifies the actual ID-token signature using pinned coreos/go-oidc
and go-jose libraries, approved PUBLIC JWKS and explicit RS256/ES256. Private,
symmetric, weak or unapproved keys/algorithms fail closed. There is no dynamic
token-supplied discovery or key URL. Exact issuer, one client audience, azp,
nonce, state/browser correlation, iat, strict nbf, expiry, auth_time and bounded
event/authentication lifetime are required. Arbitrary upstream claims never
become canonical identity or tenant authority. A failed correlated callback is
burned. A successful callback stores only normalized evidence and token digest;
raw ID tokens and browser/state/nonce secrets are never persisted.

The mapper can only provide a governed mapping result and shorten expiry; it
cannot substitute subject, event, issuer or upstream evidence. UNKNOWN remains
UNKNOWN and the consumer denies it. A4 is prohibited here. Consumption of a
verified event is single use, atomic and preserved across restart; a consumer
failure requires a fresh login rather than reuse of authentication evidence.
The consumer independently verifies current mapping approval and CP identity.

SAML2 returns unsupported. Checking Keycloak's downstream OIDC signature is
not evidence of an upstream SAML signature, NameID qualifiers or AuthnContext.
No SAML-to-OIDC assurance fabrication is implemented.

## Production gate and implementation order

This closes executable runtime PLUMBING, not live authority source integration
or production consumption. The test source facts are explicitly isolated; they
are not deployment evidence. Required next work is:

1. **Shared governance/API decisions:** allocate explicit federation governance
   permissions/scopes with maker/checker and target scope rules; define the
   approved native target/reference namespaces and public wire contracts if
   needed. Do not allocate scopes to ACTIVE workloads or promote candidate
   capability keys implicitly. `GET /admin/effective-authority` is a display
   model and cannot be the decision backend.
2. **CP source implementation:** mount authenticated source endpoints against
   #257's atomic canonical reader and existing provider/binding/topology/release
   authorities. Implement current relationship-reference approval, scope,
   security-domain/residency and deployed-artifact/profile proof. No copied
   booleans or new IAM-owned platform registry may substitute for those reads.
3. **IAM governance source:** persist coherent approved trust revisions and the
   Shared lifecycle transitions; resolve CP ExternalReferences to immutable
   non-secret configuration, public trust material and approved policy targets.
   Mount approval operations using current CP canonical administrative authority.
   Emit event-bound assurance decisions under an approved policy; retain
   audit/redaction and emergency suspension/revocation paths.
4. **Provider/BFF and SAML:** wire Keycloak's pinned broker APIs and the BFF's
   code/PKCE callback with verified upstream provenance. Add a reviewed SAML
   verifier with signed response/assertion, recipient, audience, InResponseTo,
   time, scoped persistent NameID and durable replay proof. Broker OIDC tokens
   alone must not claim upstream SAML conformance.
5. **Operational proof:** use shared durable/fenced state for multi-replica
   operation (this bbolt implementation is ONE writer), encrypted volumes and
   access-controlled backups; enforce monotonic revocation/replay through
   restores; establish rotation, redaction, incident containment and deployed
   registered consumer acceptance. The mounted authority service must enforce
   finite server timeouts/body limits and network exposure policy.

## Verification and claim limits

Tests use real TLS, actual cryptographic ID-token signatures and actual durable
ledger transactions/restart; platform/governance/CP authority facts remain
isolated test backends. Denials include wrong signature, issuer, audience/azp,
nonce/state/browser binding, stale/future time, policy/config drift, evidence
substitution, private keys, self approval, target drift, source failures,
revocation, concurrent decision/consumption and restart replay. Existing
provider/migration tests and pinned Shared schema checks remain required.

EA-04 remains ADVANCED. No deployed route acceptance, live Keycloak brokering,
canonical activation, production readiness, automatic provider dispatch,
dual-issuer enablement, Ory cutover or Keycloak retirement is claimed.
