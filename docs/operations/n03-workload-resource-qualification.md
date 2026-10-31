# IAM-N03 — Provider-neutral workload resource acceptance and revocation

**Status:** Source implementation and opt-in real-component qualification harness.
**PR:** IAM #148 DRAFT, stacked on #147 → #146 → #145. Do not merge.
**Architectural precedence:** Accepted IAM ADR-IAM-0020, 0021, 0033, 0007 and 0016; Shared ADR-SHARED-036/042/043, immutable Shared identity/v1 workload and capability/CP vocabulary; [EA v2.3](https://github.com/baobab-platform/shared/blob/main/docs/architecture/EA-implementation-plan-v2.3-2026-10-20.md); [EA-DEV](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-v2.3-development-enablement-implementation-plan-2026-10-23.md) DEV-03/04/11/13/14/15; [EA-XB v1.1](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-xb-v1.1-enterprise-corrective-architecture-2026-10-29.md).

This work does **not** re-pin the N01 Shared contract or promote any provider
support from PARTIAL. It adds no IAM token endpoint, CP authority registry,
Tenant/Organisation grant, legal mandate, Keycloak-to-Hydra token translation
or synthetic production identity.

## Why a resource-side component is essential

Baobab IAM owns workload authentication, issuer/adapters and token lifecycle.
Ory Hydra is the initial provider of standards OAuth/OIDC workload tokens.
An independent issuer could implement the same exact standards boundary under
a separately qualified provider adapter. Keycloak remains an enterprise SSO
provider, not an unapproved alternate workload issuer.

A resource server **must not** assume that an unexpired JWT remains valid after
provider revocation, CP Principal disablement, Tenant or binding withdrawal,
or an authorisation change. It must not ask IAM to synchronously proxy ordinary
OAuth validation. A signed token proves only its issuer, actor identity, granted
scope/audience and cryptographic properties; it cannot grant business
permissions, cross-tenant access, seller/buyer representation, invoice posting,
corridor clearance, shipment booking or legal compliance.

## Implemented code

- `pkg/workloadresource/gate.go`: minimal provider-neutral interfaces for
  `SignedTokenVerifier`, `IssuerStatusReader` and `CurrentAuthority`.
  Production configuration demands an exact HTTPS issuer, one resource
  audience, reviewed allowed client IDs, nonempty required scopes and
  token lifetime no greater than 15 minutes. Every operation verifies the
  **original signed bearer**, exact issuer/subject/client/actor/audience/scope,
  issued/not-before/expiry, then independent current issuer status, then
  current CP/operation authority, **then issuer status again**.
- `pkg/workloadresource/oidc.go`: standards OIDC remote JWKS validation with
  TLS certificate verification, no redirects, RS256 only (the currently
  reviewed Hydra token profile), exact issuer, resource audience and signed
  actor/authorised-party evidence. It is not an Ory-specific model.
- `pkg/workloadresource/introspection.go`: RFC 7662 HTTP status call with
  separate protected introspection credentials, timeout, TLS, no redirects,
  strict bounded/duplicate-free fields and exact issuer, subject, client,
  scope, audience and expiry comparison to the signed JWT. An inactive,
  missing or ambiguous response, 5xx/timeout, or any mismatch is DENY.
  The issuer's request-time `iat` need not equal JWT signing-time `iat`,
  as documented for the pinned Hydra implementation; the expiry and status
  must agree. No stale positive status cache is allowed.
- `pkg/workloadresource/http.go`: provider-neutral HTTP resource middleware
  accepts exactly one Bearer authorization header, derives the operation
  from the owning application's trusted resolver, and calls the complete
  issuer → CP → native veto chain on each request. Before forwarding to
  native application code, it strips raw Authorization and Cookie headers.
  It cannot replace a resource's transaction-commit policy.
- `pkg/workloadresource/cp_context.go`: production CP
  `POST /v1/platform-context/validate` HTTP adapter using a **different**
  independently registered `context:validate` workload credential, the
  original subject bearer and exact canonical Context ID. A response must
  be fresh, no-store and match the application-owned expected Tenant; an
  HTTP 200 or verified context is still **not** native engine business
  authorisation. A separate current `ResourceOperationPolicy` must veto
  unauthorised operations.
- `pkg/workloadresource/gate_test.go` and `adapters_test.go`: negative
  cases for wrong issuer, audience/client/actor/scope/time, changed subject
  or expiry, inactive issuer, status outage, second-read revocation, CP
  withdrawal, foreign tenant, native veto, injected/absent authorities, and
  TLS/introspection protocol failures.
- `pkg/workloadresource/live_test.go`:
  `TestLiveN03HydraCPResourceAcceptance` (opt-in only). It creates
  actual disposable scoped Hydra client-credentials clients under the
  pre-existing token-profile hook, obtains actual signed tokens and an
  independent CP validator bearer, verifies JWT/JWKS and RFC 7662, invokes
  the existing **pinned CP production router in a synthetic in-process CP
  fixture**, tests foreign-owner/revoked external-link/suspended Tenant,
  performs RFC 7009 token revocation **before expiry** and requires
  independent inactive introspection read-back plus resource denial of the
  exact same unexpired bearer, including at an actual in-process HTTP resource middleware boundary. A tampered real signature and a genuine wrong-audience bearer are denied at that HTTP boundary. Fresh issuance is the control; an in-process fixture cannot be relabelled as a separately deployed resource.
- `tests/ory-foundation/token_profile.sh`: appends this live proof only
  while the actual Ory hook and immutable CP consumer are running, and
  refuses skipped/missing live subcases. The sanitized report remains
  `REAL_COMPONENT_SYNTHETIC_DATA`, **not** a protected/deployed result.

The library is an owner-adoption candidate. Its package API is not a newly
published Shared contract. Consumers may adopt it or satisfy the same
canonical OAuth/CP/resource properties using their own standards stack, but
must retain equivalent positive and negative evidence.

## Correct integration order

1. Resolve the immutable Shared/CP/IAM source versions and the real provider
   client/issuer configuration for a *specific* engine, environment and
   resource audience. Verify currently ACTIVE registered workload and
   issuer+subject mapping through CP; do not turn a PROVISIONED mechanics
   fixture into ACTIVE. Existing N01 Shared re-pin hold remains.
2. Register the client through governed Ory/CP onboarding with exact
   audience/scopes, credential type (`client_credentials` or
   `federated_workload_token`) and environment. Verify Hydra actually
   persisted the credential, and distinguish client-secret rotation from
   federated assertion trust/key revocation. Neither provider-side
   configuration nor a successful token exchange is a CP business grant.
3. Resource creates one immutable trusted `Profile` per approved consumer
   and wires (a) signed JWKS verification, (b) independent **current** RFC 7662
   issuer status, (c) a protected CP `context:validate` caller **distinct**
   from the subject token, and (d) the native engine policy/commit veto.
   Neither the request nor its JWT chooses the issuer, audience, CP service
   origin, expected Tenant or operation authority.
4. Run an actual request through the resource's own API, before native
   side effects. Prove own-Tenant/current-context success and wrong audience,
   unrelated/sibling Tenant, missing grant, issuer outage, client/Principal
   disablement, current context withdrawal, signed-token tampering, scope
   inflation and real revocation while the bearer is unexpired.
5. Retry with genuine fresh issuer/CP credentials and prove controlled
   recovery. Record original source SHA, issuer/client binding, CP decision,
   native response, image digest, environment, case results, expiry,
   correlation and bounded teardown in private redacted evidence.
6. For DEV-14/15, repeat against the real Pulse and Payments engine owners.
   Pulse's evidence/Qdrant and Payments' sandbox transaction PEPs remain
   owners' responsibilities; simulated payment results may **not** be labelled
   PSP acceptance. No CMS dependency is imposed on headless consumers.

## Local and live qualification

Pure source negative tests:

```sh
go test ./pkg/workloadresource -count=1
go test -race ./pkg/workloadresource
go vet ./pkg/workloadresource
```

Real disposable provider **plus CP source router** (not deployment):

```sh
# Managed by the existing Ory Foundation Live workflow after exact upstream
# and CP consumer SHA verification, real Ory startup and live hook setup.
bash tests/ory-foundation/run.sh
bash tests/ory-foundation/token_profile.sh
```

The second command must run inside the already configured disposable Ory
Foundation with pinned CP consumer source and explicit issuer profiles;
running it against an arbitrary production endpoint is forbidden. It can
exercise real signed issuer mechanics and actual CP router logic. It does
**not** establish a separately deployed CP/resource, real tenant grant,
federated-user session, whole platform approval or protected acceptance.

| Case / evidence | Source component | Actual consumer/protected requirement |
|---|---|---|
| N03-01 signed workload + profile | Real Hydra/JWKS and exact scopes/audience in disposable hook | Named deployed issuer, reviewed Shared client and current CP binding |
| N03-02 current issuer + original subject | RFC 7662 exact original bearer before/after CP | Independently read real issuer/client/session status |
| N03-03 current CP authority / tenant | CP production router in synthetic fixture | Actual protected CP current Principal, grant, Market, Context, actor |
| N03-04 wrong-tenant/foreign-owner | Real signed bearer + CP router negative | Same case on independently authorised real sibling/external Tenants |
| N03-05 revocation before expiry | Genuine provider revocation + issuer inactive read-back + resource gate denial | Same unexpired bearer refused by actual deployed consumer (not only stub) |
| N03-06 recovery and deactivation | Fresh token accepts after specific revocation; CP fixture refuses revoked external link | Genuine Principal deactivation, issuer/client rotation, failover and recovery |
| N03-07 engine-native consequences | Source API mandates `ResourceOperationPolicy` | Real domain PEP, storage and correct business/financial consequences |
| N03-08 evidence and cleanup | CI-only sanitized fixture report, client delete + provider-owned disposable teardown | Immutable source/image/contract pins, outside-actor custody and teardown witness |

**Current N03 acceptance is therefore HELD** for a deployed CP/engine,
cross-repository ENG-ONB-01..09, protected C4-03B–E/C4-04B/C, enterprise
identity federation and production. A green source or fixture test cannot
promote Kratos/Hydra/Keycloak support above PARTIAL, change a canonical
capability or grant authority. Protected DEV-13 requires independent
staging account, credentials, roles, images, source pins, security and
operations approval; production has a separate GO. This is the same truth
boundary applied to EA-XB v1.1 XB-CORE and XB-NET external/independent
enterprises. Their business outcomes are **not** established by token proof.
