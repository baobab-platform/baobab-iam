# Gate IAM-M4 — Workload identity on Hydra

**Status:** Live provider mechanics and opt-in M4-C token profile proven; M4-F profile issuance and canonical activation blocked  
**Date:** 2026-10-03  
**Gate:** IAM-M4 / EA-04  
**Depends on:** M1 provider contracts; M2/M3 live Ory foundation; Shared workload registry  
**Does not:** enable M18 human dual-issuer cutover or retire Keycloak

## 1. Goal

Move workload authentication to Ory without changing Baobab workload identity
meaning.

There are now two explicit sub-paths:

```text
M4-C
existing client_credentials workloads
        |
        v
Hydra client credential / later stronger client auth

M4-F
federated_workload_token workloads
        |
        v
platform-projected JWT assertion
        |
        v
Hydra RFC 7523 JWT bearer grant
        |
        v
short-lived access token
```

Shared selects the credential profile per workload.

## 2. Canonical authority

The authoritative input is:

`baobab-platform/shared/contracts/identity/v1/workload-registry.yaml`

IAM SHALL consume/preserve:

- logical workload ID;
- lifecycle state;
- credential type;
- allowed audience;
- allowed scopes.

`config/clients/*.json` is retained only as Keycloak migration evidence.

## 3. M4-C deliverables

- [x] provider-neutral `WorkloadProvisioner`;
- [x] Hydra create/update/disable/rotate adapter coverage;
- [x] secure generated-secret handoff;
- [x] canonical scope preservation (`context:resolve`);
- [x] Shared-registry IDs for Thamani/ZuriBeans;
- [x] fail closed unless `ORY_ALLOWED_SCOPES` is explicitly supplied;
- [x] live isolated Hydra client + cryptographically verified token evidence;
- [x] wrong credential and scope rejected; rotation invalidates old credential; suspension denies future issuance.

## 4. M4-F design

Initial federated workloads:

| Workload | Audience | Scopes |
|---|---|---|
| `baobab-cp-workload` | `baobab-subscriptions` | `billing:manage`, `billing:read` |
| `baobab-subscriptions-workload` | `baobab-payments` | `payment:execute`, `payment:refund`, `payment:read` |

ADR-IAM-0019 §93.1 / ADR-IAM-0021 §54.2 select RFC 7523 for the first Ory
implementation. No static OAuth client secret is permitted for these identities.

Required sequence:

```text
runtime projected JWT
  iss = platform workload-token issuer
  sub = workload-specific subject
  aud = Hydra token endpoint
        |
        v
Hydra trusted JWT issuer
  allow_any_subject = false
  subject = exact workload subject
  JWK = governed signing public key
  scope = Shared allowlist
        |
        v
JWT bearer authorization grant
        |
        v
Hydra access token
        |
        v
actual resource-server verifier
```

## 5. Activation criterion

A Shared lifecycle flip:

```text
PROVISIONED -> ACTIVE
```

is permitted only after live evidence proves the resulting access token is
accepted by its actual consumer and contains the existing Baobab workload token
profile.

For CP -> Subscriptions that means, at minimum:

- issuer/signature accepted by Subscriptions;
- audience `baobab-subscriptions`;
- workload client identity resolves to `baobab-cp-workload`;
- `actor_type=workload`;
- requested scope is a subset of `billing:manage billing:read`.

The same rule applies to Subscriptions -> Payments.

A Hydra client record, trusted-issuer record, or successful token endpoint HTTP
200 on its own is insufficient activation evidence.

## 6. Current blockers

| Blocker | Why it matters |
|---|---|
| Live Ory stack evidence | Closed for the isolated pinned stack by PR #57; M4 provider mechanics evidenced in PR #58 |
| Platform projected-token issuer/JWK | Infrastructure must provide the assertion issuer and signing-key lifecycle |
| Hydra access-token profile | Opt-in M4-C profile proven in PR #59. Pinned RFC 7523 copies the assertion audience into access tokens; the governed hook denies that M4-F mismatch |
| Resource consumer E2E | status cannot move ACTIVE before Subscriptions/Payments accept the token |

## 7. Isolated live M4 evidence

[PR #58](https://github.com/baobab-platform/baobab-iam/pull/58) stacks on the
foundation PR #57. [Live run 37158448607](https://github.com/baobab-platform/baobab-iam/actions/runs/37158448607)
passed at `e831a12512e43e232d2e6ee900b2045627b79a32`, using the Compose image
versions and digests in `provider.lock.yaml` (Hydra/Kratos v26.2.0).

The runner reads the selected profiles directly from Shared at the exact
`contracts.lock.yaml` commit. It creates disposable clients for
`baobab-trade-workload`, `baobab-cp-workload` and
`baobab-subscriptions-workload` inside an isolated local issuer. Assertions use
an ephemeral RSA signer and a synthetic `.invalid` issuer, not a deployed
platform issuer. No production credential, registry lifecycle or consumer
trust configuration is changed.

The tests verify RS256 signatures against Hydra's public JWKS, issuer, bounded
lifetime, stable `client_id`, exact signed scopes and provider subjects. Both
federated paths reject wrong issuer, subject, audience, expiry, not-before,
signature and scope, plus replay. Clients have no static secret; static-secret
rotation is rejected. Revocation prevents new exchanges. Client credentials
prove old-secret rejection after rotation and future-issuance rejection after
suspension. These commands do not invalidate every already-issued JWT.

The client-credentials token has an empty audience. Both federated tokens
carry `http://127.0.0.1:4444/oauth2/token` as audience, inherited from their
assertions by pinned Hydra v26.2.0. These are not the Shared logical consumer
audiences. All three baseline token profiles have `logical_audience_matches=false` and
`actor_type_is_workload=false`. Successful provider mechanics therefore do not
satisfy the existing Baobab token profile or close M4 activation. Profile JSON
artifacts explicitly record `canonical_activation_proven=false` and
`actual_consumer_tested=false`. HTTP 200 is never recorded as ACTIVE evidence.

The opt-in [PR #59 token-profile integration](../operations/ory-workload-token-profile.md)
now proves the M4-C logical audience, workload actor, stable authorized client,
string scopes and maximum 15-minute lifetime. It consumes the same exact Shared
pin and privately authenticated provider evidence. Pinned Hydra v26.2.0 cannot
remove its propagated assertion audience through the token hook; both M4-F
profiles are denied with `access_denied` by the governed policy. The baseline
foundation config is unchanged, and no provider pin is upgraded implicitly.

Remaining work: compatible M4-F resource audience mechanics, the real
infrastructure projected issuer and signing-key lifecycle, and live acceptance
by CP, Subscriptions and Payments as applicable. An isolated JWT test verifier
is not an actual resource server. The Shared federated entries stay
PROVISIONED. No Keycloak retirement or issuer cutover is attempted.

## 8. Rollback

M4-F rollback is to stop issuing/exchanging projected assertions and keep the
Shared workload lifecycle non-ACTIVE. It is **not** to introduce a client
secret.

## Document control

| Version | Date | Change |
|---|---|---|
| 0.1–0.3 | 2026-09-27..30 | Original client-credential M4 scaffold |
| 0.4 | 2026-09-30 | Split M4-C/M4-F; selected RFC7523; made Shared authoritative; defined activation evidence |

| 0.5 | 2026-10-03 | Recorded isolated M4-C/M4-F live evidence and observed token-profile activation blockers |
