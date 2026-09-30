# Gate IAM-M4 — Workload identity on Hydra

**Status:** Client-credential migration scaffold hardened; federated path selected and awaiting live proof  
**Date:** 2026-09-30  
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
- [ ] live Hydra client + token evidence.

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
| Live Ory stack evidence | PR #42 currently has offline/CI evidence only |
| Platform projected-token issuer/JWK | Infrastructure must provide the assertion issuer and signing-key lifecycle |
| Hydra access-token claim proof | Consumer requires `actor_type=workload`; this must be proven from live token output rather than assumed |
| Resource consumer E2E | status cannot move ACTIVE before Subscriptions/Payments accept the token |

## 7. Rollback

M4-F rollback is to stop issuing/exchanging projected assertions and keep the
Shared workload lifecycle non-ACTIVE. It is **not** to introduce a client
secret.

## Document control

| Version | Date | Change |
|---|---|---|
| 0.1–0.3 | 2026-09-27..30 | Original client-credential M4 scaffold |
| 0.4 | 2026-09-30 | Split M4-C/M4-F; selected RFC7523; made Shared authoritative; defined activation evidence |
