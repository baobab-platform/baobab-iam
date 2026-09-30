# IAM-M4F — Federated workload activation runbook

**Status:** Ready for operator evidence; canonical statuses remain PROVISIONED  
**Date:** 2026-09-30  
**Applies to:** `baobab-cp-workload`, `baobab-subscriptions-workload`

## 1. Why this path exists

These two workloads are intentionally registered in Shared with
`credential_type: federated_workload_token`. They SHALL NOT receive a static
client secret merely because Hydra supports `client_credentials`.

The selected initial Ory mechanism is the RFC 7523 JWT bearer authorization
grant.

## 2. Required runtime inputs

For each workload record:

- logical client ID from Shared;
- exact allowed scopes from Shared;
- exact downstream audience from Shared;
- platform projected-token issuer;
- workload-specific projected-token subject;
- signing public JWK + `kid`;
- Hydra public token endpoint;
- trust expiration/rotation policy.

The projected JWT audience MUST identify the Hydra token endpoint.

## 3. Hydra trust posture

Create a trusted JWT grant issuer using Hydra's admin API with:

- `allow_any_subject=false`;
- exact `issuer`;
- exact `subject`;
- explicit JWK;
- only the workload's Shared scopes;
- bounded `expires_at`.

Do not use wildcard subjects.

The corresponding OAuth client uses the stable workload ID and the JWT bearer
grant. It must not depend on a stored client secret.

## 4. Token exchange evidence

Obtain a fresh platform-projected JWT, then request a Hydra token using:

```text
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
client_id=<logical workload id>
assertion=<projected JWT>
scope=<subset of Shared scopes>
```

Never commit or attach the assertion or access token.

Record only:

- issuer;
- subject identifier class (not raw sensitive token);
- client ID;
- requested scopes;
- target audience;
- HTTP outcome;
- decoded non-secret claim names/values required by the Baobab token profile.

## 5. Consumer proof

### CP -> Subscriptions

The Hydra access token must pass the current Subscriptions workload verifier as
`baobab-cp-workload`, audience `baobab-subscriptions`, actor type
`workload`, with billing scopes only.

### Subscriptions -> Payments

The equivalent token must pass Payments as
`baobab-subscriptions-workload`, audience `baobab-payments`, actor type
`workload`, with payment scopes only.

## 6. Canonical activation

Only after sections 3–5 are green may a Shared PR change each corresponding
workload status from `PROVISIONED` to `ACTIVE`.

That Shared PR is the activation event. IAM/Ory configuration is provider
evidence, not canonical lifecycle authority.

## 7. Fail-closed rules

- no static secret fallback;
- no `allow_any_subject=true`;
- no scope outside Shared;
- no estate/tenant/legal-entity claims as authorization authority;
- no ACTIVE status based only on local smoke tests;
- no production issuer cutover from this runbook.

