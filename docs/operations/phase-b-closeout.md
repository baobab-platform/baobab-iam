# Phase B closeout — Ory foundation and workload migration evidence

**Status:** In-repo hardening substantially complete; live M2/M3/M4 evidence still open  
**Date:** 2026-09-30  
**Branch / PR:** `feat/adr-iam-ory-migration` — PR #42  
**Normative ADRs:** ADR-IAM-0019, ADR-IAM-0020, ADR-IAM-0021, ADR-IAM-0022, ADR-0007

## What is now complete in repository

- pinned Ory foundation configuration and provider adapter;
- provider-neutral IAM contract surface;
- Kratos/Hydra readiness code;
- workload create/disable/rotate support for existing client-credential workloads;
- secure client-secret handoff for create/rotate;
- Shared contract pin updated to current `baobab-platform/shared`;
- Shared workload registry established as M4 authority;
- M4 scope spelling corrected to Shared's `context:resolve`;
- legacy `actor-type-workload` authorization-scope assumption removed;
- federated CP and Subscriptions workloads protected from client-secret downgrade;
- RFC 7523 selected as the initial Hydra exchange profile for
  `federated_workload_token`;
- M1-C provider-neutral CP evidence opened as `baobab-cp#225`;
- review defects corrected for cipher-key length, issuer propagation, migration
  state validation and workload secret handoff.

## Residual evidence register

| ID | Residual | Blocks |
|---|---|---|
| PB-R1 | Live Compose up and health against pinned images | M2/M3 |
| PB-R2 | Ory provider smoke against live stack | M2/M3 |
| PB-R3 | One Shared-authorized client-credential workload provisioned and token-tested | M4-C |
| PB-R4 | Rotate + disable exercised live | M4-C |
| PB-R5 | CP #225 merged | M1 |
| PB-R6 | Platform projected-token issuer + governed JWK available | M4-F |
| PB-R7 | Hydra trusted JWT issuer configured with exact subject and no wildcard | M4-F |
| PB-R8 | Hydra access token proven to satisfy Baobab audience/client/actor/scope profile | M4-F |
| PB-R9 | CP -> Subscriptions real call succeeds with federated token | `baobab-cp-workload` ACTIVE |
| PB-R10 | Subscriptions outbound Payments adapter exists and real call succeeds | `baobab-subscriptions-workload` ACTIVE |

## Important correction to the earlier closeout

The earlier M4 inventory was Keycloak-config-driven. That is no longer
acceptable after EA-04 introduced `federated_workload_token` in Shared.

The authoritative sequence is now:

```text
Shared workload registry
        |
        +--> credential profile
        +--> audience
        +--> scopes
        +--> lifecycle
        |
        v
IAM/Ory provider mechanics
        |
        v
actual resource-server verification
        |
        v
Shared lifecycle activation
```

## Exit decisions

- M1: **pending IAM #42 + CP #225 merge**
- M2/M3: **offline implementation ready; live evidence open**
- M4-C: **implementation ready; live provider evidence open**
- `baobab-cp-workload`: **PROVISIONED; do not mark ACTIVE yet**
- `baobab-subscriptions-workload`: **PROVISIONED; downstream caller not yet implemented**
- production dual issuer: **not authorized; M18**
- Keycloak retirement: **not authorized; M19**

## Why ACTIVE is intentionally withheld

For federated workloads, an ACTIVE status means the platform can prove the
workload can obtain a standards-based token and the intended resource server
will accept it under the unchanged Baobab workload profile.

A configured Hydra client or trusted JWT issuer is not enough evidence.

## Document control

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-09-30 | Original closeout |
| 2.0 | 2026-09-30 | Cross-repo EA-04 audit; Shared authority and M4-F activation gates |
