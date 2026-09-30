# Gate IAM-M4 — Canonical workload inventory

**Status:** Reconciled to Shared on 2026-09-30  
**Gate:** IAM-M4 / EA-04  
**Canonical authority:** `baobab-platform/shared/contracts/identity/v1/workload-registry.yaml`  
**Legacy discovery evidence:** `config/clients/*.json`  
**Does not:** mark a PROVISIONED workload ACTIVE without live token evidence

## 1. Rule

Keycloak client JSON is migration input. It is **not** the workload registry.

The M4 implementation SHALL preserve the logical IDs, credential type, audiences,
scopes and lifecycle recorded in Shared. Provider configuration may translate
those facts to Ory, but may not change their meaning.

## 2. Current canonical inventory

| Workload | Credential type | Status | Audiences | Canonical scopes | M4 treatment |
|---|---|---|---|---|---|
| `baobab-trade-workload` | `client_credentials` | ACTIVE | `baobab-control-plane` | `context:resolve`, `provider-migration:task` | migrate/provider-parity |
| `baobab-cms-workload` | `client_credentials` | ACTIVE | `baobab-control-plane` | `context:resolve`, `provider-migration:task` | migrate/provider-parity |
| `baobab-erp-workload` | `client_credentials` | ACTIVE | `baobab-control-plane`, `baobab-erp` | `context:resolve`, `erp:integrate`, `provider-migration:task` | migrate/provider-parity |
| `baobab-pulse-workload` | `client_credentials` | ACTIVE | `baobab-control-plane` | `context:resolve`, `provider-migration:task` | migrate/provider-parity |
| `thamani-backend` | `client_credentials` | ACTIVE | `baobab-control-plane` | `context:resolve` | preserve only; estate rollout paused |
| `zuribeans-backend` | `client_credentials` | ACTIVE | `baobab-control-plane` | `context:resolve` | preserve only; estate rollout paused |
| `baobab-cp-workload` | `federated_workload_token` | **PROVISIONED** | `baobab-subscriptions` | `billing:manage`, `billing:read` | **M4-F federated activation** |
| `baobab-subscriptions-workload` | `federated_workload_token` | **PROVISIONED** | `baobab-payments` | `payment:execute`, `payment:refund`, `payment:read` | **M4-F federated activation** |

## 3. Corrections to the original PR #42 inventory

The audit corrected three migration-branch assumptions:

1. `context:resolve` is the canonical Shared scope. The temporary
   `context-resolve` spelling is translated **back** to `context:resolve`.
2. `actor-type-workload` is a Keycloak claim-mapper/client-scope artefact,
   not a canonical Baobab authorization scope. Ory still must emit
   `actor_type=workload`, but that claim is not requested as business scope.
3. The canonical estate workload IDs are `thamani-backend` and
   `zuribeans-backend`, not the filenames ending in `-workload`.

## 4. Client-credential migration

`cmd/provision-workload` remains useful for current
`credential_type=client_credentials` workloads, with two fail-closed changes:

- `ORY_ALLOWED_SCOPES` is required and must come from the selected Shared
  registry entry;
- bulk `all-primary` provisioning is disabled because workloads have different
  canonical scope sets.

Generated/rotated Hydra secrets are written only to a private
`ORY_SECRET_OUTPUT_DIR` handoff (0700 directory / 0600 file) and never printed.

## 5. Federated workloads

`baobab-cp-workload` and `baobab-subscriptions-workload` SHALL NOT be passed
through the client-secret provisioning path. The CLI rejects that downgrade.

Their Ory path is the RFC 7523 projected-token profile defined by
ADR-IAM-0019 §93.1 and ADR-IAM-0021 §54.2.

They remain `PROVISIONED` until a live Hydra-issued access token passes the
real consumer verifier with:

- Hydra issuer/signature;
- intended service audience;
- `actor_type=workload`;
- stable workload client identity;
- only the scopes allowed by Shared.

## 6. Source-of-truth relationship

```text
Shared workload registry
        |
        +--> IAM/Ory provisioning
        |
        +--> CP workload validation
        |
        +--> Subscriptions / Payments verifier policy

Keycloak JSON
        |
        +--> legacy migration evidence only
```

## Document control

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-27 | Keycloak-derived inventory |
| 0.2 | 2026-09-30 | Replaced authority with Shared; added federated CP/Subscriptions workloads and scope corrections |
