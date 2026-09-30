# IAM-M4 live evidence checklist (non-production)

**Purpose:** Live evidence for the Ory workload migration.  
**Does not:** change production IssuerTrust, retire Keycloak, or mark a federated workload ACTIVE without consumer proof.  
**Canonical workload authority:** `baobab-platform/shared/contracts/identity/v1/workload-registry.yaml`

## 0. Preconditions

- [ ] PR #42 branch or merged equivalent checked out
- [ ] pinned Kratos/Hydra images match `provider.lock.yaml`
- [ ] no production Kubernetes/cloud context selected
- [ ] generated client secrets, JWT assertions and access tokens will not be attached to tickets or committed

## 1. Foundation evidence

Bring up the non-production Ory stack and record:

| Evidence | Expected |
|---|---|
| Kratos readiness | HTTP 2xx |
| Hydra readiness | HTTP 2xx |
| image digest verification | matches lock |
| provider smoke | PASS |

This remains PB-R1/PB-R2 until executed by an environment with container access.

## 2. M4-C — existing client-credential workload

Use an ACTIVE Shared workload such as `baobab-trade-workload`.

Extract that workload's **canonical** allowed scopes from Shared. For Trade they
are currently:

```text
context:resolve
provider-migration:task
```

Provision one workload at a time:

```bash
export ORY_PROVISION=1
export ORY_ACTION=provision
export ORY_LOGICAL_CLIENT_ID=baobab-trade-workload
export ORY_ALLOWED_SCOPES=context:resolve,provider-migration:task
export ORY_SECRET_OUTPUT_DIR=/private/runtime/handoff
go run ./cmd/provision-workload/
```

Expected:

- stable Hydra client ID;
- no non-canonical `context-resolve`;
- no `actor-type-workload` authorization scope;
- secret written to the private handoff directory, never printed;
- resulting token profile still requires live audience/claim verification.

Then exercise disable and rotate. Rotate also requires
`ORY_SECRET_OUTPUT_DIR`.

## 3. M4-F — federated workloads

Do **not** run `cmd/provision-workload` for:

- `baobab-cp-workload`;
- `baobab-subscriptions-workload`.

The CLI deliberately rejects them because Shared says their credential type is
`federated_workload_token`.

Follow `docs/operations/m4f-federated-workload-activation.md`.

### 3.1 CP -> Subscriptions evidence

Record only non-secret facts:

| Assertion | Required |
|---|---|
| projected assertion has exact trusted issuer + workload subject | PASS |
| assertion audience is Hydra token endpoint | PASS |
| Hydra JWT-bearer grant succeeds | PASS |
| Hydra access token issuer/signature accepted by Subscriptions | PASS |
| audience | `baobab-subscriptions` |
| client identity | `baobab-cp-workload` |
| actor type | `workload` |
| scopes | subset of `billing:manage billing:read` |
| CP token-file call reaches Subscriptions | PASS |

### 3.2 Subscriptions -> Payments evidence

This leg cannot be marked complete until Subscriptions has an implemented
outbound payment-execution adapter that actually presents the workload token.
Payments already has a workload JWT verifier, but architecture prose is not an
E2E caller.

Required once that adapter exists:

| Assertion | Required |
|---|---|
| Hydra JWT-bearer grant succeeds | PASS |
| Payments verifies issuer/JWKS | PASS |
| audience | `baobab-payments` |
| client identity | `baobab-subscriptions-workload` |
| actor type | `workload` |
| scopes | subset of `payment:execute payment:refund payment:read` |
| real Subscriptions -> Payments call | PASS |

## 4. Canonical lifecycle

Only after the corresponding consumer evidence is green may Shared change:

```text
PROVISIONED -> ACTIVE
```

Provider configuration alone is never the activation event.

## 5. Open technical proof

Hydra must be proven to produce the existing Baobab resource-token profile,
particularly the logical API audience and `actor_type=workload`, without
putting tenant/legal-entity/business authority in IAM. If the stock JWT-bearer
grant does not emit those claims, use a provider-supported token hook/profile
mechanism or amend the IAM implementation before activation. Do not weaken the
consumer verifiers.

## Document control

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-09-30 | Initial M4 client-credentials checklist |
| 2.0 | 2026-09-30 | Reconciled to Shared; split M4-C/M4-F; defined consumer activation evidence |
