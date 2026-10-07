# EA-01 — IAM Shared pin reconciliation

**Date:** 2026-10-04  
**Governing decisions:** EA Implementation Plan v2.0 sections 6, 8, 10 and 48;
Accepted ADR-SHARED-017 and ADR-IAM-0020/0022.  
**Previous pin:** `10810e20473709d4626da310fc9a84680f8efddd`  
**Reviewed target:** `6899a2d8f143bf23d36c4f4ac904e0a1e10c3cea`  
**IAM baseline:** `035fae168053fe91fdaa2c4218da12f36f75cb52`

IAM PRs #56–#60 are merged. Their tests establish isolated provider mechanics,
governed client-credentials claims and compatibility with CP's pinned production
verifier. They do not close federated resource audiences, deployed route
acceptance, infrastructure signer lifecycle or canonical activation.

## Consumed contract delta

The target is three commits ahead of the previous pin. All five locked contract
paths still exist. Git blob comparisons and parsed YAML comparisons establish:

| Contract | Change | IAM consequence |
|---|---|---|
| authorization/v1/scope-registry.yaml | Adds `context:validate`; every existing scope entry is semantically unchanged | Catalogue membership does not grant a scope. No IAM client or scope configuration changes |
| identity/v1/workload-registry.yaml | Documentation for explicit `validates_audiences` registration | Parsed registry is exactly equal: no identity, lifecycle, audience, scope or credential profile changes |
| control-plane/v1/access-token-claims.schema.json | Byte-identical | Existing token claim conformance retained |
| control-plane/v1/security-policy.yaml | Byte-identical | Existing required-claim/lifetime policy retained |
| identity/v1/capabilities.yaml | Byte-identical | Only the two existing canonical identity capabilities remain platform-resolvable |

The new validator scope is granted to no workload. A future grant must follow
Shared's explicit workload relationship and CP enforcement requirements; it
cannot be inferred from an existing workload's token audience or from this pin
update. See Shared `docs/architecture/context-authority-for-workloads.md`.

## Compatibility evidence

The re-pin PR must pass the existing exact-pin checks: issued scopes against
Shared, capability matrix/catalogue consistency, provider/migration tests,
Foundation contract checks, live Kratos/Hydra tests, governed workload profile
and pinned CP verifier tests, and the existing Keycloak integration. Evidence
links and final-head results are recorded in the PR; no passing status is
assumed before execution.

The CP verifier snapshot remains explicitly pinned to
`20235ac2c4e1c0285e747a5a4b41c1eefb3a4dd7`. Updating Shared does not claim
compatibility with a different CP revision or a deployed CP route.

## Operational and rollback implications

This changes the consumed contract revision, without provisioning a client,
issuing a new scope, activating a workload or changing production issuer trust.
The three federated workload records remain PROVISIONED. IAM provider support
remains planned-only until the complete canonical capability is evidenced.

If compatibility fails, retain the previous pin and remediate in the explicit
PR. A post-merge source rollback restores the previous immutable pin through a
reviewed PR; it does not revoke credentials, roll back deployment state or
alter canonical lifecycle. No permanent infrastructure deployment or Digital
Estate unfreeze is authorised by this reconciliation.

## 2026-10-07 — pin `6e9c686` → `e5faaaf` (shared#235, the audited ERP caller matrix)

Shared now allocates, as registry ceilings: `baobab-trade-workload` → `erp:read` and audience `baobab-erp`;
`baobab-erp-workload` → `context:validate` with `validates_audiences: ["baobab-erp"]`, and no longer `erp:read`/`erp:provision`; and a new
`PROVISIONED` `baobab-cp-provisioning-workload` (`erp:provision`, audience `baobab-erp`, federated). Allocation is not activation.

| Change | IAM consequence |
|---|---|
| `context:validate` allowed to `baobab-erp-workload` | New client scope `config/scopes/context-validate.json` (aud `baobab-control-plane`), default scope of the ERP client |
| `erp:read`/`erp:provision` removed from `baobab-erp-workload` | Removed from the client config; `bootstrap.sh` `revoke_client_scopes` removes them from existing deployments (the reconcile step only adds) |
| `erp:read` allowed to `baobab-trade-workload` with audience `baobab-erp` | Optional client scope on the Trade client, so default Trade tokens are not addressed to ERP (ADR-0007 sections 24-25) |
| `baobab-cp-provisioning-workload` is `PROVISIONED` | No client is created; `erp:provision` is issued to no one. Section 9 requires a client only for ACTIVE entries |

Not yet shown, so nothing here promotes any path to `ACTIVE`: ERP's acceptance of a Trade token, ERP's validation of that Trade
Context through the Control Plane, the cross-tenant negative tests, and the provisioner's federated credential exchange.
