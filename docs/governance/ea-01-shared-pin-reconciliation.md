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

## 2026-10-07 — pin `363e0ea` → `70f92ee` (shared#251, the staging evidence provisioner; FB-05)

Shared registers `baobab-cp-provisioning-evidence-workload`: the Control Plane's provisioning execution worker as it runs in the **staging**
evidence environment only. Audience `baobab-erp`, the one scope `erp:provision`, the one context purpose `TENANT_PROVISIONING`,
`federated_workload_token`, status `ACTIVE` by owner ruling (2026-10-07) so the end-to-end proof can be produced. `baobab-cp-provisioning-workload`
is unchanged: production, `PROVISIONED`. Per ADR-IAM-0033 Hydra owns workload issuance; Keycloak is not involved and gains no client.

| Change | IAM consequence |
|---|---|
| New ACTIVE federated entry in `staging` | No Keycloak client is created and none is allowed: `tests/integration/run.sh` section 9 now requires a Keycloak client only for ACTIVE `client_credentials` workloads, and fails if any federated workload has one. `provision-workload` refuses a client secret for it, like the production provisioner. |
| Environment is part of the registry entry | The token-profile policy and projection builder now enforce it. `build_workload_token_profiles.py --environment <env>` refuses a workload of another environment, and the hook's configuration names the one environment its issuer serves; a staging workload is never issued by a production issuer or the reverse (ADR-0007 section 102). |

**Not shown, so this is not acceptance:** the projected assertion issuer and its key lifecycle (infrastructure), the Hydra trust binding in a
deployed staging issuer, and a Hydra that can issue `aud=baobab-erp` on the RFC 7523 path. Pinned Hydra v26.2.0 copies the assertion's
token-endpoint audience into the access token and the governed policy denies that; `oauth2.grant.jwt.omit_assertion_audience` exists in Hydra
OSS master but in no published OSS release. No provider pin changes here (owner decision 2026-10-07: wait for an OSS release). The Shared
entry being ACTIVE is not evidence that any of this works; FB-05 is accepted only by an end-to-end staging run.
