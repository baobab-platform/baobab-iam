# IAM → Shared Canonical Capability Reconciliation — 10 November 2026

**Authority:** Accepted ADR-SHARED-017, EA-02B, ADR-IAM-0033.  
**Shared pin before this change:** `1517429bcae601a1b0288ca0279e524ce48a3d77` (2 IAM keys).  
**Shared pin after this change:** `004937ff2035fab4ac3b41e05c7887da7abe7014` (4 IAM keys; Shared #? 6 Nov native capability contracts).  
**Evidence class:** repository source and tests, not independently qualified provider/CP support.  
**State:** DEVELOPMENT PARTIAL; no capability activation, grants, tenant entitlement, binding or protected release.

## Catalogue versus IAM scaffold

| Canonical key | Contract | Provider declaration after reconciliation | Source-backed implementation evidence | Why support is PARTIAL |
|---|---|---|---|---|
| `identity.authentication.perform` | `identity/v1/human-authentication-request.schema.json`, `human-authentication-response.schema.json` | Kratos, Keycloak: PARTIAL (unchanged) | Native BFF server-owned OAuth Code+S256, state/nonce/callback, Kratos session; historical Keycloak native bridge | No independently qualified exact canonical browser contract or final estate acceptance on these provider bindings |
| `identity.authentication.assurance` | `identity/v1/assurance-evaluation.schema.json` (new pin) | **Kratos: PARTIAL (added)** | `internal/provider/ory/governed_human_handoff.go`, `internal/nativebff/handler.go`, `internal/provider/ory/governed_human_assurance_test.go` | Current AAL2, subject and revocation checks exist; canonical A1–A4 evaluator, A3 RP-bound passkey, A4 independent privileged hardware/context witness and accepted risk policy are not demonstrated |
| `identity.federation.enterprise` | `identity/v1/enterprise-federation-start.schema.json` (new pin) | **Keycloak: PARTIAL (added)** | `internal/provider/keycloak/enterprise.go`, `internal/federation/enterprise_dispatch.go`, `internal/provider/keycloak/enterprise_live_test.go`, `internal/federation/enterprise_dispatch_test.go` | OIDC/SAML trust-bound challenge and callback mechanics exist; complete canonical opaque-ref wire and independent CP resolution under this exact federation key remain unqualified |
| `identity.workload-token.issue` | `identity/v1/workload-token-request.schema.json`, `workload-token-response.schema.json` | Hydra: PARTIAL (unchanged) | `internal/provider/ory/hydra.go`, `internal/provider/ory/hydra_federated_workload_test.go`, `internal/provider/ory/token_profile_live_test.go` | Real registered workload activation, CP binding, resource-server acceptance and revocation replay still gate closure |

**Implementation source of truth:** `.baobab/capability-provider.yaml` states each provider's supported canonical major and evidence; `internal/provider/{ory,keycloak}/canonical_support.go` carries secret-free construction metadata, not authorisation. `.baobab/iam-capability-matrix.yaml` is the wider IAM engineering inventory. Its generated Markdown is not an independent registry.

## Implemented scaffold features that are *not* new platform capabilities

`identity.human.provision`, `identity.human.disable`, `identity.session.revoke`, `identity.workload.provision`, `identity.workload.disable` and `identity.workload.rotate` appear under `planned_capabilities`. Kratos Admin identity creation/state/session revocation and Hydra client provisioning provide actual source mechanics. Nevertheless, Shared `identity/v1/iam-management-operation.schema.json` explicitly describes these as **non-catalogued IAM management operations**, not consumer-resolvable capability contracts. Accepted EA-02B deferred sessions, revocation and lifecycle until a genuine consumer-invoked deprovisioning contract and saga exist. Do not convert adapter methods into CP tenant grants.

`identity.migration.map` remains a candidate because CP owns canonical Principal/ExternalIdentity mapping; no IAM provider may mint it. Provider readiness/adapter normalization, raw OIDC issuance mechanics, MFA policy, IAM roles, and Keycloak organisation membership are not separate platform capabilities.

## Known integration drift not promoted by this registration

1. `internal/federation/enterprise_dispatch.go` presently resolves CP `identity.authentication.perform`, not the newly catalogued `identity.federation.enterprise` key. Its tests have historically treated that federation key as invalid for this route. The PARTIAL declaration **does not** claim a current routed CP federation binding or authorize silently switching a live scope. Reconcile CP/Shared grant/binding/consumer contracts with a separate scoped exact-head test before activation.
2. Current BFF reads of Kratos AAL2 are **not** the full `identity.authentication.assurance` canonical evaluation for operation classes A1–A4. Distinguish protocol AAL from Baobab's canonical assurance result.
3. The Shared pin advances over earlier commits that modify authorization/workload registries. Existing CI must verify the pinned consumers, not infer compatibility from YAML parsing.

## Regression and exit conditions

- Run the normal Go provider tests and `scripts/iam_capability_matrix.py`.
- Validate the engine declaration against the pinned Shared `capability/v1/provider-declaration.schema.json`, its canonical catalogue and evidence paths.
- Verify direct canonical Go support metadata, matrix classification and provider declaration enumerate exactly the four catalogued keys with no unreviewed `IMPLEMENTED` promotion.
- Qualify complete A3/A4 assurance, Keycloak enterprise federation canonical request/response and exact CP capability resolution, native issuer/CP resource consumers, revocation, negative cross-tenant cases, and security dependency findings before any production claim.

**No new Shared catalogue keys are introduced:** all four contractually eligible IAM keys were already present in Shared main; the missing registration was in the IAM consumer pin, provider declaration and capability matrix.
