# LA-05B — Provider-neutral legal-actor assessment token admission

**Authority:** Accepted ADR-IAM-0033 and ADR-BCP-027 LA-05, Shared PR #261, CP LA-05A PR #299.

IAM authenticates workload identity; it does not decide who is a seller, contracting party, invoice issuer or legal entity. Those are Control Plane facts checked *per operation*, independent of the actor's IAM access to its own tenant.

This increment registers an OIDC client-scope definition `legal-actor:assess` with audience `baobab-control-plane` and adds tokenprofile admission tests proving:
- a scope merely defined is never automatically granted;
- a workload whose approved canonical Shared profile lacks the scope cannot acquire it by requesting it;
- even once a profile allows it, default audience scopes remain unchanged;
- only explicit requested scopes, active canonical workload status, approved audience, binding and independently authenticated provider evidence can admit the scope;
- no `legal_actor`, `seller_of_record`, `legal_entity_id`, mandate or responsible corporate entity claim is minted into a token.

**Rollout hold:** This scope is intentionally **NOT added** to any `config/clients/*-workload.json` default or optional scopes. No Kratos, Hydra or Keycloak provider grant is activated by this PR. Before an actual staging issuer grant, a separate registered scope projection plus active workload registry permission, current provider and identity profile proofs, owner-bound `context:resolve`, CP LA-05A acceptance and downstream Trade/ERP/Payments/Trade Docs PEP tests must pass.

**Acceptable runtime sequence:** the engine obtains an authenticated workload access token for `baobab-control-plane` with `context:resolve` and the expressly approved `legal-actor:assess`, redeems a previously owned PlatformContext, then invokes CP for the exact role, activity, market, capability and operation. A legal-actor `AUTHORIZED` response still does not override provider readiness or engine-specific entitlements. Missing issuer scopes or registry permission remain DENY, not a reason to loosen CP policy.
