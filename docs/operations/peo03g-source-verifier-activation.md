# PEO-03G — official-source verifier IAM activation boundary

Authority: ADR-IAM-0033; ADR-BCP-023/026/027; Shared PR #278 (merged `eecbc0edd957ac9b7a5bcd194529684824f38611`).

## Allocation — not activation

Shared declares `baobab-cipc-verifier-staging` in environment `staging` as `PROVISIONED`, `federated_workload_token`, audience `baobab-control-plane`, and scope `verification:source-capture` only. It must have an exact independently governed OIDC issuer and subject binding. No Keycloak static-secret or general-purpose verification administrator credential is permitted. The token-profile projector copies scope, audience, environment and state from pinned Shared; deployments can supply only the bound issuer/subject.

No registration, signed token, Shared allowance or synthetic HTTPS test grants CIPC verification, tax compliance, tenant activation, source-response custody rights or statutory authority. The CP resource server must require the current ACTIVE registry state as well as independently verified token signature, issuer, audience, actor_type=workload and exact scope.

## Activation proof to capture in protected staging

1. Select a real workload identity under controlled infrastructure, bind its exact issuer and subject, deploy the Hydra provider-neutral token exchange, and verify access-token claims without recording tokens.
2. Confirm CP has refreshed Shared to the exact pinned commit and configured only that client ID in its source-capture allowlist; configure certified official endpoints and credentials *only after separate provider authorization*.
3. Prove wrong issuer, subject, audience, source-capture scope, actor type, environment, unknown client, PROVISIONED/SUSPENDED/REVOKED state, forged supplier response, and replay with a mismatched case all deny.
4. Prove one allowed lookup through the CP OEV-03 pipeline yields a source observation receipt and sealed evidence only; no VERIFIED claim or admission outcome is produced automatically.
5. Gather reviewer approvals, code/CI evidence and staging run links. Only then request governed promotion from PROVISIONED to ACTIVE in a separate Shared PR. Do not treat the static file edit as live entitlement.

CP PRs #332 and #333 remain independent implementation dependencies. Real CIPC endpoint, subscription, provider schema, secure production object storage, SARS permissions and AWS trust are external acceptance gates. Never inject their secrets into GitHub or this repository.
