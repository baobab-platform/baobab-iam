# M4 workload token-profile integration

PR #59 stacks on #58. This is an opt-in, private provider integration, not a public token endpoint or a resource-server proxy.

The Accepted ADR-0006 token profile, ADR-0007 workload boundaries, ADR-IAM-0020 provider boundary and ADR-IAM-0021 workload path govern this implementation. The exact Shared pin remains `10810e20473709d4626da310fc9a84680f8efddd`. Registry identity, credential profile, lifecycle, scopes and audiences remain Shared-owned. Separately governed deployment configuration supplies exact projected assertion issuer/subject bindings; request payload does not select them.

## Provider boundary

`internal/tokenprofile` evaluates authenticated provider evidence against an immutable configuration snapshot. `internal/provider/ory` implements Hydra's private token-hook protocol. A random, independent callback key authenticates Hydra; use private networking and protected secret injection in deployed environments. The hook never verifies ordinary incoming API tokens or wraps OAuth endpoints. Neither tenant nor canonical identity, context, capability or domain authority is emitted.

Only exact governed credential grants, subjects, scopes and audiences can receive `actor_type=workload`, stable `azp`, and a string `scope`. Unknown workloads and SUSPENDED/REVOKED/RETIRED registry states fail closed. PROVISIONED permits provider mechanics only; it is never activation evidence. The current hook is workload-only and rejects other grants; do not enable it globally on an issuer serving human/browser flows without the separately reviewed human integration.

The test runner generates its JSON profile projection using the same exact-Shared-pin reader as the capability validator. CI assertion bindings and signing keys are disposable `.invalid` fixtures. Production bindings must be reconciled with governed provider trust and real infrastructure issuer/key lifecycle. The standalone command accepts a trusted deployment projection, not user-provided configuration; metadata claiming a commit is not independent proof of its contents. Production delivery must generate and protect that projection from the pinned Shared source.

## Native audiences and claims

Hydra v26.2.0 accepts the client-credentials resource audience through its native `audience` form parameter and registered client audience. The hook validates the granted audience against Shared and refuses missing or unintended audiences. It does not rewrite `aud`.

Hydra `oauth2.allowed_top_level_claims` allows the existing Shared `actor_type`, `azp`, and `scope` claims; `strategies.jwt.scope_claim=string` preserves the consumer contract. `ttl.access_token=15m` matches the maximum enforced by current Subscriptions and Payments verifiers. The protected issuer, subject, expiry, signing key and JWT ID remain provider-owned. The hook returns only the three governed extra claims.

## Pinned RFC 7523 limitation

The pinned source `oauth2/session.go` reserves `aud` against token-hook overrides, while `fosite/handler/rfc7523/handler.go` copies assertion audiences into the access token. A valid assertion is addressed to the token endpoint, not the Shared logical consumer. Such a token is denied by the governed profile. Adding an `aud` extra claim would not fix this; broadening consumer audience trust would weaken the contract.

A compatible released runtime with supported assertion-audience omission and independent resource audience handling, or another separately governed provider integration, is required for full M4-F profile issuance. No image pin or consumer trust policy is changed here. Claim policy unit tests prove exact federation bindings and allowed resource audiences; the live fixture proves current incompatible issuance fails closed, not successful consumer activation.

## Reproduce and evidence

Run `bash tests/ory-foundation/run.sh`, then `bash tests/ory-foundation/token_profile.sh` against the disposable stack. The second script runs a temporary authenticated private hook, recreates only disposable Hydra with profile settings, and records safe evidence under `ory-foundation-evidence/token-profile/`. Its exit handler stops the hook and disposable Hydra and removes private key/config files. Run `docker compose -p ory-foundation-ci -f docker-compose.ory.yml down -v --remove-orphans` afterward. The workflow always tears down.

The live suite checks signed logical audience, actor classification, stable workload identity, string scopes and a maximum 15-minute lifetime, then tests wrong/missing audience, old credential rejection after rotation and future-issuance denial after suspension. The federated profile requires an OAuth `access_denied` from the policy for both CP and Subscriptions. Unit tests cover callback authentication, claim injection, body bounds, immutable policy, lifecycle, grant, subject, scope, audience and exact federation binding failures.

Raw access tokens, assertions, callback credentials and private keys are never evidence artifacts. Profile evidence explicitly keeps `canonical_activation_proven=false` and `actual_consumer_tested=false`. Shared lifecycle, actual consumer acceptance, deployed signing, cutover and retirement remain outside this proof.

## Source checks

- Pinned Hydra token-hook protocol: https://github.com/ory/hydra/blob/v26.2.0/oauth2/token_hook.go
- Reserved JWT claims: https://github.com/ory/hydra/blob/v26.2.0/oauth2/session.go
- Assertion audience propagation: https://github.com/ory/hydra/blob/v26.2.0/fosite/handler/rfc7523/handler.go
- Pinned configuration schema: https://github.com/ory/hydra/blob/v26.2.0/.schema/config.schema.json

Live validation is pending; do not treat these test implementations as execution evidence until CI passes.

