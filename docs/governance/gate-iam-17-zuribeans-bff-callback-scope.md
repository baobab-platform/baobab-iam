# Gate IAM-17 — ZuriBeans BFF callback boundary

## Decision applied

The accepted IAM trust-boundary, OIDC/token-profile, ZuriBeans B2B, and Medusa integration decisions require Authorization Code with PKCE, exact redirect URIs, server-held sessions where a BFF is used, and a strict distinction between identity-side organisation association and Trade purchasing authority.

The repository's development client previously registered `http://localhost:3000/*`. That wildcard permitted any path on the local ZuriBeans origin to receive an authorization response and did not express the intended BFF boundary. The registered development redirect is now exactly:

```text
http://localhost:3000/api/auth/callback
```

The integration suite verifies both that exact callback is accepted and that another path on the same origin is rejected. Cross-estate redirect isolation remains covered in both directions.

## Authority boundaries

This change does not make a Keycloak Organization, organisation claim, login, or Medusa customer record into purchasing authority. Baobab IAM authenticates the human and maintains identity-side organisation participation. Control Plane resolves platform context. Baobab Trade resolves active buyer membership and authorizes each commercial action.

## Deployment dependency

The committed realm import is the reproducible local-development seed. Every deployed ZuriBeans origin must register its own exact HTTPS callback URI through the environment's governed IAM configuration. No production hostname is invented in this repository. Production readiness remains blocked until the deployment-specific callback is registered and the real browser-to-BFF-to-IAM flow passes against that environment.
