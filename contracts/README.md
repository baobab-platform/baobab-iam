# contracts/

Target path: `baobab-iam/contracts/`

This directory is reserved for **shared, versioned contract artifacts** that
cross repository boundaries (e.g. with `baobab-platform/shared` and
`baobab-cp`).

Examples of what belongs here later:

- JSON Schema / OpenAPI fragments for `Principal`, `ExternalSubject`, identity
  and security event payloads
- Locked scope definitions that must remain stable across the Keycloak → Ory
  migration
- Compatibility matrices (Kratos/Hydra version × PostgreSQL × adapter)

The Go types in `internal/provider` are the in-process contract. External
consumers should depend on the published contracts in `shared` once they are
extracted; do not import `internal/provider` from other repositories.

Until those shared contracts exist, treat this folder as a placeholder and keep
provider-neutral types inside `baobab-iam` only.
