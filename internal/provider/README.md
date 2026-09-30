# internal/provider — Provider-neutral IdP contract (ADR-IAM-0020)

This package is the **Baobab Identity Provider Contract** introduced under
**Gate IAM-M1**. It is independent of the top-level `providers/` directory,
which holds Keycloak SPI JARs for the legacy runtime until Gate IAM-M19.

## Layout

```text
internal/provider/
  doc.go               # package overview
  provider.go          # ExternalSubject, types, capability interfaces
  errors.go            # ProviderError + kind helpers
  validate.go          # offline validation helpers
  factory.go           # ParseProviderName
  ory/                 # Ory Kratos (human) + Hydra (OAuth/workloads) adapter
  keycloak/            # Dual-run stub; most methods return ErrUnsupported
```

Related (not this package):

- `internal/migration` — migration ledger domain (Gate IAM-M5, ADR-0022)
- `cmd/provision-workload` — non-prod Hydra client provision helper (Gate IAM-M4)

## Rules (normative from ADR-0020)

- Baobab owns identity **meaning**; the configured provider owns **mechanics**.
- Standards (OIDC discovery, token, JWKS, PKCE, client credentials) stay direct —
  do not wrap them in proprietary Baobab endpoints.
- Business semantics (Tenant, LegalEntity, Market, Capability, domain authz)
  **never** appear in these interfaces (see IdentityProvisioningSpec.Validate).
- Canonical resolution remains `issuer + subject` → ExternalIdentity → CanonicalIdentity (CP).
- Prefer depending on the smallest capability interface, not the full `IdentityProvider` union.

## Capabilities

| Interface | Purpose |
|-----------|---------|
| `ProviderInfoSource` | Static/runtime provider metadata + capability flags |
| `IdentityReader` | Read human identity by ExternalSubject |
| `IdentityProvisioner` | Create/import human identities |
| `IdentityLifecycleManager` | Enable / disable |
| `SessionRevoker` | Provider-side session revocation (kill-switch half) |
| `WorkloadProvisioner` | OAuth client provision / disable / rotate |
| `IdentityReconciler` | Provider-boundary reconciliation |

## Gates

- **M1** — Land this package (no Ory runtime required).
- **M2/M3** — Pin and deploy Kratos/Hydra; flesh admin HTTP calls if needed.
- **M4+** — Workloads, migration ledger, dual-issuer (ADR-0022).
- **M19** — Remove `keycloak/` adapter and legacy Keycloak runtime.

See `docs/governance/gate-iam-m1-provider-neutral-contracts-scope.md`.
