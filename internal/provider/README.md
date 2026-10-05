# internal/provider — Provider-neutral IdP contract (ADR-IAM-0020)

This package is the **Baobab Identity Provider Contract** introduced under
**Gate IAM-M1**. It is independent of the top-level `providers/` directory,
which holds retained Keycloak SPI JARs, including the permanent federation evidence bridge.
Accepted ADR-IAM-0033 supersedes global Keycloak retirement: Kratos owns native
humans, Hydra owns OAuth/workloads, and Keycloak remains enterprise federation.

## Layout

```text
internal/provider/
  doc.go               # package overview
  provider.go          # ExternalSubject, types, capability interfaces
  errors.go            # ProviderError + kind helpers
  validate.go          # offline validation helpers
  factory.go           # ParseProviderName
  ory/                 # Ory Kratos (human) + Hydra (OAuth/workloads) adapter
  enterprise.go        # EnterpriseFederationProvider capability port
  keycloak/            # Permanent enterprise adapter; separate legacy compatibility stub
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
| `EnterpriseFederationProvider` | Approved OIDC/SAML enterprise begin/complete; opaque event evidence |

## Gates

- **M1** — Land this package (no Ory runtime required).
- **M2/M3** — Pin and deploy Kratos/Hydra; flesh admin HTTP calls if needed.
- **M4+** — Workloads, migration ledger, dual-issuer (ADR-0022).
- **Historical M19** — Superseded by MP7 capability-specific reduction and
  MP18 migration reconciliation. Retain `keycloak.EnterpriseAdapter`, federation
  bridge/runtime, image pins and independent security maintenance.
- **MP3/MP4** — CP owns provider/support/bindings and resolution; IAM projects
  current approved runtime evidence and dispatches adapter mechanics.
  `ParseProviderName` is compatibility parsing, not capability resolution.

OIDC/SAML federation, maker/checker trust governance and PostgreSQL shared-state
recovery fencing are implemented. They are repository construction evidence,
not estate adoption or production acceptance. See the
[current programme status](../../docs/governance/iam-mp-programme-status.md).

See `docs/governance/gate-iam-m1-provider-neutral-contracts-scope.md`.
