# config/ory — Ory configuration as code (Gate IAM-M2/M3)

This directory will hold **versioned** Kratos and Hydra configuration for the
non-production foundation stack defined in `docker-compose.ory.yml`.

## Ownership (ADR-IAM-0021 / 0020)

| Concern | Owner |
|---------|--------|
| Kratos identity schema, flows, courier | `config/ory/kratos/` (this repo) |
| Hydra OAuth/OIDC server URLs & strategy | env + later `config/ory/hydra/` |
| Logical client IDs / Baobab scopes | existing `config/clients/`, `config/scopes/` (names PRESERVE) |
| Canonical identity / tenancy | `baobab-cp` — never Ory config |
| Secrets | platform secret store / Compose env — **never Git** |

## Layout (target)

```text
config/ory/
  README.md          # this file
  kratos/
    kratos.yml       # serve config (M2-B)
    identity.schema.json
  hydra/             # optional file-based config if not env-only (M3-B)
```

Until M2-B/M3-B land, Compose may fail if mount paths are empty — that is
expected. Add minimal valid configs in the next foundation commit before
claiming health checks green.

## Related

- `provider.lock.yaml` — image tags/digests
- `docs/governance/gate-iam-m2-m3-ory-foundation-scope.md`
- `internal/provider/ory` — admin API adapter
