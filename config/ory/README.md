# config/ory — Ory configuration as code (Gate IAM-M2/M3)

Versioned Kratos and Hydra configuration for the non-production foundation
stack in `docker-compose.ory.yml`.

## Ownership (ADR-IAM-0020 / 0021)

| Concern | Owner |
|---------|--------|
| Kratos identity schema, flows, courier | `config/ory/kratos/` |
| Hydra OAuth/OIDC server strategy | `config/ory/hydra/` |
| Logical client IDs / Baobab scopes | existing `config/clients/`, `config/scopes/` (names PRESERVE) |
| Canonical identity / tenancy / capability | `baobab-cp` — **never** Ory config (ADR-0021 §37) |
| Secrets | platform secret store / Compose env — **never production values in Git** (ADR-0021 §41) |

## Layout

```text
config/ory/
  README.md
  kratos/
    kratos.yml              # M2-B
    identity.schema.json    # human profile traits only (ADR-0021 §37)
  hydra/
    hydra.yml               # M3-B
```

### Identity schema rules (ADR-0021 §37)

**Allowed traits:** email, name, telephone where required, similar profile fields.

**Forbidden in Kratos schema:** `tenant`, `legal_entity`, `market`, `capability`,
buyer limits, supplier approval, ERP roles, or any Baobab business authority.

### Hydra role (ADR-0021 §9–11)

Hydra issues OAuth/OIDC tokens and holds OAuth **clients** (including workloads).
It does **not** store Baobab human identity as the system of record — that remains
Kratos (technical subject) + Control Plane (canonical Principal).

Login/consent URLs in `hydra.yml` are local placeholders until estate UX (ADR-0023).

## Local start

```bash
docker compose -f docker-compose.ory.yml up -d
# Kratos public  http://127.0.0.1:4433
# Kratos admin   http://127.0.0.1:4434  (localhost bind only)
# Hydra public   http://127.0.0.1:4444
# Hydra admin    http://127.0.0.1:4445  (localhost bind only)
```

Keycloak remains available via the default `docker-compose.yml`.

Adapter smoke (after containers are healthy):

```text
KratosAdminURL = http://127.0.0.1:4434
HydraAdminURL  = http://127.0.0.1:4445
PublicIssuer   = http://127.0.0.1:4444
```

## Related

- `provider.lock.yaml` — image tags/digests
- `docs/governance/gate-iam-m2-m3-ory-foundation-scope.md`
- `internal/provider/ory` — admin API adapter (ADR-0020)
