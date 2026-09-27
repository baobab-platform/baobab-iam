# Ory foundation smoke (Gate IAM-M2/M3-C)

**Audience:** engineers validating the non-production Ory overlay  
**Does not:** touch production Keycloak, dual-issuer, or live client cutover  

---

## 1. Prerequisites

- Docker Compose available
- Network access to pull `oryd/kratos:v26.3.17` and `oryd/hydra:v26.3.17` (or mirrored images matching `provider.lock.yaml`)
- Branch with `config/ory/**` and `docker-compose.ory.yml`

---

## 2. Start foundation stack

```bash
docker compose -f docker-compose.ory.yml up -d
docker compose -f docker-compose.ory.yml ps
```

Expected:

| Service | Host port | Plane (ADR-0021) |
|---------|-----------|------------------|
| kratos | 4433 | public |
| kratos | 127.0.0.1:4434 | admin |
| hydra | 4444 | public |
| hydra | 127.0.0.1:4445 | admin |

Separate Postgres instances on 5433 (kratos) and 5434 (hydra).

---

## 3. Adapter smoke

```bash
export ORY_SMOKE=1
# optional overrides:
# export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
# export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
# export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444

go test ./internal/provider/ory/ -run TestSmoke_ProviderInfoAgainstLocalStack -count=1 -v
```

Without `ORY_SMOKE=1`, the test is skipped so offline CI stays green.

---

## 4. Manual health probes (optional)

```bash
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4433/health/ready
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4434/admin/health/ready
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4444/health/ready
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4445/admin/health/ready
```

Exact health paths may vary slightly by pinned Ory minor; prefer ready over live for dependency checks.

---

## 5. Stop

```bash
docker compose -f docker-compose.ory.yml down
# add -v to drop local Postgres volumes
```

---

## 6. ADR notes

- Admin traffic only from this host / tooling (ADR-0021 §8, §10).
- `PublicIssuer` in the adapter must match `urls.self.issuer` in `config/ory/hydra/hydra.yml` for subject stability checks.
- No production secrets; local placeholders only (ADR-0021 §40–41).
