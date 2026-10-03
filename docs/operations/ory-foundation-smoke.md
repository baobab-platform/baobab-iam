# Ory foundation smoke (Gate IAM-M2/M3-C)

**Audience:** engineers validating the non-production Ory overlay  
**Does not:** touch production Keycloak, dual-issuer, or live client cutover  

For end-to-end workload provision + token steps, use
[ory-live-integration-runbook.md](./ory-live-integration-runbook.md).

---

## 1. Prerequisites

- Docker Compose available
- Network access to pull `oryd/kratos:v26.2.0` and `oryd/hydra:v26.2.0` (or mirrored images matching `provider.lock.yaml` digests)
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
- Image pins: see `provider.lock.yaml` (v26.2.0 digests resolved 2026-09-30).


## 7. Automated live gate

`.github/workflows/ory-foundation.yml` runs on pull requests and provides the
isolated M2/M3-C runtime evidence. Run the same test entry point locally with:

```bash
bash tests/ory-foundation/run.sh
```

The runner validates Compose images against `provider.lock.yaml`, starts separate
Kratos/Hydra databases, bounds startup/readiness, and enables the smoke and live
foundation tests. A skipped test is a gate failure. Live cases cover the authorized
human migration bridge, schema acceptance, read/disable/enable observations, and a
real native registration session that succeeds before revocation and is rejected
after revocation. Fixtures use random credentials and synthetic `.invalid` addresses;
no credential import or CP identity resolution is performed.

CI always tears down containers and volumes. The `ory-foundation-evidence` artifact
contains test events, readiness, image inventory, sanitized diagnostics, the lock
and tested commit. Credentials and response bodies are never written as evidence.
The local runner leaves its disposable stack available for diagnosis; remove it with
`docker compose -p ory-foundation-ci -f docker-compose.ory.yml down -v --remove-orphans`.

A green run closes foundation runtime verification, not production deployment,
canonical workload ACTIVE, credential-import certification, or resource-server
acceptance. Hydra token exchange and actual consumer enforcement belong to M4.
