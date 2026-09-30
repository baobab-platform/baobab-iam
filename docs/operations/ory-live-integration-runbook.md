# Ory live integration runbook (non-production)

**Audience:** engineers proving Kratos + Hydra admin integration on a workstation  
**Gates:** IAM-M2/M3 foundation evidence, IAM-M4 first workload  
**Does not:** production cutover, dual-issuer, Keycloak disable, human browser SSO (M6+)

Related: [ory-foundation-smoke.md](./ory-foundation-smoke.md), [gate-iam-m4-client-inventory.md](../governance/gate-iam-m4-client-inventory.md)

---

## 0. Preconditions

| Item | Notes |
|------|--------|
| Branch | `feat/adr-iam-ory-migration` (or main after merge) |
| Images | `oryd/kratos:v26.2.0`, `oryd/hydra:v26.2.0` per `provider.lock.yaml` (digest-pinned in Compose) |
| Registry | Docker Hub or mirror; digests recorded 2026-09-30 |
| Ports free | 4433, 4434, 4444, 4445, 5433, 5434 |

Admin planes must stay on **localhost** (ADR-0021).

---

## 1. Start stack

```bash
docker compose -f docker-compose.ory.yml up -d
docker compose -f docker-compose.ory.yml ps
```

Wait until `kratos` and `hydra` are healthy (migrate jobs completed).

### Health probes

```bash
curl -sf http://127.0.0.1:4433/health/ready && echo kratos-public-ok
curl -sf http://127.0.0.1:4434/admin/health/ready && echo kratos-admin-ok
curl -sf http://127.0.0.1:4444/health/ready && echo hydra-public-ok
curl -sf http://127.0.0.1:4445/admin/health/ready && echo hydra-admin-ok
```

If a path 404s on your exact patch level, check container logs and Ory version notes; prefer `/health/ready` over `/health/alive` for dependency readiness.

---

## 2. Adapter smoke (optional)

```bash
export ORY_SMOKE=1
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444

go test ./internal/provider/ory/ -run TestSmoke_ProviderInfoAgainstLocalStack -count=1 -v
```

Without `ORY_SMOKE=1` the test skips (CI-safe).

---

## 3. Provision first workload (M4-PRIMARY)

```bash
export ORY_PROVISION=1
export ORY_ACTION=provision
export ORY_LOGICAL_CLIENT_ID=baobab-trade-workload
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444

go run ./cmd/provision-workload/
```

**Save the redacted secret output offline** (create returns secret once). Re-running `provision` updates scopes/metadata and **does not** rotate the secret; use `ORY_ACTION=rotate` for rotation.

Verify client exists:

```bash
curl -sf http://127.0.0.1:4445/admin/clients/baobab-trade-workload | jq '{client_id,grant_types,scope,token_endpoint_auth_method}'
```

Expected grant: `client_credentials`. Authorization scopes must come from Shared's canonical workload registry. For `baobab-trade-workload`, use `context:resolve` and `provider-migration:task`. `actor-type-workload` is a legacy Keycloak claim-mapper scope, not a Baobab authorization permission.

---

## 4. Client-credentials token

```bash
# Replace SECRET with the value returned at create time (never commit it).
curl -sf -X POST http://127.0.0.1:4444/oauth2/token \
  -u 'baobab-trade-workload:SECRET' \
  -d 'grant_type=client_credentials' \
  -d 'scope=context:resolve provider-migration:task' | jq '{token_type,expires_in,scope}'
```

Optional: decode JWT payload (if access token is JWT in this config) and confirm `iss` matches `ORY_PUBLIC_ISSUER` / `urls.self.issuer` in `config/ory/hydra/hydra.yml`.

---

## 5. Disable and rotate

```bash
export ORY_ACTION=disable
go run ./cmd/provision-workload/
# token request should fail

export ORY_ACTION=provision   # re-enable grants without rotating secret
go run ./cmd/provision-workload/

export ORY_ACTION=rotate
go run ./cmd/provision-workload/
# use new secret for subsequent token calls
```

---

## 6. Optional: all M4-PRIMARY clients

```bash
export ORY_ACTION=all-primary
go run ./cmd/provision-workload/
```

Still non-prod only; do not point `ORY_*` URLs at production.

---

## 7. Evidence checklist (attach to PR / gate notes)

- [ ] Compose `ps` shows kratos + hydra up
- [ ] Health probes return success
- [ ] `baobab-trade-workload` present in Hydra admin
- [ ] `client_credentials` token succeeds with freeze scopes
- [ ] Disable prevents token; provision restores grants
- [ ] Rotate issues a new secret (redacted in logs)
- [ ] Keycloak stack untouched
- [x] Digests recorded in `provider.lock.yaml` (v26.2.0, 2026-09-30)

---

## 8. Tear down

```bash
docker compose -f docker-compose.ory.yml down
# docker compose -f docker-compose.ory.yml down -v   # wipe local DBs
```

---

## 9. Adapter ↔ OpenAPI notes (v26)

| Operation | Method / path | Baobab code |
|-----------|---------------|-------------|
| Create identity | `POST /admin/identities` | `kratos.provisionIdentity` |
| Get identity | `GET /admin/identities/{id}` | `kratos.getIdentity` |
| Patch state | `PATCH /admin/identities/{id}` JSON Patch `/state` | `kratos.setIdentityActive` |
| Revoke sessions | `DELETE /admin/identities/{id}/sessions` | `kratos.revokeSessions` |
| Create client | `POST /admin/clients` | `hydra.postClient` |
| Get / set client | `GET` / `PUT /admin/clients/{id}` | `hydra.getClient` / `putClient` |

Known follow-ups after first live run: confirm health path suffixes, password import field names against the exact patch release, and whether Hydra returns empty body on PUT.

---

## 10. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-28 | Initial live integration runbook |
| 0.2 | 2026-09-30 | Image pin corrected to published v26.2.0; digests recorded |
