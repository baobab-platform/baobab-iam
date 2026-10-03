# Ory live integration runbook (non-production)

**Audience:** engineers proving Kratos + Hydra admin integration on a workstation  
**Gates:** IAM-M2/M3 foundation evidence, IAM-M4 first workload  
**Does not:** production cutover, dual-issuer, Keycloak disable, human browser SSO (M6+)

Related: [ory-foundation-smoke.md](./ory-foundation-smoke.md), [gate-iam-m4-client-inventory.md](../governance/gate-iam-m4-client-inventory.md)

---

## 0. Preconditions

| Item | Notes |
|------|--------|
| Branch | PR #58 branch `feat/ory-m4-live-workload-evidence`, stacked on #57 (or main after merge) |
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

## 3. Automated isolated M4 proof

On a disposable non-production workstation with Go, Docker Compose and
Python/PyYAML available, run:

```bash
bash tests/ory-foundation/run.sh
```

The runner uses Compose project `ory-foundation-ci`, verifies exact provider
pins, loads three selected workload profiles from the exact Shared commit,
and requires explicit live PASS events for all M4 cases. For a private Shared
checkout, provide `SHARED_REPO_DIR` containing the pinned commit or `GH_TOKEN`
with read access. The GitHub workflow supplies the configured Shared read
token when available.

Evidence under `ory-foundation-evidence/` contains test results, a selected
Shared profile snapshot and safe token-profile observations. Workflow evidence
also includes runtime readiness, image pins, sanitized logs and commit SHA.
Client secrets, assertion private keys and access tokens stay in memory.

After a local run, tear down its disposable stack:

```bash
docker compose -p ory-foundation-ci -f docker-compose.ory.yml down -v --remove-orphans
```

The workflow always tears down and uploads evidence, including on failure.
The first successful [M4 live run](https://github.com/baobab-platform/baobab-iam/actions/runs/37158448607)
verified issuance and rejection mechanics but observed missing logical
consumer audiences and `actor_type=workload` on all three profiles. These
fixtures do not establish canonical ACTIVE or actual-consumer acceptance.

## 4. Manually provision one client-credentials workload

```bash
export ORY_PROVISION=1
export ORY_ACTION=provision
export ORY_LOGICAL_CLIENT_ID=baobab-trade-workload
# Use allowed_scopes from the selected workload at contracts.lock.yaml.
export ORY_ALLOWED_SCOPES=context:resolve,provider-migration:task
export ORY_SECRET_OUTPUT_DIR="$(mktemp -d)"
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444

go run ./cmd/provision-workload/
```

The CLI atomically writes the new secret to a mode-0600 file inside the private
`ORY_SECRET_OUTPUT_DIR` and prints only the handoff path. It never prints the
secret. Keep that file outside the repository and evidence artifacts. Re-running `provision` updates scopes/metadata and **does not** rotate the secret; use `ORY_ACTION=rotate` for rotation.

Verify client exists:

```bash
curl -sf http://127.0.0.1:4445/admin/clients/baobab-trade-workload | jq '{client_id,grant_types,scope,token_endpoint_auth_method}'
```

Expected grant: `client_credentials`. Authorization scopes must come from Shared's canonical workload registry. For `baobab-trade-workload`, use `context:resolve` and `provider-migration:task`. `actor-type-workload` is a legacy Keycloak claim-mapper scope, not a Baobab authorization permission.

---

## 5. Client-credentials token

The adapter registers `client_secret_post`. Supply the client ID and secret
in the form body; HTTP Basic is a different authentication method. This command
reads the secret from the handoff file without putting it in the process
argument list or printing the access token:

```bash
python3 - <<'PYTOKEN'
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request
client_id = os.environ['ORY_LOGICAL_CLIENT_ID']
secret = (Path(os.environ['ORY_SECRET_OUTPUT_DIR']) /
          (client_id + '.client-secret')).read_text().strip()
form = urllib.parse.urlencode({
    'grant_type': 'client_credentials', 'client_id': client_id,
    'client_secret': secret,
    'scope': os.environ['ORY_ALLOWED_SCOPES'].replace(',', ' '),
}).encode()
request = urllib.request.Request('http://127.0.0.1:4444/oauth2/token', data=form)
with urllib.request.urlopen(request, timeout=10) as response:
    token = json.load(response)
print(json.dumps({key: token.get(key) for key in ('token_type', 'expires_in', 'scope')}))
PYTOKEN
```

HTTP 200 and decoding a JWT payload do not prove its signature or Baobab
activation. The automated suite verifies the signature against public JWKS;
actual consumer acceptance remains required by the M4 gate.

---

## 6. Disable and rotate

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

## 7. Additional workloads

Provision client-credentials workloads individually using their own pinned
Shared scopes. `all-primary` is deliberately disabled. The client-secret CLI
cannot provision the CP or Subscriptions federated identities; use the dedicated
federation port with governed public signing keys. The live suite demonstrates
that port using ephemeral CI-only keys and exact issuer/subject trust.

Keep all `ORY_*` endpoints on this disposable non-production stack.

---

## 8. Evidence checklist (attach to PR / gate notes)

- [ ] Compose `ps` shows kratos + hydra up
- [ ] Health probes return success
- [ ] `baobab-trade-workload` present in Hydra admin
- [ ] `client_credentials` token succeeds with pinned Shared scopes
- [ ] Disable prevents token; provision restores grants
- [ ] Rotation invalidates the old secret; neither secret appears in logs
- [ ] Keycloak stack untouched
- [x] Digests recorded in `provider.lock.yaml` (v26.2.0, 2026-09-30)

---

## 9. Tear down

```bash
docker compose -f docker-compose.ory.yml down
# docker compose -f docker-compose.ory.yml down -v   # wipe local DBs
```

---

## 10. Adapter ↔ OpenAPI notes (v26)

| Operation | Method / path | Baobab code |
|-----------|---------------|-------------|
| Create identity | `POST /admin/identities` | `kratos.provisionIdentity` |
| Get identity | `GET /admin/identities/{id}` | `kratos.getIdentity` |
| Patch state | `PATCH /admin/identities/{id}` JSON Patch `/state` | `kratos.setIdentityActive` |
| Revoke sessions | `DELETE /admin/identities/{id}/sessions` | `kratos.revokeSessions` |
| Create client | `POST /admin/clients` | `hydra.postClient` |
| Get / set client | `GET` / `PUT /admin/clients/{id}` | `hydra.getClient` / `putClient` |

Live CI now exercises readiness, human lifecycle/session revocation, client creation/rotation/disable and JWT bearer trust/exchange. Credential imports remain unverified and disabled. Workload claim/audience integration and actual-consumer acceptance remain open.

---

## 11. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-28 | Initial live integration runbook |
| 0.2 | 2026-09-30 | Image pin corrected to published v26.2.0; digests recorded |

| 0.3 | 2026-10-03 | Added live M4 runner and profile blockers; corrected secret handoff and client_secret_post; removed disabled all-primary instructions |
