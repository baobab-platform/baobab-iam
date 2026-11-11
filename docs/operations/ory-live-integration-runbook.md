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

The optional [governed token-profile runner](./ory-workload-token-profile.md)
(`bash tests/ory-foundation/token_profile.sh`, after the foundation runner)
adds the Shared audience, workload claims, string scope and a 10-minute lifetime
(kept strictly under the verifiers' 15-minute maximum; see the linked profile document)
for the client-credentials fixture. It denies the current pinned RFC 7523
audience mismatch. Its private callback key/configuration is temporary input,
never evidence. The hook is workload-only; do not enable it globally on a
human/browser issuer. The workflow runs both baseline and profile proofs.

## 4. Validate an M4 workload plan offline

```bash
ORY_ACTION=plan \
ORY_LOGICAL_CLIENT_ID=baobab-trade-workload \
ORY_ALLOWED_SCOPES=context:resolve,provider-migration:task \
go run ./cmd/provision-workload/
```

The plan reports the pinned Shared revision, registered environment, requested
scope subset and derived resource audiences. The profiles in this command are
production identities. Use the owning approved issuer lifecycle for their
registration, disable and rotation.

## 5. Exercise client-credentials issuance

Use the disposable fixture and verification workflow in section 3 for local
testing. Its identities, secret custody and teardown are owned by that
workflow. Capture public issuer and resource readback separately for M4
acceptance.

## 6. Observe disable and rotation

Record the original issuer and consumer denial after disable. For rotation,
verify the intended new credentials and refusal of the previous credentials
through the owning lifecycle.

## 7. Additional workloads

Review each client-credentials workload against its own pinned Shared profile.
For CP or Subscriptions federated identities, use the dedicated
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


## Bounded current-CP route evidence

The current M4 runner also checks out CP at immutable commit
`c84063cb07dce76e1ffac4b12fa29c5e4e5ec855` (after #255), verifies clean source,
and compiles a test-only command against its unchanged production router.
It exercises `POST /v1/platform-context/validate` using genuine isolated Hydra
validator and subject tokens, registered audience checks, canonical caller
ownership, bounded contexts and active-tenant enforcement. Sixteen required
positive/negative scenarios and response/audit credential checks must pass.
See [consumer proof details](../../tests/consumer/README.md).

This produces `token-profile/cp-context-route.json`. The existing #60 verifier
artifact remains historical compatibility evidence at its own earlier pin.
The new artifact explicitly records fixture-only HTTP route execution,
`deployed_resource_route_tested=false` and `canonical_activation_proven=false`.
CI-only `m4-ci-*` profiles and registrations do not allocate production scopes
or validator audiences. Production databases, deployments and real registered
consumer acceptance remain unproven; EA-04 remains ADVANCED. The M4-F RFC 7523
resource-audience blocker, PROVISIONED workloads, dual-issuer rollout, cutover
and retirement gates are unchanged.
