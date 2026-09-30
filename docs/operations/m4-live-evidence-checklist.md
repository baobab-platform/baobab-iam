# M4 / foundation live evidence checklist (non-production)

**Purpose:** Operator record for live Ory foundation + first Hydra workload client.  
**Does not:** Touch production Keycloak, CP IssuerTrust, or estate redirect URIs.  
**Refs:** ADR-IAM-0021; ADR-0007; `gate-iam-m4-workload-hydra-scope.md`; `phase-b-closeout.md`  

Fill this on a workstation with Docker and registry access. Attach logs or redact screenshots to the PR / ticket.

---

## 0. Preconditions

- [ ] Branch `feat/adr-iam-ory-migration` (or merged equivalent) checked out
- [ ] `provider.lock.yaml` shows **v26.2.0** digests for kratos + hydra
- [ ] No production kube context selected (`kubectl config current-context` reviewed)
- [ ] Secrets will not be committed (CLI redacts; do not paste full secrets into tickets)

---

## 1. Foundation bring-up (M2/M3)

```bash
docker compose -f docker-compose.ory.yml pull
docker compose -f docker-compose.ory.yml up -d
# wait for healthy
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4434/admin/health/ready
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:4445/admin/health/ready
```

| Step | Expected | Result (operator) | Date / by |
|------|----------|-------------------|-----------|
| Compose up | containers running | | |
| Kratos admin ready | HTTP 2xx | | |
| Hydra admin ready | HTTP 2xx | | |
| Image digests match lock | `docker image inspect` / compose config | | |

---

## 2. Adapter smoke (M2/M3-C)

```bash
export ORY_SMOKE=1
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
go test ./internal/provider/ory/ -count=1 -run TestSmoke_ProviderInfoAgainstLocalStack -v
```

| Step | Expected | Result | Date / by |
|------|----------|--------|-----------|
| CheckReady both planes | PASS | | |
| ProviderInfo name=ory | PASS | | |
| Capabilities human+workload | PASS | | |

---

## 3. First workload client — `baobab-trade-workload` (M4)

```bash
export ORY_PROVISION=1
export ORY_ACTION=provision
export ORY_LOGICAL_CLIENT_ID=baobab-trade-workload
# optional: ORY_ALLOWED_SCOPES=actor-type-workload,context-resolve
go run ./cmd/provision-workload/
```

| Step | Expected | Result | Date / by |
|------|----------|--------|-----------|
| CheckReady before provision | no error | | |
| `logical_client_id=baobab-trade-workload` | stable ID | | |
| `provider_client_id` equals logical ID | yes | | |
| Scope contains `context-resolve` not `context:resolve` | TRANSLATE applied | | |
| Secret printed only redacted | yes | | |

### 3.1 client_credentials token (non-prod only)

Obtain a token from the **public** Hydra token endpoint using the provisioned secret (operator secret store — not Git). Confirm:

| Assertion | Result | Date / by |
|-----------|--------|-----------|
| HTTP 200 token response | | |
| Token usable against a non-prod resource or introspection (optional) | | |

Record **token endpoint URL** and **client_id** only — never the secret.

---

## 4. Disable / rotate (M4 lifecycle)

```bash
export ORY_ACTION=disable
go run ./cmd/provision-workload/
# re-enable path is re-provision or explicit grant restore — document what you did

export ORY_ACTION=rotate
go run ./cmd/provision-workload/
```

| Step | Expected | Result | Date / by |
|------|----------|--------|-----------|
| Disable clears grants (token fails) | | | |
| Rotate yields new secret; old secret fails | | | |

---

## 5. Rollback sanity (dual-run future)

- [ ] Keycloak client JSON under `config/clients/baobab-trade-workload.json` unchanged
- [ ] No production IssuerTrust or redirect URI edits in this exercise
- [ ] If dual-run is later authorized, Hydra disable does **not** require Keycloak delete (`migration-rollback-baseline.md`)

---

## 6. Sign-off

| Role | Name | Date | Notes |
|------|------|------|-------|
| Operator | | | |
| Reviewer (optional) | | | |

When this checklist is green, update:

- `docs/governance/gate-iam-m2-m3-ory-foundation-scope.md` exit criteria 5–6
- `docs/governance/gate-iam-m4-workload-hydra-scope.md` exit criteria 1, 4, 5
- Link evidence from `phase-b-closeout.md` residual table (PB-R1–R4)

---

## Document control

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-09-30 | Initial operator checklist (Phase B closeout) |
