# Gate IAM-M4 — Client inventory (workload candidates)

**Status:** Inventory complete from `config/clients/*.json` + M0 baseline §4  
**Date:** 2026-09-27  
**Gate:** IAM-M4 (ADR-IAM-0019 workloads-first; ADR-0007; ADR-0020 WorkloadProvisioner)  
**Source of truth for IDs:** `config/clients/` (logical client IDs are **PRESERVE** / freeze list M0 §13)  
**Does not:** Provision production Hydra clients or change Keycloak live config  

---

## 1. Classification legend

| Class | Meaning for M4 |
|-------|----------------|
| **M4-PRIMARY** | Service-account / client_credentials style — first slice on Hydra |
| **M4-DEFER** | Resource-server / bearer-only audience client — Hydra resource registration may follow, not first bootstrap |
| **LATER** | Browser / workforce SSO (authorization_code + PKCE) — needs Kratos login/consent (M6+) and estate UX (ADR-0023) |

**Stability rule (ADR-0019 §50):** Hydra `client_id` SHOULD equal the logical `clientId` from config so CP and engines need not rename references.

**Authz rule (ADR-0020):** scopes and client metadata MUST NOT become the source of truth for Tenant, LegalEntity, or Capability — those remain CP / domain engines.

---

## 2. Full inventory

| Logical client ID | Keycloak shape (from JSON) | Class | Target grant (Hydra) | Notes |
|-------------------|----------------------------|-------|----------------------|-------|
| `baobab-trade-workload` | confidential; `serviceAccountsEnabled: true`; standard/implicit/direct off | **M4-PRIMARY** | `client_credentials` | **Preferred first non-prod target** (M0 §4) |
| `baobab-cms-workload` | same pattern | **M4-PRIMARY** | `client_credentials` | |
| `baobab-erp-workload` | same pattern | **M4-PRIMARY** | `client_credentials` | |
| `baobab-pulse-workload` | same pattern | **M4-PRIMARY** | `client_credentials` | |
| `thamani-backend-workload` | same pattern | **M4-PRIMARY** | `client_credentials` | |
| `zuribeans-backend-workload` | same pattern | **M4-PRIMARY** | `client_credentials` | |
| `baobab-control-plane` | `bearerOnly: true`; no service account | **M4-DEFER** | resource / audience style | Not a token-minting workload client |
| `baobab-trade` | resource-style (see config) | **M4-DEFER** | resource / audience | |
| `baobab-cms` | resource-style | **M4-DEFER** | resource / audience | |
| `baobab-erp` | resource-style | **M4-DEFER** | resource / audience | |
| `baobab-pulse` | resource-style | **M4-DEFER** | resource / audience | |
| `baobab-control-plane-admin` | workforce; standard flow | **LATER** | auth code + PKCE | M6 / ADR-0009 |
| `baobab-trade-admin` | confidential; standard flow; PKCE S256; redirect localhost:9000 | **LATER** | auth code + PKCE | Gate IAM-5 phase 2a heritage |
| `baobab-cms-admin` | workforce admin | **LATER** | auth code + PKCE | |
| `baobab-erp-admin` | workforce admin | **LATER** | auth code + PKCE | ADR-0014 email-match deviation remains product concern |
| `zuribeans-web` | browser | **LATER** | auth code + PKCE | Estate UX ADR-0023; isolation tests PRESERVE |
| `thamani-web` | browser | **LATER** / product DEFER | auth code + PKCE | M0 notes B2C/B2B forks |

---

## 3. M4-PRIMARY scope attachment (from config)

Workload JSON files currently list default client scopes including Baobab-specific names. For Hydra provisioning via `WorkloadProvisioningSpec.AllowedScopes`, use the **Baobab freeze-list names** (M0 §5), not Keycloak built-ins as the long-term contract.

| Scope (freeze / config) | On workload defaults today | M4 guidance |
|-------------------------|----------------------------|-------------|
| `actor-type-workload` | yes (`actor-type-workload`) | **PRESERVE** — attach on workload clients |
| `context-resolve` | appears as `context:resolve` in Keycloak client JSON | **PRESERVE** name `context-resolve` per M0 §5 / scopes file; treat `context:resolve` as Keycloak-era spelling to **normalize** at TRANSLATE time, not as a second product scope |
| `openid` / `profile` / `email` / `roles` | Keycloak defaults | OIDC standards / optional; do not invent Baobab business scopes |
| `web-origins`, `acr`, `address`, `phone`, `offline_access`, `microprofile-jwt` | Keycloak defaults | Map only if still required after TRANSLATE; do not block M4 on full parity |

**Normalization note:** `config/scopes/context-resolve.json` is the Baobab artifact name. Keycloak client JSON uses `context:resolve`. M4 translation MUST pick one stable OAuth scope string and document it; preferred stable string is **`context-resolve`** to match the scopes tree and M0 freeze table. Changing meaning still requires ADR; changing only the delimiter is TRANSLATE under M0 classification.

---

## 4. Suggested non-prod bootstrap order

1. Foundation healthy (`docker-compose.ory.yml` + smoke) — M2/M3.
2. Provision **`baobab-trade-workload`** via `WorkloadProvisioner` / Ory adapter against **local or non-prod** Hydra only.
3. Obtain `client_credentials` token; validate `actor-type-workload` (and agreed context scope) appear as configured.
4. Exercise **DisableWorkload** and **RotateWorkloadCredentials** on that client.
5. Repeat for remaining M4-PRIMARY IDs before any shared non-prod dual-run with Keycloak workloads.

Do **not** delete or disable production Keycloak service accounts under this gate.

---

## 5. WorkloadProvisioner mapping

| Spec field | Source |
|------------|--------|
| `LogicalClientID` | `clientId` from JSON (e.g. `baobab-trade-workload`) |
| `DisplayName` | `name` |
| `AllowedScopes` | freeze-list subset (§3) |
| `AuthMethod` | client secret (default); `private_key_jwt` only if later ADR requires |
| `Audiences` | resource client IDs as needed (e.g. control-plane / trade) — confirm LIVE-VERIFY |
| `Metadata` | operational only; never authorization authority |

Adapter behaviour (already on branch): Hydra `client_id` = `LogicalClientID` (idempotent PUT).

---

## 6. Evidence to attach when M4 executes

- [ ] Hydra admin shows client with stable id
- [ ] Token request succeeds in non-prod
- [ ] Scope set matches agreed freeze subset
- [ ] Rotate + disable paths exercised
- [ ] Keycloak counterpart still intact until dual-run decision

---

## 7. Related documents

| Doc | Path |
|-----|------|
| M4 scope | `docs/governance/gate-iam-m4-workload-hydra-scope.md` |
| M0 baseline (clients + freeze) | `docs/governance/gate-iam-m0-migration-baseline.md` §4, §5, §13 |
| Provider contract | `internal/provider` |
| Ory foundation smoke | `docs/operations/ory-foundation-smoke.md` |

---

## 8. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Inventory from config/clients + M0; preferred first client baobab-trade-workload |
