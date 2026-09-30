# Phase C design — Gate IAM-M5 migration ledger (no production cutover)

**Status:** Design active — domain model + offline provision/credential helpers + federated-first live wiring  
**Date:** 2026-09-30  
**Gate:** IAM-M5 (ADR-IAM-0019 §94; ADR-IAM-0021; ADR-IAM-0022 §7–23)  
**Primary package:** `baobab-iam/internal/migration`  
**Does not:** Production cutover, dual-issuer traffic, Keycloak retirement, durable production ledger DB, Shared lifecycle ACTIVE  

---

## Workload paths (ADR remediation post EA-04)

| Path | When | Provider API |
|------|------|--------------|
| **M4-F (default)** | WORKLOAD / SERVICE_INTEGRATION without allow-list | `FederatedWorkloadProvisioner` (RFC 7523) |
| **M4-C (explicit)** | `ClientSecretAllowList` + Shared scopes | `WorkloadProvisioner` + `client_secret` |

Hardcoded `actor-type-workload` bridge defaults are removed. Scopes/audiences come from
Shared-aligned `FederatedTrustTemplate` maps. Secrets and private JWKs never enter the ledger.

## Package layout

| Path | Role |
|------|------|
| `bridge.go` | ProvisionBridge — federated-first; M4-C allow-list |
| `credential.go` | CredentialStage (no secrets) |
| `cmd/migrate-ledger-provision` | ORY_PROVISION=1; default M4-F env contract |

## Live opt-in (M4-F)

```bash
export ORY_PROVISION=1
export ORY_ASSERTION_ISSUER=...
export ORY_ASSERTION_JWK_JSON='{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}'
export ORY_LOGICAL_CLIENT_ID=baobab-cp-workload
export ORY_ALLOWED_SCOPES=billing:manage,billing:read
export ORY_INTENDED_AUDIENCES=baobab-subscriptions
go run ./cmd/migrate-ledger-provision/
```

## Document control

| Version | Date | Change |
|---------|------|--------|
| 0.4 | 2026-09-30 | CredentialStage + ORY_PROVISION wiring |
| 0.5 | 2026-09-30 | Federated-first ProvisionBridge; M4-C allow-list only |
