# Phase C design — Gate IAM-M5 migration ledger (no production cutover)

**Status:** Design active — domain model + offline provision/credential helpers + opt-in live Ory wiring  
**Date:** 2026-09-30  
**Gate:** IAM-M5 (ADR-IAM-0019 §94; ADR-IAM-0022 §7–23)  
**Depends on:** Phase B scaffolding; live M4 evidence preferred for ORY_PROVISION path  
**Primary package:** `baobab-iam/internal/migration`  
**Does not:** Production cutover, dual-issuer traffic, Keycloak retirement, durable production ledger DB  

---

## 1. Intent

Phase C turns the M5 **scope** into an executable **design contract** for the migration ledger:

1. Every migrated authentication binding is an auditable row.
2. Canonical identity stays in **baobab-cp** (issuer+subject → Principal).
3. The ledger never becomes a second authority for Tenant / Capability / business roles.
4. No production cutover is performed under Phase C.

---

## 3. Package layout

| Path | Role |
|------|------|
| `internal/migration/types.go` | Record, classes, strategies, structural validation |
| `internal/migration/state.go` | Allowed transition graph + `Transition` |
| `internal/migration/store.go` / `memory.go` | RecordStore + pilot store |
| `internal/migration/service.go` | Register, ApplyTransition, SetTargetBinding |
| `internal/migration/ports.go` / `policy.go` / `discovery.go` / `batch.go` | Ports + RegisterBatch |
| `internal/migration/bridge.go` | ProvisionBridge (DISCOVERED→PROVISIONED) |
| `internal/migration/credential.go` | CredentialStage (PROVISIONED→CREDENTIAL_*) |
| `cmd/migrate-ledger-provision` | ORY_PROVISION=1 live bridge + credential stage |
| `internal/migration/*_test.go` | Offline + opt-in live tests |

### Work items

| Work item | Status | Notes |
|-----------|--------|-------|
| Forbidden metadata / secret field guards | **Done** | `checkForbiddenLedgerStrings` |
| RegisterBatch + ports + PhaseCPolicyGate | **Done** | |
| ProvisionBridge | **Done** | Fakes offline; Ory via ORY_PROVISION |
| CredentialStage | **Done** | No secrets on ledger; MarkReady for external proof |
| ORY_PROVISION live wiring | **Done** | CLI + `TestLive_ProvisionBridgeAndCredentialStage` |
| Durable store | Deferred | Memory pilot |
| Cutover / IssuerTrust | **Forbidden** | M18 |

---

## CredentialStage rules (ADR-0022 §16–20)

| Strategy | Apply result |
|----------|--------------|
| NO_CREDENTIAL_REQUIRED | → CREDENTIAL_READY |
| FIRST_LOGIN / RE_ENROLMENT / FEDERATED_REBIND / PASSKEY / MFA | → CREDENTIAL_PENDING |
| DIRECT_IMPORT | → CREDENTIAL_PENDING (provider-side import only) |

`RejectCredentialMaterial` always errors — secrets never enter the ledger.
`MarkReady` advances PENDING→READY after external proof (no secret parameters).

---

## Live opt-in (non-prod)

```bash
export ORY_PROVISION=1
export ORY_KRATOS_ADMIN_URL=http://127.0.0.1:4434
export ORY_HYDRA_ADMIN_URL=http://127.0.0.1:4445
export ORY_PUBLIC_ISSUER=http://127.0.0.1:4444
go run ./cmd/migrate-ledger-provision/
# or: go test ./internal/migration/ -count=1 -run TestLive_ProvisionBridgeAndCredentialStage
```

Requires healthy local Compose (Phase B PB-R1–R3). Does **not** attempt CUTOVER.

---

## Success criteria

1–9. [x] Prior Phase C items (ports, batch, bridge, design)
10. [x] CredentialStage PROVISIONED→CREDENTIAL_* (no secrets on ledger)
11. [x] ORY_PROVISION=1 CLI + live test wiring to Ory adapters

---

## Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-30 | Phase C design opened |
| 0.2 | 2026-09-30 | Ports, RegisterBatch, PhaseCPolicyGate |
| 0.3 | 2026-09-30 | ProvisionBridge |
| 0.4 | 2026-09-30 | CredentialStage + ORY_PROVISION live bridge wiring |
