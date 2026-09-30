# Phase C design — Gate IAM-M5 migration ledger (no production cutover)

**Status:** Design active — **implementation limited to domain model + in-memory store**  
**Date:** 2026-09-30  
**Gate:** IAM-M5 (ADR-IAM-0019 §94; ADR-IAM-0022 §7–23)  
**Depends on:** Phase B scaffolding; live M4 evidence preferred but **not** a hard block for design/domain work in greenfield  
**Primary package:** `baobab-iam/internal/migration`  
**Does not:** Production cutover, dual-issuer traffic, Keycloak retirement, durable production ledger DB  

---

## 1. Intent

Phase C turns the M5 **scope** into an executable **design contract** for the migration ledger:

1. Every migrated authentication binding is an auditable row.
2. Canonical identity stays in **baobab-cp** (issuer+subject → Principal).
3. The ledger never becomes a second authority for Tenant / Capability / business roles.
4. No production cutover is performed under Phase C.

```text
Keycloak (source)                    Ory (target)
 issuer_s + subject_s    ──ledger──►  issuer_t + subject_t
         \                           /
          \                         /
           └── CanonicalIdentity ──┘
                    (CP)
```

---

## 2. Design principles (normative citations)

| Principle | Source | Design implication |
|-----------|--------|-------------------|
| Map binding, do not fork identity | ADR-0022 §1, §7 | `canonical_identity_id` required; no email-only resolve |
| Ledger is not a secret store | ADR-0022 §9 | Reject password/TOTP/passkey/client_secret fields on records |
| Identity ≠ credential ≠ verified | ADR-0022 §15 | Distinct states; no collapse of PROVISIONED into VERIFIED |
| Workloads remain M4-first | ADR-0019 order | WORKLOAD rows may audit M4 clients; bulk human path is M5 |
| Dual-issuer is later | M18 | CUTOVER state may exist in the machine but is **not authorized** for production cohorts in Phase C |
| Rollback is first-class | ADR-0022; rollback baseline | `ROLLED_BACK` edges from mutation/failure states |

---

## 3. Package layout (current + Phase C target)

### Landed (design-complete domain)

| Path | Role |
|------|------|
| `internal/migration/types.go` | Record, classes, strategies, structural validation |
| `internal/migration/state.go` | Allowed transition graph + `Transition` |
| `internal/migration/store.go` | `RecordStore` interface |
| `internal/migration/memory.go` | In-memory pilot store (non-durable) |
| `internal/migration/service.go` | Register, ApplyTransition, SetTargetBinding |
| `internal/migration/ports.go` | DiscoveryPort, CanonicalResolver, PolicyGate |
| `internal/migration/policy.go` | PhaseCPolicyGate (deny CUTOVER), AllowAllPolicyGate |
| `internal/migration/discovery.go` | FixtureDiscovery, MapCanonicalResolver |
| `internal/migration/batch.go` | RegisterBatch |
| `internal/migration/*_test.go` | Offline unit coverage |

### Phase C design (not production runners)

| Work item | Status | Notes |
|-----------|--------|-------|
| Forbidden metadata / secret field guards | **Done** | `checkForbiddenLedgerStrings` on Record |
| Cohort / batch registration | **Done** | `Service.RegisterBatch` + `BatchRegisterRequest` |
| DiscoveryPort + FixtureDiscovery | **Done** | Fixture for greenfield; live Keycloak deferred |
| CanonicalResolver + MapCanonicalResolver | **Done** | In-memory map; CP RPC deferred |
| PolicyGate default deny CUTOVER | **Done** | `PhaseCPolicyGate` wired into `ApplyTransition` |
| Provision bridge to `IdentityProvisioner` / M4 | Design only | Call-out ports; no production worker |
| Durable store (Postgres / CP-owned) | Deferred | Memory store remains pilot |
| Cutover controller + IssuerTrust | **Forbidden in Phase C** | M18 |

---

## 4. Record shape (confirmed)

Minimum fields remain as in `gate-iam-m5-migration-ledger-scope.md` §3 and `types.go` `Record`.

**Hard rules enforced in domain code:**

1. `canonical_identity_id` non-empty (do not invent Principal from email).
2. Source `provider` + `issuer` + `subject` always required.
3. Target binding required once state ≥ `PROVISIONED` (see `targetOptional`).
4. No email-only canonical resolution (`ResolveCanonicalByEmailAlone` always errors).
5. Sensitive markers forbidden on snapshot references / error codes (Phase C guard).

---

## 5. State machine (operational notes)

Happy path (design):

```text
DISCOVERED → VALIDATED → READY → PROVISIONING → PROVISIONED
  → CREDENTIAL_PENDING → CREDENTIAL_READY
  → VERIFICATION_PENDING → VERIFIED
  → CUTOVER_READY → CUTOVER → LEGACY_RETIRED
```

**Phase C authorization:**

| State | Allowed in greenfield design tests? | Allowed in production? |
|-------|-------------------------------------|------------------------|
| DISCOVERED … VERIFIED | Yes (synthetic rows) | Only under later gate approval |
| CUTOVER_READY | Yes (synthetic) | Requires M18 prerequisites |
| CUTOVER / LEGACY_RETIRED | Synthetic only with AllowAllPolicyGate | **Not authorized** (PhaseCPolicyGate) |
| ROLLED_BACK / QUARANTINED | Yes | Yes when dual-run exists |

Workers must treat `CUTOVER` as a **policy gate**, not a mere enum value.

---

## 6. Mapping algorithm (Phase C design)

```text
1. DISCOVER source (issuer, subject) — FixtureDiscovery or future Keycloak export
2. Resolve CanonicalIdentity via CanonicalResolver — refuse email-only
3. No mapping → ORPHAN_CANDIDATE + placeholder canonical id
4. RegisterBatch → DISCOVERED rows with batch id
5. VALIDATED → READY when structural + class/strategy rules pass
6. PROVISIONING (later): HUMAN* → IdentityProvisioner; WORKLOAD → M4 Hydra
7. CREDENTIAL_* per strategy (no secret material on row)
8. VERIFICATION_PENDING → VERIFIED via non-prod proof
9. STOP before production CUTOVER unless M18 PolicyGate authorizes cohort
```

---

## 7. Ports (interfaces)

```text
DiscoveryPort       // ListSourceBindings — FixtureDiscovery landed
CanonicalResolver   // issuer+subject → canonical_identity_id — MapCanonicalResolver landed
IdentityProvisioner // already internal/provider — not wired in Phase C workers
WorkloadProvisioner // already internal/provider (M4) — not wired in Phase C workers
LedgerStore         // RecordStore — MemoryStore pilot
PolicyGate          // PhaseCPolicyGate default deny CUTOVER / LEGACY_RETIRED
```

---

## 8. Success criteria for Phase C (design exit)

1. [x] Scope doc + this design note published on the migration branch
2. [x] Domain state machine + validation covered by unit tests
3. [x] Forbidden sensitive-field guard on records
4. [x] Synthetic end-to-end **unit** flow DISCOVERED → VERIFIED (no network)
5. [x] Explicit list of deferred durable-store and cutover work
6. [x] No production IssuerTrust, dual-issuer, or Keycloak disablement
7. [x] DiscoveryPort / CanonicalResolver / PolicyGate ports + FixtureDiscovery
8. [x] RegisterBatch (maps + orphans) + Phase C deny CUTOVER tests

---

## 9. Risks

| ID | Risk | Mitigation |
|----|------|------------|
| M5-R1 | Operators treat CUTOVER as local-only flag | PhaseCPolicyGate + docs; rollback baseline |
| M5-R2 | Email merge creates duplicate Principals | Reject email-only resolve in code |
| M5-R3 | Secrets leak into ledger JSON | Forbidden marker validation |
| M5-R4 | Workload double-provision vs M4 | WORKLOAD strategy NO_CREDENTIAL_REQUIRED; prefer M4 client_id |
| M5-R5 | Durable store premature | Memory-only until dedicated persistence ADR/gate |

---

## 10. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-30 | Phase C design opened after Phase B closeout |
| 0.2 | 2026-09-30 | Ports, RegisterBatch, PhaseCPolicyGate implementation |
