# Gate IAM-M5 — Migration ledger and human identity path

**Status:** Phase C design active — domain model landed; **no production cutover**  
**Date:** 2026-09-30  
**Gate:** IAM-M5 (ADR-IAM-0019; ADR-IAM-0022 §7–23)  
**Depends on:** M1 contracts; M2/M3 foundation healthy; M4 non-prod workload path proven  
**Primary repos:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp` (ExternalIdentity / Principal continuity)  
**Does not:** Dual-issuer production traffic (M18), Keycloak retirement (M19), email-only identity matching  

---

## 1. Goal

Define and later implement an **auditable migration ledger** that maps each migrated
authentication binding without changing Baobab **canonical** identity.

Invariant (ADR-0022 §1):

```text
CanonicalIdentity (CP)
        │
        ├── ExternalIdentity (Keycloak issuer + subject)  [legacy]
        └── ExternalIdentity (Ory issuer + subject)       [target]
```

One person / one workload actor remains one `Principal` / CanonicalIdentity.
The ledger records **provider bindings**, not business authority.

---

## 2. Non-goals

| Non-goal | Why |
|----------|-----|
| Create CanonicalIdentity from email alone | ADR-0022 §7 — email is not authoritative |
| Store password hashes, TOTP secrets, or passkey material in the ledger | ADR-0022 §9 — sensitive credential material forbidden |
| Copy Keycloak roles into Ory as business authz | ADR-0022 §26–27 — CP / domain engines own authority |
| Mechanical “copy all Orgs/groups” into Ory | ADR-0022 §25 |
| Production dual-issuer cutover | M18 + IssuerTrust |
| Treat M5 as replacement for M4 workload path | Workloads remain M4-first (ADR-0019 order) |

---

## 3. Ledger minimum fields (ADR-0022 §9)

See `internal/migration/types.go` `Record` and Phase C design note.

**Persistence:** in-memory pilot store only under Phase C. Durable store is deferred.

---

## 4. State machine (ADR-0022 §10–11)

Happy path:

```text
DISCOVERED → VALIDATED → READY → PROVISIONING → PROVISIONED
  → CREDENTIAL_PENDING → CREDENTIAL_READY
  → VERIFICATION_PENDING → VERIFIED
  → CUTOVER_READY → CUTOVER → LEGACY_RETIRED
```

Failure / control states include BLOCKED, FAILED_*, ROLLED_BACK, QUARANTINED.

Implemented in `internal/migration/state.go`.

---

## 5–7. Classes, strategies, mapping

Unchanged from ADR-0022; see Phase C design §5–6 and existing scope body on branch history.

---

## 8. Ordering reminder

```text
M4  workload Hydra clients (non-prod first)
M5  ledger + human path (this gate)
…
M18 dual-issuer production
M19 Keycloak retirement
```

Do not start bulk human migration before M2/M3 foundation and M4 automation exist.

---

## 9. Related documents

| Doc | Path |
|-----|------|
| Phase C design | `docs/governance/gate-iam-m5-phase-c-design.md` |
| Phase B closeout | `docs/operations/phase-b-closeout.md` |
| ADR-0022 | `docs/adr/ADR-IAM-0022 — …` |
| M0 baseline | `docs/governance/gate-iam-m0-migration-baseline.md` |
| Rollback baseline | `docs/operations/migration-rollback-baseline.md` |
| M4 inventory | `docs/governance/gate-iam-m4-client-inventory.md` |
| Provider adapters | `internal/provider` |

---

## 10. Phase C

See **`docs/governance/gate-iam-m5-phase-c-design.md`** for Phase C design principles, ports, and authorized states.

Related ops closeout: `docs/operations/phase-b-closeout.md`.

---

## 11. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Design-only M5 scope from ADR-0022 §7–23 |
| 0.2 | 2026-09-30 | Phase C design note linked; greenfield no-cutover confirmation |
