# Gate IAM-M5 — Migration ledger and human identity path

**Status:** Design scope only — **do not implement production migration under this commit**  
**Date:** 2026-09-27  
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

`baobab-iam` SHALL maintain an auditable migration ledger. At minimum:

```text
migration_id
migration_batch_id
canonical_identity_id          # CP Principal / CanonicalIdentity id — never invent from email

source_provider                # keycloak
source_issuer
source_subject

target_provider                # ory
target_issuer
target_subject                 # Kratos identity id when human; Hydra client id when workload row

identity_class                 # see §5
credential_strategy            # see §6
migration_state                # see §4
verification_state
cutover_state

source_snapshot_reference      # pointer to redacted export / batch artifact — not secrets
attempt_count
last_error_code

created_at
started_at
verified_at
cutover_at
retired_at
```

**Persistence location (decision deferred to implementation PR):** durable store owned by IAM/CP with audit access; must support idempotent retries and never silent skip (ADR-0022 §11).

---

## 4. State machine (ADR-0022 §10–11)

Happy path:

```text
DISCOVERED → VALIDATED → READY → PROVISIONING → PROVISIONED
  → CREDENTIAL_PENDING → CREDENTIAL_READY
  → VERIFICATION_PENDING → VERIFIED
  → CUTOVER_READY → CUTOVER → LEGACY_RETIRED
```

Failure / control states (non-exhaustive):

```text
BLOCKED
FAILED_RETRYABLE
FAILED_MANUAL_REVIEW
ROLLED_BACK
QUARANTINED
```

Rules:

- Every mutation stage has a failure path.
- A record SHALL NOT be silently skipped.
- Identity provisioned ≠ credential ready ≠ verified (ADR-0022 §15).

---

## 5. Identity classes (ADR-0022 §12)

Classify before migration:

```text
HUMAN
WORKLOAD
PRIVILEGED_HUMAN
BREAK_GLASS
FEDERATED_HUMAN
SERVICE_INTEGRATION
TEST_OR_NONPRODUCTION
ORPHAN_CANDIDATE
```

| Class | Notes |
|-------|--------|
| WORKLOAD | Prefer **M4** path (Hydra client); ledger may still record binding for audit |
| HUMAN | Kratos provision + credential strategy; CP ExternalIdentity link |
| PRIVILEGED_HUMAN | Extra verification + MFA/passkey (ADR-0022 §22) |
| BREAK_GLASS | Separate procedure; never leave platform without emergency admin (§23) |
| FEDERATED_HUMAN | Rebind federation relationship; enterprise subject continuity (§24) |
| ORPHAN_CANDIDATE | Manual review; do not auto-attach to Principal |

---

## 6. Credential strategies (ADR-0022 §16–20)

Each human row receives an explicit strategy:

```text
DIRECT_IMPORT
FIRST_LOGIN_MIGRATION
CONTROLLED_RE_ENROLMENT
FEDERATED_REBIND
PASSKEY_RE_ENROLMENT
MFA_RE_ENROLMENT
NO_CREDENTIAL_REQUIRED
```

Constraints:

- No plaintext password export or universal temporary passwords (§17–18).
- Passkey/WebAuthn and TOTP import only where pinned Kratos version supports and tests prove it (§19–20).
- Recovery channels revalidated; do not trust unvalidated legacy recovery addresses (§21).

---

## 7. Mapping algorithm (high level)

```text
1. DISCOVER source (issuer, subject) from Keycloak export / Admin API
2. Resolve CanonicalIdentity via existing CP mapping — refuse email-only match
3. If no mapping → ORPHAN_CANDIDATE / manual review (do not invent Principal)
4. PROVISION target (Kratos human or confirm Hydra workload from M4)
5. Apply credential_strategy
6. Link ExternalIdentity (target issuer + subject) on same Principal
7. VERIFY non-prod login or token path
8. CUTOVER only under controlled cohort gates (later M-gates)
9. RETIRE legacy binding when policy allows
```

Provider adapter calls use `internal/provider` (ADR-0020). Business fields stay out of Kratos traits (ADR-0021 §37).

---

## 8. Deliverables for this gate (when implemented)

| Deliverable | Notes |
|-------------|--------|
| Ledger schema + storage ADR-aligned | Fields §3; no secrets |
| State transitions + idempotent workers | §4 |
| Classification job from Keycloak inventory | Uses M0 LIVE-VERIFY exports when available |
| Link to CP Principal without recreating | CP API / existing domain types |
| Non-prod pilot batch evidence | Small HUMAN + TEST_OR_NONPRODUCTION set |
| Runbook: rollback / quarantine | Aligns with `migration-rollback-baseline.md` |

**Out of this design stub:** production cohort cutover, IssuerTrust dual-run, estate UX.

---

## 9. Exit criteria (implementation phase)

1. [ ] Ledger schema reviewed against ADR-0022 §9 (no credential material).
2. [ ] State machine enforced in code; failed rows visible and not skipped.
3. [ ] Email-only attachment path rejected by tests.
4. [ ] At least one non-prod HUMAN row reaches VERIFIED without new Principal.
5. [ ] WORKLOAD rows either deferred to M4 tooling or recorded without human credential strategies.
6. [ ] Break-glass procedure documented and tested before any privileged cutover.
7. [ ] This document marked Complete with evidence links.

---

## 10. Ordering reminder

```text
M4  workload Hydra clients (non-prod first)
M5  ledger + human path (this gate)
…
M18 dual-issuer production
M19 Keycloak retirement
```

Do not start bulk human migration before M2/M3 foundation and M4 automation exist.

---

## 11. Related documents

| Doc | Path |
|-----|------|
| ADR-0022 | `docs/adr/ADR-IAM-0022 — …` |
| M0 baseline | `docs/governance/gate-iam-m0-migration-baseline.md` |
| Rollback baseline | `docs/operations/migration-rollback-baseline.md` |
| M4 inventory | `docs/governance/gate-iam-m4-client-inventory.md` |
| Provider adapters | `internal/provider` |

---

## 12. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-27 | Design-only M5 scope from ADR-0022 §7–23 |
