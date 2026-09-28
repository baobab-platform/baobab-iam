# Gate IAM-M0 — LIVE-VERIFY playbook

**Status:** Playbook only — does not execute against production  
**Date:** 2026-09-28  
**Parent:** `docs/governance/gate-iam-m0-migration-baseline.md` §14  
**Purpose:** Steps to complete LIVE-VERIFY items before closing M0.  

---

## 1. Preconditions

- Access to a **non-production** Keycloak admin API matching `config/` intent (or documented drift).
- Ability to store exports **off-box** with secrets redacted / referenced by ID only.
- No changes to production IssuerTrust or dual-run under this playbook.

---

## 2. Checklist (from M0 baseline §14)

| # | Item | How | Evidence to file |
|---|------|-----|------------------|
| 1 | Export live client list vs `config/clients/*` | Admin API clients or realm export | Diff table |
| 2 | Redirect URIs + PKCE on public/admin clients | Inspect each browser client | Per-client notes |
| 3 | Human user census; password hash algs; MFA rates | User count + sample credentials metadata (**no plaintext**) | Aggregate stats only |
| 4 | Organizations list | Classify PRESERVE requirement vs REPLACE object (ADR-0022 §25) | Classification table |
| 5 | Auth flow graph | Browser + conditional OTP | Diagram or notes |
| 6 | Admin events enabled | Confirm logging still on | Screenshot / config snippet redacted |
| 7 | Break-glass accounts | Runbook still valid | Owner sign-off |
| 8 | Running KC version vs `upstream.lock.yaml` | Server info | Version string |
| 9 | R-1 digest resolution | `docker buildx imagetools inspect` with registry egress | Digest or residual risk note |
| 10 | Tests asserting KC-only URLs/claims | Repo search | List of tests to rewrite in M7+ |

---

## 3. Safety rules

- Do **not** export password hashes to Git.
- Do **not** use email alone as canonical identity (ADR-0022 §7).
- Prefer issuer+subject samples when documenting ExternalIdentity shape.
- LIVE-VERIFY may be waived item-by-item with owner + date in the baseline doc.

---

## 4. After completion

1. Update `gate-iam-m0-migration-baseline.md` §14 checkboxes.
2. Update `gate-iam-m0-adr-matrix.md` **Current evidence** where classification changes.
3. Feed credential strategy mix into Gate IAM-M5 planning.

---

## 5. Document control

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-09-28 | Initial playbook from M0 §14 |
