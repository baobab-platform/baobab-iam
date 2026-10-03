# Ory migration — Gate 0 / Gate 1 status (MCP capability-led programme)

**Branch:** `feat/ory-migrations-contd`  
**Date:** 2026-10-03  
**Authority:** ADR-IAM-0019–0032; MCP Implementation Prompt (capability-led migration)

## Gate 0 — Repository and architectural audit

| Finding | Evidence |
|---------|----------|
| Keycloak remains production runtime | `config/`, `Dockerfile`, integration tests, Keycloak baseline CI job |
| Ory scaffolding on main via PR #42 | `internal/provider/ory`, `internal/migration`, `docker-compose.ory.yml`, federated workload path |
| Capability matrix introduced on this branch | `.baobab/iam-capability-matrix.yaml`, `docs/governance/iam-capability-matrix.md` |
| Dual-provider window is intentional | Capability provider declaration contracts `baobab-iam.ory` without premature `support[]` |
| Live M2/M3/M4 evidence still open | Phase B closeout PB-R1–R10; non-prod Compose / federated token proof |
| Cutover / retirement not authorized | PhaseCPolicyGate denies CUTOVER; M18–M19 later |

### KEEP / ADAPT / SUPERSEDE

| Facility | Disposition |
|----------|-------------|
| Provider-neutral ports (`IdentityProvisioner`, `WorkloadProvisioner`, …) | **KEEP** |
| Federated-first workload path (RFC 7523) | **KEEP** |
| Migration ledger (no secrets on rows) | **KEEP** |
| Shared scope registry as scope authority (`context:resolve` canonical) | **KEEP** |
| Keycloak realm config as sole identity meaning | **SUPERSEDE** progressively by capability contracts |
| Email-as-canonical-identity | **REJECT** (ADR-0022) |

## Gate 1 — Capability and authority classification

Machine-readable matrix: `.baobab/iam-capability-matrix.yaml`

| Classification | Meaning |
|----------------|---------|
| PLATFORM_RESOLVABLE_CAPABILITY | Shared catalogue + CP resolution |
| IAM_MANAGEMENT_OPERATION | IAM admin surface; not a CapabilityBinding |
| PROVIDER_INTERNAL_OPERATION | Adapter-only mechanics |

Tier-0 rows exist for human lifecycle, authentication, session revoke, workload token issue, and provider normalize. Most rows remain **Partial** until Ory adapter + conformance evidence is attached.

### Authority exclusions (unchanged)

IAM must **not** own Tenant, LegalEntity, Market, CapabilityBinding, or domain authorization decisions — CP and domain engines remain authoritative.

## Residual blockers before Gate 5–6 evidence close

1. Live Compose + smoke (PB-R1–R2)  
2. M4-C live token lifecycle (PB-R3–R4)  
3. M4-F projected issuer/JWK + real consumer calls (PB-R6–R10)  
4. Durable migration ledger store  
5. CP CanonicalResolver + IssuerTrust dual-run (later gates)

## Next gate

**Gate 2 — Provider-neutral core:** compile-time interface coverage for workload lifecycle; CI covers migration CLI; provision paths set Baobab lifecycle status `PROVISIONED` (never auto-ACTIVE).
