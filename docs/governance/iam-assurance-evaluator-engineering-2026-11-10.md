# IAM current authentication assurance evaluator — bounded source implementation (2026-11-10)

**Governing decisions:** Accepted ADR-IAM-0024 (authentication assurance), ADR-IAM-0025 (recovery), ADR-IAM-0031 (privileged administration), ADR-IAM-0033 (Kratos native humans, Hydra OAuth, permanent Keycloak enterprise federation). The existing Shared `identity.authentication.assurance` v1 request/result schema is normative. This is development engineering **PARTIAL**, not an activated provider capability or production approval.

## Audit and correction

IAM already validates current Kratos AAL1/AAL2 during the governed native handoff and privileged browser session reads. Earlier sequential ADR PRs #171 and #173 removed incorrect MFA recovery-code inference and unsupported hardware-bound passkey assertions. Before this increment, however, the Shared assurance-evaluation request/result contract had no complete server-owned evaluator handling operation-specific floors, freshness, risk/recovery holds and independently verified A3/A4 preconditions.

Added `internal/assurance/evaluator.go` and `internal/provider/ory/governed_assurance.go`:

- Accept only the exact Shared v1 request fields with opaque event/session references and reviewed operation classes. Do not accept `acr`, `amr`, assurance level, reviewer, tenant, company or grant from request input.
- Apply copy-on-construction, server-owned operation policy with floors A1 for LOGIN, A2 for BUYER_COMMIT, A3 for HIGH_VALUE_APPROVAL/CREDENTIAL_CHANGE/RECOVERY_REBIND and A4 for PRIVILEGED_GRANT/BREAK_GLASS. These are conservative **engineering floors**, still subject to architecture/security approval before production.
- Resolve current live Kratos whoami with session credential supplied by trusted BFF, check current CP dispatch **before and after** every Kratos read, and cross-check issuer-bound event/session references. Recheck the provider and CP a second time before a favorable response. This double-read denies changed current state but is **not** a substitute for atomic revocation and domain PEP checks.
- Never infer A3 from `webauthn` or `passkey` method labels: require separate attestation, relying-party binding and user verification. A4 additionally requires separately verified hardware and privileged witness. No present Kratos adapter claims those fields are proved.
- Fail closed when current risk status, recovery hold status, attestation, privileged witness, source/CP or freshness is unavailable; the actual Kratos source intentionally supplies **no invented risk or proof**. Thus BUYER_COMMIT and privileged operations **cannot pass** through this bridge yet.
- Return only schema-compliant assurance outcomes; a positive result always reads `ASSURANCE_MET_NOT_AUTHORIZATION`. No CP Principal, IAM permission, business spend or Trade native commitment is granted.

## Qualification and outstanding implementation

Source tests cover positive current LOGIN (A1/AAL2), provider and CP revocation, issuer session substitution, assurance downgrade, changing session between independent reads, invalid reference/methods, stale authentication, risk/recovery hold, unauthenticated A3, separate A4 witness/hardware and user-controlled policy downgrade attempts.

The following are **open**: review and approve actual operation policy and freshness thresholds; provide independently verified current risk/recovery state, authenticator assertion attestation and privileged-witness readers; implement and exercise full CP canonical capability resolution and PEP integration; original live Kratos/Hydra→CP→BFF/Trade same-run assurance/authorization negative proof; PostgreSQL-backed security journal and durable revocation; exact-head formatting/build/unit/CI; protected sign-off. Do not mark `identity.authentication.assurance` IMPLEMENTED or publish a production binding.

Run locally from this branch with the repository's pinned Go version:

```sh
gofmt -l internal/assurance/*.go internal/provider/ory/governed_assurance*.go
go test ./internal/assurance ./internal/provider/ory
```

**Dependency:** This PR is stacked on IAM #173, following the earlier sequential ADR source audit; separate capability declaration IAM #169 must be reconciled without changing the runtime workload scope pin.

## CTS v2 follow-up, 12 November 2026

The evaluator now preserves the first observation's method slice before the
second provider read. A reused mutable reader buffer cannot conceal changed
methods or be sorted in place by the evaluator. A favorable result also requires
an uncancelled context and evidence still fresh at completion, with a backward
clock movement refused. Regression tests cover expiry during readback, cancelled
requests, clock rollback and a reused mutable method buffer.

These are source assurance checks. The overlapping N06 policy in #151 and the
assurance-specific CP dispatch in #177 still need convergence before connected
acceptance. Original risk, attestation and privileged approval sources remain
required, and no business grant or protected acceptance is produced here.
