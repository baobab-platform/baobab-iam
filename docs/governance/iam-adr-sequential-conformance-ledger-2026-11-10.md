# IAM ADR-by-ADR Native-Provider Conformance Ledger

**Baseline:** baobab-iam `main` as inspected 10 November 2026; this PR is a bounded first increment.  
**Authority:** ADR-IAM-0033 (Accepted), Shared canonical contracts and EA v2.3/EA-DEV.  
**Status:** DEVELOPMENT PARTIAL. No new provider support certification, runtime grant, client activation, merge approval, protected-environment authority or staging/production GO.

## Audit method

For **each** ADR in ascending order: (1) read original normative language and any accepted amendment; (2) locate owning runtime or cross-repository service; (3) identify implementation vs declaration vs tests vs original connected evidence; (4) fix a bounded gap with positive **and** fail-closed negatives; (5) open/extend a traceable PR and check exact-head CI; (6) preserve unsupported claims as BLOCKED/NOT_RUN. Do not infer an implementation from a class/interface or passing source-only tests. Avoid duplicating the N04/N06/N07/N08 draft stacks.

## Current ledger

| ADR | Audit state | Evidence / observed drift | Implementation / next action |
|---|---|---|---|
| 0001 | **PARTIAL — reviewed** | Authentication / CP context / domain authorization separation; negative checks and governed handoff exist. No same-run native runtime acceptance yet. | Provider endpoint constructor hardening + negative tests in this PR; N02/N04 connected authority remains HELD |
| 0002 | **SUPERSEDED PROVIDER CHOICE — reviewed** | Proposed Keycloak-only IdP choice conflicts with accepted ADR-IAM-0033; Keycloak remains enterprise federation. | Do not delete Keycloak or count legacy native Keycloak operation as current acceptance |
| 0003 | **PARTIAL — reviewed** | Native BFF validates signed tokens, uses CP readback and strict origins; Ory base adapter previously accepted malformed userinfo/query/fragment admin URLs. | Constructor validation and negative tests in this PR; still needs deployment/admin-network and connected issuer checks |
| 0004 | **PARTIAL — reviewed** | Provider subject is not a CP CanonicalIdentity. Existing Kratos readback lacked exact requested-subject consistency; raw subject could choose a different admin URL path. | Reject path/query/fragment injection before all native identity operations; refuse inconsistent provider readback/reconciliation and test negative cases. CP dual-issuer real runtime remains HELD |
| 0005 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0006 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0007 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0008 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0009 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0010 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0011 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0012 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0013 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0014 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0015 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0016 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0017 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0018 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0019 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0020 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0021 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0022 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0023 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0024 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0025 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0026 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0027 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0028 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0029 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0030 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0031 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0032 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |
| 0033 | **PRECEDENCE VERIFIED, implementation not audited in sequence** | Accepted multi-provider allocation Kratos/Hydra/Keycloak governs conflicting historical ADRs. | Return to full source audit at ADR-0033 in numeric sequence |
| 0034 | **NOT YET AUDITED** | No implementation conformance asserted. | Inspect accepted/amended requirements, runtime/fixtures, negative tests and original connected receipts in sequence |

### ADR-0004 implementation increment

Kratos admin client receives only validated native subjects for identity reads, lifecycle operations and reconciliation. Any response whose provider subject differs from the issuer+subject key is refused rather than mapped. Tests use an actual in-process HTTP server, not a real Kratos or CP runtime. This does **not** claim end-to-end canonical identity migration or a verified dual-issuer cutover.

## Gated follow-through after the ADR sequence

The [Consolidated Technical Specification](../adr/Consolidated-Technical-Specification.md) is dated 9 September 2026, derived from ADR-0001–0018 and names Keycloak as the identity provider. Its historical Gate IAM-0–IAM-16 criteria cannot supersede later accepted provider allocation or Thamani B2B logistics direction. Cross-check existing `docs/governance/gate-iam-*-scope.md` evidence; preserve the native IAM-N01→N08 development holds and distinguish source tests from original, connected, independently witnessed receipts.

Required runtime exits are not waived by this source PR: current CP registration/support/binding, real Kratos/Hydra/Keycloak capability-specific original tests, browser/BFF recovery/step-up/CSRF/replay, issuer/CP/native-owner enforcement with revocation and outage negatives, PostgreSQL 17 restore and teardown, and only then independently governed staging/production gates. All such unexecuted cases remain **NOT_RUN**.

## First increment — ADR-0001 / ADR-0002 / ADR-0003

- **ADR-0001:** Three distinct authorities preserved in native code; constructor guard added for provider endpoint integrity. Remaining: original same-run CP/issuer/estate/domain checks and independent evidence.
- **ADR-0002:** Do not reactivate Keycloak-only native IdP choice. Accepted ADR-IAM-0033 permanently retains Keycloak for enterprise federation. No runtime mutation in this pass.
- **ADR-0003:** Correct a real native adapter gap: raw malformed origins and credential-bearing endpoint URL strings were not refused in `ory.NewAdapter`. Enforce parser rejection before constructing privileged admin clients. This is **not** proof of private network placement, TLS/mTLS, rotated credentials, or execution-time CP authorization.

**Merge hold:** Review source + negative test results on exact PR head; do not merge/mark ADR-0001 or 0003 complete without original connected runtime evidence.
