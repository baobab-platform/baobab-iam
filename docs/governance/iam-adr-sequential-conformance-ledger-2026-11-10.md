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
| 0005 | **PARTIAL — reviewed** | ADR distinguishes Realm, IAM Organisation, canonical legal entity, Tenant, Market and Digital Estate. CP retains canonical authority and native adapter has no business-organisation fields. Older Keycloak Organization semantics remain historical/federation-specific. | No business mapping introduced in IAM; original CP+Kratos multi-context and revocation tests remain NOT_RUN for this ADR |
| 0006 | **PARTIAL — reviewed** | BFF OAuth Code/S256 uses state, nonce, server-side session vault, signed token verification, bounded lifetime and CP Principal readback; Shared token-profile hook handles actor/scope. | Current native issuer/browser/CP profile and JWT audience/issuer/step-up negative receipts remain NOT_RUN; do not treat protocol fixtures as connected acceptance |
| 0007 | **PARTIAL — reviewed** | Hydra workload issuance paths use distinct clients and inherited Shared profile; native get/put Admin client URL uses raw client IDs, and client readback previously allowed a mismatched ID. | Add explicit resource-id fencing and exact client-id readback before mutation, with HTTP negative tests. Source-only; real issuer/CP/consumer authorisation remains HELD |
| 0008 | **PARTIAL — reviewed; source boundary corrected** | CP owns context/entitlements; IAM cannot grant tenant/domain roles. The native HTTP CP Principal resolver previously accepted issuer and subject arguments without comparing them to the delegated JWT claims, so a valid bearer for a different subject could be forwarded under a false requested identity. | Added duplicate-safe exact issuer+subject claim comparison before any CP request with cross-issuer, subject-substitution and CP-deny negative fixtures. Claims are **not** trusted as proof: CP still independently verifies the same bearer, active Principal mapping and current authority. Original connected Trade/CP/domain denial and revocation receipts remain NOT_RUN |
| 0009 | **PARTIAL — reviewed** | Workforce SSO and privileged access must be named-identity/MFA/SoD, not group-based omnipotence. Native BFF supports current Kratos AAL checks; Keycloak remains enterprise federation only by ADR-IAM-0033. | No automatic executive/admin grant in IAM; real higher assurance A3/A4, CP AdministrativeGrant and workforce joiner/mover/leaver connected tests remain HELD |
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

### ADR-0005 through ADR-0007 implementation increment

ADR-0005 is a structural invariant: native Kratos and Hydra must not become a Tenant, LegalEntity or Market authority. Reviewed existing provider declarations and native BFF CP lookup; corresponding connected multi-context CP acceptance is **NOT_RUN**.

ADR-0006 has implemented protocol fences in the browser BFF and token-profile hook, but source-level OIDC tests are not original running issuer/CP/estate receipts. Current advanced assurance and brokered logout remain **HELD**.

ADR-0007 exposed a concrete boundary drift: native Hydra client GET and PUT paths interpolated raw IDs, and GET did not verify the returned client identity. The new fix refuses unsafe ID text, and mismatched readback before constructing updates. This does not prove credential rotation, CP registered workload activation, or real owner-service resource enforcement.

The Hydra create path also requires the provider to return the exact requested client ID. Empty, malformed and foreign replies result in a conflict with no returned credential. If the outcome is uncertain, reconcile the registered client by exact ID and current configuration before retrying.

CTS2-011, CTS2-021 and CTS2-022 govern these boundaries. This increment retains the merged ADR-0004 Kratos identity checks and the security baseline adopted with CTS v2.0.

### ADR-0008 / ADR-0009 authority and workforce review

The runtime surface does not confer platform or domain roles through token contents: `nativebff.PrincipalResolver` requires an independent CP read, while `NativeWorkloadReadiness` rechecks provider/CP capability before concluding readiness. Neither check substitutes for domain-native business permission; approval, organisation and market authority must remain in CP and owning engines (ADR-0008). Privileged workforce authentication must be distinct from privilege grants and accompanied by current higher-assurance provider proof (ADR-0009); Keycloak enterprise federation does not create a platform-admin role.

### Consolidated historical IAM gates — inventory, **not** implementation acceptance

The source specification (§§203–219) enumerates 17 gates, labelled IAM-0 through IAM-16. It predates Accepted ADR-IAM-0019 through ADR-IAM-0033. **Every gate remains NOT_ASSESSED in this ledger until all 34 ADRs have been audited and its current specification is reconciled.** In particular do not reuse the retired Keycloak-only native issuer or historical Thamani B2C criteria as current positive proof.

- Gate IAM-0 — Architecture Foundation — **NOT_ASSESSED**
- Gate IAM-1 — Shared Contracts — **NOT_ASSESSED**
- Gate IAM-2 — IAM Repository / Keycloak Foundation — **NOT_ASSESSED**
- Gate IAM-3 — Control Plane Identity Spine — **NOT_ASSESSED**
- Gate IAM-4 — Workload Identity — **NOT_ASSESSED**
- Gate IAM-5 — Workforce SSO — **NOT_ASSESSED**
- Gate IAM-6 — Zuribeans B2B — **NOT_ASSESSED**
- Gate IAM-7 — Thamani B2C (historical; now B2B logistics scope) — **NOT_ASSESSED**
- Gate IAM-8 — Supplier Identity — **NOT_ASSESSED**
- Gate IAM-9 — Medusa Integration — **NOT_ASSESSED**
- Gate IAM-10 — ERP Integration — **NOT_ASSESSED**
- Gate IAM-11 — Credential Security — **NOT_ASSESSED**
- Gate IAM-12 — Lifecycle / Deprovisioning — **NOT_ASSESSED**
- Gate IAM-13 — Audit / Observability — **NOT_ASSESSED**
- Gate IAM-14 — HA / DR — **NOT_ASSESSED**
- Gate IAM-15 — Multi-Region Readiness — **NOT_ASSESSED**
- Gate IAM-16 — Production Hardening — **NOT_ASSESSED**

Owner-qualified evidence must include genuine Kratos/Hydra/Keycloak/CP and engine native execution, current source SHA, independent trace, denial/replay, restore and teardown, rather than syntax checks and mock protocol fixtures.

## Gated follow-through after the ADR sequence

The [Consolidated Technical Specification](../adr/Consolidated-Technical-Specification.md) is dated 9 September 2026, derived from ADR-0001–0018 and names Keycloak as the identity provider. Its historical Gate IAM-0–IAM-16 criteria cannot supersede later accepted provider allocation or Thamani B2B logistics direction. Cross-check existing `docs/governance/gate-iam-*-scope.md` evidence; preserve the native IAM-N01→N08 development holds and distinguish source tests from original, connected, independently witnessed receipts.

Required runtime exits are not waived by this source PR: current CP registration/support/binding, real Kratos/Hydra/Keycloak capability-specific original tests, browser/BFF recovery/step-up/CSRF/replay, issuer/CP/native-owner enforcement with revocation and outage negatives, PostgreSQL 17 restore and teardown, and only then independently governed staging/production gates. All such unexecuted cases remain **NOT_RUN**.

## First increment — ADR-0001 / ADR-0002 / ADR-0003

- **ADR-0001:** Three distinct authorities preserved in native code; constructor guard added for provider endpoint integrity. Remaining: original same-run CP/issuer/estate/domain checks and independent evidence.
- **ADR-0002:** Do not reactivate Keycloak-only native IdP choice. Accepted ADR-IAM-0033 permanently retains Keycloak for enterprise federation. No runtime mutation in this pass.
- **ADR-0003:** Correct a real native adapter gap: raw malformed origins and credential-bearing endpoint URL strings were not refused in `ory.NewAdapter`. Enforce parser rejection before constructing privileged admin clients. This is **not** proof of private network placement, TLS/mTLS, rotated credentials, or execution-time CP authorization.

**Merge hold:** Review source + negative test results on exact PR head; do not merge/mark ADR-0001 or 0003 complete without original connected runtime evidence.



### ADR-0008 implementation increment

The delegated BFF bearer is now lexically bound to the exact requested external issuer and subject before posting to CP. The local check uses unverified JWT payload only to detect inconsistency, **never** as a signature verification or grant; the authenticated CP workload request and CP validation remain mandatory. Deliberately unsigned in-process test JWTs are boundary fixtures, not an issuer or Control Plane runtime acceptance. The BFF still does not create CP grants or Trade/ERP/CMS business permissions. Substituted issuer/subject, ambiguous duplicate claims and CP denial are negative tests. Protected-environment and same-run end-to-end receipts remain NOT_RUN.