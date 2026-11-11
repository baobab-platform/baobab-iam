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
| 0009 | **PARTIAL — reviewed; current assurance corrected** | Workforce SSO authentication does not convey CP AdministrativeGrant or domain admin. The AAL2-configured native BFF previously checked Kratos step-up at login/consent/callback but not on protected session reads; an existing browser session could survive loss of Kratos AAL2/subject evidence until token expiry. | Recheck fresh Kratos subject+AAL2 on every AAL2-required BFF session read before CP Principal resolution; deny downgrade, subject substitution, missing native cookie and provider outage with tests. High-risk client classification, connected CP grants, workforce JML, real SSO issuer receipts and full domain-admin denial remain HELD |
| 0010 | **PARTIAL — reviewed; direct issuer gates corrected** | Reconciled ADR-0010 §0 retains Kratos/Hydra native buyer authentication, Keycloak federation, CP Principal/context, Trade commercial authority. Native `HumanConsent`/`HumanClaims` previously relied on an external `Config.Validate()` call; direct invocations could operate over invalid/missing confidential BFF handoff, widened/incorrect profile scope→audience mappings or improper profile purpose. | Both public consent and token-hook gates now explicitly validate the pinned confidential human token profile before deciding a buyer grant. Negative tests for unvalidated malformed configurations; positive valid profile. Shared registry allocation, production dispatch, issuer/CP/Trade original transaction and real negative buyer role/membership/market receipts remain HELD |
| 0011 | **HISTORICAL B2C SCOPE — reviewed; current B2B implementation HELD** | Original proposed ADR-0011 §1–132 and historical Gate IAM-7 require B2C customer/guest cart/checkout. Accepted ADR-IAM-0033 and Thamani B2B logistics scope govern present provider allocation. Current `config/clients/thamani-web.json` and backend workload JSON retain descriptive B2C strings and Keycloak-era registration; these are legacy configurations, **not** native B2B credentials or proof of shipping customer authority. | Preserve old text for traceability; do not activate retail guest checkout, silently repurpose legacy OAuth clients, or delete Keycloak federation. Companion draft #156 explicitly reconciles ADR/gate wording and needs owner review. Real Thamani native confidential BFF, CP canonical B2B organisation/tenant/membership, TMS quote/booking native owner, provider registration and negative cross-company receipts remain NOT_RUN. No runtime change in this increment |
| 0012 | **PARTIAL — reviewed; IAM supplier/buyer boundary regression added** | Proposed ADR-0012 distinguishes individually authenticated supplier representatives from canonical supplier organisation, membership, vetting, product/market eligibility, payment-bank changes and source approval. Current native human token hook publishes identity/assurance only; its accepted ZuriBeans BFF profile cannot grant supplier roles. No complete native supplier registration/invitation/approval/step-up/connected domain flow demonstrated. | Add explicit negative token-profile regression proving registered buyer BFF refuses supplier admin, supplier approval, bank-update and procurement scopes; valid human claims do not carry supplier/market/purchasing/bank authority. Do not implement business authorisation inside IAM. Original supplier→Kratos/Hydra→CP→supplier domain/Trade/ERP connected tests and lifecycle/revocation still NOT_RUN |
| 0013 | **PARTIAL — reviewed; Trade actor/provider boundary hardened** | ADR-0013 historical Keycloak-only admin/Thamani-B2C assumptions are superseded by accepted ADR-IAM-0033 and Thamani logistics. Trade Medusa Auth Module had explicit `authMethodsPerActor`, but it still enabled independent Medusa emailpass for production customer and user, accepted local HTTP workforce callback defaults and lacked workforce OIDC configuration fail-closed. | Companion Trade draft #231 enforces explicit production confidential workforce OIDC, HTTPS issuer/callbacks and distinct customer/user provider methods; development emailpass preserved. Customer JIT/actor binding, immutable issuer+subject reconciliation, original buyer login and migration acceptance remain HELD |
| 0014 | **PARTIAL — reviewed; source identity attribute boundary strengthened** | ADR-0014 iDempiere 13 stock OIDC plugin still uses email/username to resolve AD_User, documented Gate IAM-10 deviation from issuer+subject. CP mapping and native AD_Role/AD_Client/AD_Org authority belong ERP/CP. IAM provisioning previously only rejected top-level forbidden business attribute keys. | Recursively refuse AD_Role, AD_Client, AD_Org, tenant, market, supplier approval and capability authority embedded in nested Kratos identity traits/metadata; negative unit tests. Source does not cure stock iDempiere plugin: supported issuer+subject AD_User mapping bundle and real JVM/CP tests HELD |
| 0015 | **PARTIAL — reviewed; credential identity attributes fenced** | Original proposed Keycloak credential policy is superseded by Kratos-native and Keycloak enterprise federation under ADR-IAM-0033; browser primary authentication and native Kratos AAL2 flows exist. Privileged passkey A3/A4, account recovery and proofing remain gated by ADR-IAM-0024/0025, and the ADR is not proven by realm OTP policy alone. | Harden identity provision validation against nested platform and domain authorization laundering; keep provider-owned authenticator material separate from ERP roles, buyer/supplier entitlements. Require original passkey/recovery issuer/CP/estate negative evidence, NOT_RUN |
| 0016 | **PARTIAL — reviewed; verified native provider kill-switch path added** | Kratos provider `DisableIdentity` and `RevokeSessions` exist and `KillSwitch.Execute` sequences them, but a successful PATCH/DELETE alone does not prove the actual identity is disabled; no complete CP/domain revocation or lifecycle saga is demonstrated. | Add `KillSwitch.ExecuteVerified` with two exact issuer+subject disabled readbacks, session-revocation failure denial, reactivation detection, and negative tests. It does not create CP membership revocation, durable identity-events/v1 outbox or an all-systems kill-switch; those remain HELD |
| 0017 | **PARTIAL — reviewed; provider-error secret leakage fixed** | IAM captures Keycloak admin audit and federation ledger events; canonical security event producer/distributed OTel and independent append-only custody remain unqualified. Ory Kratos/Hydra Admin error mapping had copied first 256 bytes of arbitrary provider error body into propagated errors, potentially exposing tokens/private keys to logs. | Remove raw response-body text from provider errors, retain operation and HTTP status; add secret-in-upstream-error regression test. Full identity-events/v1 producer, original traces, correlation, adversarial replay and durable evidence remain NOT_RUN |
| 0018 | **PARTIAL — reviewed; DR restoration hold preserved** | Runbook includes Keycloak/Kratos/Hydra/federation authority, post-restore recovery epoch and retention, but explicitly confirms no independent all-provider revocation journal/replay and no measured PostgreSQL 17 multi-AZ RPO/RTO disaster rehearsal. Historical Keycloak-only topology cannot satisfy Accepted ADR-IAM-0033. | Do not turn provider readiness/backup restore into traffic reopening permission; preserve protected deployment gate. Build independent revocation-journal custody, current identity+session replay, CP context denial, key rotation reconciliation and original restore acceptance before promoting |
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


### ADR-0009 implementation increment

For BFFs deliberately configured as high-assurance (`RequireAAL2`), a historical AAL2 at authentication no longer suffices at protected `/auth/session` read: the BFF independently asks Kratos for the **current** native subject and assurance, requires the same subject and `aal2`, then performs its fresh CP Principal lookup. CP and domain privileges are never inferred from identity, session or federation. Negative fixtures prove fail-closed downgrade, subject mismatch, missing cookie and Kratos outage. **This does not prove** that all privileged applications have been correctly classified/configured for AAL2, nor connected Keycloak federation, delegated CP grants, workforce mover/leaver or runtime ERP/Trade/CMS authorization.


### ADR-0010 implementation increment

Buyer identities are people, not their buyer companies. Native buyer token issuance must not occur for an invalid confidential BFF profile, including direct internal calls bypassing configuration startup. Both `HumanConsent` and `HumanClaims` now verify the registered profile's purpose, confidential-client credential type, `trade:buyer-handoff` pairing, per-scope audience projection and prohibited CP audience. This is a source-level invariant, not evidence of a real BFF registration or Trade buyer commitment. IAM does not own or invent Trade buyer membership, approval limits, company verification, invitations or ordering rights. Real ZuriBeans→IAM→CP→Trade positive/negative browser and transaction evidence remains NOT_RUN. Do not activate legacy Keycloak-only browser configurations or count the disposable synthetic fixtures as protected acceptance.


### ADR-0011 historical-scope disposition

ADR-0011 is **Proposed**, not an accepted native B2B logistics authentication design. Its retail guest/customer identity, Medusa customer mapping and guest-order-claim mandates cannot be used as completion tests for Thamani's current independent B2B logistics operation. Accepted ADR-IAM-0033 governs Kratos native human identity, Hydra OAuth/workloads and Keycloak enterprise federation. CP owns canonical actor, legal entity, market and platform authority; the native TMS/shipment owner must independently authorize shipping commitments. The already-open **draft PR #156** (`feat/iam-audit-gate-d-thamani-b2b-federation-scope-20261106`) carries the proposed ADR/Gate-7 wording reconciliation; review that PR rather than implementing a conflicting second rewrite. Existing Keycloak-era client files are historical compatibility declarations, not proof of live native BFF adoption. No runtime grant, registration or provider provisioning changed in this audit increment, and connected B2B qualification remains NOT_RUN.


### ADR-0012 implementation increment

Supplier authentication and supplier commercial approval are distinct. IAM must not create shared company credentials, infer representative authority from email or federation, expose supplier bank data, or convert a B2B buyer token into supplier-admin or procurement approval. Added a negative regression that a ZuriBeans buyer BFF profile rejects unrelated `supplier:*` and `procurement:*` scopes through both consent and direct human token-hook calls, while human claims continue to carry no supplier approval, bank, organisation, market or buyer-spend data. This is a **source-only invariant**, not evidence that supplier identity onboarding, invitations, B2B supplier marketplace approval, CP authority or bank-change step-up has been implemented. Domain owners and connected integration evidence remain HELD.
### ADR-0013–0018 conformance increment (10 November 2026)

- **0013, Trade #231:** production Auth Module rejects local password fallback and invalid callback/issuer values; current Medusa user/customer separation remains explicit. Human actor authorization still belongs CP and Trade. These code tests do not qualify real checkout or migration.
- **0014:** stock iDempiere 13 OIDC plugin's email/username AD_User lookup is a **known historical deviation**. IAM never assigns AD_Role/AD_Client/AD_Org. Nested identity data now cannot inject such authority, but the ERP native issuer+subject mapping implementation remains outstanding.
- **0015:** Kratos owns native credentials; hardened provisioning denies nested tenant/business authority. Passkey A3/A4 and full recovery are not inferred from existing Kratos AAL2.
- **0016:** added a provider-only *verified* disable-then-revoke method with two independent state reads. The older provider-only Execute retains its original semantics; no claim that a CP/domain revocation saga is deployed. Failure never silently re-enables an identity.
- **0017:** raw provider HTTP response bodies (potential secrets) no longer propagate into Go errors. No canonical security event delivery, immutable security audit or connected trace has been certified here.
- **0018:** existing DR runbook explicitly refuses automatic reopening after restore without security-journal replay. No independent verified revocation ledger or original multi-AZ RTO/RPO evidence exists. Do not accept protected topology.
