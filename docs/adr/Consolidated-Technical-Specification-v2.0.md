# Baobab Identity and Access Management — Consolidated Technical Specification v2.0

**Document ID:** IAM-CTS-002  
**Status:** DRAFT FOR RECONCILIATION REVIEW — candidate implementation interpretation; **not an Accepted ADR, capability grant, evidence receipt, or protected release**  
**Date:** 11 November 2026 (Africa/Johannesburg)  
**Owner:** Baobab IAM architecture, with Shared/CP/Infrastructure/engine-owner review for their respective boundaries  
**Reconciles:** [Consolidated Technical Specification v1.0 (9 September 2026)](./Consolidated-Technical-Specification.md), sections 1–227 and IAM Gates 0–16  
**Programmes:** [Accepted EA v2.3](https://github.com/baobab-platform/shared/blob/main/docs/architecture/EA-implementation-plan-v2.3-2026-10-20.md), [Accepted EA-DEV](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-v2.3-development-enablement-implementation-plan-2026-10-23.md), [EA-XB v1.1](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-xb-v1.1-enterprise-corrective-architecture-2026-10-29.md) (where accepted and applicable)  
**Mandatory crosswalk:** [IAM-CTS v2.0 machine-readable reconciliation](../governance/iam-cts-v2-reconciliation.json). Run **python3 scripts/check_iam_cts_v2.py** before claiming documentation consistency.  
**Evidence observation:** IAM source and draft PRs inspected 10–11 November 2026; Shared EA-DEV register last observed 8 November 2026. These are dated observations, not automatically refreshed implementation states.

> **Interpretation, not silent amendment.** This version consolidates existing accepted decisions for implementation. It does not approve proposed ADR-IAM-0034, change a canonical Shared contract, allocate a workload scope, register a provider as ACTIVE, confer CP/Trade/ERP business authority, or certify an integration. An accepted owner ADR or exact canonical Shared contract prevails over any incompatible wording here. Review this as a draft and keep v1.0 immutable as historical design apart from its navigational supersession notice.

## S01 — Purpose, scope and requirement vocabulary

Baobab IAM provides trustworthy human and workload **authentication** and interoperable security evidence across first-party estates, engines and independently onboarded external customers. IAM is a **multi-provider, provider-neutral integration boundary**, not a universal tenancy, legal, financial or domain authorization service.

The RFC 2119-style terms MUST/SHALL, MUST NOT/SHALL NOT and SHOULD retain the meaning established by v1.0. Requirements marked **CTS2-xxx** below are traceability labels for existing accepted obligations, **not additional architectural approval**. Every requirement must be reconciled to the owner ADR and current Shared consumer pin when implemented.

**CTS2-001.** Every service SHALL preserve independent identity, canonical context, platform entitlement and owner-native business decision boundaries.

**CTS2-002.** Every operational claim SHALL record its exact evidence class. An Accepted ADR, green CI, merged source, synthetic runtime, provider sandbox, protected staging, external certification and production authorization are distinct.

**CTS2-003.** A dated spec or gate report SHALL NOT be interpreted as current implementation evidence without an independently verified, timestamped source/receipt reference.

## S02 — Normative precedence and governance of change

Apply the [EA v2.3 precedence rule](https://github.com/baobab-platform/shared/blob/main/docs/architecture/EA-implementation-plan-v2.3-2026-10-20.md): applicable law and actual official/provider rights and security controls; accepted Shared canonical contracts and accepted owning ADRs; accepted EA v2.3 for cross-repository sequencing and evidence handoffs; accepted EA-DEV for development delivery; compatible accepted owner execution plans; then only proposed decisions, illustrative examples and historical records as non-authoritative investigation inputs.

Key decisions:

- [ADR-IAM-0019](./ADR-IAM-0019%20%E2%80%94%20Migration%20from%20Keycloak%20to%20Ory%20and%20Provider-Neutral%20Baobab%20Identity%20Architecture.md) supersedes ADR-0002 as the universal Keycloak provider selection, while preserving sound older security invariants.
- [Accepted ADR-IAM-0033](./ADR-IAM-0033%20%E2%80%94%20Multi-Provider%20Identity%20Runtime,%20Enterprise%20SSO%20and%20Federation%20Provider%20Architecture.md) partially supersedes ADR-IAM-0019/0022 and establishes the ongoing **Kratos + Hydra + Keycloak federation** allocation. It does **not** reinstate universal Keycloak.
- [ADR-IAM-0034](./ADR-IAM-0034%20%E2%80%94%20Native%20Commitment%20Server%20Workload%20Identity.md) is **PROPOSED**. For native commitment provenance, the accepted controlling decision is Shared ADR-SHARED-042 section 14 Decision 9; scope remains unallocated.
- [Accepted ADR-SHARED-043](https://github.com/baobab-platform/shared/blob/main/docs/adr/ADR-SHARED-043-Development-Provisioning-and-Environment-Approval-Boundaries.md) allows guarded, run-owned synthetic development provisioning without an independent human approval on **every development execution**; it does not waive owner-native PEP, separation of a Principal from its own consequential approval, actual credentials, or protected staging/production approval.
- Applicable CP, Trade, ERP, CMS, Pulse, TMS, Trade Docs, Regulations, estate and Infrastructure ADRs govern their own business/domain semantics. A migration document does not reassign their ownership.

**CTS2-004.** New provider support, canonical capability semantics, legal actor class, country rule or environment trust transition SHALL be reviewed by the independently accountable owner and accepted through its authoritative ADR/contract process, not by this document alone.

**CTS2-005.** No source declaration or local registry may promote PARTIAL provider capabilities into CP-approved provider support, binding, grant or protected operation. Provider selection SHALL be CP-governed where prescribed by accepted contracts.

## S03 — Preserved authority, tenancy and security invariants

These v1.0 principles remain mandatory:

- Authentication is not authorization; identity is not credential; a verified issuer token is not a CP Principal or an active platform entitlement.
- **IAM** owns provider credential/session verification and original authentication evidence; **CP** owns canonical Principal and external identity mapping, Tenant, Organisation, legal-entity and Market relationships, Digital Estate, approved capability/provider/engine resolution and authoritative platform grants; **domain engines** own the final business/native policy decision and durable consequences.
- Tenant, legal entity, operating Organisation, corporate group, Digital Estate, Market, region, engine instance, buyer company and supplier company are **not interchangeable**. A legal entity is the default tenant boundary, not a forced one-to-one identity or inherited group privilege.
- Opaque canonical identity is not email, phone, provider subject, Medusa customer, iDempiere AD_User or Keycloak Organisation. Identity references must be explicit.
- Scope, actor_type, IAM role, Keycloak organisation and BFF login evidence confer no buyer spending mandate, supplier verification, ERP role/posting permission, customs authority or payment authority.
- Cross-tenant, wrong Market, disabled Principal, missing grant/mandate, stale policy, unavailable issuer/CP, ambiguity and provider outage fail closed.
- Enterprise/federated source identity SHALL NOT automatically merge by email; original issuer+subject is independently verified and linked through CP.
- No unaudited cross-database joins or reuse of one workload credential for unrelated, independently revocable runtime services.
- Event replay, restore, key rotation, session recovery and issuance after revocation SHALL NOT resurrect withdrawn permissions.

**CTS2-006.** Resource servers enforce current audience, issuer, expiry, relevant scope, canonical context and owner-native veto at the consequential operation—not solely at UI login, BFF request ingress or a synthetic test harness.

**CTS2-007.** Privileged or legally consequential effects require current distinct subject, operation/Market/actor/mandate, appropriate assurance and any maker/checker/native approval, rechecked at the point of effect.

## S04 — Provider-neutral runtime and capability allocation

| Capability/concern | Initial runtime | Immutable authority boundary |
| --- | --- | --- |
| Native human identity, credential, registration, verification, recovery, MFA, passkeys and authentication sessions | **Ory Kratos** | IAM provider mechanics only; no Tenant, legal entity, business roles or spending limits in traits |
| OAuth2/OIDC authorization, authorization code/S256, resource tokens and workload JWT/credentials | **Ory Hydra** | IAM issuer mechanisms; does not create CP Principal or domain permission |
| Enterprise SAML/OIDC federation, upstream IdP trust, corporate discovery and brokering | **Keycloak**, permanently retained for this purpose | IAM trust/federation authority, with CP-governed federation capability and original issuer evidence |
| Additional SCIM, lifecycle, federated or managed provider implementations | Independently selected, contract-bound provider | No automatic trust from installed SDK, realm or admin client |
| Canonical identity, Organisation and platform authorization | **baobab-cp** | CP and Shared accepted contracts |
| Native buyer, seller, ERP, publishing, intelligence, transport or other consequential authorization | Respective engine | Its source of truth, current PEP and transaction boundary |

Keycloak realm-per-Tenant is not the Baobab tenancy model. The historical Keycloak realm/clients/themes/configuration in **config/realm/** and **config/clients/** remain meaningful for **legacy compatibility or permanent enterprise federation**, but are not instructions to deploy universal Keycloak-native login or workload issuance to new applications.

Runtime provision/dispatch is governed by provider-neutral ports in **internal/provider/** and **internal/federation/**. Shared catalogues the WHAT; IAM declares and implements WHO; CP chooses actual instance, grant and routing; the consumer verifies actual issuer and native business authority.

**CTS2-008.** A Keycloak enterprise federation grant SHALL NOT be satisfied by the native human-login capability **identity.authentication.perform**. The enterprise operation uses its separately catalogued **identity.federation.enterprise** capability and separately reviewed CP support/binding; pending source candidate IAM #175 is not merged support.

**CTS2-009.** A native assurance decision SHALL NOT reuse the general human authentication grant as if assurance had been certified. Authentication assurance is separately catalogued and must be server-owned, current and non-authorising.

**CTS2-010.** The provider-neutral support declaration must truthfully remain PARTIAL until final-source, canonical contract, original provider and real consumer acceptance establish support. A new Keycloak config or registered client is not provider certification.

## S05 — Canonical Principal, identity mapping and current context

The v1.0 **CanonicalIdentity** illustrations describe the purpose, not the current wire/model identifier. The accepted Shared identity contract and CP implementation use **Principal** and a **UUIDv7 canonical identifier** (bare UUID under identity/v1); **ExternalIdentity** links by the unique original **(issuer, subject)** pair. Do not create a parallel synthetic `cid_...` identity store or translate UUIDv7 to a different key because v1.0 illustrated one.

CP stores canonical associations; Kratos owns native human credential state; Keycloak may assert original upstream identity; Hydra issues signed OAuth tokens. Native engine reference mappings to Medusa, Payload or iDempiere are explicit, revocable or historical as their contracts require. A different issuer with an identical subject string is a different external identity unless separately linked by an approved flow.

The v1.0 route **POST /internal/v1/context/resolve** was illustrative and shall not be built as an unapproved duplicate. The implemented CP workload route is **POST /v1/platform-context/resolve**, together with approved narrower Principal, validation, provider and estate-resource APIs. Consume only the **current Shared OpenAPI/JSON schema at the accepted consumer pin**, rather than example JSON in the 9 September document.

**CTS2-011.** Issuer verification precedes CP Principal and ExternalIdentity lookup; an absent, revoked, disabled, cross-issuer or unlinked Principal cannot be treated as ACTIVE through email match or local user attributes.

**CTS2-012.** An asserted Tenant/Market/DigitalEstate header, token custom claim or UI selector is **requested context**, not authority. CP must validate membership/grant/binding, legal actor and current permitted operation.

**CTS2-013.** No Keycloak Organisation, Kratos trait, Hydra client or iDempiere company ID substitutes for CP's operating Organisation and legal-entity model.

## S06 — Multi-tenancy, Market, region and external-client isolation

The default Tenant boundary remains the legal entity, with independently reviewed exceptions; corporate group ownership does not confer sibling tenant access. Buyer and supplier organisations are separate commercial/operating relationships, not automatically Tenants. External customers may hold an independent platform tenancy; an API-only customer may have **zero DigitalEstate rows** and must still receive governed resource access without a fabricated estate.

Market is an actual business jurisdiction/participation context. Region is a runtime/data-locality and sovereignty policy dimension. South Africa **af-south-1** staging is not automatic Uganda jurisdiction or permission to replicate all personal data. Shared contracts and CP decide market/region/instance resolution; Infrastructure owns real regional deployment, network and disaster-recovery topology.

**CTS2-014.** One organisation's active entitlement must not propagate into a related/group tenant, another Market or a separate provider engine instance without its own current binding and authority.

**CTS2-015.** Execute the original external-client zero-estate and cross-tenant cases under **DEV-06/INT-07**; do not make CMS or a branded website a universal prerequisite to headless client onboarding.

## S07 — Native human authentication and Digital Estate BFF

The default native human pathway is Digital Estate/owner UI + confidential server-side BFF (where applicable) + **Kratos** native authentication/session + **Hydra** Authorization Code/PKCE S256 and governed consent/claims + independent CP Principal/context + native engine authorization. Use approved OIDC discovery/issuer configuration and actual client readback. Implicit and Resource Owner Password Credentials grants remain prohibited.

The browser sees only session-safe, origin-bound cookies (HttpOnly, Secure and appropriate SameSite); no lasting OAuth access/refresh tokens in local storage. One-time code/state/nonce/PKCE, CSRF, cookie binding, callback replay, open redirect prevention and RP session revocation must be executable controls. A Medusa token is not an IAM human token; login cookies and BFF identity are not buyer authorisation.

**CTS2-016.** A login or callback accepted by the OAuth provider MUST NOT silently establish a Baobab platform session if current CP Principal, mapping, context or original response proof is absent.

**CTS2-017.** Browser proof requires an actual estate browser, Kratos and Hydra provider, CP and genuine resource consumer with wrong-origin, wrong-audience, recovery, revoked/disabled, replay, outage and teardown cases. A Playwright test with a simulated provider is source/browser-component evidence only.

**CTS2-018.** Session logout, account recovery and step-up are separate operations; recovery of authentication never resurrects withdrawn CP or domain grants.

## S08 — Enterprise SSO and Keycloak federation

Keycloak remains a **permanent enterprise federation/broker provider**, not the general primary human credential database. Its enterprise SAML/OIDC trust is specifically reviewed per Organisation/issuer, protocol, provider instance, policy, freshness, signing/trust key and current CP binding. The real upstream assertion or original token must be verified and bound to its request, nonce, audience, issuer, signature, RP/browser session and replay state; a downstream broker-local user or email is insufficient.

IAM's federation authority, ledger and provider adapter MAY broker enterprise IdPs without giving Keycloak Tenant, Market, Trade or ERP roles. Original SAML parser and OIDC key refresh must be fail-closed; TLS roots, redirects, cookie/state replay and unknown key/issuer paths require explicit negative evidence. Lifecycle provisioning/SCIM must be independently selected and qualified, not assumed from login federation.

**CTS2-019.** Revoked trust, provider binding or CP federation grant SHALL block both *begin* and *complete* operations. A stale successful upstream broker response never overrides present CP/grant withdrawal.

**CTS2-020.** Provider support remains PARTIAL until independently reproducible real Keycloak, IAM trust, CP federation capability and estate consumer positives/negatives are verified at the final merged source and image pins.

## S09 — Workload identity, issuance and resource verification

Shared is authoritative for versioned workload registry, status, approved audiences/scopes and client/credential profile. Every independently revocable runtime has its own logical identity. Prefer federated assertion/token credentials where the reviewed workload profile specifies them; never downgrade a federated profile to a shared static client secret for convenience. Hydra issues only for an expressly registered/approved client/profile with its exact per-resource audience ceiling. Production and disposable development identities are disjoint.

The client token is **identity evidence**, not an owned business operation. A resource verifier must validate JOSE algorithm/signature with the approved issuer's JWKS through the reviewed trust transport; enforce exact issuer, audience, client ID, subject, expiry, required scopes and current **original-token** issuer status where the canonical policy requires it; then resolve current CP authority with its **separate CP-authorised credential**, and perform a native resource PEP veto.

**CTS2-021.** Do not infer scopes/audiences from operator input, token aliases, unreviewed new Shared commit, Keycloak legacy clients, Medusa publishable keys or local UI. Enforce the workload's exact pinned Shared ceiling at provisioning **and** issuance and re-evaluate at resource use.

**CTS2-022.** An inactive or unregistered workload, wrong audience/issuer, missing scope, revoked bearer, unknown CP Principal, expired/revoked binding or missing domain permission fails closed. Do not transform provider outage or uncertain consequential effect into PASS.

**CTS2-023.** New engine admission uses **DEV-14** reusable, dependency-minimal integration descriptors and **DEV-15** real Pulse/Payments examples; CMS, BFF, iDempiere and TMS are *not* universal prerequisites for headless engines.

### Native commitment server identity — explicit safety hold

Shared ADR-SHARED-042 section 14 Decision 9 governs native commitment provenance. **ADR-IAM-0034 remains Proposed.** A server submitting directly to Trade must use its **own** confidential workload profile and the Trade-only **trade:native-commitment:submit** non-authorising scope; a governed BFF uses a separate estate-client binding. The same identity must not mix native submitter and BFF handoff. CP independently verifies its original token and current governed WORKLOAD assignment; Trade still enforces legal seller, buyer, budget, Market, native commit and replay controls.

**CTS2-024.** The native commitment submit scope is **allocated to no workload** under the dated approved Shared registry. No positive production client/issuer/CP assignment is approved. Shared workload registration, IAM client, CP assignment and actual connected owner evidence require separate review. Open IAM #185 and CP #468 are **draft source candidates**, not activation or accepted runtime evidence.

## S10 — MFA, assurance, identity proofing and recovery

Kratos owns native credential mechanisms; IAM's provider-neutral assurance evaluator consumes current, original verified session/provider evidence, applies approved risk/step-up policy and returns a non-authorising decision. Enterprise federation may contribute assurance evidence only through a separately qualified current trust and mapping policy. Merely having an AMR label, group, or static ACR claim never confers business permission or A3/A4 completion.

**CTS2-025.** Privileged operations require current role-appropriate assurance and phishing-resistant proof where required; no self-attested session time, client-selected level, test fixture or synthetic browser flag can satisfy a consequential witness.

**CTS2-026.** A3 requires actual RP-bound user-verified WebAuthn/passkey proof. A4 requires the independently approved privileged/security witness and current risk/identity state. Missing evidence means DENIED/STEP_UP_REQUIRED, not acceptance.

**CTS2-027.** Password, recovery, identity-proofing, challenge, passkey, consent and sensitive personal information must be stored, handled and erased under IAM privacy/security policy; CP only stores canonical relationships and explicitly permitted evidence references. Recovery is not credential-role escalation or permission restoration.

## S11 — ZuriBeans B2B, Thamani logistics and supplier authority

**ZuriBeans** retains its B2B commodity-trade house identity. IAM authenticates buyer/supplier representatives; CP relates canonical people, independently operated Organisations, estates, Tenant and Market. Trade owns actual supplier/buyer membership, purchase mandate, RFQ, quotation, catalogue price, seller and buyer commitment, inventory/order and replay. ERP and Trade Docs own their native financial/document obligations; Regulations assesses rules without becoming a legal decision maker. The full buyer transaction is a connected **DEV-07 / INT-05** goal, not an IAM token privilege.

**Thamani** is **B2B integrated logistics**, per accepted [ADR-THA-0018](https://github.com/baobab-platform/thamani/blob/main/docs/adr/ADR-THA-0018%20%E2%80%94%20B2B%20Commercial%20Model,%20Legacy%20Supersession%20and%20Platform%20Engine%20Responsibility%20Reallocation.md). Corporate/customer organisation representatives are human actors; CP owns platform organisation/context, Thamani owns customer commercial experience, TMS owns physical transport/booking/exceptions and Trade Docs/Regulations own their respective boundaries. The legacy **Thamani B2C guest checkout, Medusa retail customer, guest-to-account and consumer social-login** requirements in v1 section 65–68 and Gate IAM-7 are **retired as current Thamani target**. Retain their security principles as generally reusable only if an independently accepted future product/estate ADR calls for B2C.

**Suppliers** are not automatically platform Tenants; approval, vetting, eligibility, documents, sourcing relationships and bank details belong to approved domain/operating authorities. IAM does not become the supplier registry.

**CTS2-028.** Identity proof authenticates the representative, never the buyer/supplier Organisation's verified status or the person's spending limit. Treat missing grant, unknown company, cross-company membership and stale legal mandate as denial.

**CTS2-029.** Thamani quotations, provider bookings, tracking and proof-of-delivery are **DEV-08/INT-04** business workflows requiring a genuinely implemented TMS/provider and original evidence; prototypes do not prove carrier consent, custody, ETA, external rights or booking.

## S12 — ERP, CMS, Pulse, Payments and independent engine consumers

**ERP/iDempiere:** human OIDC mapping must be canonical Principal + CP-entitled company/organisation/Market + actual AD_User, AD_Role, AD_Client/AD_Org at the native posting decision. An OIDC login or API wrapper is not permission to post. External payment evidence, AP/AR/GL and internal company financial consequence require own native durable decision and idempotent/transactional proof. The original Gate IAM-10 stays a useful historical scope but now maps to DEV-09 and each ERP owning ADR.

**CMS/Payload and Nabhold:** a BFF authenticates, CP resolves the correct Tenant/Organisation and capability, CMS enforces content draft/preview/read/publish/revoke; all original NAB-03 meanings remain governed. Public website visual acceptance does not activate regulated trade or finance.

**Pulse:** a headless engine can consume its correctly signed, scoped IAM/CP workload and enforce evidence classification and real PostgreSQL canonical evidence / Qdrant projection authority. It need not import CMS or BFF.

**Payments/Subscriptions/Finance:** provider-neutral IAM identity and CP mandates authorize only appropriate requests; actual money movement, settlement, PSP/merchant eligibility, subscription billing, finance/ledger and legal responsibilities are independently approved and verified. Simulated payment outcomes remain simulated.

**CTS2-030.** Every native engine maintains its own authoritative PEP, database, migration, durable consequence, idempotency/replay and independent failure evidence. CP authority does not perform a second native posting or ledger decision.

**CTS2-031.** An external API-only Tenant with no estate must be valid where Shared/CP admit it; no single engine is a compulsory onboarding dependency for all other engines.

## S13 — Identity lifecycle, privacy, privileged administration and incident containment

A complete disable/withdrawal traverses native sessions/credentials, canonical CP Principal/ExternalIdentity, memberships, current grants/bindings and domain references **without** cross-repository database writes. Use versioned, durable event/outbox/inbox or registered control-plane operations, idempotency and replay fences; reconcile orphans and partial effects. Credential recovery cannot resurrect removed capability and a backup cannot override a later denial/tombstone.

Provider audit and session controls require privacy-safe event schema, no sensitive bearer/private key in logs, controlled retention and independent authorisation for original legal/identity records. Restricted records, deletion requests, statutory retention and post-restore denial tombstones must follow owning privacy ADR and actual jurisdictional requirements.

Privileged IAM administration and break-glass require narrowly scoped, time-bounded, independently approved actions, maker/checker separation, unforgeable evidence, immutable audit and revocation. No permanent all-powerful realm role is a substitute for CP or domain governance.

**CTS2-032.** Identity disabling, key compromise or other active security containment must deny consequential operations on **current** control state even when older signed tokens or backups remain otherwise valid.

**CTS2-033.** Policy/crypto/incident/DR recovery source candidates (IAM #178–184) cannot be treated as merged until their actual final-head checks, reviews and independent native consequences are verified.

## S14 — Original events, audit, telemetry and security observability

Canonical Shared event schemas, registered event names, source/subject/correlation and immutable transaction identity govern distributed events. A business order or security event must originate from its real durable source. Producer outbox, broker delivery, consumer inbox, native effect and acknowledgements must demonstrate at-most-one legal consequence under duplicate, lost reply, restart, corrupted event, outage and replay.

**CTS2-034.** Logs/traces must propagate original causal lineage across BFF → IAM/CP → native engine → outbox → broker → consumer, redacting tokens, secrets, employee/PII and privileged material. A component unit assertion or synthetic span does not prove complete exported-trace lineage.

**CTS2-035.** DEV-11 and DEV-12 demand independently exported OpenTelemetry evidence and original PostgreSQL/native replay and crash diagnosis where required, preserving the canonical L4-OPS and domain case IDs.

## S15 — PostgreSQL 17, availability, topology and recovery

IAM's fault domains include **Kratos, Hydra, retained Keycloak broker, IAM federation/assurance governance, the relevant PostgreSQL stores, signing keys and CP dependencies**. Infrastructure owns protected network, PKI/secrets, database HA/PITR, disaster-recovery orchestration and approved regional topology; IAM owns provider configuration, safe recovery behaviour, control journals and validation. Do not treat a Keycloak-only restore as global authentication recovery.

**CTS2-036.** Use exact reviewed immutable image/contract pins, compatible migrations and rollback, private issuer/admin network boundaries and monitored signing/JWKS rotation. An image tag, new PostgreSQL image or schema file alone is not observed installed version or restored live state.

**CTS2-037.** Failover requires current security-denial replay, no stale authority or orphan credential resurrection, measured RPO/RTO and an independently verified clean test. Prefer a scoped primary multi-AZ topology with reviewed DR; active-active regional writers require separate approval.

**CTS2-038.** Market and data residency are separate. Cross-region personal-data movement, region failover and protected environment credentials require explicit legal/privacy/infrastructure acceptance, not a hardcoded country setting.

## S16 — Reconciled delivery programme: IAM gates, EA-DEV and provider qualification

The original **IAM-0–IAM-16** gates are retained as historic identifiers and requirement sources, **not a second active global delivery pipeline**. The complete machine-readable [legacy crosswalk](../governance/iam-cts-v2-reconciliation.json) maps all 227 v1 sections and all 17 old gates to current owning decisions and EA-DEV work packages. It is a *coverage and ownership register*, not an implementation status dashboard.

| Current obligation | Owner and executable proof |
| --- | --- |
| DEV-00/01/02 | Shared/Infrastructure/CP: accepted precedence, run-owned prepare → up → test → evidence → down and guarded CP synthetic authority |
| DEV-03/04 | IAM/CP/Infrastructure: real signed Kratos/Hydra and CP principal/grant/denial; unchanged seven INT-03C cases, expiry/revocation, independent teardown |
| DEV-05/06 | Nabhold/CMS and API-only adopters: real estate BFF/CMS and unrelated zero-estate external resource profiles |
| DEV-07/08 | Trade/ZuriBeans B2B and TMS/Thamani logistics with original legal-actor/native provider/Market/commitment negatives |
| DEV-09 | ERP/Finance/Subscriptions/Payments: original native JVM/PG, company context and accounting/financial consequences |
| DEV-10 | baobab-dev: reproducible toolchains, exact consumer matrix, GitHub Codespaces/private packages, images and security |
| DEV-11/12 | Native owners/Infra: exported traces, browser/a11y/performance, DB migrations, outbox replay, crash recovery and clean teardown |
| DEV-13 | Independent protected approvers: approved staging and separately production deployment/operation, never created by synthetic development |
| DEV-14/15 | Reusable engine onboarding, true Pulse/Payments issuer→CP→native consumer receipts; no universal CMS dependency |

Separately, IAM ADR-0033 provider programme N01–N03 remains **development-incomplete** under [IAM's dated N01–N03 audit](../governance/iam-n01-n03-development-closure-audit-2026-10-31.md); the historic Shared DEV-03/04 accepted **scoped receipts** do not certify *all* native provider/estate/engine compositions.

**CTS2-039.** Every implemented requirement must record (a) source SHA and canonical consumer pin, (b) exact workflow/checks, (c) real signed-issuer/CP and native cases where required, (d) redacted independently checked receipt and teardown, (e) owning reviewer and (f) explicit blockers and rollback. No pending/failing workflow becomes PASS merely because unrelated checks are green.

**CTS2-040.** The original seven INT-03C, fourteen NAB-03 and accepted L4/INT identifiers remain unchanged. New EA-XB cases apply by accepted profile and applicability, not by inventing sector-independent universal gates.

## S17 — Evidence classification and honest progress

Use EA v2.3/EA-DEV's independent stages:

1. **ARCHITECTURE_ACCEPTED / CONTRACT_ACCEPTED**: reviewed ADR and accepted Shared meaning; contract pins recorded.
2. **SOURCE_IN_PROGRESS / SOURCE_MERGED**: draft PR vs actual merged main commit, not equivalent.
3. **LOCAL_TESTED**: unit, package, contract and component tests on identified candidate.
4. **REAL_COMPONENT_SYNTHETIC_DATA**: actual version-locked issuer, CP/engine and PostgreSQL/consumer, precise positive and negative cases, source/image/contract hashes, original action evidence and clean teardown.
5. **PROVIDER_SANDBOX / EXTERNAL_CERTIFICATION**: independently approved external provider/legal/PSP/carrier/statutory scope, distinct from local simulation.
6. **PROTECTED_STAGING / PRODUCTION_DEPLOYED / LIVE_OPERATION_AUTHORISED**: distinct signed operational/identity/custody and legally scoped admission; an installed engine may be dark with no live Tenant authority.

The source of **current** package status is the checked [Shared EA-DEV JSON register](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-dev-implementation-register.json) and the actual owner evidence, not a duplicate status field in this specification. The 8 November 2026 visible register classified DEV-03–06 as *accepted scoped development evidence*, DEV-07–11/14–15 as *partial/blocked* and DEV-12/13 as *not assessed*. This statement is **dated**, not a present-tense assertion about future source.

**CTS2-041.** Open PRs, staged commits, draft provider capability declarations, test-only authenticated fixtures, installed packages and synthetic browser flows are candidate evidence only; they cannot close owner-native development nor authorize protected deployment.

**CTS2-042.** Report no blanket "IAM complete", "ADR-0033 accepted in runtime" or "only staging remains" without closing original N01–N03, mandatory DEV-14/15 consumers and their distinct protected/provider negative cases.

## S18 — Versioned migration, compatibility, operations and rollback

Adoption order:

1. Retain v1.0 and all original ADR links/legacy gate evidence without rewriting dated receipts.
2. Review Shared contract and current provider capability catalogue authority; use two deliberately separate pins where applicable: **runtime issuer/workload consumer lock** and separately accepted **read-only capability declaration metadata**. The latter never changes issuer scopes or CP grants.
3. Review IAM/CP/provider, estate and engine consumers for exact schema/name/issuer/audience changes. No speculative issuer cutover, silent Keycloak client deletion, tenant migration or one-shot private-token substitution.
4. Migrate one provider/grant/consumer at a time under explicit scope and negative tests; prove fallback/rollback, independent user/credential recovery, per-engine database migration and event replay.
5. Move to protected DEV-13/EA-REL only with actual independent approvals, selected workload/capability/Market/LegalEntity and source/image receipts.
6. Keep original v1 references via historic crosswalk until consumers explicitly adopt this interpretation. Do not change the meaning of historical production/security evidence.

**CTS2-043.** A new token/audience, canonical operation, issuer or workload profile must be contract-versioned and consumer-tested before removal of the prior supported boundary; stale issuer caches and JWKS redirects must fail safely.

**CTS2-044.** Each PR that advances a normative requirement must update its owner evidence and current Shared register if it changes a real gate. A documentation-only PR does not mark a DEV package accepted.

## S19 — Open implementation and review holds (dated audit)

| Priority | Hold and authoritative next evidence |
| --- | --- |
| P0 | IAM N01–N03: newer workload/Shared pin adoption; original browser/issuer/CP and real resource-consumer qualification; no self-reported provider support promotion |
| P0 | Enterprise federation capability: reconcile draft IAM #169/#175 and complete CP federation-specific binding with original Keycloak SAML/OIDC positive/negative consumer proof |
| P0 | Native commitment: Shared scope is unallocated; draft IAM #185, CP #468, actual Trust/IAM/CP/Trade registration and buyer/seller/budget native consequence still distinct and blocked |
| P0 | Trade DEV-07/DEV-11 original BFF/IAM/CP/Trade/ERP/outbox connected transaction with immutable independently exported trace and replay |
| P1 | Assurance, privacy, delegated admin, signing/DR candidate IAM #174/#177–184; original A3/A4 and restored security veto not accepted |
| P1 | DEV-10 toolchain/hosted Codespaces and DEV-14/15 heterogeneous consumers; no GHCR image or installed-toolchain certification inferred from source |
| P1 | DEV-12 migration/recovery and DEV-13 protected release must be assessed as distinct development and protected obligations |
| P1 | Dated gate reports claiming Keycloak feature completion must be labelled historical if their equivalent Kratos/Hydra or enterprise Keycloak qualification has not occurred |

The candidate PR inventory was inspected 10–11 November 2026. A listed candidate may have moved since; never base a merge or acceptance decision on this snapshot alone.

## S20 — Legacy v1.0 crosswalk and interpretation policy

Every original numbered v1.0 section 1–227 and original implementation Gate IAM-0–16 is covered by the [JSON crosswalk](../governance/iam-cts-v2-reconciliation.json). The crosswalk classifies each range as:

- **PRESERVED**: still an invariant, subject to current exact contract.
- **AMENDED**: retains the goal but changes provider, API, ownership or qualification.
- **SUPERSEDED**: older workflow/architecture no longer the current target; historical only.
- **ILLUSTRATIVE_ONLY**: sample identifier, API, profile or code that may not be copied as current truth.
- **REPLACED_SEQUENCE**: prior gate is retained historically but its actual engineering/evidence sequence is EA-DEV/N01–N03.

The crosswalk records **source section range, target Sxx section, governing decisions, owner and EA-DEV work packages** without inventing a current runtime status. Its CI validator refuses missing/duplicated legacy sections, absent Gates, unknown disposition, unrecognised owner/workstream, missing v2 target or accidental promotion of ADR-0034.

A range classification is a **dominant interpretation**, not a repeal of every sentence in the range. Mixed ranges are broken out where a supersession materially changes provider, customer type or trust boundary. The accepted source owns the actual meaning of any finer clause.

## S21 — Canonical references and authorisation limits

- Historical design: [IAM CTS v1.0](./Consolidated-Technical-Specification.md), 9 September 2026.
- Native/migration direction: [IAM ADR-0019](./ADR-IAM-0019%20%E2%80%94%20Migration%20from%20Keycloak%20to%20Ory%20and%20Provider-Neutral%20Baobab%20Identity%20Architecture.md), [IAM ADR-0033](./ADR-IAM-0033%20%E2%80%94%20Multi-Provider%20Identity%20Runtime,%20Enterprise%20SSO%20and%20Federation%20Provider%20Architecture.md).
- Native commitment disposition: [IAM ADR-0034 — Proposed](./ADR-IAM-0034%20%E2%80%94%20Native%20Commitment%20Server%20Workload%20Identity.md) and accepted Shared ADR-SHARED-042 section 14 Decision 9.
- Cross-repository delivery: [EA v2.3](https://github.com/baobab-platform/shared/blob/main/docs/architecture/EA-implementation-plan-v2.3-2026-10-20.md), [EA-DEV](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-v2.3-development-enablement-implementation-plan-2026-10-23.md), [EA-DEV register](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-dev-implementation-register.md), accepted owner-domain ADRs and unchanged [v2.2 L4 scenario registry](https://github.com/baobab-platform/shared/blob/main/docs/architecture/ea-v2.2-integration-acceptance-matrix.md).
- Source audit: [IAM N01–N03 closure audit](../governance/iam-n01-n03-development-closure-audit-2026-10-31.md); actual **main** and open PRs require re-observation at each acceptance event.

**End condition:** this v2.0 specification is technically reconciled as **documentation candidate only**. Its review/merge makes the document discoverable and the crosswalk checkable. It neither completes the listed runtime work nor changes current contract/admission/protected release authority.
