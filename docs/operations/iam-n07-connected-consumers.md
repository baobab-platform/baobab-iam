# IAM-N07 — Connected consumers: development engineering

## Historical review reconciliation — 26 November 2026

N07 remains DRAFT / HELD. On head `68e206fbdd988dacb41b0ad3c490033209710c88`, the CI run `43156515276` completed the normal build/integration, Foundation, secret scanning, action-pinning, federation and PostgreSQL negative suites successfully. The INT-02 candidate source/trust-boundary run also passed. Both Ory Foundation Live variants failed on the inherited N06 result `N06_A3_HELD_KRATOS_PASSKEY_REGISTRATION_UNCLASSIFIED`.

This run does not qualify N07 owner integrations. The Thamani/TMS B2B path still requires current CP-registered provider/context, legal-entity and membership authority, native booking positive/negative cases, and original owner receipts with teardown. An INT-02 Keycloak→CP pass or source-only estate probe does not substitute for those cases.

The PR base is an older N06 head (`7096171daa6c5c717011a4afde5cd8c1cdca1d5c`) than current #151 (`924ba97a7f1ebf1e74d2c457757c380b474af15e`). Reconcile N04 and the common N06 assurance model first, then update N07 to the accepted N06 parent and rerun exact-head CI. Keep cross-company, wrong-context, missing-grant, replay and revocation denials mandatory.

---

**Status:** Draft / source implemented in part / real connected acceptance HELD.
**Dependencies:** IAM N06 #151 is merged into main for development scope only; its A3/A4, recovery/revocation and protected-activation gates remain open. N02 #147/#146/#145 remain upstream dependencies; peer N03 #148 and N04 #149 remain separately governed dependencies.
**Architecture:** EA v2.3 / EA-DEV DEV-03/04/05/07/11/14/15 / EA-XB v1.1 and ADR-IAM-0020/21/23–25/28/29/33, Shared ADR-SHARED-042/043.

N07 must prove real first-party consumer integrations against genuine Kratos native identities, Hydra OAuth, CP canonical Principal and scoped tenant/organisation/market authority, and each engine's **own native PEP**. Keycloak remains enterprise federation only. Successful authentication or a 200 from an unauthenticated public health route never proves business authority.

## Consumer-by-consumer source observation (31 October 2026)

| Owner | Current source boundary | Connected development work required |
|---|---|---|
| ZuriBeans | Existing Next.js /api/iam/* confidential BFF and separate Go N02 /auth/*; draft zuribeans #141 provides first-party private identity qualification UI | Owner-review integration decision, actual Chromium Kratos/Hydra/CP Principal and AAL2, wrong Tenant, logout and revoked resource denial |
| Nabhold | Next.js /api/auth/login, callback, session, logout and context BFF | Actual workforce/CP executive context, no inherited subsidiary authority, current grant withdrawal, real browser and session termination |
| Thamani Global | Main exposes /api/health but no IAM confidential browser-session endpoint | Implement proper owner-native IAM BFF/session and B2B logistics buyer legal-actor mapping; missing route remains BLOCKED, never a simulated success |
| Pulse | Headless DEV-14 engine | Real signed Hydra JWT, independent current CP and native resource authorization, correct/incorrect audience, foreign Tenant, missing grant, outage and unexpired revoke |
| Payments | Headless DEV-15 engine | Same path plus outstanding ENG-ONB-03/06, ACTOR-MARKET-CURRENCY, MISSING-MANDATE and EVENT-REPLAY. Simulated PSP never counts as money movement |
| Trade, ERP and CMS | Separate independently governed resource owners | Opt-in only when they publish a stable protected read-only operation and native authorization with independently retained actual development receipts |

## Implemented in this IAM-N07 increment

- scripts/n07_connected_consumers.py is a read-only **real HTTP transport probe**, not an issuer simulator, privilege proxy or accepted provider. Required core consumers: Nabhold, ZuriBeans, Thamani, Pulse and Payments. Trade/ERP/CMS are optional extension targets.
- Exact 40-hex source pins, 32-hex run ID, clean checked-out IAM SHA, development-only environment, no proxy, no redirect, HTTPS by default (HTTP only for development loopback 127.0.0.1), no URL credentials, query, fragment, or encoded traversal. Requires actual owner-only (0600) bearer files.
- All three estate endpoints are probed **unauthenticated** and must return 401/403. Browser-positive and CP Principal cases stay BLOCKED in this CLI because the owner must run genuine Playwright; no exporting browser cookies or bearer secrets.
- Headless-engine read-only resource probes check anonymous denial, allowed current short-lived bearer (HTTP 200 and no-store), wrong-audience, foreign-Tenant, and missing-grant denials (401/403, not 404/302/5xx). Each negative uses a distinct original private token.
- Pre- and post-revocation phases are separate. Before-phase execution creates an independent random 256-bit correlation key in an owner-only 0600 file outside the receipt directory; after-phase execution requires the same file, exact 32-byte content and matching key identifier. The HMAC binds the token to the run ID and complete immutable source-pin map. The key is never copied into receipts or public output and must be securely destroyed only after the post-revocation observation and independent evidence custody are complete. Do not copy it into CI artifacts or the receipt tree. JWT expiration is sanity-checked only; actual cryptographic signature, current RFC7662 and CP readbacks are **not claimed** by this producer. The revocation is executed by its independent authorized owner, not by this script.
- Each engine owner must supply an exact response_contract with an operation discriminator and the fixed READ_ONLY_RESOURCE classification. A positive HTTP 200 is observed only after exact application/json MIME, no-store, a declared Content-Length no greater than 8192 bytes, valid bounded JSON and exact contract-field equality. The response body is never persisted; generic health JSON, application-level errors, malformed/oversized bodies and unknown fields remain BLOCKED.
- Private originals are published as an atomic per-phase directory containing original.json and original.sha256, each 0600 and fsynced before the directory is renamed into place. The directory is either absent or contains the complete pair; an existing phase is never overwritten. Source tests use unit doubles and never claim live evidence.
- Output classification is REAL_HTTP_READBACK_UNATTESTED with explicit false values for fully_qualified, protected_accepted, issuer_qualified, cp_authority_certified and consumer_native_consequence_qualified. Exit 3 means HTTP probes observed **without acceptance**; exit 2 means BLOCKED. Exit 0 never means acceptance.
- tests/unit/test_n07_connected_consumers.py exercises profile, source, status, privacy, revocation pre-original and expiry negatives. CI runs source compilation and the negative-first suite.

The structural worksheet is tests/connected/n07-profile.example.json. Its invalid placeholder origins, owner-operation placeholders and all-zero source SHA pins are **not a development deployment**. Replace each engine response contract only with the exact operation discriminator and response classification agreed by that resource owner; do not infer or invent a route contract.

## Thamani estate owner companion — source integrated, runtime HELD

Thamani [draft PR #44](https://github.com/baobab-platform/thamani/pull/44)
now introduces a proper first-party `/sign-in`,
`/api/auth/{login,callback,session,logout,context}` confidential BFF and
read-only CP `LOGISTICS_NAVIGATION` bound to a server-selected canonical
Organisation/Tenant/Market with current issuer and Principal checks. Its
opaque cookie, TLS Redis custody and CSRF controls are **not** Medusa
customer authentication and do not authorize native shipment/booking
operations. The N07 Chromium probe now requires Thamani's exact CP
Principal UUID and real `/api/auth/context` read, unlike ZuriBeans's
separate provider-backed buyer-session summary.

**Source ≠ connected run:** Thamani #44 is draft and disabled by default;
its actual Hydra/CP/Redis owner lease and first-party browser credentials
are not yet provisioned/read back. The TMS repo's default
`src/http/development-server.mjs` currently only exposes `/livez`
and a 503 `/readyz`; it has **no authorized booking/resource endpoint**.
N07 must therefore retain TMS native booking/commitment acceptance
as BLOCKED until the TMS owner qualifies a real native operation.
No demo workspace 200 or health check may substitute.

## Real first-party estate Chromium companion

The opt-in tests/browser/n07_estates_live.py exercises the actual first-party
entry/login form, current same-origin IAM session JSON and locally-initiated
logout against **all three** independently configured estate owners. It
requires an owner-only 0600 private profile based on
tests/browser/n07-estates-profile.example.json; the example deliberately
contains inert 40-hex SHA placeholders, invalid synthetic Tenant and
unimplemented owner selectors. It is neither a mock browser nor a recipe
that assumes Thamani already supports IAM.

For Nabhold and Thamani the runner binds the CP context Principal UUID to the exact canonical Principal UUID returned by the immediately preceding current browser session; absent, malformed or mismatched context Principal IDs remain BLOCKED. It also refuses a mismatched Tenant/Market, stale observation or any claim of executionAuthority=true. The response is read-only navigation context, **not** an executive command permit. The browser profile is closed at both top-level and per-estate levels. Session/context JSON must have exact application/json media type, no-store, and a declared Content-Length no greater than 8192 bytes before the body is read; missing or oversized declarations remain BLOCKED.
ZuriBeans's /api/iam/session only proves a current provider-backed
session, not an automatically CP-approved buyer or seller. Thamani's
absent /api/auth/session route remains BLOCKED. In all estates the true
business-resource and CP-authority positives, step-up policy, issuer
revocation and cross-Tenant negatives require independent owner receipts.

The runner never exports browser cookies, bearer tokens or browser
storage, injects a fake login form, disables TLS verification or writes
screenshots/traces. It does not persist the principal ID or session
reply. A single browser failure remains BLOCKED without a sensitive
traceback; the original only contains low-cardinality case results,
immutable source pins and source-run association. CI only compiles
this source and executes structural negative tests; the real Chromium
runner must be launched from the owner-supervised private environment
after Playwright Chromium is installed.

    BAOBAB_ENVIRONMENT=development python3 -B tests/browser/n07_estates_live.py \
      --profile /run/private/iam-n07/estates-browser.json \
      --output-dir /run/private/iam-n07/browser-originals

Expect exit 2 for incomplete owner integrations, or exit 3 for full
browser HTTP readback **without** protected, issuer or CP acceptance.
The N02 original and Infrastructure DEV-04 seven-case producer must
still match the approved actual runtime and source pins before any
development acceptance is considered.

## Real owner-supervised development execution

1. Independently inspect each consumer's current exact code SHA and accepted Shared/IAM/CP/Infrastructure pins. Obtain governed *synthetic* CP Principals, registered OAuth clients/scopes, native user sessions and actual approved engine resource paths. Do not infer legal actor or owner access from corporate structure.
2. Provision isolated development TLS real Kratos, Hydra, CP, estates and engine hosts, separate workload credentials and bounded maker/checker identities. Do not use production keys or claim protected acceptance.
3. Replace the worksheet with a private absolute-path owner-only 0600 JSON profile, actual source pins, a new random 32-hex run ID and real original owner-issued unexpired short-lived tokens. All core consumers are required; a missing Thamani session endpoint returns BLOCKED.
4. Run pre-withdrawal readbacks, complete first-party Playwright login/session/consent/recovery/step-up and CP-context journeys via their owning browser implementations, and execute IAM-N02/Infrastructure DEV-04 original seven cases under the same genuinely immutable-source run.
5. Perform a separately authorized *actual* issuer/CP revocation while the bearer is still unexpired. Require independent issuer-current and CP resource-native denial witnesses; then run the post phase with the exact same original token. No expiry-only or old browser fixture substitution.
6. Validate N03/N04 provider-resource evidence and real engine native consequences (including Payment's five held cases), failure/outage, replay and return-to-healthy behaviors. Independent evidence custody and witnessed teardown are mandatory.
7. Preserve each producer's original receipt and digest; no substitution of historical success, no re-signing a fabricated packet. Development signoff and protected staging/production approvals are separate gates.

Example use on a reviewed immutable private development host:

    export BAOBAB_ENVIRONMENT=development
    umask 077
    python3 -B scripts/n07_connected_consumers.py --profile /run/private/iam-n07/profile.json --output-dir /run/private/iam-n07/originals --correlation-key-file /run/private/iam-n07/correlation.key --phase before
    # Owner-operated and independently witnessed issuer/CP withdraw here.
    python3 -B scripts/n07_connected_consumers.py --profile /run/private/iam-n07/profile.json --output-dir /run/private/iam-n07/originals --correlation-key-file /run/private/iam-n07/correlation.key --phase after

Expect nonzero exit even for coherent HTTP originals. Never upload private originals or secrets as a public CI artifact.

## Explicit acceptance holds

N06 #151: development increment merged; real operation-bound A3/A4, recovery and issuer operations remain gated. N03 #148: independently deployed current IAM/CP/native resource. N04 #149: real CP provider-binder proof; provider support remains PARTIAL. Infrastructure #69 and ZuriBeans #141: same-run first-party real browser and seven-case original. Nabhold: current workforce CP executive context. Thamani: draft owner BFF source exists, but its live owner lease, CP context and native TMS booking operation remain unqualified. Payments: five remaining development engine negatives. No N07 feature, source test, healthy public website or provider mock bypasses any hold.

**Keep IAM-N07 draft and unmerged until genuine connected development acceptance.**
