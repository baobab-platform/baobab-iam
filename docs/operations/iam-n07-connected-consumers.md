# IAM-N07 — Connected consumers: development engineering

**Status:** Draft / source implemented in part / real connected acceptance HELD.
**Dependencies:** IAM N06 #151 (stack base) on N02 #147/#146/#145; peer N03 #148 and N04 #149 remain separate draft dependencies.
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
- Pre- and post-revocation phases are separate. Post requires an immutable private pre-original and checksum, matching run/source, previously observed positive and exact same token correlated through a private run-bound HMAC. JWT expiration is sanity-checked only; actual cryptographic signature, current RFC7662 and CP readbacks are **not claimed** by this producer. The revocation is executed by its independent authorized owner, not by this script.
- Private append-only by policy original receipt and SHA-256 sidecar: exclusive creation, 0600 files, fsync, no overwrite, no bearer/password/cookie/provider response/identity/body/URL persisted. Source tests use unit doubles and never claim live evidence.
- Output classification is REAL_HTTP_READBACK_UNATTESTED with explicit false values for fully_qualified, protected_accepted, issuer_qualified, cp_authority_certified and consumer_native_consequence_qualified. Exit 3 means HTTP probes observed **without acceptance**; exit 2 means BLOCKED. Exit 0 never means acceptance.
- tests/unit/test_n07_connected_consumers.py exercises profile, source, status, privacy, revocation pre-original and expiry negatives. CI runs source compilation and the negative-first suite.

The structural worksheet is tests/connected/n07-profile.example.json. Its invalid placeholder origins and all-zero source SHA pins are **not a development deployment**.

## Real first-party estate Chromium companion

The opt-in tests/browser/n07_estates_live.py exercises the actual first-party
entry/login form, current same-origin IAM session JSON and locally-initiated
logout against **all three** independently configured estate owners. It
requires an owner-only 0600 private profile based on
tests/browser/n07-estates-profile.example.json; the example deliberately
contains inert 40-hex SHA placeholders, invalid synthetic Tenant and
unimplemented owner selectors. It is neither a mock browser nor a recipe
that assumes Thamani already supports IAM.

For Nabhold it additionally reads the real server-side
/api/auth/context response and refuses a mismatched Tenant/Market, stale
observation or any claim of executionAuthority=true. The response is
EXECUTIVE_NAVIGATION read-only, **not** an executive command permit.
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
    python3 -B scripts/n07_connected_consumers.py --profile /run/private/iam-n07/profile.json --output-dir /run/private/iam-n07/originals --phase before
    # Owner-operated and independently witnessed issuer/CP withdraw here.
    python3 -B scripts/n07_connected_consumers.py --profile /run/private/iam-n07/profile.json --output-dir /run/private/iam-n07/originals --phase after

Expect nonzero exit even for coherent HTTP originals. Never upload private originals or secrets as a public CI artifact.

## Explicit acceptance holds

N06 #151: final CI, real native A3/A4, recovery and issuer operations. N03 #148: independently deployed current IAM/CP/native resource. N04 #149: real CP provider-binder proof; provider support remains PARTIAL. Infrastructure #69 and ZuriBeans #141: same-run first-party real browser and seven-case original. Nabhold: current workforce CP executive context. Thamani: native IAM BFF absent on main. Payments: five remaining development engine negatives. No N07 feature, source test, healthy public website or provider mock bypasses any hold.

**Keep IAM-N07 draft and unmerged until genuine connected development acceptance.**
