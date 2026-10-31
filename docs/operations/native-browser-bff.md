# IAM-N02 — Native browser/BFF handoff and CP-bound session

**Status:** SOURCE IMPLEMENTATION / COMPONENT QUALIFICATION, stacked on IAM-N01. **NOT** actual provider+CP+estate connected acceptance or production readiness.
**Authority:** accepted ADR-IAM-0023/0024/0025/0033, ADR-SHARED-042/043; EA v2.3, EA-DEV DEV-03/05/07/14 and EA-XB v1.1. N01 immutable Shared contract pin is unchanged.

## Architecture and ownership

Browser → estate BFF (internal/nativebff) → Hydra OAuth2 Code + S256 → existing CP-governed Kratos/Hydra human handoff → private Hydra code exchange → verified ID and access tokens → CP delegated Principal resolution with independently registered CP workload token → encrypted PostgreSQL session → independently authorized domain operations.

CP alone owns canonical identity, the ACTIVE Principal, issuer+subject mapping, organisation/context/grants. IAM owns provider credentials/sessions and tokens. Estates own their UX and BFF hosting; Trade/ERP/etc. decide business permissions. No organisation, tenant, legal entity, role, Market, purchasing authority, external buyer relationship or cross-tenant privilege may be inferred from Kratos traits, email, JWT subject or browser session.

## Implemented modules

- internal/nativebff/handler.go: exact configured browser Host and TLS, POST-only same-Origin start, server-generated S256/state/nonce, Secure/HttpOnly host-only transaction cookie (Lax), server-only confidential code exchange, explicit consent with CSRF, signed issuer/nonce/audience/subject checked against signed human access token, CP Principal resolution, encrypted Strict session cookie and logout.
- internal/nativebff/cp_and_revocation.go: actual CP POST /internal/identity/v1/principals/resolve with independent workload Authorization bearer and separately supplied human subject_token. The CP independently checks current issuer, token status, scope, audience, approved registered caller relationship, and ACTIVE Principal. Separate authenticated Hydra /oauth2/revoke reports unknown issuer outcomes rather than claiming successful revocation.
- internal/nativebff/postgres.go and migrations/001_native_browser_bff.sql: PostgreSQL 17 IAM-only transaction/session tables, hashed opaque cookie IDs, AES-256-GCM ciphertext bound to row ID and record kind, atomic single-use DELETE RETURNING, no in-memory production fallback.
- internal/nativebff/*_test.go: negative callback state/replay/consent/CSRF, CP outage and revocation, issuer logout uncertainty, encryption AAD and multi-replica Postgres cases.

## Browser contract

Hydra must be configured with the approved same-origin estate endpoints /auth/login and /auth/consent and the exact confidential /auth/callback URI. POST /auth/start requires exact Origin and returns a server-bound PKCE, state and nonce transaction (five minutes). Hydra challenge callbacks must present the retained transaction cookie and a genuine Kratos browser session, verified by the existing GovernedNativeHumanHandoff and its durable challenge fence. The BFF never reads credentials from callback query arguments.

GET /auth/consent renders a minimal escaped no-script consent scaffold; only a separate explicit POST with exact Origin and transaction CSRF may proceed. Existing token-profile rules decide whether business scopes can be granted. Code and state are accepted once. The transaction is irreversibly destroyed before the private OAuth token exchange; any unknown provider/CP result denies and requires a new login.

A successful callback requires an actual signed OIDC ID token, signed human access token with matching subject and expected resource audience/scope/actor, then a fresh CP Principal resolution. It establishes a short-lived Secure, HttpOnly, host-only, SameSite=Strict opaque BFF cookie. OAuth access, refresh and ID tokens remain AES-GCM encrypted server-side. GET /auth/session re-resolves the same human through current CP authority and exposes minimal identity plus session CSRF, never domain rights.

POST /auth/logout requires same-origin Origin and session CSRF, destroys the BFF session first and then requests Hydra access/refresh revocation. Local sign-out remains available when CP is unavailable or has deactivated the Principal; remote issuer revocation uncertainty is never hidden. Unknown provider revocation is HTTP 503, not a confirmed end-to-end logout; Kratos provider session revocation and global federation logout require a separate integration gate. Sessions do not outlive the current OAuth access token or thirty minutes.

## Critical CP contract / estate constraints

CP delegated resolution does **not** accept an IAM-supplied issuer+subject as canonical authority. Per Shared identity/v1/principal-resolution.schema.json and CP principal_resolution_handler.go, the registered CP workload uses its own issuer-issued CP-audience token in Authorization and submits the independently verified human JWT access token in the body as subject_token. The exact registered subject_principal_audiences relationship is independently enforced by CP. The current CP endpoint serves Trade buyer evidence with aud=baobab-trade and trade:buy; it is not automatically usable for Nabhold executive authority:self or Thamani logistics. Those require independently approved scopes, audiences and resolvers.

The current Shared pin predates newer ACTIVE development-only clients. N01 deliberately holds that re-pin pending issuer and consumer requalification. This source cannot create any actual registered workload, CP assignment, buyer Principal, tenant grant or employer authority. An unrelated external buyer must not be forced into a Baobab tenant or DigitalEstate.

## Operational assembly and acceptance holds

A production host must start ory.StartNativeHumanRuntime with real CP-governed Kratos/Hydra runtime and PostgreSQL challenge ledger, pass the GovernedNativeHumanHandoff into nativebff.New, separately provision an approved CP workload token source for HTTPPrincipalResolver, then connect OAuthRevoker and encrypted PostgreSQL store. All issuer origins, client secrets, vault key, TLS trust, resource audiences, scopes and session origins must be deployed through approved private configuration. Loopback/test verifier and injected client modes are forbidden in production. The package is not itself a deployed public BFF process, and no production service was activated.

Apply the SQL migration with an IAM database owner, restrict DML to its scoped runtime, configure expiry purge and encrypted backup, and qualify key rotation/drain, replay, crash, unexpired-token revocation, cross-tenant denial and independently checked teardown. Never log tokens, PKCE verifiers, secrets, or personal data. Use separate development/staging/production databases and keys. A reusable synthetic development fixture is governed by ADR-SHARED-043; its source and component CI do not certify protected staging or production.

Verification: Go build/test for internal/nativebff, race tests, genuine PostgreSQL 17 test when TEST_NATIVE_BFF_DATABASE_URL is supplied, and existing IAM Ory/Keycloak/CP contracts and security checks. Tests with injected providers are fixtures and cannot be reported as real connected acceptance. Branded Kratos UI/session routing, passkeys/recovery/step-up, actual confidential Hydra client and registered CP workload, browser Playwright, estate integration, operational key lifecycle, C4-03B–E and C4-04B/C remain to be qualified.

**All three canonical provider supports remain PARTIAL** pending independent N02/N03/N04 end-to-end consumer evidence. This PR proposes no new ADR, capability, grant, registration, production approval or Shared re-pin.
