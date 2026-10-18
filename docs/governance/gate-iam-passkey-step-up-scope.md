# Gate IAM: phishing-resistant passkey step-up (raw LoA 3)

**Status:** configuration and synthetic-browser qualification harness implemented; a complete current-run PASS receipt is required for the bounded browser claim. CRITICAL AdministrativeGrant enforcement in the Control Plane stays PROHIBITED until the live chain is proven (architecture-owner ruling, 2026-10-02).

## Decision (architecture owner, 2026-10-02)

| Question | Ruling |
|---|---|
| Canonical level | `urn:baobab:acr:step-up` (Shared `administration/v1/assurance-policy.yaml`). |
| Keycloak raw LoA | **3** is normative. Raw `0`/`1` are `urn:baobab:acr:basic`, `2`/`gold` are `urn:baobab:acr:mfa`. An alias such as `platinum` is optional and nothing depends on it. |
| Evidence | A signed token from this issuer carrying `acr=3` is itself the evidence that a phishing-resistant authentication was performed, *because* LoA 3 has exactly one security meaning. An `amr` naming `webauthn` or `hwk` is accepted by the Control Plane as an alternative form. |
| Custom Keycloak SPI to emit `amr` | **No** (ADR-0002 extension hierarchy: native, configuration, adapter, SPI, fork). No fork. Keycloak's native `oidc-amr-mapper` is probed first; the programme does not depend on it. |
| Freshness | 300 seconds (`loa-max-age`), matching the Shared CRITICAL requirement. |

## What this change configures

- Subflow **`Baobab - Passkey Step-Up`**, `CONDITIONAL` in `Baobab browser` at priority 35, ahead of `Baobab - Step-Up` (40). It contains only a `Condition - Level of Authentication` (level **3**, max age **300**) and the **passwordless WebAuthn** authenticator, both `REQUIRED`. There is no OTP-only, password-only or two-factor-WebAuthn alternative. Because it runs first, a completed level 3 satisfies level 2 without a second factor.
- Realm passwordless WebAuthn policy: user verification **required**, resident (discoverable) credential required, ES256/RS256.
- `scripts/bootstrap.sh` reconciles both into an already-existing realm (idempotent), as it does for the OTP step-up.
- `acr.loa.map` is unchanged: Keycloak treats a numeric `acr_values` as the LoA directly, so clients request `acr_values=3`.

## Conformance proof (`tests/integration/run.sh`, section 19b)

Run against a real Keycloak in CI, the suite proves the configuration cannot emit LoA 3 through anything weaker:

- the passkey subflow is the LoA predicate, native configured-user guard and passwordless WebAuthn factor, all `REQUIRED`, with no OTP/password/two-factor alternative; the 17 October repair adds the guard so an unenrolled essential LoA-3 request gets the native unmet-ACR HTTP 400 denial rather than a server error, while enrolled users still must prove WebAuthn;
- **exactly one** flow in the realm sets LoA 3, and it is the passkey subflow (any other flow able to set 3 would change what `acr=3` means);
- the condition is level 3 with a 300-second maximum age;
- the subflow is `CONDITIONAL` and evaluated before the OTP step-up;
- the passwordless WebAuthn policy requires user verification;
- a password-only authentication does not yield `acr=3`;
- whether the native `oidc-amr-mapper` exists is reported (INFO), never asserted.

## What is not proven here

A headless runner can exercise a virtual CTAP2 authenticator through Chromium's
WebAuthn automation. `tests/integration/passkey` now requires actual browser
registration and authentication against the disposable pinned Keycloak in every
fresh/legacy/primary variant. It verifies RS256 signatures, issuer, audience,
nonce, S256/state, fresh `auth_time` and raw LoA 3, and retains only sanitized
per-case receipts. Enrollment, ordinary SSO and TOTP cannot substitute for the
passkey proof. Bad signatures, absent UV/UP, code replay and revoked credentials
must deny. Every case and teardown must pass; no SKIP can qualify a run.

This is synthetic-browser/provider qualification, not physical-authenticator,
production enrollment/recovery or CP CRITICAL-grant acceptance. The original
CRITICAL prohibition remains. The following complete-chain requirements must
still be independently satisfied before it can be lifted:

1. a real WebAuthn/passkey step-up produces `acr=3` with a fresh `auth_time`;
2. TOTP, ordinary MFA and SSO reuse do not produce 3;
3. requesting `acr_values=3` without completing WebAuthn does not fall back to a token the Control Plane would accept (the Control Plane meets a CRITICAL requirement only with `acr` 3 and a fresh authentication, so a fallback to 1 or 2 is refused there regardless);
4. the whole chain: WebAuthn step-up, `acr`, freshness, Control Plane assurance evaluation, HIGH/CRITICAL grant, independent approval, authoritative decision.

Administrators must also enrol a passkey; enrolment and recovery policy (ADR-IAM-0024, ADR-IAM-0025) are outside this change.


## Browser qualification scope and operation

The test launcher refuses non-loopback issuers and non-disposable environments.
It creates one random synthetic user and one isolated public S256 client,
enrolls TOTP and a discoverable UV-required passkey through real provider forms,
and deletes/verifies absence of both resources even after failed assertions.
Initial synthetic required actions are fixture bootstrap, not an approved
production high-assurance binding/rebinding or notification procedure under
ADR-IAM-0025. No existing user, realm policy, workload, business grant or
AdministrativeGrant is changed.

Dependencies are exact, locked Node 24+ Playwright/OIDC/JOSE versions already
used by Infrastructure INT-02. Run `npm ci --prefix tests/integration/passkey`,
install its Chromium runtime, then run the normal integration suite in the
disposable Compose environment. CI runs all three browser configurations and
uploads `passkey-browser-*` artifacts containing complete per-case receipts and
SHA-256 digests only. Credentials, virtual private keys, assertions, tokens,
HTML, cookies, screenshots and traces are excluded. Publication occurs only
after both evidence files are written and synchronized. Physical hardware,
production identity binding/recovery, full CP grant/independent approval and
Ory-native passkey qualification remain separate acceptance work.

References: [Chromium WebAuthn automation](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)
and the pinned Keycloak 26.7.5 [registration](https://github.com/keycloak/keycloak/blob/26.7.5/themes/src/main/resources/theme/base/login/webauthn-register.ftl)
and [authentication](https://github.com/keycloak/keycloak/blob/26.7.5/themes/src/main/resources/theme/base/login/webauthn-authenticate.ftl)
forms. Current-run PASS evidence, rather than source presence, establishes the
bounded browser result.
