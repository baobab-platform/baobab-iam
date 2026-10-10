# Gate IAM-11 — Credential Security, MFA, Passkeys and Account Recovery

**Status:** Phase 1 complete (password policy fix + privileged-role MFA enforcement, structurally verified against a real Keycloak instance in CI). This is the largest ADR in the programme so far (188 sections) — most of it is scoped for later phases; see §4.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0015 — Credential Security, MFA, Passkeys and Account Recovery`
**Repositories:** `baobab-platform/baobab-iam` (owner of all human credential mechanisms per the ADR's own §178 ownership table)
**Depends on:** Gate IAM-5 (workforce role namespace — this gate wires MFA onto the roles that gate created)

---

## 1. Discovery

`docs/governance/gate-iam-0-discovery.md` (§ADR-0015 row) already flagged this correctly: "Realm has `otpPolicyType`/`webAuthnPolicy*` defaults only; no MFA-required policy for privileged populations." Reading the realm JSON directly confirmed two concrete, fixable problems, not just an absence of policy:

1. **`passwordPolicy` actively violated ADR-0015 §11-14.** The realm shipped `"length(8) and digits and lowerCase and upperCase and notUsername"` — both too short (§11-12 want a 15-character minimum for single-factor-capable passwords) and built entirely out of the composition rules §14 explicitly names as prohibited "security theater" ("one uppercase, one lowercase, one digit ... merely as security theater"). This is a real bug, not a missing feature.
2. **No authentication flow enforced MFA for anyone.** Keycloak's default `browserFlow` ships a "Browser - Conditional OTP" subflow, but it is conditional on *the user already having configured OTP* (`conditional-user-configured`), not on role/risk — meaning nobody was ever required to enroll or use a second factor, privileged workforce admins included, directly contradicting §24 ("Privileged interactive access SHALL require MFA").

Neither of Gate IAM-5's `-admin` workforce clients (`baobab-trade-admin`, `baobab-cms-admin`, `baobab-erp-admin`) sets `directAccessGrantsEnabled: true`, so all human workforce login goes through the browser (authorization-code) flow — meaning `browserFlow` is the one flow that actually matters for enforcing this gate's MFA requirement; `directGrantFlow` was left untouched since nothing uses it for humans.

## 2. Design: role-driven conditional MFA (verified against Keycloak's own source)

Rather than guessing at Keycloak's authentication-flow JSON schema, the exact shapes below were read directly from `keycloak/keycloak`'s own source and test fixtures before writing anything:

- `services/.../authenticators/conditional/ConditionalRoleAuthenticatorFactory.java` — confirmed the provider ID is `conditional-user-role`, configured via a `condUserRole` property (a realm or client role name).
- `server-spi/.../models/utils/RoleUtils.java`'s `hasRole()` — confirmed composite-role expansion runs in the direction needed: if a user is granted role A, and A's own `composites` list includes role B, `hasRole(B)` returns `true` for that user. This makes a single marker role a working "OR across many roles" condition, without one conditional subflow per privileged role.
- `testsuite/.../migration-realm-24.0.4.json` — a real Keycloak-authored realm export, used as the structural template for `authenticationExecutions`/`authenticatorConfig`/subflow (`flowAlias`) wiring, rather than inventing the shape.

**Implementation** (`config/realm/baobab-realm.json`):

- A new marker role `iam:mfa-required` (never assigned directly), added to the `composites` of every existing Gate IAM-5 workforce role (`iam:security-admin`, `iam:helpdesk`, `cp:platform-admin`, `cp:tenant-admin`, `trade:operator`, `cms:editor`, `cms:publisher`). Anyone granted any of those roles now effectively "has" `iam:mfa-required`.
- Three new, non-`builtIn` authentication flows: `Baobab browser` (a copy of Keycloak's built-in `browser` flow), `Baobab forms`, and `Baobab - Privileged MFA` — the last one runs `conditional-user-role` (config `condUserRole=iam:mfa-required`) as `REQUIRED`, followed by `auth-otp-form` as `REQUIRED`. Standard/enhanced-risk users (without the marker role) skip the subflow entirely, matching ADR-0015 §21-23's risk-tiered posture — this is not a blanket MFA requirement.
- `browserFlow` set to `"Baobab browser"`. The built-in `browser` flow itself is untouched (Keycloak's own convention: customize via a copy, never edit a `builtIn: true` flow in place).

`tests/integration/run.sh` §15 verifies, against a real Keycloak instance: the password policy string, `browserFlow`'s value, the marker role's existence, each of the 7 roles' composite membership (via `GET .../roles/{role}/composites`), and the flow's actual execution tree (via `GET .../authentication/flows/Baobab%20browser/executions`) contains both the role condition and the OTP form step.

## 3. What this phase does *not* verify (and why)

This suite has no headless-browser tooling, and every workforce `-admin` client has `directAccessGrantsEnabled: false` (Gate IAM-5's own deliberate choice) — so there is no token-endpoint shortcut that exercises `browserFlow` end-to-end the way `tests/integration/run.sh` exercises `client_credentials`/`password` grants elsewhere. What's verified here is structural: the flow exists, is wired correctly, and is bound as the realm's `browserFlow`. Whether a real browser login for a `iam:mfa-required`-composited user is actually challenged for OTP is Keycloak's own well-tested authenticator behavior operating on a structure this suite confirms is correctly assembled — not independently re-proven end-to-end in this environment.

## 4. Remaining phases (scoped, not yet implemented — this ADR has 188 sections)

Given the ADR's size, this phase deliberately targeted the two concrete, already-broken things (password policy, no privileged MFA) rather than attempting the whole document at once. Significant remaining scope, roughly ADR-section-ordered:

1. **Passkeys/WebAuthn as an alternative second factor** (§7-10, §27, §156) — today privileged users get TOTP only; WebAuthn should be offered as an `ALTERNATIVE` execution alongside `auth-otp-form` inside `Baobab - Privileged MFA`, and passwordless/passkey-first login is a larger UX trajectory each Digital Estate frontend (Thamani, Zuribeans) needs to adopt, not just an IAM realm setting.
2. **Compromised/weak-password blocking** (§15) — Keycloak's built-in `passwordBlacklist(...)` policy needs a blocklist file provisioned into the image (`providers`/deployment directory), which has no existing mechanism in this repo's `Dockerfile`/`bootstrap.sh` today; needs its own small phase.
3. **Step-up authentication for specific high-risk actions** (§37-43, §94-95) — `acr`/`amr`/`auth_time` claim-based step-up for actions like "change supplier bank details" or "release payment" is enforced by *each domain engine/CP*, not by the realm alone; IAM's job is only to make step-up requestable (Keycloak already supports `acr_values`/step-up natively), which hasn't been wired into any client or `baobab-cp` policy yet.
4. **Recovery-flow hardening** (§51-75, §160) — enumeration-resistant responses, recovery-token replay/expiry tests, privileged recovery's two-person control (§122) — Keycloak's default forgot-password flow covers the basics (single-use, expiring tokens) but none of it has been reviewed or tested here yet.
5. **Break-glass credentials** (§117-121) — explicitly deferred; needs an infrastructure/secrets-vault decision this session can't make unilaterally (mirrors Gate IAM-8's supplier-domain-ownership deferral pattern).
6. **Credential-security audit/metrics** (§128-134) — largely ADR-0017's territory (a later gate), not started here.
7. **Password-common-block/compromise detection, session-revocation-on-recovery, credential lifecycle states** (§76-80, §89-93) — not started; Keycloak provides primitives (session management, credential disable/delete) but no explicit policy wiring exists yet for these specific rules.
8. **Engine credential migration** (§111-116) — Medusa/iDempiere/CMS admin SSO already exists (Gates IAM-5, IAM-9, IAM-10); "local password disabled" isn't verified for any of them yet.
