# Gate IAM-10 — iDempiere SSO and ERP Identity Mapping

**Status:** Phase 1 complete (`baobab-iam`'s workforce SSO client). Phase 2 (`baobab-erp` — SSO configuration runbook + fixing the ERP integration boundary's missing workload authentication) in progress in this gate. Human login is wired against a **documented, accepted deviation** from ADR-0014 §9 — see §2.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0014 — iDempiere SSO and ERP Identity Mapping`
**Repositories:** `nabhold/baobab-iam` (workforce SSO client, owner), `nabhold/baobab-erp` (AD_User, AD_Role, AD_Client/AD_Org, ERP integration boundary)
**Depends on:** Gate IAM-4 (workload identity — already provides `baobab-erp-workload`, complete), Gate IAM-5 (workforce SSO pattern this gate reuses)

---

## 1. Discovery — iDempiere already ships a real, pluggable OIDC mechanism

Before writing anything, `nabhold/baobab-erp` was read in full (already attached to this session from Gate IAM-8/IAM-9 research) and cross-checked directly against `idempiere/idempiere`'s own source (`org.idempiere.p2.profile/features/core/feature.xml`, `org.idempiere.ui.sso.oidc/src/...`), not assumed:

- **`org.idempiere.ui.sso.oidc` is part of iDempiere 13's `core` feature** (`org.idempiere.p2.profile/features/core/feature.xml` lists it as a `<plugin>` directly) — it ships in every standard `idempiereofficial/idempiere:13-release` distribution with no third-party plugin install step, unlike `com.trekglobal.idempiere.rest.api` (ADR-ERP-005's still-open p2/Tycho blocker, unaffected by this gate).
- It implements iDempiere's own `ISSOPrincipalService`/`ISSOPrincipalFactory` extension points (`org.adempiere.base.sso`), matching this repo's own stated policy exactly: "Every Baobab behaviour is implemented ... using supported extension points ... `idempiere/patches/` ... is empty because no such case has arisen" (`idempiere/README.md`). No patch, no new OSGi bundle, and no ADR-ERP-004 patch-justification is needed for the login mechanism itself.
- Configuration is entirely data-driven, through an `AD_SSO_PrincipalConfig` record: Discovery URI (must end `/.well-known/openid-configuration`), Client ID, Client Secret, and per-mode Redirect URIs (WebUI / Monitor / OSGI) — read via `I_SSO_PrincipalConfig` getters in `OIDCPrincipalService.java`. Scopes requested are fixed: `openid profile email`.
- The login flow is a standard authorization-code redirect (`SSOWebUIFilter` intercepts WebUI requests, redirects to the provider's authorization endpoint with `state`/`nonce`, exchanges the code via `client_secret_basic` at the token endpoint, then calls the userinfo endpoint) — confirmed against source, not assumed.
- **No PKCE.** Verified directly: nothing in `org.idempiere.ui.sso.oidc` builds or sends a `code_challenge`. This is a real difference from `baobab-trade-admin`/`baobab-cms-admin` (Gate IAM-5), both of which require PKCE S256 because their browser-based frontends generate one. A Keycloak client requiring PKCE would reject every real login attempt from iDempiere.

## 2. Accepted deviation from ADR-0014 §9 (documented, not silently ignored)

ADR-0014 §9 is explicit: the primary identity mapping "SHALL derive from `issuer + subject`" and "SHALL NOT rely on email/username/display name as durable identity keys." Reading `OIDCPrincipalService.getUserName()` directly shows the stock plugin does exactly the prohibited thing **on every login, not just initial account linking**: it resolves the OIDC claim to either the userinfo `email` or `name` claim (controlled by `MSysConfig.USE_EMAIL_FOR_LOGIN`) and hands that string to iDempiere's own pre-existing username-based login/lookup — there is no `sub`-keyed mapping table anywhere in the plugin.

Three options were considered:

1. **Ship the stock plugin now, accept the deviation** — real login working today, using a real supported extension point, at the cost of ADR-0014 §9/§79/§80 non-conformance (a username or email rename could sever the login-to-AD_User link; this is the same class of risk §46 separately prohibits for migration auto-linking, now present on every login rather than a one-time migration step).
2. **Write a custom `org.nabhold.baobab.erp.security` OSGi bundle** implementing `ISSOPrincipalService` directly against baobab-app's `sub`-keyed canonical-mapping resolver (the same pattern `context`/`mapping` already use) — fully conformant, but real new Java/OSGi engineering with no live iDempiere+Keycloak stack in this environment to integration-test it against.
3. **Defer human ERP login entirely this gate** — document both findings, ship nothing.

**Decision (explicit check-in, 2026-09-12): option 1.** There is no JIT auto-creation anywhere in the stock plugin (confirmed — see §1), so the blast radius of the deviation is bounded to *already-provisioned* `AD_User` records losing their login link on a rename, not unauthorized account creation; ADR-0014's harder invariants (§13 no-auth-equals-provisioning, §famous AD_Role preservation, §15-17 no role mirroring) are unaffected. This is tracked here as a scoped, accepted risk — the same pattern as the `.trivyignore` Netty CVE entries — to be closed by option 2 in a later phase once there's a real integration environment to test the custom bundle against.

## 3. Phase 1 (`baobab-iam`, this PR)

Added `config/clients/baobab-erp-admin.json`, matching `baobab-trade-admin`/`baobab-cms-admin`'s exact convention (confidential, `standardFlowEnabled: true`, `bearerOnly: false`, `actor-type-human` default scope, distinct from the bearer-only `baobab-erp` client) with one deliberate difference: **no `pkce.code.challenge.method` attribute** (see §2's PKCE finding — setting it would break every real login). Redirect URI is `https://localhost:8443/webui/*`, matching `compose.yaml`'s iDempiere WebUI healthcheck path (`https://127.0.0.1:8443/webui/`) for local dev; a real deployment's redirect URI is environment-specific and configured on the `AD_SSO_PrincipalConfig` record, not hardcoded here. `tests/integration/run.sh` §14 asserts the client exists, is a distinct non-bearer-only SSO client, carries `actor-type-human`, and — unlike §11's admin-client check — asserts PKCE is *absent* rather than present, with a comment explaining why.

Also added `config/scopes/erp-integrate.json` (an `oidc-audience-mapper` for `aud=baobab-erp`) and attached it to `config/clients/baobab-erp-workload.json`, alongside its existing `context:resolve` scope. This is a separate, real gap from the login flow: `context:resolve`'s audience mapper is hardcoded to `baobab-control-plane` (Gate IAM-4), so a `baobab-erp-workload` token requesting only that scope cannot be used to authenticate to `baobab-erp`'s own HTTP boundary — a token scoped for the Control Plane should not also work against ERP (ADR-0007 §§24-25). Registered upstream first, per this programme's own convention (a workload's scope grant is registered in `nabhold/shared` before the Keycloak client picks it up): `nabhold/shared#36` adds `erp:integrate` to `scope-registry.yaml` and grants it to `baobab-erp-workload`'s `workload-registry.yaml` entry. `contracts.lock.yaml` is **not** bumped in this PR — `tests/integration/run.sh` §9's registry-consistency check only inspects the `context:resolve` scope specifically (a hardcoded filter, not a general one), so this addition isn't checked against the registry by existing CI either way; bumping the lock file to `nabhold/shared#36`'s merged commit is tracked as a small follow-up once that PR merges, matching Gate IAM-4 phase 3's own precedent of pinning to a real merged commit rather than a pre-merge branch tip. `tests/integration/run.sh` §14 also asserts the scope is attached and that a token requesting it actually carries `aud=baobab-erp`, against a real Keycloak instance.

## 4. Phase 2 (`baobab-erp`, this gate)

Two separate, real gaps existed in `baobab-erp`, found by reading its code directly (not inferred from this ADR alone):

1. **No documented path from "Keycloak client exists" to "iDempiere actually trusts it"** — `AD_SSO_PrincipalConfig` lives in iDempiere's own `adempiere` schema, which `baobab-erp`'s own `db/README.md` explicitly forbids this repository's code from writing to directly ("Neither engine's code reads or writes the other's schema directly ... only iDempiere touches its own tables", ADR-ERP-001). A checked-in SQL seed script would violate that boundary. Fixed by adding `docs/sso-configuration.md`: an operational runbook for a System Administrator to create the `AD_SSO_PrincipalConfig` record by hand (or via iDempiere's own package-export/import tooling in a later phase) with the exact field values Baobab IAM's realm now provides — the Discovery URI, `baobab-erp-admin`'s client ID, and a note that the client secret must come from the deployment's own secrets management, never committed.
2. **`/context/resolve*` and `/mapping/resolve*` have zero authentication** — this is a pre-existing, already self-documented gap (`modules/application/server.py`'s own module docstring: "have no authentication of their own yet -- they rely on network-level trust", cross-referenced in `architecture/conformance.yaml` against ADR-ERP-010: "no real IdP/authentication integration ... HTTP layer has no authentication of its own beyond the event-signing secret"). This is squarely ADR-0014 §111 territory ("Machine-accessible ERP APIs SHALL require explicit workload authentication. Internal network location alone SHALL not be sufficient") and squarely this gate's to fix, since `baobab-iam` already provisions exactly the workload identity needed (`baobab-erp-workload`, Gate IAM-4, already carries `actor-type-workload` + `context:resolve`). Fixed in `nabhold/baobab-erp` by validating the `Authorization: Bearer` header against Baobab IAM's JWKS on those four endpoints (issuer/audience/`actor_type=workload` check, matching `baobab-cp`'s own verifier shape from Gate IAM-4) before doing any resolution — see that PR for the exact diff.

## 5. Remaining phases (scoped, not yet implemented)

1. **Close the ADR-0014 §9 deviation** — the custom `sub`-keyed `ISSOPrincipalService` bundle (§2, option 2), once a real Keycloak+iDempiere integration environment exists to test it against.
2. **`AD_User`/`AD_Role`/`AD_Client`/`AD_Org` provisioning and the Control Plane context mapping** (ADR-0014 §4, §18-31, §93-98) — depends on `baobab-cp`'s own ERP-context resolution existing, which it does not yet (not investigated further this gate; `baobab-cp` was not re-opened here).
3. **Step-up/MFA for finance users** (§34-37, §105-106) — depends on Gate IAM-11 (Credential Security, ADR-0015), not yet reached.
4. **Local account migration** (§44-49) — not applicable yet; no existing iDempiere deployment with real local users exists in this codebase (same "greenfield, nothing to migrate" reasoning as Gate IAM-9 §3's migration note).
5. **Break-glass emergency access** (§41-43) — not started; needs an explicit ADR-level decision on the emergency credential mechanism, out of this gate's bounded scope.
6. **Live integration tests against a real Keycloak+iDempiere stack** (§123-129) — this environment has neither a running iDempiere instance nor Docker Compose orchestration available in this session; today's verification is source-level (§1-2) plus `baobab-iam`'s own Keycloak-only integration suite (§14). Revisit once such an environment exists.

## 6. Boundary API scopes (`erp:read`, `erp:provision`)

`baobab-erp-workload` also carries `erp:read` and `erp:provision` (`config/scopes/erp-read.json`, `erp-provision.json`; audience
`baobab-erp`), the scopes the ERP Boundary API (`contracts/erp/v1/openapi.yaml`) requires. They were defined in Shared first
(shared#206, which also allows them to `baobab-erp-workload` and to no other workload), and `contracts.lock.yaml` now pins that
commit; `scripts/check-issued-scopes.sh` proves every issued scope is registered.

**The client stays tenant-neutral.** No `tenant_id` is stamped on `baobab-erp-workload` and no tenant list is placed in its tokens.
One shared workload identity serves many tenants, and tenant entitlement is a Control Plane decision (ADR-0007 sections 88-91:
IAM scope plus Control Plane context; "Scope is not tenant access"; IAM does not own the workload-to-tenant relationship).
Per the programme owner's ruling of 2026-10-02, the ERP Boundary API takes its tenant from a trusted Control Plane context
(`context_id`), and a token `tenant_id`, when present, is only an additional binding that must equal the context's tenant. The
Shared and ERP changes for that are separate; until they land the ERP routes still require a tenant and answer 403, so these
scopes reach no tenant's data. `tests/integration/run.sh` section 14 asserts the scopes are held by this client only, that a token
carries `aud=baobab-erp`, and that it carries no `tenant_id`.

`scripts/bootstrap.sh` also reconciles *default* client scopes now, additively and for Baobab-vocabulary scopes only (those defined
under `config/scopes/`), so a scope newly declared for an existing client reaches a deployment bootstrapped before it existed.
