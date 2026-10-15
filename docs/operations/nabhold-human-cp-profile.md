# G04B-04 — Nabhold human client, CP audience and protected observations

**Status:** SOURCE PROFILE / ACCEPTANCE TOOLING ONLY. No real client approval,
staging observation or G17 acceptance is claimed by this change. Governance:
Nabhold Go-Live Master Plan v2.0 G04/G17 and ADR-NAB-0004/0014; accepted IAM
ADR-IAM-0033 and CP ADR-BCP-020. This work reuses Shared's existing human-only
non-authorising authority:self scope; it registers no new scope or platform grant.

## Provider choice and exact authority

Keycloak remains supported for permanent enterprise federation under
ADR-IAM-0033. The present Kratos/Hydra native human handoff restricts scopes to
openid/profile/email and denies resource audiences. That native path MUST NOT be
silently broadened. Nabhold's existing BFF #55 only requests openid and later
requires active introspection with aud=baobab-control-plane and authority:self.
For this bounded compatibility path, provision an **approved Keycloak
confidential human client** with the exact *default* scopes in
config/clients/nabhold-executive.json. In particular, authority:self supplies
the CP audience through its existing access-token-only mapper. It reads one's
own effective administrative grants, but creates **no** executive role or
domain/capability permission.

The committed client is intentionally disabled, has no redirect URIs, origin,
secret, direct grants, service account, implicit flow or optional privileges.
It cannot authenticate as committed. No production URL or approval record was
invented.

## Privileged operator activation (not an unattended CI step)

1. Obtain distinct independent authorisations for identity client registration
   and CP external-identity mapping. Approve Nabhold's precise *HTTPS*
   origin/callback and a nonproduction Keycloak issuer. Ensure the protected
   issuer's OIDC discovery, signing JWKS and introspection endpoint match Nabhold
   #55 settings. Do not accept a wildcard or http://localhost URI.
2. An IAM operator creates/reconciles the real Keycloak client from the committed
   template using protected administration, replacing only enabled=false with
   true and redirectUris=[] with [<origin>/api/auth/callback]; keep webOrigins=[]
   and scopes EXACT. Use a fresh independently managed confidential client
   secret, never a repository secret or deterministic workload bootstrap seed.
   Review the sanitized client record (omit secret) and hold it owner-private
   with mode 0600. The Keycloak adapter must issue the exact human issuer,
   subject, CP audience, authority:self scope, client_id and finite exp.
3. Independently register/activate current canonical CP human Principals and
   exact issuer+subject links. No email, role, provider sub or IAM administrator
   automatically creates a CP Principal or executive entitlement. Apply genuine
   CP authority under approved separated human ceremonies.
4. Enable the Nabhold confidential BFF only in an approved nonproduction
   deployment with verified-TLS Redis/session storage. Configure approved
   issuer, client ID, introspection endpoint, CP origin and BFF secret privately.
   Test PKCE, callback, canonical identity, revocation, logout, wrong audience,
   unmapped principal, session eviction/recovery and browser isolation.
5. Run the separate safe technical observer below using **real** reviewed
   staging tokens. The negative token cases require an independently obtained
   active token for another audience, a genuinely revoked token, and an active
   unmapped CP-audience human. The script does not mint or revoke any of them.
   A 404 for a nonexistent URL is not an isolation test.
6. An independent identity/security/release reviewer examines the protected
   browser and token evidence, CP action policy, restore drills and operator
   signatures. Only the established G17 authority can sign acceptance.

## Source verification

    python3 scripts/verify_nabhold_human_cp.py
    python3 -m unittest discover -s tests/unit -p test_nabhold_human_cp.py

No network secrets are required for source CI. CI still exercises the normal
Keycloak bootstrap and platform security gates.

## Protected technical observation

Populate the following environment variables from a short-lived protected
secret session, never from GitHub commits, arguments, screenshots or logs:

- NABHOLD_G04B_ENVIRONMENT=staging
- NABHOLD_G04B_ISSUER (exact HTTPS Keycloak realm issuer)
- NABHOLD_G04B_CP_ORIGIN and NABHOLD_G04B_ESTATE_ORIGIN (HTTPS origins)
- NABHOLD_G04B_REVIEWED_CLIENT_FILE (owner-private 0600 sanitized actual client JSON)
- NABHOLD_G04B_CLIENT_SECRET (confidential client secret)
- NABHOLD_G04B_PRINCIPAL_UUID and NABHOLD_G04B_SUBJECT
- NABHOLD_G04B_POSITIVE_TOKEN
- NABHOLD_G04B_WRONG_AUDIENCE_TOKEN
- NABHOLD_G04B_REVOKED_TOKEN
- NABHOLD_G04B_UNMAPPED_TOKEN

    python3 scripts/verify_nabhold_human_cp.py --protected

All HTTPS requests use system TLS trust, a five-second timeout, an exact
provider/CP destination, no redirect, bounded JSON and no retry. The script
prints sanitised status ONLY; a passed run reports OBSERVED_NOT_ACCEPTED.
Store external release evidence and reviewer sign-off in the approved protected
custody system, not in this repository.

## Remaining requirements

- The current native Kratos/Hydra path does not yet support this CP audience.
  Treat Keycloak-backed enterprise federation as the bounded compatibility
  path, subject to verified live behaviour and an explicit IAM owner decision.
  If the operator-approved human issuer is Hydra instead, leave Nabhold disabled
  and implement the resource-audience grant and corresponding BFF request in
  their owning repositories under separately reviewed contracts.
- Protected browser E2E, real CP principal/mandate, actual operator grants,
  production certification, session revocation, R1 capability authorisation and
  signed G17 release acceptance are NOT source facts.
- This profile MUST NOT be enabled in production by changing enabled in Git.
  Separate protected configuration/review is mandatory.
