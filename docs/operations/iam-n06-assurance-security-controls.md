# IAM-N06 — Authentication assurance, recovery and security operations

**Status: draft engineering source, connected evidence HELD.**
**Authority:** EA v2.3/EA-DEV; ADR-IAM-0015–0018, ADR-IAM-0023,
ADR-IAM-0024, ADR-IAM-0025, ADR-IAM-0028, ADR-IAM-0029 and ADR-IAM-0033.
Pull request: `baobab-iam#151`, **stacked on IAM #147**. Neither branch
is approved or merged. Keycloak remains enterprise federation.
The Control Plane (not IAM) owns canonical identity, membership,
tenant privileges and business authorization.

## IAM-N06 implemented source boundary

### 1. Fresh assurance policy: A1, A2, A3, A4

`internal/assurance` evaluates a **current, server-observed**
authentication session against the exact, reviewed operation.
Its output means **authentication assurance only**, never permission.
An unknown operation, missing issuer/subject/session, missing current
provider proof, unexpected auth method, stale authentication, expired
provider readback or absent risk evidence fails closed.

- **A1:** actual signed/current authenticated-provider AAL1.
- **A2:** verified current AAL2; TOTP never implies passkey use.
- **A3:** a **current authentication event** with verified WebAuthn or
  passkey use, RP-origin binding and user-verification evidence. Merely
  enrolling an authenticator or recording method=`webauthn` does not
  make it phishing-resistant proof.
- **A4:** A3 plus fresh authentication, current independently verified
  privileged context/risk, and hardware-bound evidence, subject to
  additional operation-specific constraints. No NIST certification claim.

The policy template is deliberately stricter for high-value approvals,
credential change/recovery rebind, IAM grants and break-glass.
The current risk reader may raise but cannot lower hard minima.
An actual recovery event introduces a sensitive-action hold.

### 2. First-party N02 BFF enforcement

N02's real `nativebff` now accepts a server-reviewed scope→operation
mapping and an IAM N06 guard. With `N06Required=true`, it refuses
to start if any requested non-`openid` scope lacks an exact reviewed
operation or if there is no guard. The gate runs at login, consent GET,
consent POST, and OAuth callback before issuing a new browser session;
a skipped callback cannot retain the earlier consent as permanent
assurance. The browser cannot select risk, required AAL, operation
class or the authoritative scope-to-operation map.

`KratosN06Provider` reads the *current* Kratos public session over an
exact TLS-verified origin, without redirects, forward proxies or
untrusted provider responses. It requires a live active identity,
bound session ID, exact AAL, actual authentication timestamp, valid
expiry, and nonambiguous JSON. It can currently prove A1/A2 only.

**A3/A4 support is not enabled from Kratos by this PR.**
A Kratos session's `authentication_methods` names do not alone prove
WebAuthn origin/user verification. Production requires a separately
qualified RP-bound cryptographic passkey proof reader and genuine
hardware-bound/A4 witness before A3/A4 are accepted. Existing Keycloak
passkey browser qualification is distinct and is not silently promoted
into the Ory-native path.

### 3. Recovery and high-risk identity rebinding

`internal/securityops` records only **witnessed** Kratos recovery
events and bounded post-recovery holds in a separate PostgreSQL 17
schema. It requires independently verified recovery event evidence.
Holds cannot be shortened or deleted by the online runtime, and
issuer/security-domain ownership cannot be reassigned.

A dedicated `credential_rebind` journal now requires a fresh A3
witness, exact canonical Principal and issuer identity, a distinct
independently approved second reviewer, and a reviewed credential
kind (PASSKEY/TOTP/RECOVERY_FACTOR). It is pseudonymous, append-only
and does not store a new credential secret. Completion requires real
Kratos authenticator readback, proof that previous sessions were
revoked, and the exact unchanged CP Principal. An alternate issuer,
self-approval, missing A3, or an unobserved provider operation fails
closed. A COMMITTED rebind cannot be reopened.

This **does not** automatically rebind a CP Principal, legal entity,
workforce role, supplier representative or payment mandate. Sensitive
rebindings require independent identity/relationship proof and
Kratos-owned self-service execution. The source policy denies any
operation where the mandatory witnesses are missing.

### 4. Cryptographic rotation

A governed `rotation_plan` models distinct purposes:
Hydra signing, Hydra OAuth client credentials, Kratos cookie/cipher,
TLS certificate and enterprise federation trust. It stores opaque
secret-manager **references**, not private material. Retirement
requires independent provider readback, consumer/JWKS proof, an
expired old-token/verification overlap and a separately witnessed
approval. Terminal states cannot be reopened.

**Not yet claimed:** an actual provider key rotation, original JWKS
overlap test, KMS readback, TLS renewal drill, cross-region trust
distribution or replay of still-valid tokens.

### 5. Privacy-safe audit and security incident containment

Append-only `iam_security.event` permits only a small canonical
event taxonomy, result codes and severity/outcomes. Actor/subject
identifiers are purpose-keyed HMAC-SHA256, not emails, session
cookies, IP/device fingerprints or access/refresh tokens.
No raw provider exception, passwords, TOTP, private keys, recovery
codes, client secrets or arbitrary JSON metadata are accepted by
the supported writer.

`incident_command` models three **narrow** actions: one session,
one native identity, one workload client. It cannot represent
global issuer revocation, tenant-wide disable, mass logout or
signing-key destruction. Disabling a native identity/workload
requires a second independently authorized actor, plus a current
high-assurance approval readback. Progress must prove actual issuer/
Kratos mutation and independently observed CP/resource token denial
before `VERIFIED`. A 2xx alone never proves global token withdrawal.

**Not yet claimed:** a deployed ingestion pipeline, live alerts,
actual session theft detection, provider-accepted incident mutation
or original CP denial. The journal is not itself the containment
executor or business authorization engine.

## Database/CI and threat test boundaries

Install `internal/securityops/migrations/001_n06_security.sql` via an
independent, reviewed migration pipeline. Constructing a Go store
does **not** run DDL or use production credentials. The isolated
`iam-n06-postgres17-security` GitHub Actions job must run with the
pinned PostgreSQL 17 image in a disposable `n06_ci` database.
A source-only test skip without that environment does not count as
durable N06 evidence. The required job validates:

- MFA/TOTP ≠ passkey ≠ privileged A4; fresh signed/issuer session
  and risk cannot be forged or downgraded;
- first-party native BFF scope mapping and fail-closed login/consent;
- malformed/redirected/duplicate Kratos responses and invalid AAL;
- recovery timestamp, issuer/domain ownership, no hold shortening;
- immutable privacy-safe event payloads and no raw identity;
- old signing/trust material cannot retire before verified consumers
  and token overlap expiry;
- independent incident approver, source provider confirmation and
  current resource veto required before VERIFIED.

The GitHub Actions *read-only* N06 formatter exists to submit
reproducible gofmt output without a write-capable workflow token.
It is a development helper, **not** an acceptance test and should
be deleted before merging once final-head formatting is stable.

## Remaining connected qualification (all HELD)

1. Review N02’s actual issuer/Kratos/CP source and merge gates, then
   qualify A2 in a first-party real browser including forced step-up,
   session invalidation, wrong issuer, cross-tenant negatives.
2. Implement and prove **RP-verified** Kratos passkey challenge,
   user verification, origin binding, signature counter/replay and
   credential revocation on real authenticators; no fake A3.
3. Prove protected A4 with independent CP current privilege,
   sensitive-operation policy, high-assurance device/transaction
   witness and no self-approval; existing CRITICAL CP gate remains
   PROHIBITED until evidence.
4. Exercise real recovery courier, expired/replayed recovery code,
   post-recovery session revocation, temporary hold, and two-person
   high-risk authenticator rebinding with immutable originals.
5. Execute scoped OAuth credential and signing-key rotation in actual
   Hydra/Keycloak/Kratos provider sandboxes with JWKS overlap, issuer
   revocation, current CP resource denial, secret-store references,
   rollback and independent teardown.
6. Establish operational security events/alerts, incident readbacks,
   replay/restore, privacy-safe retention and DR evidence.

**No new N04 provider support is accepted by this code.** N06 review
requires final-head mandatory CI, provider owner/security review,
first-party connected evidence and independent custody. Protected
staging/production changes require their own approvals. **Do not merge.**
