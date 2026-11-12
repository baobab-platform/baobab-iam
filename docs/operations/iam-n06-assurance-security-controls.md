# IAM-N06 — Authentication assurance, recovery and security operations

**Status: draft engineering source, connected evidence HELD.**
**Authority:** EA v2.3/EA-DEV; ADR-IAM-0015–0018, ADR-IAM-0023,
ADR-IAM-0024, ADR-IAM-0025, ADR-IAM-0028, ADR-IAM-0029 and ADR-IAM-0033.
Pull request: `baobab-iam#151`, **now based on IAM-N04 #149**. Source PRs #145–#148 were merged on 5 November 2026; #149 remains the unmerged, separately reviewed N04 dependency. The N06 branch has a non-force merge parent from the current #149 branch, with N04 blobs preserved unchanged. Neither #149 nor #151 is development-certified or authorised for protected deployment. Keycloak remains enterprise federation.
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

**Executable binding correction (4 November 2026, PR #151):** The actual
`cmd/native-browser-bff` constructor now sets `N06Required=true`, supplies
an exact server-owned `openid trade:buy` → `OrdinaryBuyer` authentication
policy, and instantiates `N06SecurityGate` with a TLS-verified current Kratos
session reader. A high-risk/privileged/current-risk witness is intentionally
unavailable and therefore denied rather than fabricated. The scope mapping
supports authentication only: neither `trade:buy` nor a successful A1/A2
login authorises a native buyer commitment. CP Principal, market mandate,
spend limits and Trade's native fence remain independently mandatory.

`cmd/native-browser-bff/n06_main_test.go` defends the actual command
constructor with an AST-based regression check: the concrete
`nativebff.New(nativebff.Config{...})` call must retain all three live
N06 fields. It additionally rejects extra/duplicated/unreviewed scopes
and an invented risk result. CI runs this executable check explicitly,
not just isolated handler tests. This is SOURCE_QUALIFIED only until the
same-run native Kratos/Hydra/CP/first-party browser negative and
independent original evidence/teardown is obtained.

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

The temporary read-only N06 formatter workflow was removed on 6 November
2026 after the mandatory `provider-contract` Go-format check passed on the
reviewed earlier head. This is housekeeping, **not** acceptance: current-head
Go formatting, security and connected evidence must still pass independently.

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

## 6 November 2026 — additional actual Kratos session/revocation qualification

- `internal/provider/ory/n06_assurance_live_test.go` now creates a synthetic identity against a **real disposable Kratos Foundation instance**, performs the genuine CSRF-bound browser login, uses `nativebff.NewKratosN06Provider` on the issued session cookie, confirms current issuer/subject/session/AAL evidence, and verifies that password authentication cannot be upgraded to RP-bound A3 or hardware-bound A4.
- The same test executes `nativebff.N06SecurityGate`: authentication-only `OrdinaryBuyer` may pass with live A1/A2, while `CommitBuyer` must remain denied without an independent current risk witness. It denies unissued bearer/cookie inputs and independently revokes Kratos sessions through the actual Ory adapter, re-reading current session and assurance to prove post-revocation refusal.
- `tests/ory-foundation/run.sh` now executes this case inside the **original** provider suite and requires the exact Go JSON `PASS` event alongside all original checks. A skip or missing case cannot qualify. Its execution result and SHA must be independently checked after this branch's latest CI; the source change alone is not a PASS.
- The Ory Foundation uses isolated loopback provider HTTP; the test is **real Kratos component behaviour** but **not** deployed TLS BFF/CP/native Trade, real WebAuthn A3/A4, high-risk recovery/rebinding, protected environment admission or production acceptance.

## 6 November 2026 — N06 original-component evidence and execution boundary

- **Current-source boundary:** #151's initial 6 November reconciliation merge commit `03fad56f49eaec3601e71f5890e5f09971b03cbe` makes #149 an actual Git ancestor, so its against-#149 diff is limited to N06 runtime, PostgreSQL, assurance and CI additions. This is source ancestry only, not a proof of running provider security operations.
- **Previous real Ory archive (historical head):** [Actions run 42098366042](https://github.com/baobab-platform/baobab-iam/actions/runs/42098366042), original artifact `13449745313`, ZIP SHA-256 `5d79a05cc149aa62019b36e0a6b1b9788d240517b3bc6335452359cf8ffdaee4`. Its recorded executed merge `89964c5ed0d4f44a893a7a1878280d1961506daf` has the older #151 head `2cc2ac870b2be277a8ca5e17c5260ad65bc0ea0e` as second parent. The native Hydra client and Ory/N03 tests have genuine PASS events. The mandatory isolated PostgreSQL 17 N06 security/race job and provider-contract job passed on this previous head. They do **not** prove Kratos-native RP-authenticated passkey A3, privileged A4, real account-rebinding courier, cross-provider signing rotation or operational containment.
- **Exact-head real CP candidate:** `.github/workflows/iam-candidate-int02.yml` now performs immutable-source disposable IAM/CP INT-02 using the current PR head and pinned Infrastructure harness `f8edcf4799534efebf35a70e999367e8ce7daaa2`. Its actual provider receipt must be independently inspected when produced. INT-02 is a **separate** Keycloak federation/CP proof and cannot replace required N06 native Kratos passkeys, recovery, security operations or A3/A4.
- **Deliberate fail-closed current runtime:** `n06NativeScopePolicy` allows only authentication-level `openid trade:buy`; `unavailableN06Risk` refuses privileged/high-risk action without independent live evidence. Neither an A1/A2 session nor a valid bearer creates CP buyer commitment, spend authority, or a native Trade execution right.

The six connected qualifications listed above remain **HELD** until original exact-head provider/CP/estate/resource evidence, negative tests, independently verified teardown and owner review exist. Do not classify any PASS from source-only Go/Python tests as a live A3/A4 operation.

## N06 real developer recovery courier test (6 November 2026)

A new **disposable, memory-only** Python SMTP trap is started on the CI host,
with the SMTP port accessible only to the Ory Foundation Docker guest through
the development-only `host.docker.internal` mapping. Message inspection uses
an unrelated loopback-only HTTP endpoint protected by an ephemeral per-run
random key. It emits no codes, mail bodies, passwords, cookies or bearer
secrets into test output or uploaded evidence, and is killed on runner exit.

`TestLiveN06KratosRecoveryCourier` registers a synthetic human with real
Kratos, obtains a live native session, starts Kratos' real recovery API,
observes actual courier delivery, rejects a wrong code, redeems the original
code only once, and demands independent denial of the **old** provider session.
The Ory Foundation runner requires the exact Go PASS event. If the pinned
Kratos runtime fails any semantic condition, this test must stay red: never
replace the server result with an HTTP fixture or downgrade the stale-session
assertion. The separate Postgres securityops recovery hold and independent
credential rebinding remain distinct requirements. A passing source test
alone is not an original live-provider execution receipt.

## 6 November 2026 — pinned real Kratos recovery courier disambiguation

The pinned Kratos v26.2.0 recovery email model includes the *original*
`RecoveryCode` field. The disposable development-only Kratos config now
renders exactly one unmistakable plaintext marker, without applying a
regex to arbitrary email headers, HTML numeric attributes, expiration
values or unrelated message codes. The in-memory SMTP sink parses the
actual MIME and gives the test only its one plaintext part. Exact code
uniqueness is required; a conflicting second marker fails closed. The
Kratos server—not a fixture—still issues the code and adjudicates its
correctness and replay. No code value enters logs, evidence files,
commit history or a protected email configuration.

## CTS v2 continuation, 12 November 2026

The merged CTS/capability baseline has been reconciled without widening the
runtime issuer registry. Earlier branch documentation and the N01 guard named
Shared 7f547cc while contracts.lock.yaml still selected 1517429. That inconsistent
partial repin is removed. The runtime contract, federation constant, N01 guard
and CMS fixture now agree with reviewed main. The read-only capability catalogue
remains separate. A future issuer-registry upgrade needs its own consumer proof.

Ory's Chromium job uses the same Ubuntu 24.04 host baseline as main's browser
matrix and installs the exact locked browser without live apt dependency
installation. The actual Kratos/Chromium ceremony remains mandatory and fails
if the browser or required host libraries are unavailable. No browser result is
inferred from this workflow correction. N04 prerequisites and independent N06
owner evidence remain open.
