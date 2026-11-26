## 26 November 2026 — independent review reconciliation and current A3 boundary

The N06 evaluator validates provider authentication time, expiry and freshness
against the clock captured **after** the trusted provider read. Its two-read
stability check independently validates each `ObservedAt` timestamp and
excludes that changing observation timestamp from security-state equality;
risk readback follows the same rule. Regression tests cover both timing cases.

The RP-bound WebAuthn challenge and verifier are implemented and exposed through
the BFF's `/auth/a3/challenge` and `/auth/a3/verify` routes. The challenge uses
the server-owned `HIGH_VALUE_APPROVAL` operation, and binds the opaque BFF
session hash as well as the current Kratos issuer/subject/session. Verification
stores encrypted, short-lived proof through `putA3Proof`. The PostgreSQL
`takeA3Proof` consumer atomically consumes that proof once and validates its
session, operation and evidence bindings.

**Production A3 remains HELD because the final enforcement connection is not
implemented:** no server-owned operation decision boundary currently invokes
`takeA3Proof` and combines the consumed proof with a fresh current provider
session and current risk/recovery evidence. The current executable's
`trade:buy` mapping is authentication-only; it is not a high-value business
operation and must not be treated as one. Do not infer an operation from a
browser parameter or generic OAuth scope. CP and the domain engine retain
canonical privilege and business authorization.

IAM-owned session revocation is implemented independently of domain
operation integration. BFF local-session deletion, all BFF sessions for the
issuer/subject, Kratos subject-session revocation, Hydra subject-session
revocation and the current BFF OAuth access/refresh-token revocation are
attempted under a bounded cleanup context that survives browser disconnect.
Any unconfirmed component returns an unavailable result; local sessions are
not restored. A3 proof custody is removed with the BFF session.

The existing Ory Foundation Chromium test now also exercises the native
Kratos credential-withdrawal sequence after its real disposable CTAP2 A3
ceremony: disable the identity, revoke sessions, verify the old browser
session is rejected, delete the WebAuthn credential and read back the
inactive identity with no old WebAuthn/passkey credentials. This qualifies
Kratos provider mechanics only. It does not yet exercise the complete
two-person securityops recovery-hold authority through the live adapter.
Connected Hydra revocation, governed credential rebinding, recovery and
containment readback remain required; they do not wait for a Trade procurement
workflow. A4 remains HELD pending independent hardware attestation and
current independent privileged approval.

**Inherited release blocker:** IAM issue [#163](https://github.com/baobab-platform/baobab-iam/issues/163)
tracks GO-2026-6909 in the active SAML federation parser. This is a separate
enterprise-federation release hold, not a defect introduced by the A3 proof
custody change. Do not claim SAML/SSO security qualification or release
readiness until the advisory-specific remediation, negative fixtures,
provenance and Security sign-off recorded in #163 are complete.

Exact-head CI and connected qualification are separate gates. Prior successful
runs are not promoted to a later head or to production A3/A4 acceptance.

---

## 26 November 2026 — one-use A3 proof custody increment

A3 proof storage is now non-overwritable while the existing proof is live.
The new PostgreSQL consumer atomically deletes and returns a proof only while
the associated BFF session remains live, then validates its AEAD context,
current Kratos issuer/subject/session, exact operation, A2 base session,
WebAuthn user-verification/RP-binding evidence and database expiry. A changed
Kratos session consumes and denies the stale proof. The PostgreSQL 17
integration test exercises concurrent consumers through two independent store
instances and requires exactly one winner; it also verifies that BFF session
revocation cascades proof deletion.

This is **not yet production A3 operation acceptance**. The BFF verification
route stores the proof, but `N06SecurityGate` does not yet invoke the one-use
consumer. The next increment must integrate it at a server-owned operation
boundary and preserve the distinction between assurance evidence and CP/domain
authorization. Connected revocation and recovery qualification follow. A4
remains gated on independent original hardware evidence and current independent
privileged approval.

---

## High-value B2B procurement operation candidate

The accepted Shared ADR-SHARED-042 and
`contracts/trade/v2/buyer-execution-context.schema.json` define the buyer-side
operation `trade.purchase-approval.decide`. The identity assurance policy
schema canonically maps it to `BUYER_COMMITMENT`; that profile is not itself
an IAM A3 level. An approved, issuer-specific policy must define the accepted
`acr`, required `amr`, freshness and step-up evidence. The operation contract
binds the decision to the selected buyer Organisation and Market, exact
resource/version and transaction digest, amount/currency, policy revision
and independent approver references. It also requires separation of duties
and continued applicability before native commit. This is the strongest
existing candidate for operation-specific A3 evidence, subject to the
approved profile's exact evidence mapping; IAM assurance remains evidence
and must not make the purchase-approval decision.

The current Trade source tree contains the `PurchaseApproval` persistence
model and buyer operation policy vocabulary, but no purchase-approval decision
route or handler was found in the inspected `src/api` and `src/baobab`
surfaces. The operation contract exists; its authoritative domain endpoint
is not yet implemented/qualified. IAM-N06 therefore records this as a
connected-operation dependency. Do not substitute `trade.order.commit`,
`trade:buy`, an OAuth scope, or a browser-selected operation, and do not
implement Trade approval workflow or spending policy in IAM. A minimal
companion contract/endpoint change requires separate approval before work.

# IAM-N06 — Authentication assurance, recovery and security operations

## Review reconciliation — 26 November 2026

The production BFF composition now sets `N06Required: true`, supplies the reviewed `N06ScopeOperations` mapping and passes the `N06Gate`; the earlier runtime-wiring omission is corrected. This does not qualify A3/A4 or grant business authority.

PR #151 is based on current `main`, which includes the merged N04 source; the branch is no longer behind `main`. N06 and the provider-neutral evaluator share the operation, level, outcome and policy vocabulary and its validated floors. Both A3 evaluation paths now require same-event RP-bound passkey proof and user verification, but do not make authenticator attestation a universal A3 prerequisite under ADR-IAM-0024. Native session readbacks compare stable provider and risk evidence across separate fresh observations. Connected qualification and the merge hold still apply.


The Go Kratos live test rejects malformed registration without persisting a credential. The Chromium test registers a real CTAP2 credential, reads it back from Kratos, performs the AAL2 assertion and denies replay. The BFF challenge and assertion routes are wired, and successful proof is stored against the opaque BFF session. The remaining A3 source gap is operation-bound consumption: no reviewed domain operation contract currently invokes the one-use consumer with a fresh provider and risk/recovery decision. Connected revocation and recovery qualification remain open. A4 requires independent hardware-attestation, risk and privileged-approval authorities.

Use exact-head CI and connected owner receipts for review. Promotion of A3/A4, recovery/rebinding, provider rotation and protected acceptance requires original evidence for the relevant operation.

## 26 November 2026 — Kratos counter and isolated-runtime assessment

The current `provider.lock.yaml` and `docker-compose.ory.yml` pin the OSS `oryd/kratos:v26.2.0` image by digest. Ory's v26.3.4 changelog documents persistence of WebAuthn/passkey signature counters, clone-warning state and backup state after successful login. It explicitly allows non-increasing counters (including static counters from synced passkeys) while recording a possible-clone warning. The release note described the change as available for Ory Network/OEL and forthcoming in the next OSS release. Do not change the OSS pin until the exact OSS tag, published digest, migration behaviour and actual browser behaviour have been verified for the image Baobab will run.

This upstream behaviour is useful credential-state machinery, not Baobab's atomic replay authority. A non-increasing counter is not a sufficient basis to reject a valid assertion from a static-counter authenticator, and a persisted counter does not make a challenge single-use. The current `WebAuthnA3Verifier` still rejects zero and non-increasing counters and its `KratosCredentialReader.AdvanceKratosSignCounter` contract assumes a strictly increasing value. This must be reconciled before A3 activation: preserve Kratos as credential authority, accept authenticators whose counter is zero/static where policy permits, and retain durable, atomic, single-use challenge consumption independently of the counter. Do not introduce a parallel counter authority until the pinned provider capability has been tested and the exact missing guarantee identified.

The disposable Kratos config disables external breach checks for synthetic fixture passwords. This setting exists in the pinned v26.2.0 configuration schema. The Foundation workflow uses a Docker internal bridge with no IPv6 and no provider port publications. Fixed runner-loopback relays carry only the four Kratos/Hydra API listeners. SMTP and the Hydra token hook bind to the bridge gateway. The local developer Compose definition and protected password policies are outside this override. Qualify breach checking separately with a controlled local endpoint or offline corpus. Adopt the same egress evidence requirement in DEV-10 and DEV-14.

The implementation sequence is now explicitly split:
1. **A3 increment:** qualify the provider release, connect the implemented credential reader, counter ledger and RP-bound proof custody to the production BFF, then run connected browser, concurrency, revocation and recovery negatives.
2. **A4 increment:** only after A3 acceptance, connect independent hardware provenance and current privileged-approval/risk witnesses; retain deny by default until both authorities are independently verified.

A1/A2-only operations may progress under their own reviewed policy and qualification. They must not inherit A3/A4 acceptance, and assurance never substitutes for CP or domain business authorization.

---

**Status: engineering source open for review. Connected acceptance is held.**
**Authority:** EA v2.3/EA-DEV; ADR-IAM-0015–0018, ADR-IAM-0023,
ADR-IAM-0024, ADR-IAM-0025, ADR-IAM-0028, ADR-IAM-0029 and ADR-IAM-0033.
PR `baobab-iam#151` targets `main` after the N04 source merge in #149. Independent N04 and N06 connected qualification still applies before protected deployment. Keycloak remains the enterprise federation provider.
The Control Plane (not IAM) owns canonical identity, membership,
tenant privileges and business authorization.

### Kratos release and assertion counters

Ory's [v26.3.4 changelog](https://changelog.ory.com/announcements/ory-network-ory-hydra-ory-kratos-ory-keto-ory-oathkeeper-ory-elements-v26-3-4-released) describes persisted counter and clone-warning state and permits non-increasing counters. The public `ory/kratos` Git tag and `oryd/kratos:v26.3.4` registry manifest were unavailable in the 26 November 2026 check. The pinned v26.2.0 registry digest resolved and stays in use. A candidate upgrade requires an approved obtainable edition, exact image digest and source, PostgreSQL 17 migration and rollback evidence, admin credential readback, and live login, concurrency, revocation and recovery tests.

The PostgreSQL single-use challenge deletion is the replay control, including for zero-counter authenticators. Under the [WebAuthn signature-counter rules](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter), zero on both observations can represent a counterless authenticator. A decreasing or equal nonzero counter is a credential-risk signal that needs a reviewed policy. The A3 verifier accepts two zero counters and denies rollback and equal nonzero counters. The concrete reader and ledger require connected BFF qualification before activation. The component browser result does not activate production A3 or A4.

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
2. Complete connected positive/negative qualification of the implemented
   **RP-verified** Kratos passkey challenge and assertion routes: user
   verification, origin binding, signature-counter policy, replay denial,
   current BFF/Kratos session binding and credential revocation on real
   authenticators. Then connect one-use proof consumption to the reviewed
   server-owned operation/resource boundary; no fake A3.
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


## 26 November 2026 — Hydra subject-session and token revocation read-back

The native BFF now uses a dedicated Hydra token revoker. It first submits the
confidential-client-authenticated access-token and refresh-token revocation
requests to the public issuer, then independently calls the private
`POST /admin/oauth2/introspect` endpoint for each supplied token. Logout is
reported as complete only when each supplied token is read back with
`active=false`; transport errors, malformed responses, active tokens and
partial revocation remain UNKNOWN/failed.

The subject-session adapter deletes all consent sessions and login sessions
for the exact signed Kratos subject. It then reads the subject's consent
sessions through `GET /admin/oauth2/auth/sessions/consent` and requires an
empty JSON array. The pinned Hydra v26.2.0 OpenAPI exposes this consent-session
list endpoint but does not expose a corresponding login-session list/read
endpoint. Therefore the login-session DELETE response is acknowledged, not
independently read back; this limitation is explicit and is not represented as
a verified login-session inventory.

The existing Ory Foundation suite now includes a live Hydra case that creates
a disposable confidential client, obtains a real client-credentials access
token, confirms it is active, performs revocation through the native BFF
adapter, and requires Hydra Admin introspection to report it inactive. The
same live case exercises subject-wide consent/login deletion and consent-list
read-back. Disposable client cleanup is attempted in test teardown.

**Resource boundary:** the development Hydra configuration selects JWT access
tokens. Hydra reporting a JWT as inactive does not prove that every resource
server which validates JWT signatures offline has stopped accepting it. CP
and domain-resource denial remains a separate required read-back; this IAM
change does not claim that downstream resource caches or validators have
been invalidated. See the pinned [Hydra v26.2.0 OAuth2 API](https://docs.rs/crate/ory-hydra-client/26.2.0/source/docs/OAuth2Api.md)
for the documented introspection and session endpoints.

The live Foundation result is not yet available for the new head. Until the
exact-head Ory Foundation workflow passes, this increment remains source and
test implemented, not connected-qualified.
