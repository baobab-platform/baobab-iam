# N06 Kratos A3 cryptographic RP boundary

**Status:** Credential readback and the IAM PostgreSQL counter ledger have
source implementations. The optional native BFF route can collect and bind
A3 evidence for high-value approval. Assurance activation and connected
qualification remain held.

- `KratosWebAuthnReader` uses a TLS-only, fixed private Admin API origin with
  explicit trust roots. It requests the active session subject's WebAuthn
  credentials without forwarding a browser cookie. It selects one exact
  credential ID, rejects reported clone warnings and validates the pinned
  provider's COSE ES256/P-256 public key.
- `WebAuthnA3Verifier` checks a current Kratos AAL2 WebAuthn session, consumes
  the server-minted one-use challenge, and verifies the RP, origin, user
  presence, user verification and signature. It reads the provider credential
  again before recording the assertion counter.
- `PGWebAuthnCounterStore` is separate from the provider reader. An atomic
  PostgreSQL upsert preserves IAM's high-water mark and refuses key substitution,
  equal nonzero counters and rollback. Counters of zero are accepted when
  both the provider count and IAM's committed high-water mark are zero. The
  challenge remains one-use for every counter value.
- The counter table stores HMAC references in place of subject and credential
  data. A ledger key commitment prevents a silent reset if the configured
  key changes. Provision one stable private 32-byte key per ledger. Apply
  migration 002 alongside migration 001 in the reviewed database step.
  The component never updates Kratos credential state.

The pinned Kratos v26.2.0 login strategy
[validates an assertion without persisting its counter](https://github.com/ory/kratos/blob/v26.2.0/selfservice/strategy/webauthn/login.go#L290-L306).
IAM records counters only for its own independently verified assertions.
A failed or interrupted ledger operation yields a denial and a new challenge
is required. ## Native BFF qualification

Apply `001_native_browser_bff.sql`, `002_subject_session_revocation.sql`,
`001_n06_webauthn.sql`, `002_n06_webauthn_counter.sql` and
`003_n06_a3_browser_proof.sql` from `internal/nativebff/migrations` with the
reviewed migration identity before starting the BFF. The BFF runtime uses
PostgreSQL 17 over authenticated TLS. Its configuration must name distinct
protected 32-byte files in `a3_challenge_key_file` and `a3_counter_key_file`.
Set `-ca-file` to the reviewed private Kratos trust bundle and permit
only the IAM runtime to reach Kratos Admin. Keep the counter key stable across
restarts and replicas. Both key settings are required to enable the routes.

The qualification browser first completes a current Kratos WebAuthn AAL2
session and establishes the native BFF session. The protected BFF origin must
be reviewed as the exact RP ID host and registered Kratos WebAuthn origin.
For the same-origin POSTs below, keep both session cookies and use the
browser session's `X-CSRF-Token` with `Content-Type: application/json`.

1. POST `/auth/a3/challenge` with the unpadded base64url `credential_id`.
   Read the returned `challenge_id`, binary `challenge` and `rp_id`.
2. Use `navigator.credentials.get` with the returned challenge and RP ID,
   the exact registered credential, and `userVerification: "required"`.
3. POST `/auth/a3/verify` with `challenge_id`, `credential_id`,
   `client_data_json`, `authenticator_data` and `signature_der`.
   The three binary assertion fields use standard padded base64.
4. Expect a 204 only after a same-operation proof is encrypted in the BFF
   vault. Repeat the request and verify refusal. Repeat across a second BFF
   session with the same identity and verify refusal. Revoke the BFF session
   and verify its stored proof is removed.

The BFF owns the operation (`HIGH_VALUE_APPROVAL`). The proof expires within
30 seconds, is scoped to the original BFF and current Kratos sessions, and is
retained under the browser session's deletion boundary. The endpoint does
not issue a token or grant a privilege. An activation decision still requires
a reviewed current recovery and risk authority, operation-specific consumption
of the stored proof, and connected qualification. A4 additionally requires a
separate operation binding and independent hardware and CP approval witnesses.


## Actual Chromium / pinned Kratos positive and replay test

The Ory Foundation Live workflow now also installs the *locked* Node 24
Playwright 1.64.1/Chromium browser and executes
`tests/integration/passkey/n06-kratos-browser.mjs` **against the same
running disposable Kratos v26.2.0**, immediately after foundation setup.
No live browser proof is accepted if that test is skipped or fails. The
browser uses the configured reviewed loopback RP `localhost` at `http://localhost:4455`, a fresh
Kratos browser-cookie/CSRF password session, original provider settings
challenge, and CTAP2 virtual authenticator to register a credential in
Kratos. An independent Admin API readback must contain the registered key.
It then creates a fresh password-only browser session, obtains an AAL2 login flow, and performs an actual WebAuthn
assertion and demands the Kratos `/sessions/whoami` AAL2/WebAuthn method,
followed by denial of a repeated original assertion. Teardown must delete
the synthetic identity; no private credential, password, browser recording,
recovery code or token is stored in evidence.

This is original **browser/cryptographic A3 candidate qualification** only.
Chromium virtual CTAP2 is not hardware-backed attestation. Production A3 acceptance requires execution through the IAM verifier, with
admin-plane credential readback and the durable ledger exercised on the same
request. CP authorization and A4 hardware-backed approval have separate gates.
