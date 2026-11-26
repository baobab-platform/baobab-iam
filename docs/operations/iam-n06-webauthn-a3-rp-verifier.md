# N06 Kratos A3 cryptographic RP boundary

**Status:** Credential readback and the IAM PostgreSQL counter ledger have
source implementations. Production BFF integration and connected A3
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
is required. Production acceptance still needs BFF proof custody, immediate
revocation and recovery evidence, and connected concurrency qualification.
A4 also needs its independent hardware, privilege and risk witnesses.

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
