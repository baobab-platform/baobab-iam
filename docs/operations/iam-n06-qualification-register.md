## 26 November 2026 — bounded session revocation after browser disconnect

The native BFF's explicit all-session logout now uses a bounded cleanup
context independent of the browser request cancellation after the request's
session and CSRF token have been authenticated. It attempts local BFF session
deletion, deletion of all BFF sessions for the exact issuer/subject, Kratos
subject-session revocation, Hydra subject-session revocation and revocation
of the current BFF's access/refresh tokens. A failure in one provider does
not skip the remaining attempts; any unconfirmed result returns unavailable.
Local session deletion is not rolled back. A3 proof custody follows the BFF
session lifecycle and is removed with its parent session.

A regression test cancels the browser request immediately after the trusted
session read and verifies that all provider revocation calls still execute
with a live bounded cleanup context. This is source/test evidence. Real
Kratos/Hydra deployment evidence, credential withdrawal, recovery/rebinding
and containment readback remain separate connected qualification items.

---

## 26 November 2026 — A3 proof custody and single-use consumption

The optional BFF ceremony now stores a successful RP-bound assertion as a
short-lived encrypted record keyed to the opaque BFF session and the
server-owned `HIGH_VALUE_APPROVAL` operation. The first implementation
allowed a later proof to replace an earlier unexpired proof and had no
atomic consumer. This increment closes that storage-lifecycle gap:

- An unexpired proof for the same BFF session/operation cannot be overwritten.
- PostgreSQL 17 `DELETE ... RETURNING` atomically consumes a live proof only
  while its parent BFF session remains live.
- The consumer authenticates the sealed record with the opaque BFF session ID
  as AEAD context and verifies the exact Kratos issuer, subject, session,
  operation, A2 base session, WebAuthn method, user verification, RP binding
  and stored expiry.
- A proof presented against a changed Kratos session is consumed and denied,
  preventing retry against a later session.
- Cross-replica concurrency qualification requires exactly one consumer to
  win. BFF session deletion still cascades proof custody.

**Boundary:** this is the durable single-use consumption primitive, not yet
its production operation-gate integration. The existing `/auth/a3/verify`
route still records proof; the current `N06SecurityGate` does not call
`takeA3Proof`, and no business operation is executed by IAM. Production A3
therefore remains HELD. Next increment: connect this one-use consumer to a
server-owned operation-specific assurance evaluation boundary, while keeping
CP/domain authorization separate; then execute connected revocation and
recovery qualification. A4 remains independently gated.

Exact-head PostgreSQL 17 N06 CI for this change must pass before the primitive
is treated as qualified. No result from the preceding head is promoted.

---

# IAM-N06 implementation and qualification register

PR #151 owns authentication assurance. PR #152 owns connected consumer
qualification. Record the exact candidate commit, original evidence location,
reviewer and observed outcome for each acceptance gate.

| Gate | Implemented | Acceptance required |
| --- | --- | --- |
| Source reconciliation | PR #151 was mergeable at the start of this increment | Verify the final head and required gates |
| Disposable Ory Foundation | Synthetic identities, test-only breach checking disabled, private Docker network and loopback relays | Preserve controlled outbound access. Provision a separate authenticated HTTPS listener and a reviewed RP ID and origin for the handset |
| Provider credential evidence | Current Kratos session and private TLS Admin readback, exact registration and key, provider recheck | Run the same request through deployed BFF and Kratos. Verify revocation, recovery and rebinding |
| Replay and counters | Atomic single-use PostgreSQL challenges and separate IAM high-water mark for independently verified assertions | Run real PostgreSQL 17 concurrent assertions, restart and interrupted-write cases. Counterless credentials still require a fresh challenge |
| A3 browser integration | Optional BFF ceremony and short-lived encrypted session-bound proof | Review and connect independent risk and recovery evidence, operation-specific consumption, and physical browser run |
| Android utility | API 35 probe, disposable biometric-gated Keystore key and client evidence transport | Verify exact APK and run the local capability checkpoint. Connected submission requires reviewed routes and a disposable ticket |
| A4 hardware | Verifier requires a separate trusted attestation authority | Bind original certificate chain, leaf signing key and issued attestation challenge. Review root rotation, revocation freshness, device lifecycle and TEE eligibility before enabling |
| A4 privilege | Verifier requires a separate approval authority | Obtain the current independent reviewer, scoped authority and approval from the CP-owned path under ADR-BCP-020. Verify self-approval, withdrawal and expiry denial |
| A4 live | Existing verifier checks exact operation-bound transcript and separate one-use challenge | Connect real authorities and current operation-bound A3 proof. Verify negative paths and absence of a CP business grant |
| N07 | Separate stacked PR | Advance A1/A2 qualification under reviewed per-operation policy. User assurance changes do not add requirements to workload credentials. Requalify the stacked head after N06 gates |
| Independent review | Repository CODEOWNERS identifies platform engineering and security | Review the exact code increment. Record independent acceptance separately from workflow completion |

Retain Kratos v26.2.0 for this increment. Evaluate the newer provider's
immutable OSS image, exact credential representation, persisted counter,
non-increasing counter treatment and revocation before changing the pin.
The v26.2.0 development fixtures and Chromium virtual authenticator tests
are useful browser evidence. Physical evidence requires the supervised
HONOR 90 Lite and a separate recorded run.

For the independent attestation verifier, first evaluate the maintained
[Android Key Attestation verifier](https://github.com/android/keyattestation)
against the existing IAM interface and original evidence requirements.
Use Google's
[official verification and root rotation guidance](https://developer.android.com/privacy-and-security/security-key-attestation).
Require explicit root custody, fresh revocation data, correct security-level
policy and verified boot state. No service or trust policy is selected by
this register.

See the [BFF ceremony](iam-n06-webauthn-a3-rp-verifier.md) and the
[device operator runbook](../../tools/n06-android-probe/README.md).
