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
