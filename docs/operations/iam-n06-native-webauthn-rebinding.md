# IAM-N06 WebAuthn credential invalidation and recovery hold

**6 November 2026 — source implementation candidate, live native credential
revocation and two-independent-reviewer proof not yet accepted.**

`Adapter.BeginNativeWebAuthnRebind` is a **first phase** of a governed
two-person credential rebinding workflow, NOT an API for browser self-service
recovery and NOT an A3/A4 success assertion. A separate IAM securityops reader
must confirm current original recovery evidence, distinct requester/reviewer,
security decision, exact issuer+subject, and a non-shrinking recovery hold
of at least 24 hours.

Against the **real private Kratos Admin API**, the method reads the exact
current active identity and original WebAuthn credential configuration with
`include_credential=webauthn`, refuses a separate passkey credential
(which this Kratos admin endpoint cannot delete), sets identity inactive,
revokes all sessions, independently verifies no active native sessions,
deletes the `webauthn` credential and rereads the provider. Only an
inactive identity with no old WebAuthn/passkey credentials and no live
session may return the bounded result `NativeReenrolmentRequired=true`.
After any failure the identity MUST NOT be auto-enabled; the 24-hour hold
remains. A subsequent fresh WebAuthn ceremony, independently reviewed
credential binding and securityops hold-release are entirely separate.

Credential deletion by provider-local operation does NOT remove CP grant,
Hydra JWT, enterprise Keycloak SSO, or retained audit evidence. Negative
and real native tests plus original runtime proof are required before
this is marked development-qualified.
