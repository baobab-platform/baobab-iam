# N06 Kratos A3 cryptographic RP boundary

**Implementation candidate; REAL Kratos/Chromium ceremony not yet qualified.**

`internal/nativebff/n06_webauthn.go` implements an actual ES256 WebAuthn
assertion verifier using Go standard crypto primitives. It requires a current
Kratos AAL2 session whose observed authentication method is WebAuthn, a
server-issued atomic one-use challenge for the **same issuer/subject/session**,
exact reviewed RP origin and SHA-256 RP ID, user presence+verification flags,
type=webauthn.get, signed challenge, exact provider-owned credential ID,
P-256 signature and strictly increasing atomic Kratos credential counter.

Browser-supplied RP/origin, cross-origin context, duplicate JSON keys, replay
counters, forged signatures, unknown credentials and stale challenges fail
closed. Only an **issuer-authenticated credential reader** populated from
current Kratos provider state and durable compare-and-swap nonce/counter
implementations may be wired to a real server. A memory fixture alone is NOT
deployment-ready. The verifier never treats authenticator enrolment, TOTP,
historical ACR, browser claims or unverified method labels as A3 evidence.

**Crucially:** the produced evidence is `HardwareBound=false`. A4 continues
to require independently witnessed hardware-backed private key attestation,
current privileged CP risk/context and distinct approval. No business PEP,
CP grant or consumption is conveyed by this verifier.

Next native development closure requires real pinned Kratos/Chromium
registration and proof, durable challenge/counter storage, live forged
origin/UV/counter/credential negatives, recovery/rebinding tests and
independent original artifacts. Those are NOT claimed by this source.
