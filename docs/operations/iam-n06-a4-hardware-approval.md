# IAM-N06 A4 independent hardware and privileged approval

**Source-only implementation candidate. NOT A4 development-qualified.**

`internal/nativebff/n06_a4.go` is a narrow A4 *authentication assurance*
gate for reviewed IAM privileged-grant or break-glass operations only. It
cannot be selected by a browser and cannot grant CP or domain permissions.

The verifier requires a current server-sourced A3 proof bound to the same
issuer+subject+session, a separate **one-use** IAM challenge, an actual ES256
signature covering an unambiguous length-prefixed session, operation and
nonce transcript, and an independent device-attestation authority proving
that the exact signing key is hardware-backed, trusted and non-exportable.
It further requires an independently approved distinct current privileged
reviewer, the same exact operation, original references, and fresh risk
that is neither high/critical nor post-recovery suspicious.

Negative conditions refuse A4. It cannot derive hardware trust from a
virtual Chromium authenticator or from browser-supplied attestation booleans.
Development qualification still requires live independent hardware vendor
attestation and trust anchors, original approval/provider receipts,
fault/replay/expiry/withdrawal tests and browser+BFF/CP-negative observation.
An injected test authority is not a hardware attestation certificate.
Do not advertise `A4 IMPLEMENTED`, execute protected actions or count
source-level positive fixtures as independent acceptance.
