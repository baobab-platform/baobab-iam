# ADR-IAM-0026 and ADR-IAM-0033 SAML assertion validation

CTS v2.0 adoption in IAM #187 replaced the previous SAML dependency with
the maintained verifier pinned in `go.mod`. This branch carries that same
dependency and checksum baseline. Local checks are applied before the signed
protocol verifier.

- Require one direct SAML assertion, one subject and one NameID under that
  subject. Check their namespaces and reject ambiguous identity elements.
- Preserve signature verification, certificate trust, audience, confirmation,
  expiry and replay checks in the existing verification and consumption path.
- Convert an unexpected parser panic into a generic denial without releasing
  assertion data or an external identity.
- Exercise malformed XML and panic handling alongside the existing signed SAML
  acceptance and replay cases.

CTS2-019 and CTS2-020 still require connected CP, Keycloak, IAM trust and estate
evidence for the final source and image pins. These tests establish local
verification behavior. Production federation remains subject to its own gate.
