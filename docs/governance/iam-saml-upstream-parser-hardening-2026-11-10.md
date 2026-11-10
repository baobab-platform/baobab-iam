# ADR-IAM-0026/0033 — SAML2 upstream-parser security hardening (2026-11-10)

## Source and security evidence

GitHub Foundation `govulncheck` discovered **GO-2026-6909** in `github.com/crewjam/saml v0.5.1`, a reachable `ServiceProvider.ParseXMLResponse` path at `internal/federation/broker_verification.go`. The advisory describes (1) a nil-pointer panic in `validateAssertion` and (2) namespace-blind `Subject.NameID` processing. The advisory reports **no available fixed version**. Earlier protections in `boundedSAMLXML` already limit input size/depth, signed-response shape, algorithm profile, number of assertions and duplicate IDs, but do not explicitly require unique and namespace-qualified `Subject/NameID`.

## Additional local defences

- Make the preflight namespace-aware for SAML2 assertion, Subject, direct NameID, Issuer, Conditions, confirmation, authentication context and audience structures. Reject a duplicate Subject or NameID, unqualified/foreign-namespace identity fields and a NameID outside the single direct Subject.
- Keep exactly one Assertion and a supported signature count; the signed SAML verifier still performs cryptographic validation, certificate pinning, requested SP audience, replay and clock checks.
- Wrap the vulnerable upstream parser at this untrusted-input boundary in a panic-containment function. A panic becomes an anonymous denial without releasing XML, tokens or a partial external principal.
- Add attack-shaped negative tests for namespace-blind NameID, duplicate/nested identity fields, invalid namespace and parser panic, alongside existing genuine signed SAML OIDC/Keycloak and replay fixtures.

## Release disposition

**NOT AN ADVISORY FIX.** A local structural check and panic containment mitigate known paths, but cannot prove the vulnerable library is safe against every malformed signed XML. `govulncheck` will still correctly report GO-2026-6909. Do not suppress the vulnerability gate, issue VEX without independent evidence, or enable protected SAML2 on the basis of these tests. Required before protected release: evaluate a maintained fixed fork/upstream or isolated security-reviewed verifier, run malicious and valid originally signed Keycloak SAML cases, independent crypto and namespace review, and prove no path accepts attacker-selected NameID. The OIDC enterprise path remains logically independent.
