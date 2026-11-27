# Keycloak enterprise-only federation session containment

**Status: source implementation + negative tests pending; no upstream IdP or CP-wide SLO claim.**

`internal/provider/keycloak/enterprise_containment.go` implements the
narrow current-provider operation **revoke one verified Keycloak broker user's
existing sessions**. It does not implement Keycloak-native authentication
or workload issuance. A different separately reviewed component owns any
Kratos/Hydra issuer revocation or CP grants.

To execute, the broker server must supply a reviewed **current trust**,
matching exact upstream issuer/subject and federation alias, an exact broker
user ID from the provider, and distinct independent approval evidence.
The adapter independently GETs the actual Keycloak broker federated-identity
link and requires the exact alias+upstream subject; then GETs sessions
(requiring at least one actual active session), POSTs the user's
`/logout`, and finally GETs sessions again, requiring an empty result.
Redirects, failed/uncertain HTTP responses, missing review, foreign identity
links, stale issuer observations, missing readback or surviving sessions
fail closed. Admin tokens live only in the non-browser trusted component.
No secrets or raw upstream exceptions are emitted.

**Scope limitation:** Keycloak admin session termination is a broker-local
logout. It does not automatically terminate upstream enterprise SAML/OIDC
IdP SSO sessions, revoke Kratos/Hydra tokens, or remove CP grants. Cross-
provider compromise containment must coordinate independently owned
revocation and actual consumer PEP denials, then produce original evidence.
Existing GO-2026-6909 remains a dependency security blocker until
upstream code replacement/remediation is verified with govulncheck.
