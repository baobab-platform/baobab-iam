# ADR-0003/0028 native provider transport trust-boundary remediation (2026-11-10)

## Audited source

`internal/provider/ory/human_handoff.go` constructed a privileged Kratos/Hydra HTTP client with an ambient default transport. Go's default transport may honor host proxy environment variables. When an application supplied `NativeHumanConfig.Client`, the constructor previously copied its unrestricted transport without reviewing the proxy, network dialers or TLS verification settings. Kratos session credentials and Hydra admin responses must not be routed to an arbitrary proxy, redirected or accepted from an unverified host.

## Implementation

- The native client now uses an explicit no-proxy `http.Transport`, TLS minimum 1.2, fixed 10-second timeout and no redirect-following.
- An optional caller-supplied `*http.Transport` is accepted only when it has no custom proxy, socket dialer, TLS dialer or protocol handler and has not disabled or overridden host certificate verification. Unsafe cryptographic knobs, TLS key logging, client certificates and weakened protocol profiles are rejected at construction.
- The accepted transport and TLS configuration are cloned to prevent the caller changing the policy after construction, including its trust roots.
- Existing private test CA support is retained: `httptest.NewTLSServer` and its authenticated client trust bundle remain usable. No insecure development-only TLS fallback is added.
- Regression tests deny proxy/DNS transport substitution, weak TLS, certificate validation bypass, key export, custom protocol and fake RoundTripper, and verify a real TLS connection with the cloned approved root CA.

## Holds and qualification

This corrects a source-level trust-boundary defect, not runtime proof of private-network placement, mTLS, credential rotation, actual key custody or protected deployment topology. Strict transport configuration should be run against all private-CA and containerized Kratos/Hydra integration fixtures, followed by exact-head `gofmt`, Go tests and CI. Source tests do not activate a provider capability or CP authority.

**PR stack:** #173 → #174 → #175 → this increment. All open as drafts and unmerged; complete trusted routing and independent connected CP/issuer qualification before a release decision.
