# C4-03 — live Kratos/Hydra–CP qualification programme

**Status: IN PROGRESS (C4-03A only).** This branch is stacked on IAM #122
(`feat/live-passkey-step-up`), not `main`. ADR-IAM-0033 and the accepted
assurance/identity-proofing boundaries remain authoritative. This increment
creates **no** workload client, access token, tenant, grant, context, privilege,
authenticator, canonical identity or CP registration.

## Evidence and gates

| Gate | Real acceptance required | Present status |
| --- | --- | --- |
| C4-03A | Live CP-issued IAM context and two current workload capability/runtime reads through C4-02 production composition | Executable, requires live CP configuration |
| C4-03A negatives | Wrong facet, invalid service credential, simulated network outage, simulated future-expired evidence, cancelled supervision | Executable; outage/expiry are simulations and must never be called live withdrawal |
| C4-03B | Real Hydra hook dispatch, signed workload token, scope/audience/binding/artifact/expiry and issuance revocation | Open; requires approved runtime registration and isolated provider |
| C4-03C | Live Kratos human session + Hydra challenge + current CP native context, binding, authorisation, revocation and fence | Open |
| C4-03D | Actual **running** protected CP/domain resource request with correct/incorrect audience, scope, tenant/organisation, independent grant withdrawal, session revocation and CP outage/recovery | Open; offline CP verifier probes do not qualify |
| C4-03E | Complete receipt chain, protected staging evidence, registration approval and operational review | Open |

The C4-03A qualifier is deliberately **read-only**. It refuses a claims-only
authorization substitute, refuses a test/mock authority in lieu of the real
configured CP, and tests the existing `federation.StartRuntimeComposition`
factory. CP remains the sole source of current resolution, support, tenant
context, bindings and grants. Do not use INT-02's proof-bootstrap exception or
mint bootstrap credentials from the governed Hydra issuer that depends on the
same CP authorization hook.

### Invocation on a provisioned, protected integration environment

```bash
go run ./cmd/c4-03-qualify \
  -runtime-config /run/secrets/iam-c4-runtime.json \
  -cp-ca-file /run/secrets/cp-ca.pem \
  -source-commit "$(git rev-parse HEAD)" \
  -evidence-dir /run/baobab-evidence/c4-03
```

The runtime config is the *same* protected, reviewed JSON used by C4-02's
Hydra hook, bound to a real HTTPS CP, exact deployed provider/instance,
organisation, estate, security-domain and configuration references.
`LoadServiceDocument` and `FileAuthorityTokens` apply their existing
credential-file protections. Omitting `-cp-ca-file` uses system trust.
TLS verification must remain enabled. No synthetic server, CP runtime
projection or local fake responses are acceptable positive evidence.

The CLI's `baobab-c4-03-live-authority/v1` PASS means only that **the eight
named CP read-only checks succeeded**. It must still explicitly report
`hydra_issuance_proven=false`, `protected_resource_proven=false`,
`real_revocation_proven=false` and `production_ready=false`.
The evidence directory holds only restricted JSON booleans, source SHA and
SHA-256 checksum. Never retain raw bearer tokens, OTP/passkeys, signed claims,
response bodies, auth codes, browser traces, URLs, personal data or provider
private keys. A failed CP request, missing credentials, expired authority,
unknown status or uncertain receipt publication is FAIL.

### Following increments

C4-03B must bind the existing production Hydra hook to the same real
registered CP runtime, exercise real client issuance through the provider, and
send its signed token to a running protected resource. C4-03C must reuse
`ory.StartNativeHumanRuntime` and its durable challenge fence, not bypass
Kratos session validation. C4-03D requires explicitly authorised, isolated CP
grant/binding/artifact withdrawal and independently confirmed revocation while
a previously issued bearer remains unexpired, plus actual outage and recovery.
These are additional mandatory live gates, **not** satisfied by a passing
C4-03A receipt or by older wire fixtures. Provider support declarations stay
PARTIAL; no CRITICAL AdministrativeGrant restriction is lifted by either this
branch or the stacked passkey PR.
