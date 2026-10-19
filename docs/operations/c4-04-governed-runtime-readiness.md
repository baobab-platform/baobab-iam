# C4-04 — Governed native/workload dispatch and operational readiness

**Status:** C4-04A executable readiness observation implemented; C4-04B/C
registration, activation and protected acceptance pending. **Not** evidence that
C4-03's real registered-provider → protected-CP B–E chain has passed.

This programme follows the accepted ADR-IAM-0033, ADR-IAM-0024/0025,
Shared capability/provider-support declarations and CP-owned current
resolution, runtime evidence and binding authority. Retained Keycloak remains
the enterprise federation provider. No C4 increment may grant, allocate, widen,
promote, bypass or migrate tenant rights based on a local health check.

## Increment and hard boundaries

C4-04A adds `ory.CheckGovernedNativeWorkloadReadiness` and
`ory.CheckComposedNativeWorkloadReadiness`. The production factory uses:

- The **existing** `federation.StartNativeRuntimeComposition` for Kratos
  human authentication, Hydra workload issuer and OAuth authorization-server
  facet. All share a CP-owned context/organisation/estate/security domain.
- An **independent** `federation.StartRuntimeComposition` for workload issuance,
  with fresh CP context, exact capability resolution, current grant/binding and
  runtime profile/artifact proof.
- The actual existing Kratos **and** Hydra administrative health endpoints.
- Fresh authority checks **after** provider health. Withdrawal, stale support,
  artifact drift, wrong provider instance, incompatible contract, shutdown,
  expired context, either admin-plane outage or caller revocation denies.

The observation is `OBSERVED_CURRENT` only, not `AUTHORIZED`,
`PRODUCTION_READY`, a capability registration, CP health publication, release
approval, a consumer security decision or an independent maker/checker receipt.
Current operational traffic MUST continue to check CP inside each native login,
consent or workload token issuance. The consumer independently validates the
actual token and CP context. Never cache this observation as entitlement or
silently fall back to Keycloak when Ory is unavailable.

## Protected read-only command

`go run ./cmd/c4-04-readiness` takes a reviewed, owner-protected JSON document
with no inline secrets and optional private CA trust roots. Example shape:

```json
{
  "human_runtime": {
    "cp_origin": "https://cp.example.invalid",
    "resolution_token_file": "/run/secrets/c404-resolution",
    "runtime_token_file": "/run/secrets/c404-kratos-runtime",
    "context_target": {
      "tenant_id": "APPROVED_SYNTHETIC_TENANT",
      "organisation_id": "APPROVED_SYNTHETIC_ORGANISATION",
      "country_code": "ZA"
    },
    "provider_id": "APPROVED_KRATOS_PROVIDER",
    "engine_instance_id": "APPROVED_KRATOS_INSTANCE",
    "estate_id": "APPROVED_DIGITAL_ESTATE",
    "service_reference": "APPROVED_HUMAN_SERVICE",
    "configuration_reference": "APPROVED_KRATOS_CONFIG",
    "security_domain_reference": "APPROVED_SECURITY_DOMAIN"
  },
  "issuer_runtime": {
    "cp_origin": "https://cp.example.invalid",
    "resolution_token_file": "/run/secrets/c404-resolution",
    "runtime_token_file": "/run/secrets/c404-hydra-runtime",
    "context_target": {
      "tenant_id": "APPROVED_SYNTHETIC_TENANT",
      "organisation_id": "APPROVED_SYNTHETIC_ORGANISATION",
      "country_code": "ZA"
    },
    "provider_id": "APPROVED_HYDRA_PROVIDER",
    "engine_instance_id": "APPROVED_HYDRA_INSTANCE",
    "estate_id": "APPROVED_DIGITAL_ESTATE",
    "service_reference": "APPROVED_ISSUER_SERVICE",
    "configuration_reference": "APPROVED_HYDRA_CONFIG",
    "security_domain_reference": "APPROVED_SECURITY_DOMAIN"
  },
  "kratos_admin_origin": "https://kratos-admin.example.invalid",
  "hydra_admin_origin": "https://hydra-admin.example.invalid",
  "public_issuer": "https://issuer.example.invalid"
}
```

The placeholders **cannot pass** actual runtime conformance and must never
be substituted for canonical registration. Only approved protected IAM/CP
service credentials with exact scoped authority and trusted TLS may be used.

```bash
go run ./cmd/c4-04-readiness \
  -config /run/secrets/iam-c4-04-readiness.json \
  -ca-file /run/secrets/baobab-ca.pem
```

No secret or identity is logged. The command emits only `OBSERVED_CURRENT` or
`DENIED` and returns nonzero for missing protected config, stale/withdrawn
authorities or absent provider health. The command does not write a live
acceptance receipt and must **not** promote a provider on its output alone.

## Next ordered gates

| Gate | Requirement | Evidence |
| --- | --- | --- |
| C4-03 live | Register approved isolated Kratos/Hydra and CP synthetic identities/capability runtime targets; run the real C4-03B–E protected journey and independent revocation | Verified signed provider tokens, actual running CP resource responses, cross-tenant/withdrawal denial, cleanup and complete closed-source-bound receipt |
| C4-04A | Observe both current canonical CP runtime authorities around actual two-provider health | Production composition build/tests, registered read-only runtime observation; no activation implied |
| C4-04B | Current Shared support conformance, CP owner-controlled lifecycle/activation and health certification | CP source checks of verified support, exact contract major/facet, active instance/release/config/artifact and scoped grant; independent approval evidence |
| C4-04C | End-to-end issued-token/resource consumption, revoked session/issuer/binding/grant, outage/recovery and no cross-provider silent fallback | Live evidence of positive/negative registered consumer operations including unexpired token withdrawal; CP authority remains sole owner |

**Exit condition before Nabhold Go-Live resumption:** C4-03's actual protected
receipt and C4-04's CP-governed support/activation and consumption acceptance
must be demonstrable at the intended integration/staging boundary. Green Go
tests are source evidence only, not proof of registered runtime or staging.
The CRITICAL AdministrativeGrant prohibition remains unchanged.
