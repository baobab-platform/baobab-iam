# C4-03 — live Kratos/Hydra–CP qualification programme

**Status: C4-03A–E source qualification implemented, live B–E acceptance pending protected provider/CP evidence.** This implementation builds on IAM #122's
independent browser passkey qualification. ADR-IAM-0033 and the accepted
assurance/identity-proofing boundaries remain authoritative. The runner uses
pre-provisioned identities, clients, tenants, grants and provider registrations.
During a live run it requests provider tokens and CP contexts; it does not
provision or activate the underlying authorities.

## Evidence and gates

| Gate | Real acceptance required | Present status |
| --- | --- | --- |
| C4-03A | Live CP-issued IAM context and two current workload capability/runtime reads through C4-02 production composition | Executable, requires live CP configuration |
| C4-03A negatives | Wrong facet, invalid service credential, simulated network outage, simulated future-expired evidence, cancelled supervision | Executable; outage/expiry are simulations and must never be called live withdrawal |
| C4-03B | Real Hydra hook dispatch, signed workload token, scope/audience/binding/artifact/expiry and issuance revocation | Runner implemented for signed issuance/current authority; live fixture and issuance-revocation proof pending |
| C4-03C | Live Kratos human session + Hydra challenge + current CP native context, binding, authorisation, revocation and fence | Runner implemented; requires approved disposable session and registered native bindings |
| C4-03D | Actual running protected CP resource, ownership/tenant isolation and real withdrawal while bearer remains unexpired | Runner implemented for CP context-validation resource, cross-tenant proof and supervised manual withdrawal; protected execution pending |
| C4-03E | Complete receipt chain, protected staging evidence, registration approval and operational review | Closed-schema receipt implementation committed; protected acceptance evidence and review remain open |

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

Both receipt schemas use the same private atomic publisher. Unknown check keys
are rejected before serialization, and write, sync and close failures are
preserved. Code replay requires `invalid_grant`, rather than a generic 400/401.
Session revocation and CP withdrawal qualify only while the original session,
bearer and context remain unexpired when the denial response arrives.

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

## C4-03B–E registered live qualification

The executable now supports `-full-config`, deliberately **without** a mock
fallback, bootstrap identity provisioning or producer-only issuer assertion.
Source CI compiles and tests the executable; source CI does not prove live
provider admission. The full runner refuses to start unless
`BAOBAB_C403_DISPOSABLE=1` is explicitly set in a dedicated, approved,
isolated, pre-provisioned qualification environment.

The `full-config` JSON is loaded through the existing protected service
document loader. It contains no secrets, only absolute **private files**
holding pre-provisioned credentials:

```json
{
  "workload_runtime": {
    "cp_origin": "https://cp.integration.example.invalid",
    "resolution_token_file": "/run/secrets/c403-resolution",
    "runtime_token_file": "/run/secrets/c403-runtime",
    "context_target": {
      "tenant_id": "tn-approved-fixture",
      "organisation_id": "org-approved-fixture",
      "country_code": "ZA"
    },
    "provider_id": "ory-hydra-approved",
    "engine_instance_id": "hydra-approved-instance",
    "estate_id": "estate-approved",
    "service_reference": "service-approved",
    "configuration_reference": "ref-approved",
    "security_domain_reference": "ref-approved-domain"
  },
  "human_runtime": {},
  "native_issuer_runtime": {},
  "hydra_issuer": "https://hydra.integration.example.invalid",
  "hydra_admin": "https://hydra-admin.integration.example.invalid",
  "kratos_public": "https://kratos.integration.example.invalid",
  "kratos_admin": "https://kratos-admin.integration.example.invalid",
  "primary": {
    "client_id": "c403-primary-approved",
    "client_secret_file": "/run/secrets/c403-primary-secret",
    "tenant_id": "tn-primary-fixture",
    "organisation_id": "org-primary-fixture",
    "country_code": "ZA"
  },
  "foreign": {
    "client_id": "c403-foreign-approved",
    "client_secret_file": "/run/secrets/c403-foreign-secret",
    "tenant_id": "tn-foreign-fixture",
    "organisation_id": "org-foreign-fixture",
    "country_code": "UG"
  },
  "resource_audience": "baobab-erp",
  "resource_scope": "context:resolve",
  "validator_token_file": "/run/secrets/c403-validator",
  "native_session_file": "/run/secrets/c403-kratos-session",
  "native_identity_id": "approved-synthetic-kratos-uuid",
  "native_client_id": "approved-oidc-client-id",
  "native_callback": "https://callback.integration.example.invalid/oidc"
}
```

This is an **illustrative schema**, not a deployable config: identifiers must be
real approved CP canonical identifiers and provider references. Both native
composition objects must include full approved values using the exact
`RuntimeComposition` format. `workload_runtime` must equal the separate A
`-runtime-config` document, byte-equivalent at the parsed model boundary.
Never use the example's names to fabricate an ACTIVE entitlement.

```bash
BAOBAB_C403_DISPOSABLE=1 go run ./cmd/c4-03-qualify \
  -runtime-config /run/secrets/c403-runtime.json \
  -full-config /run/secrets/c403-live.json \
  -cp-ca-file /run/secrets/c403-roots.pem \
  -source-commit "$(git rev-parse HEAD)" \
  -evidence-dir /run/c403-evidence
```

The protected live deployment must have: an Ory Hydra issuer with actual
`client_credentials` issuance through the governed C4-02 hook; a synthetic
primary and a different-tenant synthetic foreign workload, each with exact
registered OAuth audiences/scopes and current CP external identity mappings;
an **independently registered** validator granted `context:validate` and
`validates_audiences` for the subject's resource audience; the actual CP
context resolution/validation routes; and an approved Kratos synthetic session
plus an approved OIDC client and exact CP native/Hydra runtime bindings. The
Kratos session identity must carry provider-owned
`metadata_public.c403_disposable_fixture=true`; absence fails before any
session revocation. Never mark a real employee identity as disposable.
Provide HTTPS with validated server identities and CA roots. CP origin and
runtime secrets must not be selected from browser input.

The harness requires these real proofs:

- **B:** C4-02 current CP dispatch both before and after actual Hydra token
  exchange; RS256/JWKS signature, issuer, exact audience, client/actor, scope
  and bounded token lifetime.
- **C:** CP-governed Kratos/Hydra runtime composition, existing synthetic
  Kratos session validation, Hydra login and consent challenges, S256
  authorization-code exchange, signed ID token nonce and subject, code replay
  denial, and revocation of that **exact synthetic Kratos identity's** session.
- **D:** Real `POST /v1/platform-context/resolve` on the primary and foreign
  principal; authenticated real protected CP
  `POST /v1/platform-context/validate` success **for both independently
  registered principals and their own bounded contexts**; 404 cross-owner/foreign
  context denial; 401 tampered still-issued subject signature denial; and
  post-withdrawal CP denial of the **same unexpired bearer**.
- **E:** A fresh complete closed-schema private receipt plus SHA-256 digest,
  where *every* case is true and the CP withdrawal is actually observed.
  Every missing, skipped, uncertain or failed case yields FAIL.

### Approval and intervention

To prove *real* CP withdrawal instead of a fake or simulated expiry, this
runner reaches a short, controlled operator checkpoint **after** the signed
token has passed the running CP. An authorised operator must suspend or
withdraw **only** the pre-approved synthetic tenant or principal in CP
according to its existing governance flow and then enter `REVOKED` on stdin.
This input is merely a synchronization signal: it **never** counts as proof.
The runner must still observe a `TENANT_NOT_ACTIVE` (403) or
`CONTEXT_NOT_FOUND` (404) denial for the unchanged, independently verified,
still-unexpired bearer. If the operator has not completed the action, if the
token has expired, if CP is unavailable, or if an unexpected 401/500 occurs,
the gate fails. Restore the controlled fixture using the authorised CP
reconciliation process after collecting evidence. Never point this procedure
at production companies, real employees or shared staging tenants.

### Claims explicitly NOT made

A complete C4-03B–E integration PASS is **not** production activation,
physical passkey acceptance, release of CRITICAL grants, an approved legal
mandate, or tenant-onboarding certification. The receipt always states
`production_ready=false` and `physical_passkey_qualified=false`.
The parent IAM #122 browser passkey qualification remains independently
gated. Live registration credentials/CP state are external prerequisites;
the repository contains no magic substitute and never promotes PARTIAL
provider support on the strength of executable source.



## Independent C4-03E receipt integrity verification

After the **real protected C4-03B–E execution** has published its private
`full/run-*/` bundle, the reviewer can verify its closed receipt, exact source
SHA, SHA-256 digest, private file permissions and complete positive gate set:

```bash
go run ./cmd/c4-03-qualify \
  -verify-bundle /run/c403-evidence/full/run-REVIEWED-ID \
  -source-commit "$(git rev-parse HEAD)"
```

The result `INTEGRITY_VERIFIED_ONLY` means **only** that a locally presented
bundle is structurally complete and internally digest-consistent. It is not
cryptographic proof of who ran the fixture: a malicious party able to replace
both JSON and checksum can fabricate an internally consistent bundle. An
independent reviewer must still reconcile the GitHub/AWS protected execution
identity, immutable source/image revision, approved synthetic fixture boundary,
actual CP/issuer logs, authorised withdrawal and teardown before accepting
live operational evidence. No registration, production support, CRITICAL grant
or Nabhold Go-Live gate is promoted by this command.
