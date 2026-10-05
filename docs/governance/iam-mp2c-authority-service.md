# Private MP2-C federation-authority service

`cmd/federation-authority` is a separate executable and image from Keycloak.
It mounts IAM governance and private BFF event operations, not a public login
API or provider registry/resolver. Keycloak retains bounded enterprise SSO.

## Authority boundaries

The composition opens four distinct protected single-writer files: native
targets, reference approvals, trust revisions and OIDC requests/events/replay.
CP supplies target-registration, canonical identity, platform binding and human
approval authority. IAM native targets and ledgers supply final target/trust
decisions. An independently configured IAM protocol-policy source supplies
approved OIDC configuration/public JWKS and assurance mapping; it must implement
the existing private ports with real governed sources. This command does not
manufacture policy or treat missing policy as approval.

Inbound admission requires BOTH verified client TLS and a signed workload bearer
with the configured exact service audience, `actor_type=workload` and
`federation-authority:read`. A protected admission snapshot binds the certificate
SHA-256, issuer and subject to current lifecycle, finite validity, private
operation allowlist and exact organisation/estate scopes. It is reread on every
authorization. This is service admission configuration, not a replacement for
CP canonical identity, AdministrativeGrants or domain authorization. Deployments
must reconcile it from approved workload provisioning; automated live snapshot
publication remains an operational dependency. No default workload is admitted.

Governance mutations additionally require `X-Baobab-Governance-Subject` containing
the human subject token. It is forwarded request-locally to CP's independently
verified human authority. It is never substituted with the workload token,
stored in a ledger or logged. Proposal/checker/revocation decisions remain in the
existing CP/ledger implementation. Other operations also consume current CP
platform binding authority. ID-only operations derive scope from durable trust
state. CP and IAM target routes retain distinct ownership.

## Configuration

Run `/federation-authority -config /run/iam/service.json`. The configuration,
admission snapshot and optional reviewed target manifest must be regular Linux
files owned by the service UID with mode `0600`, without symlinks/hard links.
JSON rejects duplicate, unknown, null and trailing values; documents are bounded
to 64 KiB. Parent directories and persistent state must be access-controlled.
Configuration contains paths and approved origins, never literal credentials.

```json
{
  "Address": ":8443",
  "Certificate": "/run/iam/tls/server.crt",
  "Key": "/run/iam/tls/server.key",
  "ClientCA": "/run/iam/tls/workload-ca.crt",
  "AuthorityCA": "/run/iam/tls/authority-ca.crt",
  "WorkloadIssuer": "https://hydra.private.example",
  "WorkloadAudience": "REVIEWED_SERVICE_AUDIENCE",
  "RegistryPath": "/run/iam/admission.json",
  "CPOrigin": "https://cp.private.example",
  "CPTokenFile": "/run/iam/cp-token",
  "ProtocolOrigin": "https://iam-policy.private.example",
  "ProtocolTokenFile": "/run/iam/policy-token",
  "StateDirectory": "/var/lib/iam",
  "ReadinessTrustID": "11111111-1111-4111-8111-111111111111",
  "ReviewedTargets": "/run/iam/reviewed-targets.json",
  "Policy": {
    "Scope": {"OrganisationID": "org_example", "EstateID": "estate_example"},
    "MaxEventLifetime": 300000000000,
    "MaxAuthenticationAge": 300000000000,
    "MaxDecisionLifetime": 60000000000
  }
}
```

Durations use Go JSON nanoseconds. The audience placeholder requires an approved
deployment registration; this change does not allocate a new Shared audience or
scope. One process has one explicitly configured consumer scope. Additional
scope-bound consumers require separately governed composition.

Admission documents are arrays of records with `CertificateSHA256`, `Issuer`,
`Subject`, `Active`, `ValidUntil`, `Actions`, and `Scopes`. Arrays must be present
and non-null. Actions are private handler operations, not new Shared permission
codes: `TRUST_READ`, `REFERENCE_READ`, `TARGET_READ`, `CONFIGURATION_READ`,
`ASSURANCE_MAP`, `APPROVAL_PROPOSE`, `APPROVAL_DECIDE`, `APPROVAL_REVOKE`,
`EVENT_BEGIN`, `EVENT_COMPLETE`, and `EVENT_CONSUME`. Use minimum required actions.

An optional reviewed target manifest is an array of `{Expectation, Content}`
records. `Content` contains reviewed NON_SECRET native JSON bytes. Activation
targets instead use `{Expectation, Snapshot}` so the existing canonical snapshot
digest writer is mandatory. Loading is immutable and idempotent; it does not
register CP references or approve anything. Failed startup may have persisted a
prefix of the manifest; unchanged entries can safely be replayed. Secrets remain
outside this manifest and ledger. Do not supply both Content and Snapshot.

## Private operations and lifecycle

All existing `/internal/federation/v1/` IAM-owned source and governance operations
are mounted behind admission. CP-only operations remain unsupported by this
IAM composition. No route is exposed through ALB/APISIX.

Private event POST operations are:

| Path under `/internal/federation-events/v1/` | Request fields |
| --- | --- |
| `begin` | `TrustID`, `SessionDigest` |
| `complete` | `TrustID`, `EventID`, `State`, `BrowserSecret`, `IDToken` |
| `consume` | `TrustID`, `EventID` |

Only a registered trusted BFF may complete events after its server-side
authorization-code/PKCE flow. Begin returns correlation material only to that
BFF. Completion verifies actual OIDC signatures and consumes correlation;
consumption performs existing governance/platform/canonical checks and durable
single-use replay fencing. These endpoints are not an implementation of the
Keycloak broker adapter. SAML remains unsupported; a downstream OIDC token does
not certify an upstream SAML assertion.

`/health/live` indicates the process is running. `/health/ready` requires the
configured approved OIDC trust, CP binding and protocol configuration source to
answer. Readiness is dependency evidence, not federation certification. It does
not exercise assurance mapping without a real event. Health endpoints also
require a trusted TLS client certificate. Staging health infrastructure must
support that boundary. No plaintext health listener is added.

Finite read/header/write/idle timeouts and body/header limits bound requests.
SIGTERM/SIGINT drain HTTP requests before closing all stores. Certificate changes
require controlled restart; outbound bearer files are reread for every request.

## Deployment and acceptance

Build `docker build -f Dockerfile.federation-authority -t iam-authority .`.
The builder is digest pinned and the final static Linux image runs as UID 65532.
Mount CA/certificate/key/config/token files and encrypted durable state with
appropriate ownership. The scratch image relies on explicitly mounted roots.

For bounded staging, enforce one writer and durable storage through replacement;
ECS ephemeral task storage is insufficient. ECS rolling deployment must not
start a competing writer. Preserve replay/revocation state across recovery.
AWS provisioning, backup/restore fencing, multi-replica storage, live policy
sources, workload admission reconciliation and real Keycloak broker evidence
remain acceptance dependencies. No AWS deployment or production activation is
claimed by this service increment.

Validation includes actual signed workload bearer admission, exact audience and
actor type denial, current snapshot revocation, TLS admission, protected-file
rejection, strict configuration, the existing federation cryptographic/ledger
suite and its race detector run. CI additionally builds the separate image.
