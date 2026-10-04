# MP2-C: authoritative federation consumption boundary

Shared MP2-A/B are merged at `b10388460c23ac6d7d99bb8a22e2ee4821ad22f6`. This increment pins that revision and adds `internal/federation` as a provider-neutral consumption boundary. Keycloak remains the intended SSO implementation. Factory aliases remain compatibility parsing and never approve a binding, select a capability or establish assurance.

The consumer accepts opaque trust/event IDs only. A trusted composition root must provide the following readers/verifier and governed scope/time policy. Missing implementations, typed nils, unsupported protocols, unverified approvals and storage failures deny. There is no fixture-backed production reader or permissive default.

| Port | Independent authoritative duty |
| --- | --- |
| GovernanceAuthority | Current approved IAM trust revision; exact CP ExternalReference targets, purpose, ownership, immutable approval/evidence coverage and coherent snapshot |
| PlatformAuthority | CP provider/instance/binding/scope association; current approved MP2-A profile/release and fresh VERIFIED OIDC/SAML facet support |
| EventVerifier | Actual signature, issuer, client/recipient audience, algorithm, stable subject, freshness and replay checks through the approved provider boundary |
| CanonicalAuthority | Exact issuer+subject lookup to existing ACTIVE human Principal and ACTIVE ExternalIdentity; independently approved mapping reference |

Internal receipt/query structs are trusted ports, not new Shared registries, public HTTP contracts or organisation EvidenceRecords. Reference purpose labels are internal requirements, not new canonical entity types. A native object's existence or unverified manual import is insufficient approval. Reference targets must be non-secret; no private credential/assertion is fetched through this interface.

## Checks and limits

The consumer enforces approved trust revision/snapshot, explicit organisation/estate scope, ACTIVE lifecycle, current non-secret typed references and exact provider-instance association. Runtime support must be VERIFIED for the federation facet, with matching profile/deployed artifact digests and fresh proof. PlatformAuthority must independently read approved profile/release records and enforce monotonic revisions; copying a digest proves nothing.

Trust/event/provider/issuer/subject and authentication times must match across Shared records. Evidence is bounded by configured event lifetime, authentication age and decision lifetime. UNKNOWN assurance is not elevated. MAPPED A1–A3 requires a decision covering exact event, identity, trust policy/revision and normalized upstream evidence. A4 cannot be asserted by upstream federation. The internal evidence digest is SHA-256 of JSON emitted for this Go UpstreamEvidence model; this is a consistency check for its trusted reader, not a new cross-language signing protocol or an authenticity substitute.

CP's mapping is always consulted. Adapter RESOLVED claims must match it; UNRESOLVED evidence can resolve only through an existing authoritative mapping. No provisioning or email linking occurs. The CanonicalAuthority must verify the non-secret mapping reference identifies that exact CP ExternalIdentity-to-Principal relationship, never business CanonicalEntity/Mapping or a fabricated `ref_` placeholder.

The trust is re-read before success to catch observed suspension/configuration changes. Result expiry is bounded by every approval/evidence/mapping, authentication age and decision lifetime. Final clock rollback/expiry or context cancellation denies. This does not provide atomic cross-repository revocation; adapters must supply current coherent reads and enforce replay/consumption and revocation policy. The result is identity/assurance only, not a token, Context, estate admission, role, entitlement or workload activation.

Backend errors return fixed invalid/denied/unverified/unsupported/unavailable categories; raw messages are never returned. Operational logs must not contain external subjects, raw evidence, reference targets or complete authority structs.

## Contract evidence

Go wire models mirror pinned Shared trust/principal/assurance schemas. OIDC evidence is reused; SAML does not invent acr/amr. Strict JSON decoding rejects unknown/duplicate fields, nulls, trailing data and oversized records. Publication checks are separate from current approval checks.

Both fixtures are exact copies of pinned Shared synthetic VERIFYING/UNRESOLVED/UNKNOWN examples and permit no login. CI verifies checkout SHA, lock, Go pin constant and fixture hashes; actual Go-emitted synthetic OIDC/SAML records validate against the pinned schemas and Shared semantic validator. Denial tests cover coverage/type/ownership/scope, unsupported/unverified support, mismatched artifacts, stale evidence, identity lifecycle, time changes and concurrent trust suspension. Federation tests run with the race detector; existing provider/migration/provisioning suites remain enabled.

## Outstanding live integration

This is MP2-C's contract/consumer boundary, not production activation. The
[live runtime increment](iam-mp2c-live-runtime.md) adds private authenticated
transport, a durable reference-approval workflow and a persistent actual OIDC
signature verifier/composition root. Source-side CP/IAM authority integration,
full trust governance, Keycloak/BFF callback wiring and SAML verification remain
production prerequisites. CP's companion reader supplies both existing identity
records from one PostgreSQL snapshot, without provisioning or fabricated mapping
references. It does not approve IAM evidence/configuration.

The deployment still requires real Governance/Platform/Canonical sources and
approved target/policy backends. The private transport is not a substitute for
those sources, and no handler is mounted in production. Missing support remains
unsupported/unverified. MP3 registry/projection and MP4 dispatch are separate
increments. EA-04, federation/workload activation, dual-issuer enablement, Ory
cutover and Keycloak retirement remain incomplete.
