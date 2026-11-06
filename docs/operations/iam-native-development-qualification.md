# IAM native capability completion — independent development boundary

**6 November 2026 | engineering gate under development | NOT QUALIFIED**

This plan refines the original IAM-N04 connected gate in response to the revised
*Baobab IAM Native Provider Capability Audit and Development-Completion Plan*.
Accepted ADR-IAM-0033 and Shared ADR-SHARED-017 remain normative.

## Development exit is provider-first

**Required IAM source and runtime proof:** all Kratos native human, A1–A4 assurance,
passkey, lifecycle, verification/recovery/rebinding, session revocation and
privacy controls; all Hydra OAuth/OIDC, workload issue, audience/scope, issuer
revocation and signing/JWKS rotation; bounded Keycloak enterprise OIDC/SAML
federation, broker lifecycle/logout and compromise containment; provider-neutral
normalisation; real PostgreSQL/Ory/Kratos/Hydra whole-runtime restore and no
revoked credential/session resurrection. Positive AND adversarial cases
must run on real disposable components and original owner-source digests.

**What is explicitly outside this acceptance:** CP provisioning or ACTIVE provider
registration, CP Tenant/Market/Organisation entitlement, consumer owner-native
operations, Nabhold/ZuriBeans/Thamani rollout, staging, production. CP may be
used as a **disposable contract stub or real neutral compatibility test**; it
is not an activation prerequisite and does not confer business authority.

The existing `scripts/n04_development_gate.py` remains intact as a **separate
downstream CP+consumer connected gate**. It still requires real Pulse and
Payments originals and all mandatory payment cases. Do not weaken or relabel
that test to make IAM qualification pass.

## Independent native provider evidence

`scripts/iam_native_development_readback.py` validates *only* owner-private
original Go JSONL case streams and digest sidecars, in distinct Kratos, Hydra,
Keycloak, security/A4 and recovery suites. Missing/skip/fail/foreign cases,
wrong custody, stale or duplicated paths or corrupt checksums cause HELD.
Even a fully populated internally consistent original yields exit **3** and
`IAM_NATIVE_REQUIRED_CASES_RECONCILED_UNATTESTED`: file hashes alone do not
independently prove the real provider ran. It never outputs a CP registration
or a qualification certificate.

To qualify development, IAM must independently verify the actual original
GitHub Actions run/ZIP artifact **from the authenticated API**, match reviewed
exact source SHA and provider/runtime digests, read original successful and
negative traces from the owner process, confirm no skipped test, perform
teardown and obtain separate reviewer provenance. The existing
`n04_github_archive_readback.py` anchors workflow/ZIP source but alone is
insufficient; this new case reader anchors case coverage but alone is
insufficient. Reconcile both with independently observed runtime consequences,
not two self-authored JSON booleans. All named advanced cases lacking actual
test implementation **remain REQUIRED AND BLOCKED**.

## Shared declaration / later enablement

Shared #433 proposes canonical `identity.authentication.assurance` and
`identity.federation.enterprise` contracts, a non-grantable IAM management
inventory and a provider-facet target matrix. It is **a draft** and does not
justify an IAM source pin or changing a PARTIAL declaration to IMPLEMENTED
until the Shared decision is accepted and actual component evidence passes.
`identity.token.issuance` is deliberately subsumed by existing canonical
human authentication and workload token issue contracts.

After real complete native provider development qualification, IAM may
individually declare `IMPLEMENTED` against the exact accepted Shared key and
major contract. Actual CP provider/facet activation and consumer bindings are
later owner-controlled decisions. Never treat an IAM-go-green status as
permission to execute a commerce, payment or logistics commitment.
