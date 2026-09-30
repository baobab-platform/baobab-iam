# Gate IAM-M1 — Evidence checklist (M1-D)

**Status:** Cross-repository convergence in review — IAM branch complete enough for CI; CP M1-C is PR #225  
**Date:** 2026-09-30  
**Gate:** IAM-M1 (ADR-IAM-0019; ADR-IAM-0020)  
**Branch evidence:** `feat/adr-iam-ory-migration`  
**Does not:** enable production dual issuer or migrate human identities

## Exit criteria matrix

| # | Criterion | Evidence | Status |
|---|---|---|---|
| 1 | `internal/provider` builds/tests | provider-neutral package + Ory/Keycloak adapters | **On PR #42; CI required** |
| 2 | Capability interfaces match ADR-0020 | `provider.go`, adapter compile assertions | **Done on branch** |
| 3 | Shared identity schemas are not Keycloak-only | current Shared `external-identity.schema.json` keeps `provider_type` optional/unrestricted; principal/workload contracts are provider-neutral | **Done; no Shared schema change required** |
| 4 | CP resolves by issuer + subject; no identity authz on `provider_type == keycloak` | CP audit + `docs/governance/iam-m1c-ory-provider-neutral-evidence.md` | **In review: baobab-cp#225** |
| 5 | CP Ory-shaped fixture | CP #225 tests `provider_type=ory`, Ory issuer + workload subject through canonical Principal | **In review: baobab-cp#225** |
| 6 | No provider-native canonical IDs | searches of Shared + CP found no `keycloak_user_id` or `ory_identity_id`; IAM branch adds neither | **Pass** |
| 7 | Phase-0 identity meanings preserved | no canonical tenant/legal-entity/capability authority moved into IdP | **Done on branch** |
| 8 | Cross-repo PR links recorded | IAM #42; CP #225 | **Done** |

## Important boundary found by the audit

CP's **canonical identity** path is provider-neutral, which is what M1-C requires.

CP's separate `IamOrganisationReference` model is still Keycloak-specific. That
is a later human/B2B organisation migration concern. It does not block the
machine workload path, but it must be addressed before Ory becomes authoritative
for organisation-side IAM projections.

## M1 close condition

M1 may be called complete when:

1. IAM #42 is CI-clean and merged; and
2. CP #225 is CI-clean and merged.

Production dual issuer remains M18 and is not an M1 exit criterion.

## Document control

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-09-27 | Initial checklist |
| 0.2 | 2026-09-30 | Link IAM #42 |
| 0.3 | 2026-09-30 | Re-audit Shared; link CP #225; distinguish canonical identity from IAM-organisation migration |
