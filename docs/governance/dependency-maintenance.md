# BA-SEC-DEP-001 — IAM dependency/security maintenance adoption

**Governing standard:** [Approved Baobab Dependency & Security Maintenance Policy v1.0](https://github.com/baobab-platform/shared/blob/feat/dev11-observability-source-contract-20261102/docs/governance/baobab-dependency-security-maintenance-policy-v1.0.md).  
**Implementation:** IAM #153, a source-only maintenance companion on the IAM-N08 draft branch. The underlying IAM-N04/N06/N07/N08 dependency chain and protected service readiness are unchanged.  
**State:** SOURCE_COMMITTED; verification and runtime qualification are independent.  
**Review:** IAM owner, Platform Engineering and Security, plus independent provider/CP authority as appropriate.

## Confirmed manifests and coverage

| Ecosystem | Source of truth | Dependabot v1.0 |
| --- | --- | --- |
| GitHub Actions | `.github/workflows/*.yml` | `github-actions` at `/` |
| Go identity/federation | Root `go.mod` / `go.sum`; Go 1.27.3; OIDC/JOSE, SAML, PostgreSQL clients | **NEW** `gomod` at `/` |
| OCI/Keycloak/native BFF | `Dockerfile`, `Dockerfile.federation-authority` and `Dockerfile.native-browser-bff` at repo root | **NEW** `docker` at `/` |
| Local Ory/Keycloak/PG test topology | `docker-compose.yml` and `docker-compose.ory.yml` at root | **NEW** `docker-compose` at `/` |
| Devcontainer and centrally provisioned environments | `.devcontainer`, `upstream.lock.yaml` and native provider/image authorities | Owner-governed review; not assumed to be interchangeable with runtime image Dependabot |

IAM's audited `.github/dependabot.yml` previously tracked GitHub Actions alone, with an unconstrained group and none of the required PR limits, labels or commit prefixes. The updated file now covers four real ecosystems; groups routine minor/patch **version updates only**; requires positive open-PR limits, labels and commit prefixes; and schedules updates each Monday in SAST. Security patch response remains advisory/incident driven and not bounded by the routine schedule. Major Go, Keycloak, Ory and identity protocol changes require isolated owner review. No blanket ignore or `target-branch` is introduced.

`.github/workflows/enforce-dependabot-config.yml` keeps the immutable accepted Shared validator `31de2bc3dcd56128c019c640dc7e12c10ae9ca69` and now explicitly requires `github-actions,gomod,docker,docker-compose`. Shared #429 introduces an opt-in *strict* level; only migrate this caller after the validator is independently accepted/merged and pinned to a released commit. Do not point protected CI at an unmerged PR's SHA.

## Security response and native proof

An IAM dependency update is consequential: scanner success alone cannot prove credential/issuer correctness. Release qualification includes:

- Go `go build`/`go test`/`go test -race`, `govulncheck` (Foundation native adapter), source/checksum checks and relevant `go vet` gates.
- Keycloak container digest, Ory Kratos/Hydra/Keycloak release provenance, patched Java jar dependencies and independently verified `upstream.lock.yaml` pin ownership.
- SAML signature trust, OIDC/JOSE verification, delegated/scope authority, token revocation, workload/client authentication, replay and cross-tenant refusal tests. Native browser BFF/CP registered-binding evidence remains distinct.
- Foundation Trivy image/library scanning, secrets and SAST fallback. An unavailable private GHAS/CodeQL or dependency-review feature is recorded as **unavailable**, not falsely passed.
- Real PostgreSQL 17 native provider and restore/replay checks where applicable; production approval and provider/legal release gates remain independent.

**No live advisory assertion:** Neither the root YAML nor repository PR metadata proves current Dependabot Alerts/Security Updates are enabled, that Keycloak/Go are free of CVEs, or that SHA-pinned Actions are safe. Security owns the live advisory inventory and affected SHA/image/version analysis. A blanket suppressor would require an explicit Foundation exception with owner, justification and expiry; none is added here.

## Completion/readback

Before this adoption is marked verified: run `python3 -B -m unittest discover -s tests/unit -p 'test_dependency_maintenance.py' -v`, inspect the pinned Shared Dependabot structural check against the **exact final head**, confirm Go and Docker/Compose Dependabot jobs actually start, and preserve IAM-N08/N04 connected provider negatives. Security must verify the relevant GitHub security settings independently. Record `SOURCE_COMMITTED`, `CI_VERIFIED`, `SECURITY_ALERT_PATH_VERIFIED`, `CONSUMER_QUALIFIED` and protected environment evidence separately. No CI or protected deployment is claimed by this source-only policy change.
