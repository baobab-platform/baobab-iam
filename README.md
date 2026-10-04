# Baobab IAM (`baobab-iam`)

> **Baobab IAM** is the central authentication and identity provider for the Baobab platform. It implements **who** you are, while the Control Plane (`baobab-cp`) determines **where** and **what** you are entitled to, and domain engines enforce business authorization.

---

## Provider migration status

Accepted ADR-IAM-0033 defines the multi-provider target: **Kratos for native
human identities/credentials/sessions; Hydra for general OAuth/OIDC and workloads;
Keycloak retained for enterprise SAML/OIDC federation and identity brokering**.
Current Keycloak configuration still carries legacy native/client capabilities;
retention does not prove that its scope has already been reduced.
Provider-neutral interfaces preserve CP canonical identity and Shared capability/lifecycle authority.
The Keycloak Go adapter remains incomplete: it is a retained boundary, but the
permanent EnterpriseFederationProvider port/adapter is not implemented.
Production dual-run, per-capability cutover and canonical workload activation
remain blocked by their evidence gates. Global Keycloak deletion is not a target.
Unit/mock tests do not establish production interoperability or activation.

The [MP implementation plan](docs/governance/iam-mp-implementation-plan.md)
sequences Shared contracts, provider registry/resolution and federation work.

Human migration requires an authorized `HumanTraitsSource` keyed by the exact source
binding and opaque snapshot reference. Missing traits fail closed; neither synthetic
mailboxes nor snapshot strings supply login identifiers. Email never resolves canonical identity.
Credential import remains unverified until pinned-version login fixtures pass.

The capability matrix is validated against the exact Shared catalogue pin in
`contracts.lock.yaml`; regenerate its Markdown with
`python3 scripts/iam_capability_matrix.py --write` (PyYAML 6.0.3).
For a local Shared checkout, set `SHARED_REPO_DIR`; private remote reads require a
read token in `GH_TOKEN`. CI may supply `SHARED_READ_TOKEN` for cross-repository access.

## Status

- **Architecture:** [ADR index](./docs/adr/README.md); Accepted ADR-IAM-0033 controls multi-provider allocation and amends the earlier retirement programme
- **Implementation:** All sixteen gates (IAM-0 through IAM-16) have had at least a phase 1
  pass; Gate IAM-2 (Keycloak foundation) hardening itself remains open — see
  [Gate IAM-0 discovery](./docs/governance/gate-iam-0-discovery.md) for the verified
  historical implementation state and open risks. R-1
  (unresolved image pin) is now closed in repository configuration: `upstream.lock.yaml`
  contains a resolved digest verified by CI; deployment/DR acceptance remains separate. Gate IAM-3's
  Control Plane identity spine (`CanonicalIdentity`/`ExternalIdentity`, in `baobab-cp`) and
  Gate IAM-4 (workload identity, ADR-0007) are **complete** — see
  [Gate IAM-3 scope](./docs/governance/gate-iam-3-canonical-identity-scope.md) and
  [Gate IAM-4 scope](./docs/governance/gate-iam-4-workload-identity-scope.md). Gate IAM-5
  (workforce SSO, ADR-0009) phase 1 (distinct workforce admin clients, a starter role
  namespace, a real `baobab-cp` admin-authorization defect fixed), phase 2a
  (`baobab-trade` OIDC wiring, `baobab-platform/baobab-trade#70`), and phase 2b (`baobab-cms` OIDC
  wiring, `baobab-platform/baobab-cms#9` — real PKCE/state/nonce/ID-token verification against
  `openid-client`, since Payload ships no OIDC plugin; two review-caught bugs, a missing
  password on JIT provisioning and a missing database migration, were fixed and verified
  against a real local Postgres instance before merge) are all complete — see
  [Gate IAM-5 scope](./docs/governance/gate-iam-5-workforce-sso-scope.md) §5.1. Gate IAM-6
  (Zuribeans B2B, ADR-0010) phase 1 (Keycloak Organizations enabled, verified end-to-end
  against a real Keycloak instance) is complete — see
  [Gate IAM-6 scope](./docs/governance/gate-iam-6-zuribeans-b2b-scope.md) for phases 2+
  (`baobab-cp` canonical-entity wiring, cross-buyer isolation against real tokens). Gate
  IAM-7 (Thamani B2C, ADR-0011) is **scoped, not yet implemented** — discovery found two
  genuine architectural forks (where the customer OIDC redirect terminates; how a guest
  order's claim proof is delivered) that need their own decisions before code — see
  [Gate IAM-7 scope](./docs/governance/gate-iam-7-thamani-b2c-scope.md) §3. Gate IAM-8
  (Supplier Identity, ADR-0012) is **scoped, not yet implemented** — discovery found no
  repository anywhere owns "supplier domain" logic yet (a bigger blocker than Gate IAM-7's
  forks), so implementation is deferred pending that ownership decision — see
  [Gate IAM-8 scope](./docs/governance/gate-iam-8-supplier-identity-scope.md) §3. Gate
  IAM-9 (Medusa Integration, ADR-0013) found most of its scope already satisfied by Gate
  IAM-5's admin OIDC wiring, plus one real gap fixed — `authMethodsPerActor` was unset,
  making the admin `oidc` provider also implicitly reachable by the customer actor
  (`baobab-platform/baobab-trade#71`) — see
  [Gate IAM-9 scope](./docs/governance/gate-iam-9-medusa-integration-scope.md). Gate IAM-10
  (ERP Integration, ADR-0014) found iDempiere 13 ships a real, pluggable, built-in OIDC
  mechanism (`org.idempiere.ui.sso.oidc`) — a workforce SSO client (`baobab-erp-admin`) is
  provisioned for it, and `baobab-erp`'s previously-unauthenticated
  `/context/resolve*`/`/mapping/resolve*` endpoints now validate workload tokens. Ships
  against one explicit, documented deviation from ADR-0014 §9 (the stock plugin matches by
  email/username, not `issuer+subject`) — see
  [Gate IAM-10 scope](./docs/governance/gate-iam-10-erp-integration-scope.md) §2. Gate
  IAM-11 (Credential Security/MFA/Passkeys, ADR-0015) phase 1 fixes a real password-policy
  violation (§11-14: was requiring composition rules the ADR explicitly prohibits) and
  makes MFA mandatory for every existing workforce admin role via a role-driven
  conditional-OTP browser flow, verified structurally against a real Keycloak instance —
  see [Gate IAM-11 scope](./docs/governance/gate-iam-11-credential-security-scope.md) §4
  for this ADR's large remaining scope (passkeys as an MFA alternative, step-up for
  specific high-risk actions, recovery hardening, break-glass, and more). Gate IAM-12
  (Identity Lifecycle/Revocation/Deprovisioning, ADR-0016) phase 1 closed a real
  administrative-audit gap (`adminEventsEnabled` was never set) and proved the IAM-side
  "kill switch" — disable identity + revoke sessions — end-to-end against a real Keycloak
  instance; most of this 213-section ADR is `baobab-cp`/domain-engine territory, not
  `baobab-iam`'s — see
  [Gate IAM-12 scope](./docs/governance/gate-iam-12-identity-lifecycle-scope.md) §1, §5. Gate
  IAM-13 (Audit/Observability, ADR-0017) phase 1 proved — against a real Keycloak instance,
  not by trusting upstream claims — that Gate IAM-12's admin-event logging actually redacts
  secrets (a plaintext-password marker never appears in the resulting audit record) and that
  credential revocation is captured in the audit trail; most of this 205-section ADR is
  `baobab-cp`/domain-engine/infrastructure territory — see
  [Gate IAM-13 scope](./docs/governance/gate-iam-13-audit-observability-scope.md) §1, §4. Gate
  IAM-14 (Availability/Backup/DR, ADR-0018) phase 1 adds this repo's first
  [DR runbook](./docs/operations/disaster-recovery-runbook.md), verifies the running
  Keycloak instance's version actually matches `upstream.lock.yaml`'s pin (not just that the
  file claims one), and closes a real PKCE coverage gap (`baobab-control-plane-admin` was
  never checked by the old hardcoded client list). The historical R-1 egress blocker
  is superseded by the current resolved pin and CI baseline check. An unrelated defect (`loginTheme`/`accountTheme:
  "baobab"` references a theme that was never built) was found and deliberately left open —
  see [Gate IAM-14 scope](./docs/governance/gate-iam-14-availability-dr-scope.md) §5, §7. Gate
  IAM-15 (Multi-Region Readiness) required no `baobab-iam` code changes — discovery found
  `baobab-cp` already implements the region/market/`CapabilityBinding`/`EngineInstance` model
  this gate's checklist describes (including real residency-mismatch enforcement in its
  topology resolver), the IAM/CP boundary needs no region claim, and this repo's current
  single-global-realm architecture is the correct Phase A per the Consolidated Spec's own
  multi-region evolution model. One item does NOT get a clean bill of health: the "revoked
  account survives DR restore" row from the spec's Multi-Region Test Matrix is real but not
  yet proven end-to-end (no actual backup/restore/reconciliation exercise exists) — see
  [Gate IAM-15 scope](./docs/governance/gate-iam-15-multi-region-readiness-scope.md) §5, §7.
  Gate IAM-16 (Production Hardening) — the final gate in the program — validated all twelve
  checklist items against real evidence rather than assuming them satisfied: closed two real
  gaps (SBOM generation added to CI; a new
  [security incident-response runbook](./docs/operations/security-incident-runbook.md) for
  compromised credentials/clients, distinct from the DR runbook), gave a reasoned (not just
  deferred) answer on login-storm risk against this realm's actual brute-force configuration,
  and reported cross-tenant isolation accurately as partial (workload isolation proven;
  buyer/Organization cross-isolation still Gate IAM-6 phase 2+) rather than repeating an
  overclaim — see
  [Gate IAM-16 scope](./docs/governance/gate-iam-16-production-hardening-scope.md).
- **Next:** All sixteen numbered gates (IAM-0 through IAM-16) have now had at least a phase 1
  pass. What remains is every gate's own deferred work, none of it resolved by reaching
  IAM-16: Gate IAM-2 (environment separation, MFA/Organizations baseline), Gate IAM-5's
  remaining phases (now that both engine OIDC wirings are done: `baobab-cp` role-aware admin
  authorization, the workforce membership model, MFA/step-up, break-glass/access review),
  Gate IAM-6's remaining phases (including cross-buyer isolation testing), the shared Gate
  IAM-7/IAM-9 customer-OIDC-termination decision, Gate IAM-8's supplier-domain ownership
  decision, Gate IAM-10's remaining phases (closing its ADR-0014 §9 deviation,
  AD_User/Role/Client/Org provisioning), Gate IAM-11's remaining phases, Gate IAM-12's open
  architectural fork (custom Keycloak event-listener SPI vs. `baobab-cp` polling the native
  Admin Events API), Gate IAM-13's deferred retention-policy decision, Gate IAM-14's real
  remaining operational gaps (the missing `baobab` theme and a post-backup security journal; image-pin R-1 is resolved), Gate
  IAM-15's deferred multi-region phases B-D and its unproven DR-restore test-matrix row, and
  Gate IAM-16's own open items (a penetration test, a real DR/load-testing exercise, a
  bulk-revocation tool, an actually-run incident-response drill).

---

- **Control Plane onboarding entitlements:** the Platform Onboarding Operator and Approver
  (`onboarding-requester` / `onboarding-authoriser` client roles of
  `baobab-control-plane-admin`, carrying `onboarding:request` / `onboarding:authorise`) and
  their toxic-combination check `scripts/check-role-policy.sh` — see
  [the onboarding entitlements runbook](./docs/operations/cp-onboarding-entitlements-runbook.md).
- **Control Plane `authority:self`:** the human-only, read-only scope with which a workforce
  administrator reads their own effective administrative authority (ADR-BCP-020). An optional
  scope of `baobab-control-plane-admin` only, never of a workload or other client. Baobab owns
  its semantics (Shared `scope-registry.yaml`); this provider only issues it, and it stays
  valid unchanged when the identity provider changes.

- **Control Plane `administrator:read` / `administrator:write` / `administrator:approve`:** human-only optional scopes of
  `baobab-control-plane-admin` only, for inspecting and administering AdministrativeGrants
  (ADR-BCP-020). They only make the Control Plane routes callable and confer no authority;
  `administrator:write` and `administrator:approve` are privileged and are never attached to a workload or other client; `administrator:approve` lets a checker decide a grant change but is not approval authority (the Control Plane also requires `changeset:approve` and enforces separation of duties).

## Capability baseline

The migration baseline and provider-neutral capability map are documented in:

- [docs/governance/iam-capability-matrix.md](./docs/governance/iam-capability-matrix.md)
- [.baobab/iam-capability-matrix.yaml](./.baobab/iam-capability-matrix.yaml)
- [ADR-IAM-0033 migration rebaseline](./docs/governance/gate-iam-m0-migration-baseline.md)
- [MP0–MP20 implementation plan](./docs/governance/iam-mp-implementation-plan.md)

## What this repository is

`baobab-iam` owns the provider-neutral authentication boundary. Its assigned
runtimes are Kratos, Hydra and retained Keycloak enterprise federation. It owns:

- Authentication (OIDC, OAuth, MFA, passkeys)
- Credential management
- Authentication sessions
- Account recovery
- Identity federation
- Workload authentication and governed token issuance

It does **not** own:

- Tenant lifecycle (that is `baobab-cp`)
- Business authorization (that is domain engines)
- Commerce or ERP data

---

## Relationship with other repositories

| Repository | Relationship |
|------------|--------------|
| `baobab-platform/shared` | Consumes canonical identity, scope, and event contracts. |
| `baobab-platform/baobab-cp` | Validates tokens from this service and resolves canonical identity/context. |
| `baobab-platform/baobab-trade` | Authenticates buyers, customers, and administrators via this service. |
| `baobab-platform/baobab-erp` | Uses OIDC SSO for workforce and integration identities. |
| `baobab-platform/infrastructure` | Provides production runtime, database, and network. |

---

## Tech stack

| Concern | Choice |
|---------|--------|
| Identity runtimes | Kratos (native humans), Hydra (OAuth/workloads), Keycloak 26.7.5 (retained enterprise federation target) |
| Database | PostgreSQL 17 |
| Container | Digest-pinned runtime images; Keycloak runtime retained for enterprise federation |
| Configuration | JSON realm exports + idempotent bootstrap |
| CI/CD | Reusable workflows from `baobab-platform/shared` |

---

## Getting started

Clone the repository and start the local development stack:

```bash
git clone git@github.com:baobab-platform/baobab-iam.git
cd baobab-iam
cp .env.example .env
make dev-up
make bootstrap
make test
```

Run the ADR-0002 Section 48 verification suite against a running, bootstrapped stack:

```bash
BOOTSTRAP_WORKLOAD_CLIENT_SECRET=dev-secret make bootstrap
BOOTSTRAP_WORKLOAD_CLIENT_SECRET=dev-secret ./tests/integration/run.sh
```

