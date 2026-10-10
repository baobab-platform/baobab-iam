# Gate IAM-0 — ADR Traceability Matrix, Gap Analysis & Risk Register

**Status:** Complete
**Date:** 2026-09-10
**Scope:** Cross-repository discovery for the Baobab IAM programme (ADR-0001 through ADR-0018)
**Repositories inspected:** `baobab-platform/baobab-iam`, `baobab-platform/baobab-cp`, `baobab-platform/shared`, `baobab-platform/baobab-trade`, `baobab-platform/baobab-erp`, `baobab-platform/baobab-cms`, `baobab-platform/baobab-pulse`, `baobab-platform/infrastructure`

This document satisfies Gate IAM-0 of the IAM implementation programme: it records the
actual, verified implementation state against the ADRs, rather than assuming the
repositories match their own documentation. Every finding below was confirmed by reading
source, config, or CI files directly — not inferred from README claims alone. Several
README/ADR claims are contradicted by what is actually committed; those contradictions are
called out explicitly.

---

## 1. Method

For each repository: read the README, relevant ADRs, CI workflows, and a targeted sample of
source/config files; grep for identity/auth-related code; and cross-reference against the
architectural invariants in ADR-0001 through ADR-0018 and the Consolidated Technical
Specification. Two structural facts constrain this matrix:

- **`baobab-platform/baobab-iam`'s own README claims "Gate IAM-2 (scaffold) complete."** This is
  contradicted by its own committed CI workflow, which cannot currently pass (see §4.1).
- **`baobab-platform/baobab-cp` is materially further ahead than `baobab-iam`'s README implies.**
  It already has a working (if incomplete) OIDC verifier, tenant-isolation enforcement, and
  a context-resolution pipeline with real negative-security tests — this is IAM-3/IAM-8
  territory, not scaffold-only.

---

## 2. Repository Maturity Summary

| Repository | Maturity | IAM-relevant state |
|---|---|---|
| `baobab-iam` | Scaffold, CI non-functional | Keycloak realm/client JSON exists; bootstrap script exists; **CI cannot pass as committed** (§4.1); no tests beyond a health-check curl; no `actor_type` claim wiring |
| `baobab-cp` | Partial, further along than documented | Real OIDC token verification, tenant isolation with passing negative tests, context-resolution pipeline — but no `CanonicalIdentity`/`ExternalIdentity(iss+sub)` model yet, and Tenant/CanonicalEntity are conflated in the resolver |
| `shared` | Partial, contracts drafted but broken | Identity/authorization/event contracts exist under `contracts/`, but 3 of 3 identity-event schemas reference a nonexistent file and are unresolvable; no working schema tests; no reason-code registry |
| `baobab-trade` | Substantial (non-IAM) | Full Medusa app, calls `baobab-cp`'s `/v1/context/resolve`; **zero** OIDC/Keycloak auth wiring — greenfield for Gate IAM-9 |
| `baobab-erp` | Partial scaffold | iDempiere-native login only; identity module is an explicit passthrough stub deferring to "the approved platform identity provider" — greenfield for Gate IAM-10 |
| `baobab-cms` | Substantial (non-IAM) | Payload local auth only; docs explicitly state no IdP is integrated yet — greenfield |
| `baobab-pulse` | Scaffold (self-declared) | No auth code; defers identity entirely to `baobab-cp` by reference |
| `infrastructure` | Early scaffold ("Foundation 1") | No Keycloak/IAM service anywhere in Compose or planned layout; APISIX admin API has no OIDC plugin configured |

**Conclusion:** `baobab-iam` and `shared` are the correct place to invest first — every
downstream engine (`trade`, `erp`, `cms`, `pulse`) is architecturally ready to consume OIDC
but has literally nothing to consume yet, because no repository provisions a working,
tested Keycloak instance with the token profile ADR-0006 requires.

---

## 3. ADR Traceability Matrix

| ADR | Title | Primary repo(s) | Status | Evidence |
|---|---|---|---|---|
| 0001 | Baobab IAM Architecture | all | Documented, not enforced in code | Authority model stated; no automated test proves layering (§8 invariants unverified) |
| 0002 | Keycloak as IdP | `baobab-iam` | Partially implemented | Realm/client JSON present, version pinned (26.7.3); **image digest is a placeholder** (§4.2); no Organizations config; no environment separation |
| 0003 | Identity Authority & Trust Boundaries | `baobab-cp` | Partially implemented | OIDC verification + `actor_type` enforcement exist; issuer not propagated into `Principal` |
| 0004 | Canonical Identity & External Identity Mapping | `baobab-cp` | **Not implemented** | No `CanonicalIdentity` type distinct from OIDC `sub`; no `ExternalIdentity(issuer, subject)` mapping at all |
| 0005 | Realm/Org/Tenant/LegalEntity Model | `baobab-iam`, `baobab-cp` | Partially implemented | Tenant IDs are opaque/server-minted (good); but `baobab-cp`'s resolver passes `TenantID` as `CanonicalEntityID` — a direct violation of this ADR's core invariant |
| 0006 | OIDC/OAuth/Token Profile | `baobab-iam` | **Not implemented** | No client has an `actor_type` protocol mapper; PKCE S256 is configured on public clients (good); no custom scopes (`context:resolve` etc.) defined anywhere |
| 0007 | Workload Identity | `baobab-iam`, `baobab-cp` | Partially implemented | Workload client JSON exists per-service (no shared credential — good); `baobab-cp` enforces `actor_type=workload` server-side, but tokens can never actually carry that claim today (see 0006) |
| 0008 | Platform Authorization Architecture | `baobab-cp` | Partially implemented | Fail-closed ambiguous-mapping handling exists; deny precedence is a flat AND, not a layered fail-first; `/v1/resolve` leaks internal denial reasons, contradicting the opaque-denial requirement |
| 0009 | Workforce SSO & Privileged Access | none | Not started | No workforce client separation from ordinary clients yet |
| 0010 | Zuribeans B2B | `baobab-trade` | Not started (IAM side) | Trade has B2B domain modules but no IAM-side buyer-representative flow |
| 0011 | Thamani B2C | `baobab-trade` | Not started (IAM side) | Same — commerce domain exists, IAM-side customer OIDC does not |
| 0012 | Supplier Identity | `shared`, `baobab-cp` | Partially implemented | `shared` has a real `supplier-domain` package with lifecycle/tests; no IAM-side representative identity flow |
| 0013 | MedusaJS Auth Integration | `baobab-trade` | **Not started** | No `AuthModuleProvider`; Medusa's default auth module is implicitly active |
| 0014 | iDempiere SSO | `baobab-erp` | **Not started** | Explicit stub; only native iDempiere login exists |
| 0015 | Credential Security/MFA/Passkeys | `baobab-iam` | Not started | Realm has `otpPolicyType`/`webAuthnPolicy*` defaults only; no MFA-required policy for privileged populations |
| 0016 | Identity Lifecycle/Revocation/Deprovisioning | `shared`, `baobab-cp` | Partially implemented | 3 of 12 required lifecycle events exist in `shared`, and those 3 are schema-broken (§4.3); no deprovisioning saga anywhere |
| 0017 | IAM Audit/Security Events/Observability | `shared` | Partially implemented | Event envelope contract exists; no reason-code registry; no `AuthenticationAssurance` contract |
| 0018 | IAM Availability/Backup/DR | `baobab-iam`, `infrastructure` | Not started | Single-instance Postgres/Keycloak in Compose only; `infrastructure` has no Keycloak provisioning at all |

---

## 4. Concrete, Verified Defects (not architectural gaps — actual bugs)

These were confirmed by direct inspection and are independent of any design discussion; they
block the "Gate IAM-2 complete" claim in `baobab-iam`'s own README.

### 4.1 `baobab-iam` CI cannot pass as committed
- `.github/workflows/ci.yml`'s `foundation` job calls
  `baobab-platform/shared/.github/workflows/foundation-gates.yml@<SHA>` — this workflow file
  **does not exist** in `baobab-platform/shared` (the real path is
  `foundation-repository-gates.yml`), and `<SHA>` is a literal placeholder, not a commit
  SHA. Every `uses:` step in the `build` job (`actions/checkout`, `docker/setup-buildx-action`,
  `docker/build-push-action`, `aquasecurity/trivy-action`) has the same `@<SHA>` placeholder.
  GitHub Actions will fail to resolve any of these refs.
- The repository **already has a correct, separately-pinned** `.github/workflows/foundation.yml`
  (verified against `baobab-platform/shared`'s real `v1.2.0` tag: peeled commit
  `38defb11aacd95a6f68b7db8026fe336417a2af6`). `ci.yml`'s `foundation` job is a broken,
  redundant duplicate of this and should be removed rather than fixed in place.

### 4.2 `upstream.lock.yaml` pins a fabricated digest
The file's own comment admits it: *"Yes, the digest above is an example; we will replace it
with the actual SHA after pulling."* `quay.io` is not reachable from this session's network
policy (confirmed: proxy returns `403` on `CONNECT quay.io:443`, logged as a policy denial,
not a transient failure). **This cannot be resolved without registry access this session
does not have** — see Risk Register R-1.

### 4.3 Every identity-event schema in `shared` is unresolvable
`identity-created.schema.json`, `identity-disabled.schema.json`, and
`membership-revoked.schema.json` all `$ref` a nonexistent file
(`../../common/event-envelope.schema.json`). No `contracts/common/` directory exists; the
real canonical envelope lives at `contracts/events/v1/envelope.schema.json`. Any consumer
attempting to validate against these schemas today gets a resolution error, not a validation
result.

### 4.4 `baobab-iam` documentation links are 100% broken
Every ADR link in both `README.md` and `docs/adr/README.md` points at filenames like
`./docs/adr/0001-baobab-iam-platform.md`; the actual files are named
`ADR-0001 — Baobab Identity and Access Management Architecture.md` (em dash, spaces, no
number-prefix slug). All 18 links are dead.

### 4.5 No `actor_type` claim is ever issued
ADR-0006's token profile and `baobab-cp`'s own enforcement (`internal/auth/oidc.go`,
`api/router.go`) both depend on an `actor_type` claim (`human` | `workload`). No client
config in `baobab-iam/config/clients/*.json` has a protocol mapper that injects this claim,
and the realm has no default client scope for it either. **As configured today, no token
issued by this realm could ever satisfy `baobab-cp`'s workload-endpoint authorization
check** — this is a load-bearing gap between the two repositories, not a cosmetic one.

### 4.6 `bootstrap.sh` double-processes workload clients
`*-workload.json` files are imported once by the workload-specific loop, then matched again
by the general `*.json` glob on the next loop — harmless today only because the second
`kcadm.sh create` attempt is swallowed by `|| echo ... skipping`, which also means a real
failure on the second pass would be silently masked.

### 4.7 Keycloak 26.7.3 bundles two vulnerable dependencies (discovered post-merge attempt)
Once `baobab-iam`'s CI could finally build a real image (after the `4.1`–`4.6` fixes above
plus a builder-stage non-root-`USER` fix found while watching PR #2's checks), the
`foundation / vulnerability-scan` job's Trivy scan surfaced real findings for the first
time — this job could never previously complete a scan because the image never built.
`netty-handler-4.1.136.Final.jar` (CVE-2026-75595, **CRITICAL**, fixed in `4.2.17.Final`/
`4.1.137.Final`) and `mssql-jdbc-13.2.1.jre11.jar` (CVE-2025-59250, **HIGH**) are bundled by
upstream Keycloak 26.7.3 itself — not something a `baobab-iam` config change can patch
without a Keycloak point-release bump, which ADR-0002 §39 requires going through a
deliberate upgrade process (release-notes review, candidate image, contract/OIDC tests,
staging rollout) that this session cannot safely execute without registry access. See R-8.

(A third, related finding — 3 HIGH CVEs in the `curl`/`libcurl` package this session's own
Dockerfile fix had added to satisfy `bootstrap.sh`'s health-check wait loop — was self-
inflicted by that fix and has been corrected by removing the curl dependency entirely
in favor of retrying `kcadm.sh`'s own login instead of curl-polling a health endpoint;
it does not appear in the risk register because it was fully resolved within this PR.)

### 4.9 Four workload clients silently collided with their resource-server counterparts
Once the integration suite could actually run end-to-end, `baobab-trade-workload.json`'s
service-account client intermittently failed to authenticate with its own correct secret —
not a flake. `config/clients/baobab-cms-workload.json`, `baobab-erp-workload.json`,
`baobab-pulse-workload.json`, and `baobab-trade-workload.json` all declared the **same**
`clientId` as their non-workload, `bearerOnly` counterpart (`baobab-cms.json`,
`baobab-erp.json`, `baobab-pulse.json`, `baobab-trade.json` respectively) — e.g. both
`baobab-trade.json` and `baobab-trade-workload.json` used `clientId: "baobab-trade"`.
`bootstrap.sh` creates both, so the realm ends up with two distinct client resources
answering to the same `clientId`; which one Keycloak's token endpoint resolves for a given
request is undefined, so a `client_credentials` grant against that `clientId` sometimes hit
the correct service-account client and sometimes hit the `bearerOnly` one (which has no
service account at all and can never authenticate), producing exactly the non-deterministic
`invalid_client_credentials` failures observed. This is a direct violation of ADR-0002 §15
("Client Isolation" — "Each service SHALL have distinct credentials... independently
revocable identities"). `thamani-backend-workload.json`/`thamani-web.json` and
`zuribeans-backend-workload.json`/`zuribeans-web.json` already used distinct clientIds
correctly (`thamani-backend` vs `thamani-web`, etc.) — only the four engines without a
paired browser client had this collision. Fixed by renaming each affected workload
client's `clientId` (and matching `serviceAccountsClientId`) to `<engine>-workload`,
matching its filename.

### 4.10 R-8 re-examined: one finding is a false positive, one is real and unfixable today
Gate IAM-3 revisited R-8 (§4.7) instead of leaving it as a single "needs a Keycloak
upgrade" line. `quay.io` is still network-blocked in this session (same as R-1), so the
image itself couldn't be pulled directly — but `keycloak/keycloak`'s and
`quarkusio/quarkus`'s own `pom.xml` files at the exact pinned tags (`26.7.3` and
`3.33.3.1` respectively) are public and were fetched directly, which is enough to
resolve both findings without registry access:

- **`mssql-jdbc` (CVE-2025-59250, HIGH) — false positive, now suppressed.**
  `keycloak/keycloak`'s `pom.xml` at the `26.7.3` tag pins
  `<mssql-jdbc.version>13.2.1.jre11</mssql-jdbc.version>` — not bare `13.2.1`. Microsoft's
  published fixed-version list for this CVE includes `13.2.1.jre11` explicitly. The false
  positive is a documented, maintainer-acknowledged Trivy/Grype defect class for this
  exact package: the shipped JAR's internal `pom.properties` records the version without
  its `.jreNN` suffix (`13.2.1`), and Maven's version-ordering rules judge
  `13.2.1 < 13.2.1.jre8` — so a scanner reading `pom.properties` flags an already-patched
  build as vulnerable (see `aquasecurity/trivy` discussion #9745 and `anchore/grype` issue
  #3042). Suppressed via a new root `.trivyignore` entry with this justification recorded
  inline, the same standard applied to the one confirmed `.gitleaksignore` false positive
  earlier in this programme (verify externally first, document why, never suppress a
  finding that isn't actually resolved).
- **`netty-handler` (CVE-2026-75595, CRITICAL) — real, and no fix exists to upgrade to
  yet.** `quarkusio/quarkus`'s `pom.xml` at the `3.33.3.1` tag (the Quarkus version
  Keycloak 26.7.3 embeds) pins `<netty.version>4.1.136.Final</netty.version>`, below the
  vendor's fixed version (`4.1.137.Final`, released 2026-08-06). Keycloak 26.7.3
  (released ~2026-08-31/09-03) is confirmed the latest available Keycloak release as of
  this session's date (2026-09-10) — there is no `26.7.4`, `26.8.0`, or `27.x` yet. The
  CVE's own disclosure appears to postdate Keycloak's 26.7.3 release cut, so upstream has
  had no opportunity to respond; this is not a case of Baobab lagging behind an available
  fix. **Not suppressed** — it is a real, currently-unpatched vulnerability in a bundled
  dependency, not a scanner artifact, so hiding it would be exactly the "masking a genuine
  issue" this programme has refused to do elsewhere (e.g. the curl CVEs in §4.7's
  parenthetical).

  One mitigating fact worth recording rather than acting on: CVE-2026-75595 is an SNI
  routing bypass that only matters to a Netty server doing per-SNI virtual-hosting with
  mutual TLS (`clientAuth=REQUIRE`) as its *sole* authentication gate. This Dockerfile's
  `CMD` runs Keycloak with `--http-enabled=true` and no `--https-*`/keystore flags — grep
  across the whole repo turns up no TLS/keystore/SNI configuration anywhere — consistent
  with ADR-0002 §32's "TLS boundary" + "proxy/forwarded-header trust" pairing, which reads
  as TLS terminating upstream (the platform's API gateway, not Keycloak's own embedded
  Netty/Vert.x listener). So this deployment does not appear to exercise the vulnerable
  code path today. That is context for triage priority, not a reason to close R-8: the
  library is still bundled, "not currently exercised" can silently stop being true if the
  deployment topology changes, and the fix is still owed the moment one ships upstream.

`.trivyignore` and this section are the only changes from this pass; the Dockerfile/image
pin (`quay.io/keycloak/keycloak:26.7.3`) is untouched, since it is already the latest
available release and re-pinning to itself would be a no-op.

---

## 5. Risk Register

| ID | Risk | Severity | Status |
|---|---|---|---|
| R-1 | `upstream.lock.yaml` Keycloak image digest cannot be verified from this session (quay.io network-blocked by policy) | High — production image pin is currently fabricated | **Needs human/CI action**: run `docker buildx imagetools inspect quay.io/keycloak/keycloak:26.7.3` from an environment with registry egress and commit the real digest |
| R-2 | No `actor_type` claim wiring anywhere in `baobab-iam` config (§4.5) | High — blocks all workload authentication end-to-end | Addressed in this session's IAM-2 hardening PR |
| R-3 | `baobab-cp` conflates `TenantID` with `CanonicalEntityID` in the resolver pipeline (violates ADR-0005 §2) | High — a core platform invariant is currently false in running code | **Fixed** in `baobab-platform/baobab-cp#63`, then the full Gate IAM-3 `CanonicalIdentity`/`ExternalIdentity` layer this conflation blocked was completed in `baobab-platform/baobab-cp#64`-`#71` — see [`gate-iam-3-canonical-identity-scope.md`](./gate-iam-3-canonical-identity-scope.md) |
| R-4 | `shared`'s identity-event schemas are unresolvable (§4.3); only 3 of 12 required lifecycle events exist | High — blocks Gate IAM-12 (lifecycle/deprovisioning) entirely until fixed | Out of this session's bounded scope; tracked for next IAM-1 session |
| R-5 | No reason-code registry, `AuthenticationAssurance`, or `Delegation` contract exists in `shared` | Medium — blocks step-up auth (ADR-0015) and confused-deputy defenses (§69 of programme spec) | Tracked for next IAM-1 session |
| R-6 | `infrastructure` repo provisions no Keycloak service at all | Medium — no path to a real deployed environment yet | Tracked for a future IAM-2/IAM-14 session |
| R-7 | Zero automated tests exist against a live Keycloak instance in `baobab-iam` (ADR-0002 §48 "Required Verification" is entirely unmet) | High — "Gate IAM-2 complete" cannot be substantiated | Partially addressed in this session's IAM-2 hardening PR (OIDC discovery/JWKS/client-credentials/actor_type assertions); full PKCE browser-flow and DR-restore tests remain out of scope |
| R-8 | Keycloak 26.7.3 bundles `netty-handler` 4.1.136.Final (CVE-2026-75595, **CRITICAL**, real — no fixed Keycloak release exists yet as of 2026-09-10) and previously also flagged `mssql-jdbc` 13.2.1.jre11 (CVE-2025-59250, HIGH — confirmed **false positive**, now suppressed via `.trivyignore`) (§4.10) | High — `foundation / vulnerability-scan` will stay red on `netty-handler` until upstream Quarkus/Keycloak bumps netty past 4.1.137.Final; not exploitable in this deployment's actual topology today (§4.10), which is context for priority, not a reason to close this row | **Needs human/CI action**: watch for the next Keycloak point release and bump the pin the moment one ships with netty ≥ 4.1.137.Final/4.2.17.Final; re-verify via `quay.io/keycloak/keycloak`'s manifest once registry egress is available (R-1's same constraint) |

---

## 6. Recommended Sequencing

1. **This session (bounded):** Gate IAM-2 hardening in `baobab-iam` — fix CI (§4.1), fix
   docs links (§4.4), wire `actor_type` claims (§4.5), fix `bootstrap.sh` (§4.6), add a real
   integration test job, and record R-1 as a blocked follow-up rather than fabricating a
   digest.
2. **Next:** Gate IAM-1 hardening in `shared` — fix the broken `$ref`s (§4.3), add the
   missing lifecycle events, add a reason-code registry, add real schema-validation tests.
3. **Done:** Gate IAM-3 hardening in `baobab-cp` — a real `CanonicalIdentity`/
   `ExternalIdentity(issuer, subject)` layer is implemented (`baobab-platform/baobab-cp#64`-`#71`,
   see [`gate-iam-3-canonical-identity-scope.md`](./gate-iam-3-canonical-identity-scope.md)),
   and the Tenant/CanonicalEntity conflation (R-3) is fixed. `/v1/resolve`'s opaque-denial
   -reasons switch was not part of this pass — it remains a separate, unrelated gap (see
   `baobab-platform/baobab-cp#63`'s "Not in scope" note).
4. **In progress:** Gate IAM-4 (workload identity, ADR-0007) — scoped and phase 1 underway, see
   [`gate-iam-4-workload-identity-scope.md`](./gate-iam-4-workload-identity-scope.md). Gates
   IAM-5 through IAM-16 remain next, as originally sequenced, now that the identity spine
   underneath them is actually sound.

This sequencing deliberately does not jump ahead to Gates IAM-6/7/9/10 (Zuribeans, Thamani,
Medusa, iDempiere) even though those repos are otherwise mature, because none of them have
anything correct to integrate against yet — building B2B/B2C OIDC flows against a realm that
cannot even issue a correct `actor_type` claim would mean redoing that work twice.
