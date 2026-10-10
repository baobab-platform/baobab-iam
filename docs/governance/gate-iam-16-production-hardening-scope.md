# Gate IAM-16 — Production Hardening

**Status:** Phase 1 complete. This is the final gate in the program (§218-219). Its own text
says "Validate:", not "Implement:" — most of its twelve-item checklist turned out to already
be satisfied by controls built across earlier gates and this repo's existing CI, verified here
rather than assumed. Two real, previously-missing items were closed (SBOM generation; a
security incident-response runbook). One item this document's first draft almost overclaimed
(cross-tenant/cross-buyer isolation) is instead reported accurately as partially proven,
having learned from Gate IAM-15's review the cost of an inaccurate governance document.
**Date:** 2026-09-12
**Governing spec:** `docs/adr/Consolidated-Technical-Specification.md` §219 ("Gate IAM-16 —
Production Hardening")
**Repositories:** `baobab-platform/baobab-iam`
**Depends on:** Gates IAM-2, IAM-4, IAM-6, IAM-11, IAM-12, IAM-13, IAM-14 (this gate cites, not
duplicates, controls each of those already built)

---

## 1. The checklist, item by item

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Penetration tests | **Not done** | An external/manual exercise; nothing to "implement" in this repo. See §3. |
| 2 | Cross-tenant isolation | **Partial** | See §2 — workload isolation is proven; buyer/Organization cross-isolation is explicitly deferred by Gate IAM-6's own scope doc, not this gate's to newly resolve. |
| 3 | Credential attack controls | **Done** | `bruteForceProtected: true` + `maxFailureWaitSeconds`/`failureFactor`/etc. (`config/realm/baobab-realm.json`, Gate IAM-2); password policy + mandatory privileged MFA (Gate IAM-11). |
| 4 | Rate limiting | **Partial, rest deferred** | See §4 — Keycloak's own brute-force protection is a credential-specific rate limit; general HTTP rate limiting is an infrastructure/edge-layer concern, not this repo's. |
| 5 | Secret scanning | **Done** | `.github/workflows/security-secrets-scan.yml` (weekly + every push/PR) delegates to `baobab-platform/shared`'s reusable scanner; `foundation.yml`'s Trivy run also scans in `secret` mode. |
| 6 | Container hardening | **Done** | `Dockerfile`: built `FROM quay.io/keycloak/keycloak:26.7.3` (upstream-hardened, non-root `USER 1000` already set), a throwaway UBI9 stage only for `jq` (no package manager shipped in the final image), `curl` deliberately excluded after a CVE scan flagged it, a real `HEALTHCHECK`. |
| 7 | SBOM | **Fixed this gate** | See §3 — no SBOM existed anywhere in this repo's or the org's shared CI before this PR. |
| 8 | Dependency scanning | **Done** | `foundation.yml`'s `dependency_review_enabled: true` + Trivy `vuln` scan (both `ci.yml`'s image scan and `baobab-platform/shared`'s filesystem scan). |
| 9 | DR exercise | **Not done, already tracked** | Gate IAM-14's DR runbook and Gate IAM-15's scope doc both already document that no real backup/restore/reconciliation exercise has been run. Not duplicated as a new open item here — see §5. |
| 10 | Load testing | **Not done** | Needs a live, production-like environment this session doesn't have. See §5. |
| 11 | Login storm testing | **Analyzed, not executed** | See §4 — a real, reasoned answer about whether a login storm risks mass lockout, not a deferral without analysis. |
| 12 | Incident runbooks | **Fixed this gate** | See §3 — a DR runbook existed (Gate IAM-14); an incident-response runbook for a *security* incident (compromised credential/client/mass event) did not. |

## 2. Discovery — cross-tenant isolation is real but only partially proven

"Tenant" is explicitly `baobab-cp`'s concept, not `baobab-iam`'s (every prior gate's ownership
table agrees on this). What `baobab-iam` itself can prove is narrower:

- **Workload isolation** — `tests/integration/run.sh` §10 proves each workload's token
  carries its own `azp` and that two workload clients resolve to distinct subjects. This is
  real and already tested.
- **Buyer/Organization isolation (Gate IAM-6, ADR-0010)** — `README.md` and
  [Gate IAM-6 scope](./gate-iam-6-zuribeans-b2b-scope.md) are explicit that this remains
  **phase 2+**, not yet implemented: "cross-buyer isolation against real tokens" is listed as
  future work, not something already proven. Restating it as done here would repeat exactly
  the kind of overclaim Gate IAM-15's review caught and corrected — deliberately not done.

So "cross-tenant isolation" is **partially** satisfied: the pieces `baobab-iam` owns and has
tested (workload identity) are solid; the piece most people mean by "tenant isolation" in a
multi-buyer B2B context (Gate IAM-6's cross-buyer case) is still open, tracked where it already
was, not newly discovered or newly resolved by this gate.

## 3. Phase 1 (this PR) — two real gaps closed

1. **SBOM (`.github/workflows/ci.yml`)** — added a second Trivy step in CycloneDX output mode
   against the same image the job already builds and scans, uploaded as a build artifact.
   Checked directly: neither this repo's `ci.yml` nor `baobab-platform/shared`'s reusable
   `foundation-repository-gates.yml` (`vulnerability-scan` job) generated an SBOM anywhere —
   both only ran Trivy in vulnerability/secret/misconfig-scan mode. Reused the same
   already-vetted `trivy-action` pin (no new third-party action to get approved) and an
   `actions/upload-artifact` pin already in use and presumably vetted elsewhere in this org
   (`baobab-platform/baobab-trade`'s `release-readiness.yml`), rather than introducing an unverified
   SHA pin of my own.
2. **`docs/operations/security-incident-runbook.md`** (new) — a security-incident (not
   disaster-recovery) playbook for three shapes: a compromised identity credential, a
   compromised workload client secret, and a suspected mass-compromise event. Every action in
   it reuses Admin API calls Gates IAM-11/12/13 already built and proved end-to-end against a
   real Keycloak instance (session revocation, identity disablement, credential deletion,
   secret rotation, admin-event audit query) — this document is the first place they're
   assembled into an actual incident-response procedure rather than left as individually
   tested capabilities with no playbook connecting them.

## 4. Discovery — rate limiting and login storms, analyzed rather than hand-waved

**Rate limiting.** Keycloak's `bruteForceProtected` (already on, Gate IAM-2) throttles
*failed* authentication attempts per username — a real, credential-specific rate limit, and
the one `baobab-iam` itself can own. General HTTP-level rate limiting (requests/second per IP,
API abuse/scraping protection) is not configured anywhere in this repo and structurally
belongs at the edge/reverse-proxy/API-gateway layer per ADR-0018's own pattern of assigning
infrastructure-layer concerns to `baobab-platform/infrastructure` — not something a Keycloak
realm-configuration repository can add.

**Login storm testing.** Rather than defer this without analysis, the actual risk was
reasoned through against this realm's real configuration: Keycloak's brute-force counter
increments on *failed* login attempts, keyed per username — a storm of simultaneous
*successful* logins (e.g., a Monday-morning peak, or the immediate aftermath of an incident
resolution) does not increment any user's failure count and so does not risk mass lockout by
this mechanism. The real risk a login storm poses is capacity (can Keycloak/PostgreSQL handle
the concurrent request volume), which is a load-testing question, not a security-control
question — see §5.

## 5. What remains open (deferred, not started)

1. **Penetration tests** — an external/manual security exercise; nothing to build in code.
   Flagged as a prerequisite before a real production go-live, not something this gate can
   perform.
2. **Cross-buyer isolation testing (Gate IAM-6 phase 2+)** — unchanged by this gate; still
   `baobab-cp`'s canonical-entity wiring work, tracked in that gate's own scope doc.
3. **General HTTP rate limiting** — `baobab-platform/infrastructure`'s territory (edge/API-gateway
   layer); not something to add to a Keycloak realm-configuration repo.
4. **A real DR exercise** — already tracked by Gates IAM-14/IAM-15; not duplicated here.
5. **Load testing / login-storm capacity testing, executed for real** — needs a live,
   production-like environment and load-testing tooling (e.g. k6, Gatling) this session has
   neither of. Writing an unexecuted load-test script now, with no environment to validate it
   against, risks shipping the same kind of unverified artifact Gate IAM-15's review just
   caught in this gate's own sibling document — deliberately not done; left for whoever has
   an environment to build and immediately run it against.
6. **A scripted bulk-revocation tool** for the mass-compromise incident case
   (`security-incident-runbook.md` §5.1) — no such tooling exists yet; building one against a
   real incident's actual shape, rather than a guessed one, is deferred.
7. **A tested, timed incident-response drill** exercising `security-incident-runbook.md`
   end-to-end against a real (non-production) realm — the runbook is a draft until it's been
   run once, per the same "tested objective, not just documented" principle ADR-0018 §118
   already applies to RPO/RTO.

## 6. Program status

This is the last of the sixteen numbered gates (IAM-0 through IAM-16). Every gate's own
"what remains open" section still stands — this gate closed two concrete production-hardening
gaps (SBOM, incident runbook) and gave every other checklist item an honest status rather than
a blanket "done," but it does not itself close out the many deferred items earlier gates
already identified (Gate IAM-2's environment separation, Gate IAM-5's `baobab-cms` wiring,
Gate IAM-6/7/8/9's B2B/B2C/supplier work, Gate IAM-10/11's remaining phases, Gate IAM-12's
event-producer fork, Gate IAM-13's retention policy, Gate IAM-14's missing theme and
post-backup journal, Gate IAM-15's unproven DR-restore row). Those remain exactly what they
were: real, tracked, and not this gate's to resolve.
