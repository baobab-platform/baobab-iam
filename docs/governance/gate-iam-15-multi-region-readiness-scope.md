# Gate IAM-15 — Multi-Region Readiness

**Status:** Phase 1 complete — a verification gate, not a build-out gate. No code or
configuration changes were needed in `baobab-iam` itself; this gate's job (per its own
governing text) is to confirm "architectural readiness." Most of the checklist is genuinely
satisfied, owned by `baobab-cp`'s already-built region/market/`CapabilityBinding` model — but
review caught this document initially overclaiming one item (§164's "revoked account survives
DR restore" row is real but NOT yet proven end-to-end; see §5, §6a, §7.1) and citing the wrong
function for residency enforcement (fixed in §2, §6a). Corrected before merge, not glossed
over.
**Date:** 2026-09-12
**Governing spec:** `docs/adr/Consolidated-Technical-Specification.md` §218 ("Gate IAM-15 —
Multi-Region Readiness"), cross-referenced against §23-27 (Multi-Region Model), §122-125
(Multi-Region IAM Strategy), §146-148 (Region Context/Sovereignty), §164 (Multi-Region Test
Matrix), §178-180 (Multi-Region Infrastructure/Regional Engine Architecture)
**Repositories:** `baobab-platform/baobab-iam` (this gate's nominal owner), `baobab-platform/baobab-cp`
(read-only discovery this gate — where the actual region model lives)
**Depends on:** Gate IAM-3 (canonical identity spine), Gate IAM-4 (workload identity), Gate
IAM-12 (kill switch), Gate IAM-14 (DR runbook)

---

## 1. What this gate actually asks for

§218's own text is explicit that this is not a full multi-region build-out:

> Do not necessarily enable multi-region active-active IAM at this Gate. The goal is
> architectural readiness.

Its checklist — region model, residency constraints, regional `EngineInstance` mapping,
regional `CapabilityBinding`, approved DR routing, cross-region security tests — reads like
an implementation list, but §24 ("Region Data Model") itself says the region registry
"SHOULD exist in the Control Plane **or** infrastructure control model," and the separation
the spec insists on (§23: "Market / Region / Tenant / LegalEntity SHALL remain separate," none
of them a `baobab-iam` concept) already signals this checklist targets `baobab-cp`, not a
Keycloak realm-configuration repository.

## 2. Discovery — `baobab-cp` already implements this checklist

Rather than assume the checklist item was `baobab-iam`'s to build, `baobab-platform/baobab-cp` was
read directly. It already has, real and substantial:

- `internal/capability/domain/capability.go`, `grant.go`, `scope.go` — the `CapabilityBinding`/
  `EngineInstance` domain model §25/§180 describe.
- `internal/resolver/relocation.go` — `PlanEngineRelocation()`, an atomic capability-binding
  cutover between two `EngineInstance`s, explicitly documented as "an infrastructure move
  must never rewrite business identity" — exactly §180's "IAM architecture and domain-engine
  regionalization are related but not identical" principle, already enforced in code.
- `internal/resolver/topology.go` — `TopologyResolverImpl.Resolve()` denies resolution
  ("engine instance residency mismatch") when `instance.ResidencyRegion` doesn't match the
  trusted context's `DeploymentRegion`, and separately denies on region/environment/isolation
  mismatches too. This is real residency *enforcement* (a DENY on mismatch), not just a
  presence check — it is the mechanism behind §164's "failover violates residency policy →
  DENY" row. (`internal/resolver/policy.go`'s `PolicyChecker.Check()` only asserts that
  `CountryCode`/`MarketID` is non-empty before resolution proceeds; it does not itself compare
  against a residency policy, so it is not evidence of enforcement on its own — corrected here
  after review, see §6a below.)
- `internal/repository/postgres_market_test.go`, `internal/resolver/topology_test.go` — Market
  and topology already have real, tested persistence/resolution logic.

This is not a gap `baobab-iam` needs to fill. It's already built, on the repository the spec
itself names as the right owner.

## 3. Discovery — the IAM/CP boundary doesn't need a region claim

Checked whether `baobab-cp`'s region/market resolution depends on `baobab-iam` emitting a
region or market claim in its tokens (it would be a real gap if so — nothing in this repo's
token profile carries one). Reading `internal/resolver/context.go`'s `ResolutionEvidence`
struct and `ContextResolverImpl.Resolve()`: `TenantID`, `MarketID`, `CountryCode`, etc. are
supplied by CP's own callers from CP's own domain data, not extracted from an IAM-issued JWT.
`baobab-iam`'s actual contribution to this pipeline is exactly what Gates IAM-3/IAM-4 already
built and Gate IAM-10/13's tests already exercise: a verifiable `issuer + subject` (and, for
workloads, `actor_type`/`aud`) that `baobab-cp` uses to resolve `CanonicalIdentity`, from which
*CP itself* — not IAM — derives tenant, market, and region. No new claim, scope, or mapper is
needed in `baobab-iam` for regional resolution to work.

## 4. Discovery — the current single-realm architecture is Phase A, not an oversight

§124 ("Multi-Region Evolution") lays out four phases: (A) single region + multi-AZ, (B)
primary + warm DR region, (C) supported multi-site Keycloak, (D) regional identity strategy
"only if residency/scale justify it." §123 explicitly recommends Phase A "before introducing
active-active cross-region IAM." `baobab-iam` today is a single global `baobab` realm behind
one Keycloak deployment — this is Phase A, and per §123/§124 that is the *correct* current
state, not a gap this gate needs to close. ADR-0018 §216's own target-production-architecture
diagram (read during Gate IAM-14) already shows this exact shape: two failure domains, each
running Keycloak instances against one shared HA PostgreSQL — multi-AZ HA within a single
region, consistent with Phase A.

## 5. Discovery — §164's IAM-relevant test-matrix row is real but NOT yet proven end-to-end

§164's "Multi-Region Test Matrix" has one row that is `baobab-iam`'s to prove: "Revoked
account in primary then DR restore → Remains revoked." This is word-for-word the same
invariant ADR-0018 §94-95 states ("a backup restore SHALL NOT return previously revoked
identity authority to service").

**Corrected after review (see §6a below): this is not yet proven, and this document
originally overstated it.** Gate IAM-12's kill-switch test (`tests/integration/run.sh` §16)
proves that a *currently* disabled identity cannot authenticate — it never exercises an
actual backup, restore, or post-restore reconciliation step, so it says nothing about what
happens if a backup taken *before* a revocation is restored *after* it. Gate IAM-14's own DR
runbook is explicit that no automated mechanism exists to prevent that resurrection (§96-100's
"post-backup security journal" is unbuilt) and that reconciling it today is a manual,
unverified step. This test-matrix row therefore stays open — tracked in §7 below, not claimed
as done — until a real backup/restore/reconciliation exercise (Gate IAM-14's own §7.4 item)
actually proves it.

The other rows ("ZA user routed to ZA engine," "duplicate identity in two regions reconciles
to one CanonicalIdentity," "failover violates residency policy → DENY") are `baobab-cp`'s
routing and identity-uniqueness invariants, not `baobab-iam`'s — §2 above confirms the
mechanism (`topology.go`'s residency-mismatch DENY) is real for engine routing; whether it
extends to identity data itself is `baobab-cp`'s own scope to verify, not restated here.

## 6. Phase 1 (this PR)

No code or realm-configuration changes. This scope document and the accompanying `README.md`
update are the deliverable: they record that Gate IAM-15's checklist has been verified against
real code in the two repositories that actually implement it, rather than left unstated or
assumed satisfied. Manufacturing a `baobab-iam`-side change for its own sake — e.g., adding a
redundant region claim nothing consumes, or an integration-test section that only re-asserts
what §16/§18 already prove — was deliberately avoided.

## 6a. Review findings (Codex) — verified and fixed

Automated PR review flagged two real accuracy problems in this document's first draft, both
verified directly against `baobab-cp`'s and this repo's own code before fixing (not taken on
faith, and not dismissed as pedantic either — a governance document that overclaims is worse
than one that says nothing):

1. **§2's residency-enforcement citation was the wrong function.** The original draft cited
   `internal/resolver/policy.go`'s `PolicyChecker.Check()` as evidence residency is enforced —
   but that function only checks that `CountryCode`/`MarketID` is *non-empty*, never that the
   resolved binding is actually *permitted* for that context. Re-reading further into
   `baobab-cp` found the function that actually does this:
   `internal/resolver/topology.go`'s `TopologyResolverImpl.Resolve()`, which denies resolution
   with `"engine instance residency mismatch"` when `instance.ResidencyRegion` doesn't match
   the trusted context's `DeploymentRegion`. Fixed §2 to cite the real mechanism.
2. **§5 claimed the "revoked account survives DR restore" test-matrix row was "already
   proven."** It wasn't — Gate IAM-12's test never exercises an actual backup/restore cycle,
   and Gate IAM-14's own DR runbook already documents that no automated post-backup
   reconciliation exists. Fixed §5 to state this accurately and moved it into §7 as an open
   item rather than a claimed result.

## 7. What remains open (deferred, not started)

1. **Prove §164's "revoked account survives DR restore" row for real** (§5 above) — needs an
   actual backup/restore/reconciliation exercise, not just the current-state DENY Gate IAM-12
   already proves. This is the same work as Gate IAM-14's §7.4 "post-backup security journal"
   item; not duplicated as a separate task here.
2. **Phase B (warm DR region), Phase C (supported multi-site Keycloak), Phase D (regional
   identity strategy)** (§124) — explicitly `baobab-platform/infrastructure`'s territory, and per §123
   deliberately not attempted before Phase A is solid. Nothing to design here until
   Infrastructure proposes standing up a second Keycloak-capable region.
3. **§148's Data Sovereignty Rule, exercised for real** — untestable today because there is
   only one IAM region; the moment a genuine second region/DR site exists, this gate should be
   revisited to add a real cross-region test proving `baobab-iam` never processes identity data
   outside an approved jurisdiction. Note `baobab-cp`'s `topology.go` already enforces an
   analogous residency invariant for engine routing — whether an equivalent needs to exist for
   IAM's own identity data specifically is unresolved, since IAM has no second region to
   enforce it against yet.
4. **`baobab-cp`'s own remaining work** on `CapabilityBinding`/`EngineInstance`/relocation is
   that repository's own gate program, not tracked here.
