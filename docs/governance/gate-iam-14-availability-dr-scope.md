# Gate IAM-14 — IAM Availability, Backup, Recovery and Disaster Resilience

**Status:** Phase 1 complete (a real DR runbook exists per §90; the version half of §221's
"exact Keycloak version/image digest is pinned" checklist item is now verified against a
live instance instead of only declared; a real, previously-uncaught PKCE coverage gap is
fixed; R-1 re-confirmed still blocked). This ADR has 225 sections — the largest yet — and
is overwhelmingly infrastructure territory; `baobab-iam`'s own slice is narrow — see §1.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0018 — IAM Availability, Backup, Recovery and Disaster Resilience`
**Repositories:** `baobab-platform/baobab-iam` (Keycloak application/signing configuration, DR
runbook — this gate's scope), `baobab-platform/infrastructure` (attached to this session but not
investigated this gate — see §5)
**Depends on:** Gate IAM-12 (admin-event audit — this gate's revocation-reconciliation
discussion builds on it), Gate IAM-13 (audit redaction)

---

## 1. Why this gate's IAM-side scope is narrow

ADR-0018's own ownership table (§215) assigns almost everything to `baobab-platform/infrastructure`:
IAM runtime, PostgreSQL HA, database backup/PITR, secret management, TLS/PKI. `baobab-iam`'s
own rows are "Keycloak application configuration," "Keycloak signing configuration"
(jointly with Infrastructure), and "DR runbooks" (jointly with Infrastructure). This
repository is a declarative Keycloak realm-configuration repo with no database, backup, or
infrastructure tooling of its own — it cannot implement PITR, HA topology, or secret
recovery unilaterally, the same shape of constraint as Gates IAM-12 and IAM-13.

## 2. Discovery — R-1 (image digest) re-confirmed still blocked

`upstream.lock.yaml`'s Keycloak image digest has been an unresolved placeholder since Gate
IAM-0 discovery (tracked as R-1). Re-verified directly rather than assumed still-blocked:

```
$ docker buildx imagetools inspect quay.io/keycloak/keycloak:26.7.3
ERROR: failed to do request: Head "https://quay.io/v2/keycloak/keycloak/manifests/26.7.3": Forbidden
```

Same failure mode as originally documented — this development environment's network policy
still denies `quay.io` egress. No change in status; still needs a human or a CI job with
registry egress to resolve. Not re-litigated further this gate.

## 3. Discovery — the *version* half of the same checklist item was never actually checked

ADR-0018 §221 requires "exact Keycloak version/image digest is pinned." The digest half is
R-1 (blocked). But the **version** half — does the realm actually run the version
`upstream.lock.yaml` claims? — had never been verified either; `upstream.lock.yaml`'s
`keycloak.version` field and `Dockerfile`'s `FROM quay.io/keycloak/keycloak:26.7.3` are two
independent places recording the same fact, with nothing checking they still agree. A
`FROM` bump without a corresponding `upstream.lock.yaml` edit (or vice versa) would go
unnoticed indefinitely. Fixed: `tests/integration/run.sh` §18 now queries the live
instance's `/admin/serverinfo` (`systemInfo.version`) and compares it against
`upstream.lock.yaml`'s pinned version.

## 4. Discovery — a real PKCE coverage gap in the existing test suite

Auditing every `config/clients/*.json` file directly (not assuming the existing test's
hardcoded list was complete) found three `publicClient: true` clients requiring PKCE S256:
`zuribeans-web`, `thamani-web`, and **`baobab-control-plane-admin`**. `tests/integration/run.sh`
§7's PKCE check only ever looped over the first two — `baobab-control-plane-admin` (added in
Gate IAM-5) was never covered by this specific invariant, even though its own config is
correct today. This is exactly the kind of drift ADR-0018 §221's "no authentication bypass
exists" checklist item exists to catch, and a hardcoded client list can't catch a future
public client the suite's author forgets to add.

Fixed: §7 now also runs an exhaustive pass — but over `config/clients/*.json` (every client
*Baobab* declares), not over the live realm's full client list. The first version of this
fix queried the realm directly and broke CI: Keycloak provisions its own built-in system
clients (`account`, `admin-cli`, `broker`, `realm-management`, `security-admin-console`)
into every realm, and two of them (`account`, `admin-cli`) are `publicClient: true` with no
PKCE requirement. `admin-cli` in particular has `standardFlowEnabled: false` — it is used
throughout this very suite for password-grant logins — so PKCE (an authorization-code-flow
concept) does not even apply to it. These clients aren't Baobab's to configure and asserting
a PKCE requirement on them would be asserting a requirement on infrastructure this repo
doesn't own. Scoping the exhaustive pass to `config/clients/*.json`'s own declared clients
fixed this while still closing the original `baobab-control-plane-admin` gap.

## 5. Discovery — a real, adjacent, out-of-scope defect: `loginTheme`/`accountTheme: "baobab"` doesn't exist

While scoping ADR-0018 §165's "authorization-code flow works" restore-validation
requirement, an attempt to write a real browser-driven authorization-code + PKCE test (GET
the authorization endpoint, parse the rendered login form, POST credentials, exchange the
code) surfaced that `config/realm/baobab-realm.json` sets `"loginTheme": "baobab"` and
`"accountTheme": "baobab"`, but `themes/README.md` states plainly: "no custom theme has
been built yet" — `themes/` contains only that README, and `Dockerfile`'s
`COPY themes/ /opt/keycloak/themes/` therefore copies nothing named `baobab`. No existing
test in this suite has ever caught this because every existing check talks to Keycloak's
JSON APIs (admin API, token endpoint) — nothing before this gate ever asked Keycloak to
render an actual HTML page for this realm. Whether Keycloak silently falls back to a
built-in theme or errors when a named theme is missing was not verified against a live
instance (none is available in this session), so the practical impact (broken login pages
vs. silent fallback) is unconfirmed.

This is real and worth fixing, but it is a presentation/theming concern under ADR-0002 §28
(themes), not an availability/backup/DR concern — fixing it here would be scope creep past
what ADR-0018 governs, and building an actual theme is a substantially larger effort than
this gate's bounded phase. **Deliberately not fixed in this PR.** Flagged here as a new,
concrete, previously-unknown risk for whichever gate or follow-up next touches themes or
attempts a real browser-flow test (see also `docs/governance/gate-iam-0-discovery.md`'s risk
register — this is a candidate for a new risk row, not added there directly since this
gate's job is IAM-14, not a rewrite of Gate IAM-0's discovery doc).

## 6. Phase 1 (this PR)

1. **`docs/operations/disaster-recovery-runbook.md`** (new) — the ADR-0018 §91 seventeen-step
   recovery sequence mapped against what `baobab-iam` actually owns (steps 6, 8, 9, 14) versus
   what is `baobab-platform/infrastructure`'s or another repo's (everything else), per §215's
   ownership table. Documents the manual, unautomated nature of §94-100's post-backup
   revocation reconciliation as a known, explicit gap rather than pretending it's handled.
2. **`tests/integration/run.sh` §7** (modified) — the PKCE-on-public-clients check now also
   runs exhaustively over every client in the realm, closing the `baobab-control-plane-admin`
   coverage gap (§4 above).
3. **`tests/integration/run.sh` §18** (new) — Keycloak version-pin consistency check (§3
   above) against `upstream.lock.yaml`; an explicit, commented mapping of ADR-0018 §165's ten
   required "Restore Validation Suite" checks to where each one is actually proven in this
   suite today (or which repository/limitation owns the gap).

## 6a. Review findings (Codex) — verified and fixed

Automated PR review flagged three real issues, each verified directly against this
repo's own scripts before fixing (not taken on faith):

1. **`scripts/bootstrap.sh` does not reconcile drift on existing objects** — confirmed
   by reading the script: if the realm already exists, realm-level import is skipped
   entirely; scopes/clients are only ever `kcadm create`d, with a create-against-existing
   failure silently swallowed rather than followed by an update. The runbook originally
   claimed bootstrap "reconciles to the checked-in JSON" — false. Fixed the runbook's
   wording to state the real behavior (fills in what's missing; does not correct what's
   already wrong) and added this as an open item (§7 below) rather than papering over it.
2. **Runbook's own recovery steps were internally inconsistent about
   `BOOTSTRAP_WORKLOAD_CLIENT_SECRET`** — step 2 (`make bootstrap`) omitted it while step 3
   (`tests/integration/run.sh`) assumed a client secret was already known, which only
   works if both steps use the same value (workload secrets are seeded at
   client-*creation* time only). Fixed the runbook to make both steps use the same value
   explicitly, and to state plainly that this variable is a local/CI-only mechanism
   (per `scripts/bootstrap.sh`'s own comment) — a real production restore sources workload
   secrets from Infrastructure's secret-management boundary instead.
3. **The exhaustive PKCE check queried the live realm instead of this repo's own declared
   clients** — already covered in §4 above (this was the CI-failing version of the fix,
   caught by CI itself before the bot's matching review comment landed).

## 7. What remains open (deferred, not started)

1. **`scripts/bootstrap.sh` is create-only, not a real reconciler** (§6a.1) — a restore
   that leaves stale-but-present realm/client/scope configuration (as opposed to
   missing configuration) is not corrected by `make bootstrap` today. Building real
   `kcadm update`-based reconciliation (or switching to Keycloak's declarative
   realm-import-on-boot mechanism, if it supports true upsert semantics) is a
   meaningfully sized change to this repo's core provisioning tool, not something to
   fold into this gate's bounded phase 1 — flagged here for a future gate or a
   dedicated provisioning-hardening PR.
2. **R-1** (image digest) — still blocked on `quay.io` registry egress; unchanged this gate.
3. **`loginTheme`/`accountTheme: "baobab"` doesn't exist** (§5 above) — a real, newly
   discovered defect; not fixed here, flagged for a future theming/ADR-0002 pass.
4. **A real authorization-code + PKCE round trip test** — blocked by #3 above until a real
   theme exists (or the realm is pointed at a built-in theme), and by the lack of
   headless-browser tooling in this suite's CI (the same limitation Gate IAM-11's scope doc
   already documents for the OTP-challenged case).
5. **Post-backup security journal** (§96-100) — no mechanism exists to record
   revocations/disablements that happen after the most recent backup so they can be
   correctly re-applied on restore. This is the single largest remaining IAM-relevant gap in
   this ADR; building it well requires deciding where it lives (a durable log this repo
   owns, vs. `baobab-cp` owning it as part of its own lifecycle event consumption per Gate
   IAM-12 §5's still-open architectural fork) — not guessed at here.
6. **RPO/RTO targets, DR exercises, HA topology, backup/PITR, secret recovery, TLS/PKI,
   multi-AZ failure domains** (§18-120, §215-220) — entirely `baobab-platform/infrastructure`'s
   territory; not investigated this session (that repository is attached but out of scope
   for a Keycloak realm-configuration gate).
7. **Digital Estate / ERP / Trade / CP post-restore validation** (§166-171) — each
   downstream repository's own responsibility to test against a restored IAM instance; not
   `baobab-iam` code.
