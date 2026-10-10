# Gate IAM-13 — IAM Audit, Security Events and Observability

**Status:** Phase 1 complete (redaction of secrets in admin audit proven end-to-end against a real Keycloak instance; credential revocation confirmed audited). This ADR has 205 sections and, like Gates IAM-12/IAM-16, is overwhelmingly cross-repo — see §1.
**Date:** 2026-09-12
**Governing ADR:** `ADR-0017 — IAM Audit, Security Events and Observability`
**Repositories:** `baobab-platform/baobab-iam` (authentication/credential/session audit, this gate's scope)
**Depends on:** Gate IAM-12 (enabled `adminEventsEnabled`, which this gate verifies actually redacts secrets rather than just existing)

---

## 1. Why this gate's IAM-side scope is narrow

ADR-0017's own ownership table (§194) assigns most of its scope elsewhere: CP decision audit (`baobab-cp`), buyer/customer domain audit (`baobab-trade`), ERP audit (`baobab-erp`), CMS/Pulse audit (their own repos), canonical security-event contracts (`baobab-platform/shared` — already substantially built per Gate IAM-12's discovery), and telemetry transport/SIEM/security monitoring (`baobab-platform/infrastructure`, not attached to this session). `baobab-iam` owns exactly two rows: **authentication audit** and **credential/session audit**.

## 2. Discovery — what was already correct, verified rather than assumed

Before writing anything, two things this gate might otherwise have "fixed" were checked directly and found already sound:

1. **Event type coverage (ADR-0017 §175's required IAM tests).** The realm's `enabledEventTypes` list (58 entries) already includes `LOGIN`/`LOGIN_ERROR`, `UPDATE_PASSWORD`, `UPDATE_TOTP`/`REMOVE_TOTP`, `RESET_PASSWORD`, `LOGOUT`, and more — essentially the full built-in Keycloak event-type enum. Nothing to add here.
2. **Redaction (ADR-0017 §94-98, "Redaction Targets" including `password`).** Gate IAM-12 enabled `adminEventsDetailsEnabled: true`, which stores each admin action's request body verbatim as the event's `representation` field — the one place in this realm's configuration a raw password plausibly could have leaked. Read directly against `keycloak/keycloak`'s own source: `AdminEventBuilder.representation()` calls `stripSecretsFromRepresentation()`, which delegates to `StripSecretsUtils.stripSecrets()` before the representation is ever persisted. Keycloak already does this correctly upstream — this gate does not need to (and per this repo's own `providers/README.md` policy, should not) build redaction itself.

Trusting an upstream claim isn't the same as proving it holds in *this* realm's real configuration, so phase 1 turns finding #2 into an executable test instead of taking it on faith.

## 3. Phase 1 (this PR)

`tests/integration/run.sh` §17, against a real Keycloak instance:

1. **Redaction proof on creation** — creates a throwaway user whose password is a distinctive, greppable marker string, then fetches the resulting `CREATE` admin-event and confirms the marker does not appear anywhere in its JSON.
2. **Redaction proof on reset** — resets that user's password to a second distinctive marker via `PUT .../reset-password`, then confirms the resulting admin-event doesn't leak *that* value either (a different code path through Keycloak's admin API than user creation, so worth checking independently rather than assuming one proof covers both).
3. **Credential revocation is audited** (ADR-0017 §175) — deletes the user's password credential via the Admin API and confirms an admin-event actually recorded it, closing one of §175's specific required-test items that Gate IAM-12 didn't already cover (that gate tested session revocation and identity disablement, not credential deletion specifically).
4. Cleans up the test user unconditionally.

## 4. What remains open (deferred, not started)

1. **Everything CP/Trade/ERP/CMS/Pulse own**: their own decision/domain audit, none of which is `baobab-iam` code.
2. **OpenTelemetry tracing** (§63-67, §167-170) — needs a trace collector and cross-service propagation convention at the infrastructure layer; nothing to configure inside a Keycloak realm export for this.
3. **SIEM integration** (§127-130) — explicitly `baobab-platform/infrastructure`/Security-owned; not attached to this session.
4. **Differentiated retention classes / `eventsExpiration`** (§86-91) — the realm currently has no `eventsExpiration` set (unlimited retention by Keycloak's own default). Deliberately **not** set here: the ADR itself says "Exact SLOs SHALL be defined operationally" — picking a specific retention duration is a real operational/compliance policy decision, not something to invent unilaterally. Flagged for an explicit decision, not guessed at.
5. **A unified authentication failure reason-code taxonomy** (§26) — Keycloak's own native `error` field on login-failure events already carries equivalent values (`invalid_client_credentials`, `user_disabled`, `resolve_required_actions`, etc., confirmed directly from this repo's own CI logs) — building a redundant, centrally-governed reason-code registry on top of what Keycloak already emits natively was judged low-value and was not done.
6. **Non-admin event redaction** — this gate only proved redaction for *admin* events (the ones carrying full request-body representations via `adminEventsDetailsEnabled`). Ordinary user-facing events (`LOGIN`, `UPDATE_PASSWORD`, etc.) don't carry comparable raw-body representations in the same way, so the leak surface is much smaller, but this wasn't independently verified.
7. **Investigation tooling, dashboards, alerting, anomaly detection** (§115-146, §182) — operational/product tooling, entirely unstarted.
