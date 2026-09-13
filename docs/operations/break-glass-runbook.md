# IAM Break-Glass Runbook

**Governing spec:** `ADR-0009 — Workforce SSO and Privileged Access` §53-58 ("Break-Glass Access",
"Break-Glass Requirements", "Break-Glass Flow", "Break-Glass SHALL Not Bypass Domain Governance
Indefinitely", "Privileged Access Approval", "Self-Grant Prohibition"); `ADR-0002 — Keycloak as the
Baobab Identity Provider` §30-31 ("Privileged Authentication", "Bootstrap Administrator");
`ADR-0018 — IAM Availability, Backup, Recovery and Disaster Resilience` §84 ("Bootstrap Account")
**Owner of this document:** `nabhold/baobab-iam`

This is a third, distinct document from
[`security-incident-runbook.md`](./security-incident-runbook.md) and
[`disaster-recovery-runbook.md`](./disaster-recovery-runbook.md). Both of those assume the
`baobab` realm's own governed administrators (humans holding `iam:security-admin`/
`iam:helpdesk`, authenticating via the SSO flow Gate IAM-5/IAM-11 built) can still log in and act.
This document is for the case where they cannot: the `baobab` realm's own admin path is itself
unavailable — a misconfigured authentication flow rejects every login, every governed admin
identity is locked out or disabled, federation to an upstream IdP is down, or the realm
configuration itself needs emergency repair. ADR-0009 §53 lists exactly these scenarios (IAM
configuration failure, federation outage, administrative lockout, severe incident, disaster
recovery).

---

## 1. The mechanism: the master realm's bootstrap administrator

`baobab-iam` does not build a bespoke break-glass credential or emergency-token mechanism.
ADR-0009 §56 explicitly warns against "an invisible permanent bypass", and ADR-0018 §221's
production-readiness checklist independently requires "no universal emergency token exists" — so
this repo reuses a mechanism Keycloak itself already provides and separates by design: the
**master realm's bootstrap administrator** (`KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD` today, the
non-deprecated `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD` going forward — see
`docker-compose.yml` and `scripts/bootstrap.sh`).

This satisfies ADR-0009 §54's requirements structurally, not just procedurally:

- **Separately stored** — the master realm is a completely different realm from `baobab`; a
  lockout, misconfiguration, or compromise confined to the `baobab` realm's own authentication
  flow, roles, or federation cannot touch it.
- **Strongly protected** — in production this credential SHALL be issued through the platform
  secret-management boundary (ADR-0002 §25, the same boundary `scripts/bootstrap.sh` already
  documents for workload client secrets), never the `docker-compose.yml` default
  (`KEYCLOAK_ADMIN_PASSWORD:-admin123}`, which exists only for local development and CI).
- **Rarely used / not routine** — ADR-0002 §31 ("Bootstrap Administrator") and §30 ("Privileged
  Authentication ... not be used for routine administration") both say so directly. Routine IAM
  administration is done by governed `baobab`-realm humans holding `iam:security-admin`/
  `iam:helpdesk` via the SSO flow (Gate IAM-5/IAM-11), with MFA enforced (`iam:mfa-required`).
  The bootstrap admin's only *routine* use today is `scripts/bootstrap.sh`'s own non-interactive
  realm/client provisioning at deploy time — a human should not be logging in as it day to day.

## 2. Verified: break-glass actions are captured by the `baobab` realm's own existing audit trail

This was verified directly against a real Keycloak 26.7.3 instance rather than assumed: an action
taken against the `baobab` realm by a token issued from the **master** realm (i.e., exactly what
using this break-glass path looks like) is recorded in the `baobab` realm's own `admin-events` —
the same audit mechanism Gate IAM-13 already proved captures and redacts routine admin actions —
with no new code or configuration needed (`config/realm/baobab-realm.json` already has
`adminEventsEnabled`/`adminEventsDetailsEnabled` set to `true`).

The distinguishing signal is `authDetails.realmId` on the event: for a routine action by a
`baobab`-realm governed admin it equals the `baobab` realm's own id; for any action authenticated
from the master realm — break-glass use included — it equals the **master** realm's id instead.

That signal alone is **not** specific to break-glass, though: `scripts/bootstrap.sh` also
authenticates as this same master-realm bootstrap administrator and runs against `baobab` on every
container start (its client-scope/client provisioning loops), so a raw `authDetails.realmId !=
baobab` query also returns that routine automation, not just emergency use. Narrowing by
`resourceType` removes the bulk of it — verified directly against a real Keycloak instance:
`scripts/bootstrap.sh`'s own routine actions are exclusively `CLIENT` and `CLIENT_SCOPE`
`CREATE` events, while every break-glass example in §3 step 4 above (re-enabling/resetting a user,
repairing the realm's `browserFlow`, disabling an identity provider) is a `USER`, `REALM`, or
`IDENTITY_PROVIDER` event instead:

```bash
BAOBAB_REALM_ID=$(kcadm.sh get realms/baobab -r baobab | jq -r '.id')
kcadm.sh get admin-events -r baobab \
  -q resourceTypes=USER -q resourceTypes=REALM -q resourceTypes=IDENTITY_PROVIDER \
  | jq --arg id "$BAOBAB_REALM_ID" '[.[] | select(.authDetails.realmId != $id)]'
```

(`resourceTypes` takes repeated `-q` flags, one per value — a single comma-joined value is
rejected by the Admin API with a 500, confirmed against a real Keycloak instance.)

This still is not a perfect discriminator: a `REALM` event also fires for
`reconcile_step_up_flow`'s realm-attribute patch (`scripts/bootstrap.sh`), but that one is a
one-time, easily time-correlated event (it only ever fires once per environment, at this
repository's Gate IAM-5 phase 3 rollout, then never again — the function is idempotent and skips
on every subsequent run) rather than ongoing routine noise like `CLIENT`/`CLIENT_SCOPE`. An
incident review cross-checks any `REALM` hit's timestamp against deployment history before
treating it as break-glass. The fully precise fix — a dedicated automation identity for
`scripts/bootstrap.sh`, separate from the break-glass credential, so routine provisioning never
shares `authDetails.realmId` with actual emergency use at all — is future work (§4 below), not
built here.

The query above returns the break-glass actions taken against `baobab` from outside it, modulo
that residual overlap — this is what an incident review (§5 below) or a routine access review
runs to confirm the break-glass path was not used outside a declared incident window.

## 3. Break-glass flow (ADR-0009 §55)

1. **Confirm normal privileged login is genuinely unavailable** — a single governed admin being
   locked out is `security-incident-runbook.md` §2 ("a single identity's credential is
   compromised") territory, not break-glass; escalate to break-glass only when the `baobab`
   realm's admin path itself is unusable (every governed admin locked out, the browser
   authentication flow itself broken, federation down and no local governed admin can log in).
2. **Declare the incident and get approval before retrieving the credential** (ADR-0009 §57-58,
   ADR-0002 §30's "auditable" requirement) — this repository has no approval-workflow tooling for
   this; the control is procedural: the person retrieving the break-glass credential from
   secret storage SHOULD NOT be the same person who declares the incident, where the
   organization has more than one person available to do so (§58's self-grant prohibition —
   nobody escalates their own access unilaterally and silently).
3. **Retrieve the bootstrap administrator credential** from the platform secret-management
   boundary (ADR-0002 §25) and authenticate to the **master** realm — never to `baobab` directly,
   since by construction the incident means `baobab`'s own admin path may not be trustworthy.
4. **Take the minimum emergency action needed to restore governed access to `baobab`** — examples,
   least-invasive first:
   - Re-enable or reset a locked-out governed admin's `baobab`-realm user directly
     (`PUT /admin/realms/baobab/users/{id}` with `{"enabled": true}`, or
     `PUT .../users/{id}/reset-password`).
   - Repair a broken authentication flow binding
     (`PUT /admin/realms/baobab` with `browserFlow` restored to `"Baobab browser"`, per
     `tests/integration/run.sh` §15's own check of that value).
   - Disable a broken identity-provider federation link blocking every login
     (`PUT /admin/realms/baobab/identity-provider/instances/{alias}` with `{"enabled": false}`).
   Do **not** use this path to grant new privileged roles, create new admins, or perform any
   action beyond restoring the normal governed path — ADR-0009 §56's "SHALL not create an
   invisible permanent bypass around ... business authorization" applies to `baobab-cp`/
   ERP/Trade authorization exactly as much as it applies to IAM itself.
5. **Security alert** — notify per this repo's existing incident-escalation practice (same
   audience as `security-incident-runbook.md`'s incidents); do not treat break-glass use as
   routine enough to skip this.
6. **Audit** — run §2's query immediately after the incident, scoped to the incident's time
   window (`dateFrom`/`dateTo`), and attach the result to the incident record. This is the
   authoritative, tamper-evident record of exactly what the break-glass path was used to do.
7. **Credential rotation/reseal** — rotate the bootstrap administrator's password immediately
   after use, whether or not it is believed to have been exposed; ADR-0009 §54's "rotated after
   use where appropriate" and §84 of ADR-0018 both point the same direction. A break-glass
   credential's value is that it is *not* routinely live in anyone's memory or session — using it
   once is exactly the appropriate trigger to rotate it, not evidence that nothing further is
   needed. **Rotating only the secret-manager value is not enough by itself** — verified directly
   against a real Keycloak instance: `KEYCLOAK_ADMIN_PASSWORD`/`KC_BOOTSTRAP_ADMIN_PASSWORD` only
   ever *creates* this account; once it already exists in a persistent database, changing the
   environment variable and restarting the container leaves the old password fully valid and does
   not adopt the new one (confirmed by restarting an instance with a changed value and observing
   the *original* password, not the new one, still authenticate). The actual sequence:
   1. While the old (potentially-exposed) password is still known, authenticate to the **master**
      realm with it one more time and set a new password directly on that same admin user
      (`PUT /admin/realms/master/users/{id}/reset-password` with `"temporary": false`, or
      `kcadm.sh set-password`) — this is the step that actually changes what is live.
   2. Update the secret-management store to the new value immediately afterward, so it matches
      what is now actually live.
   3. Also update the deployment's `KEYCLOAK_ADMIN_PASSWORD`/`KC_BOOTSTRAP_ADMIN_PASSWORD`
      environment variable to the same new value, even though *this* running instance will not
      re-read it — a genuinely fresh redeploy (a wiped or rebuilt database, per
      `disaster-recovery-runbook.md`) uses exactly that variable to *create* this account from
      scratch, so leaving it stale would silently reintroduce the old, retired password on the
      next disaster-recovery rebuild.
8. **Incident review** — confirm governed (`baobab`-realm, MFA-enforced) admin access is fully
   restored and verified working before considering the incident closed; do not leave the
   master-realm bootstrap path as the ongoing way anyone administers `baobab`. This is the
   concrete meaning of ADR-0009 §56's "SHALL not bypass domain governance indefinitely" and
   ADR-0002 §31's "remove / disable bootstrap path where Keycloak's supported operational model
   permits" — where the deployment's operational model still needs the bootstrap env vars present
   at every container start (this repo's current `docker-compose.yml`/`scripts/bootstrap.sh`
   shape), "disable the path" concretely means: rotate its password immediately per step 7, and
   treat any further login to it outside a declared incident as itself an incident.

## 4. What this document does not cover (deferred, not started)

1. **A tested, timed break-glass drill** — like `security-incident-runbook.md` §5.3, this
   procedure has been verified piece-by-piece against a real Keycloak instance (§2 above) but not
   exercised end-to-end as a timed incident drill.
2. **An approval-workflow tool** for §3 step 2 — the two-person control described there is
   procedural only; no tooling in this repo enforces or records it today (the same gap
   `security-incident-runbook.md` §5.1 already records for bulk revocation).
3. **Automated detection of break-glass use outside a declared incident window** — §2's query is
   manual today; wiring it into ADR-0017's alerting is Gate IAM-13-ish territory, not this gate.
4. **A dedicated automation identity for `scripts/bootstrap.sh`**, separate from the master-realm
   bootstrap administrator — §2's `authDetails.realmId` signal only distinguishes break-glass use
   from routine automation because they currently share the same credential; giving routine
   provisioning its own service account would remove that overlap entirely rather than relying on
   `resourceType` filtering and time-correlation to approximate it.
