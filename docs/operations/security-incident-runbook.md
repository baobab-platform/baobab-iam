# IAM Security Incident Runbook

**Governing spec:** `docs/adr/Consolidated-Technical-Specification.md` §219 ("Gate IAM-16 —
Production Hardening"), checklist item "incident runbooks"
**Owner of this document:** `baobab-platform/baobab-iam`

This is deliberately a different document from
[`disaster-recovery-runbook.md`](./disaster-recovery-runbook.md): that one is for
infrastructure loss (Keycloak/database/site failure). This one is for a **security incident**
— a credential, session, or identity that is confirmed or suspected compromised while
`baobab-iam` itself is healthy and running. Every action below reuses primitives Gates
IAM-11/12/13 already built and proved against a real Keycloak instance; this document is the
first place they're assembled into an incident-response playbook rather than left as
individually-tested capabilities.

---

## 1. Scope

Covers three incident shapes:

1. A specific workforce/customer identity's credential is confirmed or suspected compromised
   (phished password, leaked credential, suspicious login).
2. A workload client's secret is confirmed or suspected compromised (leaked in a log, a commit,
   a misconfigured service).
3. A suspected mass-compromise event (many identities affected, e.g., a credential-stuffing
   campaign succeeding at scale, or an admin account takeover).

Does **not** cover: infrastructure/database/site loss (see the DR runbook), or business-layer
fraud/abuse that doesn't involve an IAM credential or session (that's the owning
domain engine's incident response, not `baobab-iam`'s).

## 2. Incident: a single identity's credential is compromised

This is Gate IAM-12's "kill switch" (`tests/integration/run.sh` §16), used for real:

1. **Disable the identity first** — `PUT /admin/realms/baobab/users/{id}` with
   `{"enabled": false}`. This order matters: if sessions were revoked first while the identity
   stays enabled, an attacker still holding the compromised password can simply log in again
   before the next step completes, obtaining a fresh session and access token. Disabling first
   closes that window — per ADR-0016 §211 ("DISABLED identity + valid token = DENY" from the
   IAM side), this prevents any *new* authentication; it does not itself invalidate an
   already-issued, still-valid access token still being accepted downstream — the affected
   engine(s) enforce that from their own side (short-lived-token expiry, or their own
   revocation-check against IAM).
2. **Then revoke sessions** — `POST /admin/realms/baobab/users/{id}/logout`. Ends every active
   session for that identity now that no new one can replace it.
3. **Delete the compromised credential** — `DELETE
   /admin/realms/baobab/users/{id}/credentials/{credentialId}` (find the credential ID via
   `GET /admin/realms/baobab/users/{id}/credentials`, filtering `type == "password"`). Gate
   IAM-13's test (`tests/integration/run.sh` §17) already proves credential deletion is
   captured in the admin-event audit trail.
4. **Re-enable only after a new credential is set** — reset the password via `PUT
   /admin/realms/baobab/users/{id}/reset-password` with a new value and `temporary: true`
   (forces the user to set their own password on next login), then re-enable the identity.
5. **Pull the audit trail** — `GET /admin/realms/baobab/admin-events?resourceTypes=USER
   &resourcePath=users/{id}` gives a complete, timestamped record of steps 1-4 for the incident
   report. Gate IAM-13 already proved this record never contains the plaintext password,
   old or new, so it's safe to attach directly to an incident ticket.
6. **If the identity holds a privileged role** (any role compositing in `iam:mfa-required` —
   see Gate IAM-11): treat as the mass-compromise procedure below as well, since a privileged
   account takeover risks having been used to create or modify other identities/roles/clients.

## 3. Incident: a workload client's secret is compromised

1. **Disable the client immediately** — `PUT /admin/realms/baobab/clients/{uuid}` with
   `{"enabled": false}`. Gate IAM-4's test (`tests/integration/run.sh` §8) already proves this
   independently revokes only that client's ability to obtain tokens — other workload clients
   are unaffected (ADR-0007's independent-revocation requirement).
2. **Rotate the secret** — follow
   [`client-secret-rotation.md`](./client-secret-rotation.md) steps 1-4 (capture the old
   secret, generate and set a new one, deploy it to the workload). **Do not run that
   document's step 5 (verification) yet** — the client is still disabled, so every check in
   it would fail regardless of whether rotation actually worked.
3. **Re-enable** once the affected system(s) have the new secret deployed — `PUT
   /admin/realms/baobab/clients/{uuid}` with `{"enabled": true}`.
4. **Now run `client-secret-rotation.md`'s step 5** (verify the new secret works and the old
   one is rejected) — this only produces a meaningful result once the client is enabled again.
5. **Audit** — the same `admin-events` query as step 5 in §2 above, scoped to
   `resourceTypes=CLIENT`.
6. **Check for tokens already issued** with the compromised secret before it was disabled —
   these remain valid until natural expiry (`accessTokenLifespan: 900` seconds, per
   `config/realm/baobab-realm.json`); the consuming resource server (`baobab-cp`, an engine)
   is responsible for its own short-lived-token exposure window, matching ADR-0018 §92's
   principle that IAM health doesn't by itself guarantee downstream safety.

## 4. Incident: suspected mass compromise

1. **Do not disable the entire realm** — `baobab-iam` has no "pause all authentication" switch,
   and building one is explicitly out of scope (ADR-0002/ADR-0009's "no universal
   authentication bypass or emergency token" invariant, re-affirmed by
   §221's "no universal emergency token exists" production-readiness checklist item — a
   platform-wide kill switch would itself be exactly that kind of bypass).
2. **Identify the blast radius first**: query `admin-events` for the suspected window
   (`dateFrom`/`dateTo` query params) filtered to `operationTypes=CREATE,UPDATE,DELETE` and
   the relevant `resourceTypes` (`USER`, `CLIENT`, `REALM_ROLE_MAPPING`) to see exactly which
   identities/clients/roles were touched.
3. **Apply §2 or §3's procedure per affected identity/client** — there is no bulk kill-switch
   endpoint in this repo's tooling today; each affected identity/client is revoked
   individually via the Admin API. (A genuinely large-scale incident may need a
   scripted loop over the Admin API rather than manual per-identity action — no such script
   exists in this repo yet; writing one against a real incident's actual shape, rather than a
   hypothetical one, is deferred.)
4. **If a privileged admin identity was the entry point**: also audit every role grant and
   client created or modified during the suspected window (same `admin-events` query as step
   2) — a compromised admin account's most severe risk is what *else* it did while it had
   access, not just its own subsequent misuse.
5. **Escalate for a security review of `baobab-cp`, `baobab-trade`/`baobab-erp`/etc.** once IAM
   containment is complete — a compromised identity's downstream authorization grants,
   sessions, and data access are those systems' own incident response, not `baobab-iam`'s.

## 5. What this runbook does not cover (deferred, not started)

1. **A scripted bulk-revocation tool** for the mass-compromise case (§4.3) — no such tooling
   exists; building one against a real incident's actual constraints, rather than a guessed
   shape, is deferred.
2. **Automated anomaly detection** that would trigger this runbook proactively (e.g., detecting
   a credential-stuffing pattern before a human notices) — ADR-0017 §115-146/§182 territory,
   explicitly deferred in Gate IAM-13's own scope doc.
3. **A tested, timed incident-response drill** — this runbook has not been exercised end-to-end
   against a real (non-production) realm; per ADR-0018 §118's "RPO/RTO are tested objectives"
   principle applied to security incidents generally, an untested runbook is a draft, not a
   proven procedure.
