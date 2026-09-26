# Control Plane Onboarding Entitlements

**Governing specs:**
- `baobab-platform/baobab-cp`, ADR-BCP-017 §§22-24, 39 (the handoff from approval to provisioning, and separation of duties). The operational detail is in baobab-cp's runbook `docs/runbooks/adr-bcp-018-organisation-operations.md` §12.
- `baobab-platform/shared`, `contracts/admission/v1` (the `onboarding:request` and `onboarding:authorise` scopes).
- ADR-0009 §§13, 27, 102-104 (least privilege and a small realm-role namespace).

**Owner of this document:** `baobab-platform/baobab-iam`

An APPROVED admission decision activates nothing. A tenant reaches provisioning only through a TenantOnboardingRequest. One person requests it, and a different person authorises it. This document explains how IAM decides who may do each.

---

## 1. The two responsibilities

| Responsibility | IAM entitlement | Scope | Also required |
|---|---|---|---|
| **Platform Onboarding Operator**: creates, fulfils and cancels onboarding requests | client role `onboarding-requester` of `baobab-control-plane-admin` | `onboarding:request` | realm role `cp:platform-admin` (which brings MFA) and a registered Control Plane principal |
| **Platform Onboarding Approver**: authorises a requested onboarding | client role `onboarding-authoriser` of `baobab-control-plane-admin` | `onboarding:authorise` | the same |
| Admission Reviewer / Admission Decider | none by default | neither | |
| Tenant Administrator | none | neither | baobab-cp refuses them regardless |

Both roles are **client roles**, not realm roles. They are fine-grained Control Plane responsibilities, and the realm-role namespace stays small (ADR-0009 §102-104).

Each role composites `iam:mfa-required`. Neither is a default role, and neither includes `cp:platform-admin`, which must be granted separately. Admission Reviewers and Deciders do not receive either role automatically. Anyone may hold a combination of responsibilities if organisational policy allows it, except the one combination in §3.

The roles are declared in `config/client-roles/baobab-control-plane-admin.json`. `scripts/bootstrap.sh` creates them, and adds them to an existing deployment on its next run.

## 2. Why a role and a scope

Keycloak cannot restrict which users may request an optional client scope. Any user of `baobab-control-plane-admin` can therefore obtain a token whose `scope` claim says `onboarding:authorise`.

For that reason, baobab-cp honours an onboarding scope only when the token also carries the matching client role in `resource_access.baobab-control-plane-admin.roles`. The scope says what the login asked for; the role says what the person is entitled to do.

Each onboarding scope also adds `aud=baobab-control-plane`, which is the audience baobab-cp's admin verifier requires. Tokens without a Control Plane scope carry no Control Plane audience.

## 3. Toxic combination: never both roles

`onboarding-requester` and `onboarding-authoriser` must not be held by the same person, whether directly, through a group or subgroup, or through a composite role. `config/governance/role-policy.json` records this rule, and also records that each role requires `cp:platform-admin`.

Keycloak cannot refuse such an assignment itself, so `scripts/check-role-policy.sh` checks the running realm:

```bash
KC_URL=https://identity.example.com KEYCLOAK_ADMIN=... KEYCLOAK_ADMIN_PASSWORD=... \
  ./scripts/check-role-policy.sh
```

The script exits 0 when there are no violations and 1 when there are, printing one `VIOLATION:` line per person or composite role. It exits 2 if the check could not run. The integration suite (`tests/integration/run.sh` §22) runs it against a compliant assignment and against both kinds of violation.

**Run it after every privileged assignment, and on a schedule.**

- **If a person holds both roles:** remove the role that does not match their assigned responsibility, then re-run the check. Until the role is removed, baobab-cp's per-request separation of duties is the only remaining defence. The database refuses a request authorised by its own requester, so that person can never authorise their own request. It is a defence, not a reason to leave the violation in place.
- **If an onboarding role is held without `cp:platform-admin`:** the entitlement does nothing, because the routes are for platform administrators only. Remove the role, or grant `cp:platform-admin` through the normal privileged-access approval (ADR-0009 §57-58).
- **If a composite role contains an onboarding role:** remove it from the composite. Onboarding roles are assigned directly or through a group, so every holder is a deliberate decision.

## 4. Granting and revoking

Grant or revoke an onboarding role through the Keycloak admin console or API, under the privileged-access approval process (ADR-0009 §57-58, with no self-grant). Then run `check-role-policy.sh`.

A token already issued keeps its roles until it expires; workforce access tokens are short-lived. For an urgent revocation, also end the person's sessions (ADR-0016).

## 5. Transitional by design

IAM role bundles are the **transitional** way these responsibilities are enforced. Under ADR-BCP-020 they become Control Plane `AdministrativeGrant`s, each with a permission, scope, validity, conditions, delegation and a separation-of-duties policy. The toxic combination above then becomes a formal AdministrativeGrant constraint.

The Shared scope names `onboarding:request` and `onboarding:authorise` will not change when that happens.
